import hashlib
import logging
import socket


logger = logging.getLogger(__name__)


def _encode_word(word):
    data = word.encode("utf-8")
    length = len(data)
    if length < 0x80:
        return bytes([length]) + data
    if length < 0x4000:
        length |= 0x8000
        return bytes([(length >> 8) & 0xFF, length & 0xFF]) + data
    if length < 0x200000:
        length |= 0xC00000
        return bytes(
            [
                (length >> 16) & 0xFF,
                (length >> 8) & 0xFF,
                length & 0xFF,
            ]
        ) + data
    if length < 0x10000000:
        length |= 0xE0000000
        return bytes(
            [
                (length >> 24) & 0xFF,
                (length >> 16) & 0xFF,
                (length >> 8) & 0xFF,
                length & 0xFF,
            ]
        ) + data
    return bytes([0xF0]) + length.to_bytes(4, "big") + data


def _read_length(sock):
    first = sock.recv(1)
    if not first:
        raise ConnectionError("RouterOS API connection closed.")
    value = first[0]
    if value < 0x80:
        return value
    if value < 0xC0:
        second = sock.recv(1)
        return ((value & 0x3F) << 8) + second[0]
    if value < 0xE0:
        second = sock.recv(1)
        third = sock.recv(1)
        return ((value & 0x1F) << 16) + (second[0] << 8) + third[0]
    if value < 0xF0:
        rest = sock.recv(3)
        return ((value & 0x0F) << 24) + (rest[0] << 16) + (rest[1] << 8) + rest[2]
    rest = sock.recv(4)
    return int.from_bytes(rest, "big")


def _read_word(sock):
    length = _read_length(sock)
    if length == 0:
        return ""
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("RouterOS API connection closed while reading word.")
        data += chunk
    return data.decode("utf-8", errors="replace")


class RouterOSClient:
    def __init__(self, host, port, username, password, timeout=5):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self.sock = None

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        self._login()
        return self

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = None

    def _write_sentence(self, words):
        for word in words:
            self.sock.sendall(_encode_word(word))
        self.sock.sendall(b"\x00")

    def _read_sentence(self):
        words = []
        while True:
            word = _read_word(self.sock)
            if word == "":
                break
            words.append(word)
        return words

    def talk(self, words):
        self._write_sentence(words)
        replies = []
        while True:
            sentence = self._read_sentence()
            if not sentence:
                continue
            replies.append(sentence)
            if sentence[0] in ("!done", "!trap"):
                break
        return replies

    def _login(self):
        replies = self.talk(["/login", f"=name={self.username}", f"=password={self.password}"])
        for sentence in replies:
            if sentence[0] == "!trap":
                raise RuntimeError(f"RouterOS login failed: {sentence}")
            if sentence[0] == "!done":
                for word in sentence[1:]:
                    if word.startswith("=ret="):
                        challenge = word.split("=", 2)[2]
                        self._login_challenge(challenge)
                return

    def _login_challenge(self, challenge):
        challenge_bytes = bytes.fromhex(challenge)
        md5 = hashlib.md5(b"\x00" + self.password.encode("utf-8") + challenge_bytes).hexdigest()
        response = f"00{md5}"
        replies = self.talk(["/login", f"=name={self.username}", f"=response={response}"])
        for sentence in replies:
            if sentence[0] == "!trap":
                raise RuntimeError(f"RouterOS login challenge failed: {sentence}")

    def list_address_list(self):
        replies = self.talk(["/ip/firewall/address-list/print"])
        entries = []
        for sentence in replies:
            if sentence[0] != "!re":
                continue
            data = {}
            for word in sentence[1:]:
                if not word:
                    continue
                if word.startswith("="):
                    word = word[1:]
                if "=" in word:
                    key, value = word.split("=", 1)
                    data[key] = value
            entries.append(data)
        return entries

    def add_address_list(self, list_name, address, comment):
        replies = self.talk(
            [
                "/ip/firewall/address-list/add",
                f"=list={list_name}",
                f"=address={address}",
                f"=comment={comment}",
            ]
        )
        for sentence in replies:
            if sentence[0] == "!trap":
                raise RuntimeError(f"RouterOS add failed: {sentence}")

    def remove_address_list(self, entry_id):
        replies = self.talk(["/ip/firewall/address-list/remove", f"=.id={entry_id}"])
        for sentence in replies:
            if sentence[0] == "!trap":
                raise RuntimeError(f"RouterOS remove failed: {sentence}")

    def set_address_list_comment(self, entry_id, comment):
        replies = self.talk(["/ip/firewall/address-list/set", f"=.id={entry_id}", f"=comment={comment}"])
        for sentence in replies:
            if sentence[0] == "!trap":
                raise RuntimeError(f"RouterOS set failed: {sentence}")


def reconcile_address_lists(client, desired_entries, comment_tag):
    existing = client.list_address_list()
    desired_keyed = {(entry["list"], entry["address"]): entry for entry in desired_entries}
    existing_keyed = {}
    for entry in existing:
        list_name = entry.get("list")
        address = entry.get("address")
        comment = entry.get("comment") or ""
        entry_id = entry.get(".id")
        if not list_name or not address or not entry_id:
            continue
        existing_keyed[(list_name, address)] = {
            "id": entry_id,
            "comment": comment,
        }

    actions = {"added": 0, "removed": 0, "updated": 0, "skipped": 0}
    warnings = []
    for key, desired in desired_keyed.items():
        if key in existing_keyed:
            entry = existing_keyed[key]
            if entry["comment"] == comment_tag:
                continue
            if not entry["comment"]:
                client.set_address_list_comment(entry["id"], comment_tag)
                actions["updated"] += 1
            else:
                warnings.append(f"Existing address-list {key[0]} {key[1]} has comment '{entry['comment']}', skipped.")
                actions["skipped"] += 1
        else:
            client.add_address_list(desired["list"], desired["address"], comment_tag)
            actions["added"] += 1

    for key, entry in existing_keyed.items():
        if entry["comment"] != comment_tag:
            continue
        if key not in desired_keyed:
            client.remove_address_list(entry["id"])
            actions["removed"] += 1

    return actions, warnings
