import os
import shlex
import subprocess
import tempfile


def _build_ssh_base(ssh_cfg):
    host = (ssh_cfg.get("host") or "").strip()
    port = str(int(ssh_cfg.get("port", 22) or 22))
    user = (ssh_cfg.get("user") or "").strip()
    use_key = bool(ssh_cfg.get("use_key", False))
    key_path = (ssh_cfg.get("key_path") or "").strip()
    base = [
        "ssh",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "ConnectTimeout=10",
        "-p",
        port,
    ]
    if use_key and key_path:
        base.extend(["-i", key_path, "-o", "IdentitiesOnly=yes"])
    return base, f"{user}@{host}"


def run_ssh_command(ssh_cfg, remote_command):
    password = (ssh_cfg.get("password") or "").strip()
    remote_command = (remote_command or "").strip()
    if not remote_command:
        raise RuntimeError("Radius list command is empty.")
    base, target = _build_ssh_base(ssh_cfg)
    if not target or target.startswith("@"):
        raise RuntimeError("Radius SSH host/user is not configured.")

    command = base + [target, remote_command]
    env = os.environ.copy()
    askpass_path = None
    try:
        if password and not bool(ssh_cfg.get("use_key", False)):
            fd, askpass_path = tempfile.mkstemp(prefix="askpass_", text=True)
            os.write(fd, b"#!/bin/sh\n")
            os.write(fd, b"echo \"$SSH_PASSWORD\"\n")
            os.close(fd)
            os.chmod(askpass_path, 0o700)
            env["SSH_PASSWORD"] = password
            env["SSH_ASKPASS"] = askpass_path
            env["SSH_ASKPASS_REQUIRE"] = "force"
            env["DISPLAY"] = "dummy"
            command = ["setsid", "-w"] + command

        result = subprocess.run(
            command,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
            check=False,
        )
    finally:
        if askpass_path and os.path.exists(askpass_path):
            os.remove(askpass_path)

    if result.returncode != 0:
        err = (result.stderr or "").strip()
        raise RuntimeError(f"radius ssh failed: {err or 'unknown error'}")
    return result.stdout or ""


def parse_radius_lines(text):
    out = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        user = ""
        status = ""
        if "," in line:
            parts = [p.strip() for p in line.split(",", 1)]
            user = parts[0]
            status = parts[1] if len(parts) > 1 else ""
        elif "|" in line:
            parts = [p.strip() for p in line.split("|", 1)]
            user = parts[0]
            status = parts[1] if len(parts) > 1 else ""
        else:
            parts = line.split()
            user = parts[0].strip() if parts else ""
            status = parts[1].strip() if len(parts) > 1 else ""
        if not user:
            continue
        out[user] = status
    return out


def fetch_radius_accounts(radius_cfg):
    if not isinstance(radius_cfg, dict):
        return {}
    ssh_cfg = radius_cfg.get("ssh") if isinstance(radius_cfg.get("ssh"), dict) else {}
    cmd = (radius_cfg.get("list_command") or "").strip()
    text = run_ssh_command(ssh_cfg, cmd)
    return parse_radius_lines(text)


def _derive_mysql_prefix(list_command: str) -> list[str]:
    cmd = (list_command or "").strip()
    if not cmd:
        raise RuntimeError("Radius list command is empty.")
    try:
        tokens = shlex.split(cmd, posix=True)
    except ValueError:
        raise RuntimeError("Radius list command could not be parsed. Use a simple mysql ... -e \"SQL\" command.")

    if not tokens:
        raise RuntimeError("Radius list command is empty.")

    mysql_idx = 0
    if tokens[0] == "sudo":
        if len(tokens) < 2:
            raise RuntimeError("Radius list command is invalid.")
        mysql_idx = 1

    if tokens[mysql_idx] != "mysql":
        raise RuntimeError("Radius list command must start with mysql (or sudo mysql) to load account details.")

    exec_idx = None
    for i, tok in enumerate(tokens):
        if tok in ("-e", "--execute"):
            exec_idx = i
            break
    if exec_idx is None or exec_idx + 1 >= len(tokens):
        raise RuntimeError("Radius list command must include -e/--execute to load account details.")

    prefix = tokens[:exec_idx]
    for tok in prefix:
        if tok in ("|", "||", "&&", ";"):
            raise RuntimeError("Radius list command must not include pipes/compound shell operators.")
    return prefix


def _mysql_prefix_has_arg(prefix: list[str], *names: str) -> bool:
    for tok in prefix:
        if tok in names:
            return True
        for name in names:
            if tok.startswith(name + "="):
                return True
    return False


def _ensure_mysql_flags(prefix: list[str]) -> list[str]:
    out = list(prefix)
    if "-N" not in out and "--skip-column-names" not in out:
        out.append("-N")
    if "-B" not in out and "--batch" not in out:
        out.append("-B")
    return out


def _ensure_mysql_db(prefix: list[str], default_db: str) -> list[str]:
    out = list(prefix)
    if _mysql_prefix_has_arg(out, "-D", "--database"):
        return out
    for i, tok in enumerate(out):
        if tok and not tok.startswith("-") and tok not in ("sudo", "mysql"):
            return out
    out.append(default_db)
    return out


def _build_mysql_remote_command(prefix: list[str], sql: str) -> str:
    prefix = _ensure_mysql_flags(prefix)
    prefix = _ensure_mysql_db(prefix, "radius_db")
    sql = (sql or "").strip().replace("\n", " ").replace("\r", " ")
    sql = sql.replace('"', '\\"')
    parts = [shlex.quote(p) for p in prefix]
    return " ".join(parts) + f' -e "{sql}"'


def _parse_mysql_tsv(text: str, headers: list[str]) -> list[dict]:
    rows = []
    for raw in (text or "").splitlines():
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < len(headers):
            parts = parts + ([""] * (len(headers) - len(parts)))
        row = {}
        for k, v in zip(headers, parts):
            row[k] = (v or "").strip()
        rows.append(row)
    return rows


def fetch_radius_account_details(radius_cfg: dict, limit: int = 5000) -> list[dict]:
    if not isinstance(radius_cfg, dict):
        return []
    ssh_cfg = radius_cfg.get("ssh") if isinstance(radius_cfg.get("ssh"), dict) else {}
    list_cmd = (radius_cfg.get("list_command") or "").strip()
    prefix = _derive_mysql_prefix(list_cmd)

    limit = int(limit or 0)
    if limit <= 0:
        limit = 5000
    limit = max(min(limit, 50000), 1)

    sql = f"""
      SELECT
        u.username AS username,
        CASE WHEN rej.username IS NOT NULL THEN 'reject' ELSE 'active' END AS status,
        CASE WHEN act.username IS NOT NULL THEN 1 ELSE 0 END AS online,
        IFNULL(act.ip, '') AS ip,
        IFNULL(act.nas_ip, '') AS nas_ip,
        IFNULL(grp.groups, '') AS groups,
        IFNULL(DATE_FORMAT(act.online_since, '%Y-%m-%d %H:%i:%s'), '') AS online_since,
        IFNULL(TIMESTAMPDIFF(SECOND, act.online_since, NOW()), '') AS uptime_sec,
        IFNULL(DATE_FORMAT(ls.last_start, '%Y-%m-%d %H:%i:%s'), '') AS last_start,
        IFNULL(DATE_FORMAT(ls.last_stop, '%Y-%m-%d %H:%i:%s'), '') AS last_stop
      FROM
        (
          SELECT DISTINCT username FROM radcheck WHERE username <> ''
          UNION
          SELECT DISTINCT username FROM radusergroup WHERE username <> ''
        ) u
      LEFT JOIN (
        SELECT DISTINCT username
        FROM radcheck
        WHERE attribute='Auth-Type' AND value='Reject'
      ) rej ON rej.username = u.username
      LEFT JOIN (
        SELECT
          username,
          GROUP_CONCAT(DISTINCT groupname ORDER BY priority, groupname SEPARATOR ', ') AS groups
        FROM radusergroup
        GROUP BY username
      ) grp ON grp.username = u.username
      LEFT JOIN (
        SELECT
          a.username,
          a.framedipaddress AS ip,
          a.nasipaddress AS nas_ip,
          a.acctstarttime AS online_since
        FROM radacct a
        INNER JOIN (
          SELECT username, MAX(acctstarttime) AS max_start
          FROM radacct
          WHERE acctstoptime IS NULL
          GROUP BY username
        ) x ON x.username=a.username AND x.max_start=a.acctstarttime
        WHERE a.acctstoptime IS NULL
      ) act ON act.username = u.username
      LEFT JOIN (
        SELECT username, MAX(acctstarttime) AS last_start, MAX(acctstoptime) AS last_stop
        FROM radacct
        GROUP BY username
      ) ls ON ls.username = u.username
      ORDER BY u.username
      LIMIT {limit}
    """

    remote_cmd = _build_mysql_remote_command(prefix, sql)
    text = run_ssh_command(ssh_cfg, remote_cmd)
    headers = [
        "username",
        "status",
        "online",
        "ip",
        "nas_ip",
        "groups",
        "online_since",
        "uptime_sec",
        "last_start",
        "last_stop",
    ]
    rows = _parse_mysql_tsv(text, headers)
    for row in rows:
        row["online"] = str(row.get("online") or "0").strip() in ("1", "true", "yes")
        uptime = (row.get("uptime_sec") or "").strip()
        row["uptime_sec"] = int(uptime) if uptime.isdigit() else None
    return rows
