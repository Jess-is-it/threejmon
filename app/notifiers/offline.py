import os
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

