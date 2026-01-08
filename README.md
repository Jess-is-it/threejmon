# ThreeJ Notifier Suite

Unified web portal for Optical, RTO, and ISP Ping notifications.

## Quick Start (local build)

```bash
cd threejnotif-portal
docker compose up -d --build
```

Open `http://localhost:8000` and configure settings in the portal.

## One-line install (remote server)

Host this repository in Git, then run:

```bash
curl -fsSL https://your-host/install.sh | sudo THREEJ_REPO_URL=https://your-host/threejnotif-portal.git bash
```

Options:
- `THREEJ_REPO_URL`: Git clone URL
- `THREEJ_INSTALL_DIR`: install directory (default `/opt/threejnotif`)
- `THREEJ_APP_USER`: service user (default `threejnotif`)
- `THREEJ_PORT`: host port (default `8000`)

## Notes
- Settings and runtime state are stored in `./data/threejnotif.db` on the host.
- Ensure the server can reach GenieACS, the SSH host, and Telegram.
