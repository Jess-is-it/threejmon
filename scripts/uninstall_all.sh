#!/usr/bin/env bash
set -euo pipefail

HOST_REPO=${1:-/opt/threejnotif}

# Stop and remove all containers/images/volumes.
if command -v docker >/dev/null 2>&1; then
  docker rm -f $(docker ps -aq) 2>/dev/null || true
  docker system prune -a -f || true
  docker volume prune -f || true
fi

# Remove app files.
rm -rf "$HOST_REPO" || true

# Uninstall Docker packages (Ubuntu/Debian).
if command -v apt-get >/dev/null 2>&1; then
  apt-get purge -y docker.io docker-ce docker-ce-cli containerd.io docker-compose-plugin || true
  apt-get autoremove -y --purge || true
  rm -rf /var/lib/docker /var/lib/containerd /etc/docker || true
fi

# Last note: systemd will stop docker services if still running.
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop docker || true
  systemctl disable docker || true
fi

printf "Uninstall complete.\n"
