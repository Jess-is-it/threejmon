#!/usr/bin/env bash
set -euo pipefail

APP_USER=${THREEJ_APP_USER:-threejnotif}
INSTALL_DIR=${THREEJ_INSTALL_DIR:-/opt/threejnotif}
PORT=${THREEJ_PORT:-8000}
REPO_URL=${THREEJ_REPO_URL:-}

log() {
  printf "%s\n" "$*"
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    log "This installer needs sudo/root. Re-run with sudo."
    exit 1
  fi
}

detect_pkg_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
    return
  fi
  if command -v dnf >/dev/null 2>&1; then
    echo "dnf"
    return
  fi
  if command -v yum >/dev/null 2>&1; then
    echo "yum"
    return
  fi
  echo "unknown"
}

install_packages() {
  local pkg_mgr=$1
  case "$pkg_mgr" in
    apt)
      apt-get update -y
      apt-get install -y curl git ca-certificates
      ;;
    dnf)
      dnf -y install curl git ca-certificates
      ;;
    yum)
      yum -y install curl git ca-certificates
      ;;
    *)
      log "Unsupported package manager. Install curl/git manually."
      exit 1
      ;;
  esac
}

ensure_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    log "Docker not found. Installing Docker..."
    curl -fsSL https://get.docker.com | sh
  fi
}

ensure_compose() {
  if docker compose version >/dev/null 2>&1; then
    return
  fi
  log "Docker Compose plugin not found. Installing..."
  mkdir -p /usr/local/lib/docker/cli-plugins
  curl -fsSL https://github.com/docker/compose/releases/download/v2.29.7/docker-compose-linux-x86_64 \
    -o /usr/local/lib/docker/cli-plugins/docker-compose
  chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
}

ensure_user() {
  if ! id "$APP_USER" >/dev/null 2>&1; then
    log "Creating system user $APP_USER..."
    useradd --system --create-home --shell /bin/bash "$APP_USER"
  fi
  usermod -aG docker "$APP_USER" >/dev/null 2>&1 || true
}

check_port() {
  if command -v ss >/dev/null 2>&1; then
    if ss -lnt | awk '{print $4}' | grep -q ":${PORT}$"; then
      log "Port ${PORT} is already in use. Set THREEJ_PORT to a free port."
      exit 1
    fi
  fi
}

clone_repo() {
  if [ -z "$REPO_URL" ]; then
    log "THREEJ_REPO_URL is required."
    exit 1
  fi
  if [ ! -d "$INSTALL_DIR/.git" ]; then
    log "Cloning repository to $INSTALL_DIR..."
    rm -rf "$INSTALL_DIR"
    git clone "$REPO_URL" "$INSTALL_DIR"
  else
    log "Repository already present at $INSTALL_DIR."
  fi
  chown -R "$APP_USER:$APP_USER" "$INSTALL_DIR"
}

run_compose() {
  log "Starting services..."
  cd "$INSTALL_DIR"
  mkdir -p data
  chown -R "$APP_USER:$APP_USER" data
  docker compose up -d --build
}

main() {
  require_root
  pkg_mgr=$(detect_pkg_manager)
  install_packages "$pkg_mgr"
  ensure_docker
  ensure_compose
  ensure_user
  check_port
  clone_repo
  run_compose
  log "ThreeJ Notifier Suite is starting on port ${PORT}."
}

main "$@"
