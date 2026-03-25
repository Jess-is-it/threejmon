#!/usr/bin/env bash
set -euo pipefail

APP_USER=${THREEJ_APP_USER:-threejnotif}
INSTALL_DIR=${THREEJ_INSTALL_DIR:-/opt/threejnotif}
BRANCH=${THREEJ_BRANCH:-}
REPO_URL=${THREEJ_REPO_URL:-}
GIT_USER=${THREEJ_GIT_USER:-${SUDO_USER:-$APP_USER}}
SKIP_REBUILD=${THREEJ_SKIP_REBUILD:-0}
FORCE_REBUILD=${THREEJ_FORCE_REBUILD:-0}

log() {
  printf "%s\n" "$*"
}

fail() {
  log "$*"
  exit 1
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    fail "This updater needs sudo/root. Re-run with sudo."
  fi
}

ensure_prereqs() {
  command -v git >/dev/null 2>&1 || fail "git is required."
  command -v docker >/dev/null 2>&1 || fail "docker is required."
  docker compose version >/dev/null 2>&1 || fail "docker compose plugin is required."
}

ensure_repo() {
  if [ ! -d "${INSTALL_DIR}/.git" ]; then
    fail "No existing install was found at ${INSTALL_DIR}. Run install.sh on a fresh server first."
  fi
}

resolve_git_user() {
  if ! id "${GIT_USER}" >/dev/null 2>&1; then
    GIT_USER=root
    GIT_HOME=/root
    return
  fi
  GIT_HOME=$(getent passwd "${GIT_USER}" | cut -d: -f6)
  if [ -z "${GIT_HOME}" ] || [ ! -d "${GIT_HOME}" ]; then
    GIT_USER=root
    GIT_HOME=/root
    return
  fi
  if [ "${GIT_USER}" != "root" ]; then
    if command -v runuser >/dev/null 2>&1; then
      if ! runuser -u "${GIT_USER}" -- test -w "${INSTALL_DIR}/.git"; then
        GIT_USER=root
        GIT_HOME=/root
      fi
    elif [ ! -w "${INSTALL_DIR}/.git" ]; then
      GIT_USER=root
      GIT_HOME=/root
    fi
  fi
}

run_as_git_user() {
  if [ "${GIT_USER}" = "root" ]; then
    "$@"
    return
  fi
  if command -v runuser >/dev/null 2>&1; then
    runuser -u "${GIT_USER}" -- env HOME="${GIT_HOME}" USER="${GIT_USER}" LOGNAME="${GIT_USER}" "$@"
    return
  fi
  local quoted=""
  local arg
  for arg in "$@"; do
    quoted+=" $(printf '%q' "${arg}")"
  done
  su -s /bin/bash "${GIT_USER}" -c "HOME=$(printf '%q' "${GIT_HOME}") USER=$(printf '%q' "${GIT_USER}") LOGNAME=$(printf '%q' "${GIT_USER}")${quoted}"
}

git_repo() {
  run_as_git_user git -c safe.directory="${INSTALL_DIR}" -C "${INSTALL_DIR}" "$@"
}

detect_branch() {
  if [ -n "${BRANCH}" ]; then
    return
  fi
  BRANCH=$(git_repo rev-parse --abbrev-ref HEAD 2>/dev/null || true)
  if [ -z "${BRANCH}" ] || [ "${BRANCH}" = "HEAD" ]; then
    BRANCH=master
  fi
}

ensure_clean_repo() {
  local tracked_status
  tracked_status=$(git_repo status --short --untracked-files=no)
  if [ -n "${tracked_status}" ]; then
    log "Tracked local changes were found in ${INSTALL_DIR}:"
    printf "%s\n" "${tracked_status}"
    fail "Update stopped. Commit or stash local changes first."
  fi
}

write_version_file() {
  local version version_date
  version=$(git_repo rev-parse --short HEAD 2>/dev/null || echo "unknown")
  version_date=$(git_repo log -1 --format=%cs 2>/dev/null || echo "unknown")
  printf "%s %s" "${version}" "${version_date}" > "${INSTALL_DIR}/.threej_version"
}

run_update() {
  local source_ref old_commit new_commit
  source_ref=origin
  if [ -n "${REPO_URL}" ]; then
    source_ref="${REPO_URL}"
    log "Using override repo URL: ${REPO_URL}"
  fi

  old_commit=$(git_repo rev-parse HEAD)
  log "Fetching ${BRANCH}..."
  git_repo fetch "${source_ref}" "${BRANCH}"
  log "Pulling latest ${BRANCH}..."
  git_repo pull --ff-only "${source_ref}" "${BRANCH}"
  new_commit=$(git_repo rev-parse HEAD)

  write_version_file

  if [ "${SKIP_REBUILD}" = "1" ]; then
    log "Repository updated to $(git_repo rev-parse --short HEAD). Rebuild skipped by THREEJ_SKIP_REBUILD=1."
    return
  fi

  if [ "${old_commit}" = "${new_commit}" ] && [ "${FORCE_REBUILD}" != "1" ]; then
    log "Already up to date at $(git_repo rev-parse --short HEAD). Skipping rebuild."
    return
  fi

  log "Rebuilding services..."
  cd "${INSTALL_DIR}"
  mkdir -p data
  chown -R "${APP_USER}:${APP_USER}" data >/dev/null 2>&1 || true
  THREEJ_VERSION=$(git_repo rev-parse --short HEAD 2>/dev/null || echo "unknown")
  THREEJ_VERSION_DATE=$(git_repo log -1 --format=%cs 2>/dev/null || echo "unknown")
  export THREEJ_VERSION THREEJ_VERSION_DATE
  export BUILDX_NO_DEFAULT_ATTESTATIONS=1
  docker compose up -d --build
  log "Update complete at ${THREEJ_VERSION}."
}

main() {
  require_root
  ensure_prereqs
  ensure_repo
  resolve_git_user
  detect_branch
  ensure_clean_repo
  run_update
}

main "$@"
