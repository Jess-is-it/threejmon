#!/usr/bin/env bash
set -euo pipefail

APP_USER=${THREEJ_APP_USER:-threejnotif}
INSTALL_DIR=${THREEJ_INSTALL_DIR:-/opt/threejnotif}
BRANCH=${THREEJ_BRANCH:-}
REPO_URL=${THREEJ_REPO_URL:-}
GIT_USER=root
SKIP_REBUILD=${THREEJ_SKIP_REBUILD:-0}
FORCE_REBUILD=${THREEJ_FORCE_REBUILD:-0}
TARGET_COMMIT=${THREEJ_TARGET_COMMIT:-}
ALLOW_DIRTY=${THREEJ_ALLOW_DIRTY:-0}
STATUS_FILE=${THREEJ_STATUS_FILE:-${INSTALL_DIR}/data/system_update_status.json}
UPDATE_TRIGGER=${THREEJ_UPDATE_TRIGGER:-manual}
STATUS_TOTAL_STEPS=5
STATUS_CURRENT_STEP=0
STATUS_PHASE=queued
STATUS_STARTED_AT=""
STATUS_UPDATED_AT=""
STATUS_BRANCH=""
STATUS_OLD_COMMIT=""
STATUS_NEW_COMMIT=""
STATUS_REMOTE_URL=""
STATUS_ERROR=""

log() {
  printf "%s\n" "$*"
}

json_escape() {
  printf '%s' "${1:-}" | tr '\r\n' ' ' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

iso_now() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

status_percent() {
  local step total
  step=${1:-0}
  total=${2:-1}
  if [ "${total}" -le 0 ]; then
    total=1
  fi
  printf '%s' "$(( step * 100 / total ))"
}

write_status() {
  mkdir -p "$(dirname "${STATUS_FILE}")"
  STATUS_UPDATED_AT=$(iso_now)
  if [ -z "${STATUS_STARTED_AT}" ]; then
    STATUS_STARTED_AT="${STATUS_UPDATED_AT}"
  fi
  local status phase message runner_id
  status=${1:-running}
  phase=${2:-${STATUS_PHASE}}
  message=${3:-}
  runner_id=${THREEJ_UPDATE_RUNNER_ID:-}
  if [ -z "${runner_id}" ] && [ -f "${STATUS_FILE}" ]; then
    runner_id=$(sed -n 's/.*"runner_id":[[:space:]]*"\([^"]*\)".*/\1/p' "${STATUS_FILE}" | head -n 1)
  fi
  cat > "${STATUS_FILE}.tmp" <<EOF
{
  "status": "$(json_escape "${status}")",
  "phase": "$(json_escape "${phase}")",
  "message": "$(json_escape "${message}")",
  "step_index": ${STATUS_CURRENT_STEP:-0},
  "step_total": ${STATUS_TOTAL_STEPS},
  "percent": $(status_percent "${STATUS_CURRENT_STEP:-0}" "${STATUS_TOTAL_STEPS}"),
  "started_at": "$(json_escape "${STATUS_STARTED_AT}")",
  "updated_at": "$(json_escape "${STATUS_UPDATED_AT}")",
  "branch": "$(json_escape "${STATUS_BRANCH}")",
  "old_commit": "$(json_escape "${STATUS_OLD_COMMIT}")",
  "new_commit": "$(json_escape "${STATUS_NEW_COMMIT}")",
  "remote_url": "$(json_escape "${STATUS_REMOTE_URL}")",
  "trigger": "$(json_escape "${UPDATE_TRIGGER}")",
  "runner_id": "$(json_escape "${runner_id}")",
  "error": "$(json_escape "${STATUS_ERROR}")"
}
EOF
  mv "${STATUS_FILE}.tmp" "${STATUS_FILE}"
}

set_phase() {
  STATUS_CURRENT_STEP=${1:-0}
  STATUS_PHASE=${2:-running}
  write_status "running" "${STATUS_PHASE}" "${3:-}"
}

fail() {
  STATUS_ERROR=${1:-Update failed.}
  write_status "failed" "${STATUS_PHASE}" "${STATUS_ERROR}"
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

repair_git_store() {
  if [ ! -d "${INSTALL_DIR}/.git" ]; then
    return
  fi
  chown -R root:root "${INSTALL_DIR}/.git"
  find "${INSTALL_DIR}/.git" -type d -exec chmod u+rwx {} \; >/dev/null 2>&1 || true
  find "${INSTALL_DIR}/.git" -type f -exec chmod u+rw {} \; >/dev/null 2>&1 || true
}

resolve_git_user() {
  repair_git_store
  GIT_USER=root
  GIT_HOME=/root
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
    STATUS_BRANCH=${BRANCH}
    return
  fi
  BRANCH=$(git_repo rev-parse --abbrev-ref HEAD 2>/dev/null || true)
  if [ -z "${BRANCH}" ] || [ "${BRANCH}" = "HEAD" ]; then
    BRANCH=master
  fi
  STATUS_BRANCH=${BRANCH}
}

ensure_clean_repo() {
  local tracked_status
  tracked_status=$(git_repo status --porcelain=v1 --untracked-files=no | awk 'substr($0,4) != ".threej_version"' || true)
  if [ -n "${tracked_status}" ]; then
    if [ "${ALLOW_DIRTY}" = "1" ]; then
      log "Tracked local changes will be overwritten by the selected update:"
      printf "%s\n" "${tracked_status}"
      return
    fi
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
  STATUS_REMOTE_URL=${source_ref}

  old_commit=$(git_repo rev-parse HEAD)
  STATUS_OLD_COMMIT=${old_commit}
  set_phase 1 "fetching" "Fetching latest ${BRANCH}..."
  log "Fetching ${BRANCH}..."
  git_repo fetch --quiet "${source_ref}" "${BRANCH}"
  if [ -n "${TARGET_COMMIT}" ]; then
    set_phase 2 "switching_commit" "Switching to selected commit..."
    log "Switching to selected commit ${TARGET_COMMIT}..."
    git_repo cat-file -e "${TARGET_COMMIT}^{commit}" >/dev/null 2>&1 || fail "Selected commit ${TARGET_COMMIT} was not found after fetch."
    git_repo checkout -f -B "${BRANCH}" "${TARGET_COMMIT}"
  else
    set_phase 2 "pulling" "Pulling latest ${BRANCH}..."
    log "Pulling latest ${BRANCH}..."
    git_repo pull --ff-only "${source_ref}" "${BRANCH}"
  fi
  new_commit=$(git_repo rev-parse HEAD)
  STATUS_NEW_COMMIT=${new_commit}

  write_version_file

  if [ "${SKIP_REBUILD}" = "1" ]; then
    set_phase 5 "done" "Repository updated. Rebuild skipped."
    log "Repository updated to $(git_repo rev-parse --short HEAD). Rebuild skipped by THREEJ_SKIP_REBUILD=1."
    return
  fi

  if [ "${old_commit}" = "${new_commit}" ] && [ "${FORCE_REBUILD}" != "1" ]; then
    set_phase 5 "done" "Already up to date. Rebuild skipped."
    log "Already up to date at $(git_repo rev-parse --short HEAD). Skipping rebuild."
    return
  fi

  set_phase 3 "rebuilding" "Rebuilding services..."
  log "Rebuilding services..."
  cd "${INSTALL_DIR}"
  mkdir -p data
  THREEJ_VERSION=$(git_repo rev-parse --short HEAD 2>/dev/null || echo "unknown")
  THREEJ_VERSION_DATE=$(git_repo log -1 --format=%cs 2>/dev/null || echo "unknown")
  export THREEJ_VERSION THREEJ_VERSION_DATE
  export BUILDX_NO_DEFAULT_ATTESTATIONS=1
  docker compose up -d --build
  set_phase 4 "health_check" "Waiting for the updated service to come back..."
  set_phase 5 "done" "Update complete."
  log "Update complete at ${THREEJ_VERSION}."
}

main() {
  require_root
  ensure_prereqs
  ensure_repo
  resolve_git_user
  detect_branch
  STATUS_STARTED_AT=$(iso_now)
  write_status "queued" "queued" "Update queued."
  ensure_clean_repo
  run_update
}

main "$@"
