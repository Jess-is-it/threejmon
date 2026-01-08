#!/usr/bin/env bash
set -euo pipefail

REPO="Jess-is-it/threejmon"
EMAIL="threejmon-deploy"
KEY_PATH="$HOME/.ssh/threejmon_deploy"
PUBLIC_REPO=${PUBLIC_REPO:-0}

if [ "$PUBLIC_REPO" = "1" ]; then
  curl -fsSL https://raw.githubusercontent.com/${REPO}/master/install.sh | sudo THREEJ_REPO_URL=https://github.com/${REPO}.git bash
  exit 0
fi

if [ ! -f "${KEY_PATH}" ]; then
  ssh-keygen -t ed25519 -C "${EMAIL}" -f "${KEY_PATH}" -N ""
fi

mkdir -p "$HOME/.ssh"
cat <<'CONFIG_EOF' >> "$HOME/.ssh/config"
Host github.com
  IdentityFile ~/.ssh/threejmon_deploy
  IdentitiesOnly yes
CONFIG_EOF
chmod 600 "$HOME/.ssh/config"

PUB_KEY=$(cat "${KEY_PATH}.pub")

cat <<EOF2

Add this deploy key to GitHub:
Repo: https://github.com/${REPO}
Settings -> Deploy keys -> Add deploy key (read-only)

${PUB_KEY}

After adding the key, press Enter to continue.
EOF2
read -r

curl -fsSL https://raw.githubusercontent.com/${REPO}/master/install.sh | sudo THREEJ_REPO_URL=git@github.com:${REPO}.git bash
