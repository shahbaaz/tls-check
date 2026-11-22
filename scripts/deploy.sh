#!/usr/bin/env bash
# Deploys one commit of main on the droplet.
#
# Runs as the `deploy` user, as the forced command on its SSH key:
#   restrict,command="/usr/local/bin/tls-check-deploy" ssh-ed25519 ...
# GitHub Actions connects with the commit hash as the SSH command, which
# arrives here in SSH_ORIGINAL_COMMAND. Install a root-owned copy with:
#   sudo install -o root -g root -m 755 scripts/deploy.sh /usr/local/bin/tls-check-deploy
#
# Everything is inside main() so bash reads the whole script before running
# any of it.

main() {
  set -euo pipefail
  export PATH=/usr/local/bin:/usr/bin:/bin
  umask 022 # files stay readable by tlscheck (the app) and www-data (Nginx)

  local app_dir=/srv/tls-check
  local sha="${SSH_ORIGINAL_COMMAND:-}"

  if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
    echo "deploy: expected a 40-character commit hash" >&2
    exit 2
  fi

  cd "$app_dir"
  git fetch --quiet origin main

  if ! git merge-base --is-ancestor "$sha" origin/main; then
    echo "deploy: $sha is not on main" >&2
    exit 2
  fi

  git checkout --quiet --force --detach "$sha"
  npm ci --ignore-scripts --no-audit --no-fund
  npm run build
  sudo /usr/bin/systemctl restart tls-check

  echo "deploy: $sha is live"
}

main
exit
