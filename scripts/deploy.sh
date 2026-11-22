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
  export LC_ALL=C                         # byte-exact hash check, whatever the client sends
  export NPM_CONFIG_USERCONFIG=/dev/null  # ignore ~/.npmrc
  export NPM_CONFIG_UPDATE_NOTIFIER=false # no "new npm version" notice in deploy logs
  umask 022 # files stay readable by tlscheck (the app) and www-data (Nginx)

  local app_dir=/srv/tls-check
  local sha="${SSH_ORIGINAL_COMMAND:-}"

  if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
    echo "deploy: expected a 40-character commit hash" >&2
    exit 2
  fi

  cd "$app_dir"

  # One deploy at a time: a second one exits instead of racing npm ci.
  exec 9>"$app_dir/.git/tls-check-deploy.lock"
  if ! flock -n 9; then
    echo "deploy: another deploy is running" >&2
    exit 75
  fi

  git fetch --quiet origin main

  if ! git merge-base --is-ancestor "$sha" origin/main; then
    echo "deploy: $sha is not on main" >&2
    exit 2
  fi
  # Only move forward. Rolling back to an older commit is done by hand.
  if ! git merge-base --is-ancestor HEAD "$sha"; then
    echo "deploy: $sha is older than the deployed commit" >&2
    exit 2
  fi

  git checkout --quiet --force --detach "$sha"
  npm ci --ignore-scripts --no-audit --no-fund
  npm run build
  sudo /usr/bin/systemctl restart tls-check

  echo "deploy: $sha is live"
}

# Git without hooks or fsmonitor, so files in .git can't run code here.
git() {
  command git -c core.hooksPath=/dev/null -c core.fsmonitor=false "$@"
}

main
exit
