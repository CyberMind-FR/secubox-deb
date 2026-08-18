#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# scripts/lib/streamlit-ingest-app.sh
# Per-app ingest function for Streamlit apps. Sourceable.
#
# Provides: ingest_streamlit_app <app_dir>
#   - prints one status keyword on stdout:
#       ingested-fresh         : app had no .git, fresh init + push + tag
#       ingested-with-history  : app had .git, retargeted + pushed + tag
#       skip-already-current   : remote HEAD == local HEAD, idempotent skip
#       fail-<reason>          : something went wrong
#   - returns 0 on any "ingested-*" or "skip-*", non-zero on "fail-*"
#
# Mirrors scripts/lib/metablog-ingest-site.sh with two differences:
#   - Repo name prefix is "streamlit-" instead of "metablog-"
#   - LXC bind mount is /srv/streamlit/apps (vs /srv/metablogizer/sites)
#
# Important: Gitea SSH user is "gitea" (NOT "git").

GITEA_HOST="${GITEA_HOST:-gitea.gk2.secubox.in}"
GITEA_SSH_PORT="${GITEA_SSH_PORT:-2222}"
GITEA_SSH_USER="${GITEA_SSH_USER:-gitea}"
GITEA_REPO_OWNER="${GITEA_REPO_OWNER:-gandalf}"
LXC_HOST="${LXC_HOST:-192.168.1.200}"

_streamlit_git_ssh_cmd() {
  echo "ssh -p $GITEA_SSH_PORT -o BatchMode=yes -o StrictHostKeyChecking=accept-new"
}

ingest_streamlit_app() {
  local app_dir="$1"
  [[ -z "$app_dir" ]] && { echo "fail-no-arg"; return 1; }

  local name repo_url
  name=$(basename "$app_dir")
  repo_url="ssh://${GITEA_SSH_USER}@${GITEA_HOST}:${GITEA_SSH_PORT}/${GITEA_REPO_OWNER}/streamlit-${name}.git"

  ssh "root@$LXC_HOST" bash <<EOSH
set -euo pipefail
APP="$app_dir"
NAME="$name"
REPO_URL="$repo_url"
GIT_SSH_COMMAND="$(_streamlit_git_ssh_cmd)"
export GIT_SSH_COMMAND

if [[ ! -d "\$APP" ]]; then
  echo "fail-no-such-dir"
  exit 1
fi

# Permit git in dirs we don't own (LXC apps live as uid 1000)
git config --global --add safe.directory "\$APP" 2>/dev/null || true

cd "\$APP"

remote_head=\$(git ls-remote "\$REPO_URL" main 2>/dev/null | awk '{print \$1}' || true)

if [[ -d .git ]]; then
  local_head=\$(git rev-parse --verify HEAD 2>/dev/null || true)
  if [[ -n "\$remote_head" && "\$remote_head" == "\$local_head" ]]; then
    echo "skip-already-current"
    exit 0
  fi

  if [[ -z "\$local_head" ]]; then
    # .git exists but no commits (unborn branch). Treat as fresh.
    git symbolic-ref HEAD refs/heads/main 2>/dev/null || true
    git add -A
    if git diff --cached --quiet; then
      echo "fail-empty-dir"
      exit 1
    fi
    git -c user.email=streamlit-ingest@cybermind.fr -c user.name="Streamlit Ingest" \
        commit -q -m "feat: import from /srv/streamlit/apps/\$NAME"
    git remote add origin "\$REPO_URL" 2>/dev/null \
      || git remote set-url origin "\$REPO_URL"
    git push --quiet origin main
    git tag v1.0.0
    git push --quiet origin v1.0.0
    echo "ingested-fresh"
    exit 0
  fi

  git remote set-url origin "\$REPO_URL" 2>/dev/null \
    || git remote add origin "\$REPO_URL"
  src_branch=\$(git symbolic-ref --short HEAD 2>/dev/null || echo HEAD)
  if [[ -n "\$remote_head" ]]; then
    git push --quiet --force-with-lease origin "\$src_branch:main"
  else
    git push --quiet --force origin "\$src_branch:main"
  fi
  git tag -f v1.0.0
  git push --quiet --force origin v1.0.0
  echo "ingested-with-history"
  exit 0
else
  git init -q -b main
  git config user.email "streamlit-ingest@cybermind.fr"
  git config user.name "Streamlit Ingest"
  git add -A
  if git diff --cached --quiet; then
    echo "fail-empty-dir"
    exit 1
  fi
  git commit -q -m "feat: import from /srv/streamlit/apps/\$NAME"
  git remote add origin "\$REPO_URL"
  git push --quiet origin main
  git tag v1.0.0
  git push --quiet origin v1.0.0
  echo "ingested-fresh"
  exit 0
fi
EOSH
}
