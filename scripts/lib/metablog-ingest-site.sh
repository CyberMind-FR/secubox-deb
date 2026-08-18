#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# scripts/lib/metablog-ingest-site.sh
# Per-site ingest function. Sourceable.
#
# Provides: ingest_site <site_dir>
#   - prints one status keyword on stdout:
#       ingested-fresh         : site had no .git, fresh init + push + tag
#       ingested-with-history  : site had .git, retargeted + pushed + tag
#       skip-already-current   : remote HEAD == local HEAD, idempotent skip
#       fail-<reason>          : something went wrong
#   - returns 0 on any "ingested-*" or "skip-*", non-zero on "fail-*"
#
# Important: Gitea SSH user is "gitea" (NOT "git") because Gitea's built-in
# SSH server validates the username against the OS user it runs as.

GITEA_HOST="${GITEA_HOST:-gitea.gk2.secubox.in}"
GITEA_SSH_PORT="${GITEA_SSH_PORT:-2222}"
GITEA_SSH_USER="${GITEA_SSH_USER:-gitea}"
GITEA_REPO_OWNER="${GITEA_REPO_OWNER:-gandalf}"
LXC_HOST="${LXC_HOST:-192.168.1.200}"

# Shared SSH command used by every git operation
_git_ssh_cmd() {
  echo "ssh -p $GITEA_SSH_PORT -o BatchMode=yes -o StrictHostKeyChecking=accept-new"
}

ingest_site() {
  local site_dir="$1"
  [[ -z "$site_dir" ]] && { echo "fail-no-arg"; return 1; }

  local name repo_url
  name=$(basename "$site_dir")
  repo_url="ssh://${GITEA_SSH_USER}@${GITEA_HOST}:${GITEA_SSH_PORT}/${GITEA_REPO_OWNER}/metablog-${name}.git"

  # All operations happen on the MOCHAbin (where the site dir lives), via ssh.
  # We wrap a single big ssh+heredoc to keep it transactional from caller's view.
  local result exit_code
  result=$(ssh "root@$LXC_HOST" bash <<EOSH
set -euo pipefail
SITE="$site_dir"
NAME="$name"
REPO_URL="$repo_url"
GIT_SSH_COMMAND="$(_git_ssh_cmd)"
export GIT_SSH_COMMAND

if [[ ! -d "\$SITE" ]]; then
  echo "fail-no-such-dir"
  exit 1
fi

cd "\$SITE"

# #121: every git op below runs as root (ssh root@host), so a freshly created
# .git ends up root:root — but metablogizer runs as 'secubox' and must be able
# to write the repo (webhook deploys, sub-E #113). Re-own the site dir after any
# ingest that touches .git. Matches the chown pattern in module postinsts.
fix_perms() { chown -R secubox:secubox "\$SITE" 2>/dev/null || true; }

# Determine remote HEAD (might fail if repo doesn't exist yet — that's OK)
remote_head=\$(git ls-remote "\$REPO_URL" main 2>/dev/null | awk '{print \$1}' || true)

if [[ -d .git ]]; then
  # Determine if there are any commits (--verify exits non-zero on unborn branch)
  local_head=\$(git rev-parse --verify HEAD 2>/dev/null || true)
  if [[ -n "\$remote_head" && "\$remote_head" == "\$local_head" ]]; then
    echo "skip-already-current"
    exit 0
  fi

  if [[ -n "\$local_head" ]]; then
    # Has commits — retarget and push existing history
    git remote set-url origin "\$REPO_URL" 2>/dev/null \
      || git remote add origin "\$REPO_URL"
    # Source branch is whatever HEAD points at; rename to main on push
    src_branch=\$(git symbolic-ref --short HEAD 2>/dev/null || echo HEAD)
    # Use --force-with-lease only when remote already has a main branch;
    # for first push (remote_head empty), use --force (bootstrapping case).
    if [[ -n "\$remote_head" ]]; then
      git push --quiet --force-with-lease origin "\$src_branch:main"
    else
      git push --quiet --force origin "\$src_branch:main"
    fi
    git tag -f v1.0.0
    git push --quiet --force origin v1.0.0
    fix_perms
    echo "ingested-with-history"
    exit 0
  fi
  # Falls through: .git exists but no commits (unborn branch) — treat as fresh.
  # Rename branch to 'main' in-place (safe with no commits: just rewrite HEAD)
  git config user.email "metablog-ingest@cybermind.fr"
  git config user.name "MetaBlogizer Ingest"
  git symbolic-ref HEAD refs/heads/main
  git remote set-url origin "\$REPO_URL" 2>/dev/null \
    || git remote add origin "\$REPO_URL"
  git add -A
  if git diff --cached --quiet; then
    echo "fail-empty-dir"
    exit 1
  fi
  git commit -q -m "feat: import from /srv/metablogizer/sites/\$NAME"
  git push --quiet origin main
  git tag v1.0.0
  git push --quiet origin v1.0.0
  fix_perms
  echo "ingested-fresh"
  exit 0
else
  # No local git — fresh init
  git init -q -b main
  git config user.email "metablog-ingest@cybermind.fr"
  git config user.name "MetaBlogizer Ingest"
  git add -A
  if git diff --cached --quiet; then
    # Empty directory — nothing to commit
    echo "fail-empty-dir"
    exit 1
  fi
  git commit -q -m "feat: import from /srv/metablogizer/sites/\$NAME"
  git remote add origin "\$REPO_URL"
  git push --quiet origin main
  git tag v1.0.0
  git push --quiet origin v1.0.0
  fix_perms
  echo "ingested-fresh"
  exit 0
fi
EOSH
  )
  exit_code=$?

  # Print the result keyword
  echo "$result"

  # Return non-zero if result starts with "fail-"
  if [[ "$result" == fail-* ]]; then
    return 1
  fi
  return $exit_code
}
