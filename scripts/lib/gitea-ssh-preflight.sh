#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# scripts/lib/gitea-ssh-preflight.sh
# Verify SSH path to git@gitea.gk2.secubox.in:2222 works (as the MOCHAbin root).
# If not, enrol the MOCHAbin root's id_ed25519.pub into gandalf's Gitea account.
#
# Sourceable: provides ssh_preflight + enrol_mochabin_root_key functions.
# Standalone: bash gitea-ssh-preflight.sh [--check | --enrol]
#
# Enrol path (gitea 1.22 CLI lacks "user keys add"):
#   1. lxc-attach -n gitea -- su gitea -c \
#        "gitea admin user generate-access-token --config <ini> --username gandalf --scopes write:user"
#      Output format: "Access token was successfully created: <token>"
#   2. POST /api/v1/user/keys via LXC loopback IP (avoids public TLS path)
#   3. Best-effort token cleanup via sqlite3 on the Gitea DB (token list/delete
#      API requires basic auth, not token auth, in Gitea 1.22)

set -euo pipefail

GITEA_HOST="${GITEA_HOST:-gitea.gk2.secubox.in}"
GITEA_SSH_PORT="${GITEA_SSH_PORT:-2222}"
GITEA_USER="${GITEA_USER:-gandalf}"
# SSH login user for Gitea's builtin SSH server (must match the OS user Gitea runs as).
# This instance runs as "gitea", NOT "git" — using "git" triggers
# "Invalid SSH username git - must use gitea" in the builtin server.
GITEA_SSH_USER="${GITEA_SSH_USER:-gitea}"
LXC_HOST="${LXC_HOST:-192.168.1.200}"
LXC_NAME="${LXC_NAME:-gitea}"
GITEA_APP_INI="${GITEA_APP_INI:-/var/lib/gitea/custom/conf/app.ini}"
GITEA_DB="${GITEA_DB:-/var/lib/gitea/gitea.db}"

ssh_preflight() {
  # Returns 0 if SSH to GITEA_SSH_USER@gitea is authenticated from the MOCHAbin; 1 otherwise.
  # Prints the SSH banner/error on stdout.
  # NOTE: Gitea's builtin SSH server requires the username to match the OS user
  # Gitea runs as (here: "gitea").  The conventional "git@" will be rejected
  # unless the Gitea daemon also runs as "git".
  local out
  out=$(ssh "root@${LXC_HOST}" \
    "ssh -p ${GITEA_SSH_PORT} -o ConnectTimeout=5 -o BatchMode=yes \
         -o StrictHostKeyChecking=accept-new \
         ${GITEA_SSH_USER}@${GITEA_HOST} 2>&1 | head -3" || true)
  echo "$out"
  if echo "$out" | grep -qE "successfully authenticated|Hi there"; then
    return 0
  fi
  return 1
}

enrol_mochabin_root_key() {
  # 1. Fetch the MOCHAbin's root pubkey.
  local pubkey
  pubkey=$(ssh "root@${LXC_HOST}" \
    'cat /root/.ssh/id_ed25519.pub 2>/dev/null || cat /root/.ssh/id_rsa.pub 2>/dev/null' \
    || true)
  if [[ -z "$pubkey" ]]; then
    echo "ERROR: no MOCHAbin root pubkey found" >&2
    return 1
  fi
  local title
  title="metablog-ingest-$(date +%s)"

  # 2. Generate a one-shot access token via Gitea admin CLI inside the LXC.
  #    Gitea 1.22 output: "Access token was successfully created: <token>"
  local token_raw token
  token_raw=$(ssh "root@${LXC_HOST}" \
    "lxc-attach -n ${LXC_NAME} -- \
       su gitea -c 'gitea admin user generate-access-token \
         --config ${GITEA_APP_INI} \
         --username ${GITEA_USER} \
         --scopes write:user \
         --token-name ${title} 2>/dev/null'" 2>&1 || true)
  # Extract last whitespace-delimited word on any line containing "Access token"
  token=$(echo "$token_raw" | awk '/Access token/ {t=$NF} END{print t}')
  if [[ -z "$token" ]]; then
    echo "ERROR: could not generate Gitea access token for ${GITEA_USER}" >&2
    echo "  gitea output: ${token_raw}" >&2
    echo "Manual fallback: add the key via https://${GITEA_HOST}/user/settings/keys" >&2
    echo "Pubkey to add:" >&2
    echo "$pubkey" >&2
    return 1
  fi

  # 3. Resolve LXC loopback IP (avoids public TLS path for the API call).
  local lxc_ip
  lxc_ip=$(ssh "root@${LXC_HOST}" "lxc-info -n ${LXC_NAME} -iH" | head -1)
  if [[ -z "$lxc_ip" ]]; then
    echo "ERROR: could not determine LXC IP for ${LXC_NAME}" >&2
    return 1
  fi

  # 4. POST the SSH key to Gitea via the loopback API.
  local lxc_resp key_id
  lxc_resp=$(ssh "root@${LXC_HOST}" \
    "curl -sS -X POST \
       -H 'Authorization: token ${token}' \
       -H 'Content-Type: application/json' \
       http://${lxc_ip}:3000/api/v1/user/keys \
       -d '{\"title\":\"${title}\",\"key\":\"${pubkey}\"}'" 2>&1)
  if ! echo "$lxc_resp" | grep -q '"id"'; then
    echo "ERROR: API call to add SSH key failed:" >&2
    echo "$lxc_resp" >&2
    return 1
  fi
  key_id=$(echo "$lxc_resp" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
  echo "Key enrolled (id=${key_id}): ${title}"

  # 5. Best-effort: delete the one-shot token directly from the Gitea SQLite DB.
  #    (The /api/v1/users/{user}/tokens list+delete endpoint requires basic auth
  #     in Gitea 1.22, not token auth — so we go via sqlite3 on the LXC.)
  local del_rc
  del_rc=$(ssh "root@${LXC_HOST}" \
    "lxc-attach -n ${LXC_NAME} -- \
       sqlite3 ${GITEA_DB} \
         \"DELETE FROM access_token WHERE name='${title}'; SELECT changes();\"" \
    2>/dev/null || echo "0")
  if [[ "$del_rc" -ge 1 ]]; then
    echo "Token ${title} removed from DB."
  else
    echo "Note: could not remove one-shot token ${title} — remove manually if needed."
  fi
  return 0
}

if [[ "${1:-}" == "--check" ]]; then
  if ssh_preflight; then
    echo "OK."
    exit 0
  else
    echo "Preflight failed — run with --enrol to add the MOCHAbin's key to ${GITEA_USER}."
    exit 1
  fi
elif [[ "${1:-}" == "--enrol" ]]; then
  if ssh_preflight; then
    echo "Already authenticated — no enrolment needed."
    exit 0
  fi
  if ! enrol_mochabin_root_key; then
    exit 1
  fi
  echo "Re-running preflight..."
  if ssh_preflight; then
    echo "OK."
  else
    echo "Preflight still failing — manual intervention required."
    exit 1
  fi
elif [[ "${1:-}" == "" ]]; then
  # Sourced mode: just define the functions, do nothing.
  :
else
  echo "Usage: $(basename "$0") [--check | --enrol]" >&2
  exit 2
fi
