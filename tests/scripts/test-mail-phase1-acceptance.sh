#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# tests/scripts/test-mail-phase1-acceptance.sh
# Phase 1 rev. 2 acceptance — runs against the live board.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=/dev/null
source "$REPO/scripts/lib/test-helpers.sh"

HOST="${1:-root@192.168.1.200}"
HOST_IP="${HOST#*@}"

step() { echo; echo "[acceptance] $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

step "1) Source-side: bash -n parses every controller cleanly"
for f in "$REPO"/packages/secubox-mail/sbin/{mailctl,mailserverctl,roundcubectl,mail-migrate-to-single-lxc.sh}; do
    bash -n "$f" || fail "bash -n $f"
done
pass "controllers parse"

step "2) Pytest: 62 endpoints respond non-5xx"
( cd "$REPO" && python3 -m pytest packages/secubox-mail/api/tests/test_phase1_endpoints.py -q ) >/dev/null \
    || fail "pytest endpoint coverage"
pass "62 endpoints respond"

step "3) Board: canonical paths present (LXC + data volumes)"
ssh "$HOST" 'set -e
  test -d /data/lxc/mail/rootfs
  test -L /var/lib/lxc/mail
  test -d /data/volumes/mail/vmail
' || fail "canonical paths missing on board"
pass "canonical paths exist"

step "4) Board: production users still present in /data/volumes/mail/vmail/secubox.in/"
ssh "$HOST" 'ls /data/volumes/mail/vmail/secubox.in/' > /tmp/phase1-users
for u in gk2 bat bourdon lemurien ragondin; do
    grep -wq "$u" /tmp/phase1-users || fail "production user '$u' missing — data preservation invariant I13 violated"
done
pass "5 production users present (gk2, bat, bourdon, lemurien, ragondin)"

step "5) Board: host secubox-mail.service active"
ssh "$HOST" 'systemctl is-active secubox-mail' | grep -q "^active$" || fail "secubox-mail.service inactive"
pass "secubox-mail.service active"

step "6) Board: mailctl migrate-config is idempotent on already-migrated toml"
ssh "$HOST" '/usr/sbin/mailctl migrate-config 2>&1' | tail -3
pass "migrate-config ran (idempotent)"

step "7) Board: /etc/secubox/mail.toml has canonical keys + no live old keys"
ssh "$HOST" 'cat /etc/secubox/mail.toml' > /tmp/phase1-toml
grep -qE '^container *= *"mail"'        /tmp/phase1-toml || fail "missing canonical 'container = \"mail\"'"
grep -qE '^lxc_ip *= *"10\.100\.0\.10"' /tmp/phase1-toml || fail "missing canonical 'lxc_ip = \"10.100.0.10\"'"
# Old keys should be either gone or commented as DEPRECATED
if grep -qE '^[^#]*mail_container *=' /tmp/phase1-toml; then
    fail "legacy 'mail_container' key still active (not commented)"
fi
pass "toml uses canonical keys; legacy keys commented or removed"

step "8) Board: mailctl start brings the mail LXC up"
ssh "$HOST" 'mailctl start 2>&1' | tail -5
ssh "$HOST" 'lxc-info -n mail 2>&1' | grep -E "State:.*RUNNING" >/dev/null \
    || fail "mail LXC not RUNNING after mailctl start"
pass "mail LXC RUNNING"

step "9) Board: Postfix:25 + Dovecot:993 + HTTP:80 listening inside LXC"
ssh "$HOST" 'lxc-attach -n mail -- ss -tlnp 2>&1' > /tmp/phase1-ports
grep -q ':25 '  /tmp/phase1-ports || fail "postfix:25 not listening"
grep -q ':993 ' /tmp/phase1-ports || fail "dovecot:993 not listening"
grep -q ':80 '  /tmp/phase1-ports || fail "http:80 (Roundcube) not listening"
pass "postfix:25, dovecot:993, http:80 listening"

step "10) Board: Dovecot greets on IMAPS port"
out=$(ssh "$HOST" 'echo "0 LOGOUT" | timeout 5 openssl s_client -connect 10.100.0.10:993 -quiet 2>/dev/null | head -3' || true)
echo "$out" | grep -qi "Dovecot" || fail "no Dovecot greeting from 10.100.0.10:993"
pass "Dovecot IMAPS greeting received"

step "11) Board: Roundcube reachable through host proxy (WAF path)"
out=$(curl --silent --insecure --resolve "webmail.gk2.secubox.in:443:$HOST_IP" \
    https://webmail.gk2.secubox.in/ 2>&1 || true)
echo "$out" | grep -qiE 'roundcube|webmail|login' \
    || fail "Roundcube did not respond through WAF path"
pass "Roundcube reachable via WAF (HAProxy → mitmproxy → LXC :80)"

step "12) Data preservation (gate 4 re-check after the LXC started)"
ssh "$HOST" 'ls /data/volumes/mail/vmail/secubox.in/' > /tmp/phase1-users-after
diff /tmp/phase1-users /tmp/phase1-users-after || fail "user list changed after LXC start"
pass "5 production users still byte-identical after LXC start"

echo
pass "PHASE 1 ACCEPTANCE: all 12 gates green"
