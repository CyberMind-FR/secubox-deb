#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# SecuBox Eye Remote — host cleanup + bridge installer
#
# Idempotent. Run on the SecuBox host (e.g. 192.168.1.200) to:
#   1. Remove hand-installed networkd / ifupdown leftovers that are NOT
#      owned by any dpkg package and that fight with the canonical
#      bridge approach (link rename collision when ≥2 gadgets plug in).
#   2. Install the canonical eye-br0 bridge .netdev + .network from
#      packages/secubox-eye-remote/networkd/.
#   3. Sync the per-gadget connect/disconnect handlers + udev rule from
#      packages/secubox-system/.
#   4. Reload systemd-networkd + udev so both Pi gadgets (Zero W + 4B)
#      come up as L2 ports of eye-br0, with 10.55.0.1/24 living on the
#      bridge.
#
# Safe to re-run: every step checks state before mutating.
#
# Usage:
#     sudo ./host-cleanup-dead-config.sh         # run locally on the host
#     bash host-cleanup-dead-config.sh --dry-run # show what would change
#
# Issue: https://github.com/CyberMind-FR/secubox-deb/issues/155

set -euo pipefail

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=1
fi

# Resolve repo root: this script lives at remote-ui/round/, so the repo
# root is two levels up. SCRIPT_DIR is robust to symlinks via realpath.
SCRIPT_DIR=$(cd "$(dirname "$(realpath "${BASH_SOURCE[0]}")")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)

DEAD_FILES=(
    /etc/systemd/network/10-eye-remote.link
    /etc/systemd/network/50-eye-remote.network
    /etc/network/interfaces.d/usb0
)

NETPLAN_FILE="/etc/netplan/00-secubox.yaml"

CANONICAL_NETWORKD=(
    "$REPO_ROOT/packages/secubox-eye-remote/networkd/05-eye-br0.netdev:/etc/systemd/network/05-eye-br0.netdev"
    "$REPO_ROOT/packages/secubox-eye-remote/networkd/10-eye-br0.network:/etc/systemd/network/10-eye-br0.network"
)

CANONICAL_UDEV=(
    "$REPO_ROOT/packages/secubox-system/etc/udev/rules.d/90-secubox-eye-remote.rules:/etc/udev/rules.d/90-secubox-eye-remote.rules"
)

CANONICAL_HOOKS=(
    "$REPO_ROOT/packages/secubox-system/usr/lib/secubox/eye-remote-connected.sh:/usr/lib/secubox/eye-remote-connected.sh"
    "$REPO_ROOT/packages/secubox-system/usr/lib/secubox/eye-remote-disconnected.sh:/usr/lib/secubox/eye-remote-disconnected.sh"
)

say() { printf '[eye-remote-fix] %s\n' "$*"; }
do_cmd() {
    if (( DRY_RUN )); then
        printf '[dry-run] %s\n' "$*"
    else
        eval "$@"
    fi
}

# ---- 0. netplan: drop the eye-remote ethernet stanza ------------------------
# The deployed netplan declares `eye-remote` as an ethernet (with 10.55.0.1/30),
# which only works after a separate .link rename — and that rename collides
# when ≥2 gadgets are plugged in. Drop the stanza; the packaged .netdev/.network
# below own the bridge that holds the IP.
say "Netplan: dropping any eye-remote ethernet stanza in $NETPLAN_FILE"
if [[ -f "$NETPLAN_FILE" ]] && grep -qE '^[[:space:]]+eye-remote:' "$NETPLAN_FILE"; then
    if (( DRY_RUN )); then
        printf '[dry-run] would edit %s to remove eye-remote: stanza\n' "$NETPLAN_FILE"
    else
        cp -a "$NETPLAN_FILE" "${NETPLAN_FILE}.bak.155"
        python3 - "$NETPLAN_FILE" <<'PY'
import sys, re

path = sys.argv[1]
lines = open(path).readlines()

def leading_spaces(s):
    return len(s) - len(s.lstrip(' '))

out = []
i = 0
removed = False
while i < len(lines):
    ln = lines[i]
    # Detect "<indent>eye-remote:" (possibly followed by trailing whitespace).
    m = re.match(r'^([ \t]+)eye-remote:\s*$', ln)
    if m and not removed:
        block_indent = leading_spaces(ln)
        # Skip the key line itself plus every following line whose indent is
        # strictly greater than block_indent, or which is blank.
        i += 1
        while i < len(lines):
            nxt = lines[i]
            if nxt.strip() == '':
                # Blank line: drop it only if it precedes another child of the
                # same block; otherwise let it survive as a separator.
                # Peek ahead for the next non-blank line's indent.
                j = i + 1
                while j < len(lines) and lines[j].strip() == '':
                    j += 1
                if j < len(lines) and leading_spaces(lines[j]) > block_indent:
                    i += 1
                    continue
                break
            if leading_spaces(nxt) > block_indent:
                i += 1
                continue
            break
        removed = True
        continue
    out.append(ln)
    i += 1

if not removed:
    sys.stderr.write("WARN: eye-remote stanza not found, nothing changed\n")
    sys.exit(0)

open(path, 'w').writelines(out)
PY
        say "  ✓ patched (backup at ${NETPLAN_FILE}.bak.155)"
    fi
else
    say "  = no eye-remote stanza present, nothing to do"
fi

# ---- 1. remove hand-installed dead config (only if not dpkg-owned) -----------
say "Removing hand-installed dead config (only files not owned by any package):"
for f in "${DEAD_FILES[@]}"; do
    if [[ ! -e "$f" ]]; then
        say "  - $f (already absent)"
        continue
    fi
    if dpkg -S "$f" >/dev/null 2>&1; then
        say "  ! $f is dpkg-owned — refusing to delete (manual review)"
        continue
    fi
    say "  - rm $f"
    do_cmd "rm -f \"$f\""
done

# ---- 2. install canonical bridge networkd files -----------------------------
say "Installing canonical eye-br0 networkd files:"
for pair in "${CANONICAL_NETWORKD[@]}"; do
    src="${pair%%:*}"
    dst="${pair##*:}"
    if [[ ! -f "$src" ]]; then
        say "  ! source missing: $src — abort"
        exit 1
    fi
    if cmp -s "$src" "$dst" 2>/dev/null; then
        say "  = $dst (already up-to-date)"
    else
        say "  + install $dst"
        do_cmd "install -D -m 0644 \"$src\" \"$dst\""
    fi
done

# ---- 3. sync udev rule + handler scripts ------------------------------------
say "Syncing udev rule + connect/disconnect handlers:"
for pair in "${CANONICAL_UDEV[@]}"; do
    src="${pair%%:*}"; dst="${pair##*:}"
    if cmp -s "$src" "$dst" 2>/dev/null; then
        say "  = $dst (already up-to-date)"
    else
        say "  + install $dst"
        do_cmd "install -D -m 0644 \"$src\" \"$dst\""
    fi
done
for pair in "${CANONICAL_HOOKS[@]}"; do
    src="${pair%%:*}"; dst="${pair##*:}"
    if cmp -s "$src" "$dst" 2>/dev/null; then
        say "  = $dst (already up-to-date)"
    else
        say "  + install $dst"
        do_cmd "install -D -m 0755 \"$src\" \"$dst\""
    fi
done

# ---- 4. reload services -----------------------------------------------------
say "Regenerating netplan + reloading networkd + udev:"
if [[ -f "$NETPLAN_FILE" ]]; then
    do_cmd "netplan generate"
fi
do_cmd "systemctl restart systemd-networkd"
do_cmd "udevadm control --reload"
do_cmd "udevadm trigger --subsystem-match=net --action=add"

# ---- 5. quick verification --------------------------------------------------
say "Post-fix state (informational):"
if (( DRY_RUN )); then
    say "  (dry-run: skipping verification)"
    exit 0
fi

sleep 2

if ip -br addr show eye-br0 2>/dev/null | grep -q '10.55.0.1'; then
    say "  ✓ eye-br0 carries 10.55.0.1/24"
else
    say "  ✗ eye-br0 has no 10.55.0.1 — see: ip -br addr show eye-br0"
fi

slaves=$(bridge -j link show 2>/dev/null | python3 -c 'import json,sys
try:
    data=json.load(sys.stdin)
except Exception:
    print(""); sys.exit(0)
print(" ".join(x["ifname"] for x in data if x.get("master")=="eye-br0"))' 2>/dev/null || true)
if [[ -n "$slaves" ]]; then
    say "  ✓ eye-br0 slaves: $slaves"
else
    say "  • no gadget enslaved yet — plug a Pi Zero W or check /dev/ttyACM*"
fi

say "Done. Restart secubox-eye-remote.service if it failed to bind earlier:"
say "    systemctl restart secubox-eye-remote.service"
