#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# SecuBox-Deb :: setup-admin-tunnel.sh  (#529)
#
# Provision a dedicated WireGuard admin tunnel (wg-admin) for secure
# out-of-band management access, distinct from the R3 cabine tunnel
# (wg-toolbox). Idempotent : keys are generated once and reused.
#
#   wg-admin : UDP 51821, server 10.98.0.1/24, peer(s) 10.98.0.2+/32
#   endpoint : admin.gk2.secubox.in:51821
#
# ADDITIVE ONLY : this script opens udp/51821 and brings up the tunnel.
# It does NOT touch sshd or the existing nft rules — sshd hardening is a
# deliberate separate step (after the tunnel is confirmed) to avoid
# locking anyone out.
#
# Usage (run as root on the board):
#   setup-admin-tunnel.sh                 # provision + show server status
#   setup-admin-tunnel.sh add <name>      # add a peer, print its client .conf
set -euo pipefail
readonly MODULE="setup-admin-tunnel"
readonly VERSION="529"

WG_IFACE="wg-admin"
WG_PORT="${ADMIN_WG_PORT:-51821}"
WG_NET4="10.98.0"
WG_SERVER_IP="${WG_NET4}.1"
WG_CIDR="24"
ENDPOINT_HOST="${ADMIN_WG_ENDPOINT:-admin.gk2.secubox.in}"
WG_DIR="/etc/wireguard"
SRV_CONF="${WG_DIR}/${WG_IFACE}.conf"
KEY_DIR="${WG_DIR}/${WG_IFACE}.keys"
PEERS_STATE="${KEY_DIR}/peers.tsv"     # name<TAB>ip<TAB>pubkey
NFT_DROPIN="/etc/nftables.d/secubox-admin-wg.nft"

log() { echo "[$MODULE] $*" >&2; }
die() { log "ERROR: $*"; exit 1; }

[ "$(id -u)" = "0" ] || die "must run as root"
command -v wg >/dev/null 2>&1 || die "wireguard-tools not installed (apt install wireguard)"

umask 077
mkdir -p "$WG_DIR" "$KEY_DIR"

# ── 1. Server keypair (generate once) ──
if [ ! -s "${KEY_DIR}/server.key" ]; then
    wg genkey | tee "${KEY_DIR}/server.key" | wg pubkey > "${KEY_DIR}/server.pub"
    chmod 600 "${KEY_DIR}/server.key"
    log "generated server keypair"
fi
SRV_PRIV=$(cat "${KEY_DIR}/server.key")
SRV_PUB=$(cat "${KEY_DIR}/server.pub")

# ── 2. Server config (rewritten from the peers state each run) ──
write_server_conf() {
    {
        echo "# SecuBox admin tunnel (wg-admin) — managed by setup-admin-tunnel.sh (#529)"
        echo "[Interface]"
        echo "Address = ${WG_SERVER_IP}/${WG_CIDR}"
        echo "ListenPort = ${WG_PORT}"
        echo "PrivateKey = ${SRV_PRIV}"
        echo
        if [ -s "$PEERS_STATE" ]; then
            # NB: local loop vars — read into pip/ppub here would clobber
            # the caller's $pip used for the client config (subtle bug).
            local _pn _pip _pub
            while IFS=$'\t' read -r _pn _pip _pub; do
                [ -n "$_pub" ] || continue
                echo "# peer: ${_pn}"
                echo "[Peer]"
                echo "PublicKey = ${_pub}"
                echo "AllowedIPs = ${_pip}/32"
                echo
            done < "$PEERS_STATE"
        fi
    } > "$SRV_CONF"
    chmod 600 "$SRV_CONF"
}

# ── 3. nft drop-in : allow the WG handshake on udp/51821 (persistent) ──
write_nft_dropin() {
    install -d -m 0755 /etc/nftables.d
    cat > "$NFT_DROPIN" <<EOF
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Phase admin-tunnel (#529) — allow the wg-admin handshake.
# inet filter input has policy=drop ; this rule MUST exist or no admin
# peer ever completes a handshake. Loaded by nftables.service at boot.
add rule inet filter input udp dport ${WG_PORT} accept comment "secubox wg-admin"
EOF
    chmod 644 "$NFT_DROPIN"
    # Apply now (best-effort) so the running ruleset matches.
    if systemctl is-active --quiet nftables.service 2>/dev/null; then
        nft -f "$NFT_DROPIN" 2>/dev/null || true
    fi
}

# ── peer add ──
next_peer_ip() {
    local last=1
    if [ -s "$PEERS_STATE" ]; then
        last=$(awk -F'\t' '{n=split($2,a,"."); if(a[4]>last) last=a[4]} END{print last+0}' last=1 "$PEERS_STATE")
    fi
    echo "${WG_NET4}.$((last + 1))"
}

add_peer() {
    local name="$1"
    [ -n "$name" ] || die "peer name required"
    touch "$PEERS_STATE"
    if grep -qP "^${name}\t" "$PEERS_STATE" 2>/dev/null; then
        die "peer '${name}' already exists"
    fi
    local pip ppriv ppub
    pip=$(next_peer_ip)
    ppriv=$(wg genkey)
    ppub=$(echo "$ppriv" | wg pubkey)
    printf '%s\t%s\t%s\n' "$name" "$pip" "$ppub" >> "$PEERS_STATE"
    echo "$ppriv" > "${KEY_DIR}/peer-${name}.key"
    chmod 600 "${KEY_DIR}/peer-${name}.key"

    write_server_conf
    # Hot-add the peer to the running interface if up (no full restart).
    if wg show "$WG_IFACE" >/dev/null 2>&1; then
        wg set "$WG_IFACE" peer "$ppub" allowed-ips "${pip}/32" 2>/dev/null || \
          systemctl restart "wg-quick@${WG_IFACE}" 2>/dev/null || true
    fi

    # Emit the client config to stdout.
    cat <<EOF

# ================= CLIENT CONFIG : ${name} =================
# Save as ${name}.conf and import into WireGuard, or scan the QR below.
[Interface]
PrivateKey = ${ppriv}
Address = ${pip}/32
# DNS via the box (optional — comment out for split-tunnel without DNS)
DNS = ${WG_SERVER_IP}

[Peer]
PublicKey = ${SRV_PUB}
Endpoint = ${ENDPOINT_HOST}:${WG_PORT}
# Admin tunnel reaches the box only (split tunnel). Add LAN/admin subnets
# here if you want them routed through the tunnel too.
AllowedIPs = ${WG_NET4}.0/${WG_CIDR}
PersistentKeepalive = 25
# ===========================================================
EOF
    if command -v qrencode >/dev/null 2>&1; then
        echo "# QR (scan from the WireGuard mobile app):" >&2
        qrencode -t ansiutf8 <<EOF2 >&2
[Interface]
PrivateKey = ${ppriv}
Address = ${pip}/32
DNS = ${WG_SERVER_IP}
[Peer]
PublicKey = ${SRV_PUB}
Endpoint = ${ENDPOINT_HOST}:${WG_PORT}
AllowedIPs = ${WG_NET4}.0/${WG_CIDR}
PersistentKeepalive = 25
EOF2
    fi
    log "peer '${name}' added at ${pip}"
}

# ── ssh hardening (idempotent) ──
# Run ONLY after the wg-admin tunnel is confirmed working (key auth over
# the tunnel). Closes the public SSH brute-force surface :
#   - sshd : key-only (PasswordAuthentication no, root prohibit-password),
#   - nft  : drop tcp/22 from any source not in the LAN or the 10.x
#     tunnels, inserted BEFORE the blanket `iif eth1 accept` so the
#     router's port-forwarded public SSH (real public source IP) is
#     dropped while LAN + wg-admin stay reachable.
# Trusted SSH source sets are tunable via env.
SSH_LAN_CIDR="${ADMIN_SSH_LAN:-192.168.1.0/24}"
SSH_TUN_CIDR="${ADMIN_SSH_TUN:-10.0.0.0/8}"
NFTCONF="/etc/nftables.conf"
SSHD_DROPIN="/etc/ssh/sshd_config.d/99-secubox-hardening.conf"

harden_ssh() {
    # Pre-flight : a working key in root's authorized_keys, or we refuse
    # (don't lock the operator out by disabling passwords with no key).
    [ -s /root/.ssh/authorized_keys ] || die "no /root/.ssh/authorized_keys — refusing to disable password auth"

    # 1) sshd key-only (idempotent : just (re)write the drop-in).
    cat > "$SSHD_DROPIN" <<EOF
# SecuBox admin hardening (#529) — key-only ; admin via wg-admin / LAN.
PasswordAuthentication no
PermitRootLogin prohibit-password
KbdInteractiveAuthentication no
EOF
    sshd -t || die "sshd config invalid — left drop-in in place, NOT reloaded"
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    log "sshd hardened : key-only (password auth disabled)"

    # 2) nft SSH-guard — persist in $NFTCONF (after the established-accept).
    local guard="tcp dport 22 ip saddr != { ${SSH_LAN_CIDR}, ${SSH_TUN_CIDR} } drop"
    if ! grep -qF "SSH-guard (#529)" "$NFTCONF" 2>/dev/null; then
        cp "$NFTCONF" "${NFTCONF}.bak.$(date +%s)" 2>/dev/null || true
        sed -i "/ct state established,related accept/a\\    # SSH-guard (#529): drop public-sourced SSH — LAN + 10.x tunnels only.\\n    ${guard}" "$NFTCONF"
        nft -c -f "$NFTCONF" || die "nftables.conf failed syntax check after edit — restore from .bak"
        log "SSH-guard persisted in ${NFTCONF}"
    else
        log "SSH-guard already in ${NFTCONF}"
    fi
    # 3) Apply live without flushing other tables : insert before the
    # blanket `iif <lan> accept` rule (looked up by handle).
    if ! nft list chain inet filter input 2>/dev/null | grep -q "dport 22 ip saddr !="; then
        local h
        h=$(nft -a list chain inet filter input 2>/dev/null \
              | awk '/iif "eth1" accept/ {for(i=1;i<=NF;i++) if($i=="handle"){print $(i+1); exit}}')
        if [ -n "$h" ]; then
            nft insert rule inet filter input position "$h" $guard 2>/dev/null \
              && log "SSH-guard applied live (before handle $h)" \
              || log "WARN: live insert failed — applies on next nft reload"
        else
            log "WARN: could not find LAN-accept handle — guard applies on next reload"
        fi
    else
        log "SSH-guard already live"
    fi
    log "hardening done. VERIFY now: ssh root@${WG_SERVER_IP} (tunnel, must work) ; public :22 must time out."
}

# ── main ──
case "${1:-provision}" in
    provision)
        write_server_conf
        write_nft_dropin
        systemctl enable "wg-quick@${WG_IFACE}" >/dev/null 2>&1 || true
        systemctl restart "wg-quick@${WG_IFACE}" 2>/dev/null || \
          wg-quick up "$WG_IFACE" 2>/dev/null || true
        log "provisioned. server pubkey: ${SRV_PUB}"
        log "endpoint: ${ENDPOINT_HOST}:${WG_PORT}  server ip: ${WG_SERVER_IP}"
        wg show "$WG_IFACE" 2>/dev/null || true
        log "next: $0 add <device-name>   # to mint an admin client config"
        ;;
    add)
        add_peer "${2:-}"
        ;;
    harden)
        harden_ssh
        ;;
    *)
        die "usage: $0 [provision | add <name> | harden]"
        ;;
esac
