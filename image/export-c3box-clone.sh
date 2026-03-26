#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox-DEB — export-c3box-clone.sh
#  Export current c3box device configuration for cloning
#  Usage: sudo bash image/export-c3box-clone.sh [OPTIONS]
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# ── Defaults ──────────────────────────────────────────────────────
C3BOX_HOST="${C3BOX_HOST:-localhost}"
C3BOX_PORT="${C3BOX_PORT:-2222}"
C3BOX_USER="${C3BOX_USER:-root}"
OUT_DIR="${REPO_DIR}/output"
EXPORT_NAME="c3box-clone"
INCLUDE_LXC=1
INCLUDE_DATA=1
SSH_KEY=""

RED='\033[0;31m'; CYAN='\033[0;36m'; GOLD='\033[0;33m'
GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[export]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK  ]${NC} $*"; }
err()  { echo -e "${RED}[FAIL  ]${NC} $*" >&2; exit 1; }
warn() { echo -e "${GOLD}[ WARN ]${NC} $*"; }

# ── Parse args ────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: sudo bash export-c3box-clone.sh [OPTIONS]

  --host HOST      C3Box host (default: localhost, or \$C3BOX_HOST)
  --port PORT      SSH port (default: 2222, or \$C3BOX_PORT)
  --user USER      SSH user (default: root, or \$C3BOX_USER)
  --key  FILE      SSH private key file
  --out  DIR       Output directory (default: ./output)
  --name NAME      Export name (default: c3box-clone)
  --no-lxc         Don't export LXC containers
  --no-data        Don't export /data partition contents
  --help           Show this help

This script exports the current c3box device configuration:
  - System configuration (/etc/secubox/, /etc/netplan/, etc.)
  - User accounts and SSH keys
  - Service configurations (nginx, HAProxy, etc.)
  - SSL certificates
  - LXC containers (optional)
  - Data partition contents (optional)

Output:
  c3box-clone-preseed.tar.gz   - Preseed archive for cloning
  c3box-clone-manifest.txt     - List of exported items

Use with build-installer-iso.sh:
  sudo bash build-installer-iso.sh --preseed output/c3box-clone-preseed.tar.gz

EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)     C3BOX_HOST="$2";     shift 2 ;;
    --port)     C3BOX_PORT="$2";     shift 2 ;;
    --user)     C3BOX_USER="$2";     shift 2 ;;
    --key)      SSH_KEY="$2";        shift 2 ;;
    --out)      OUT_DIR="$2";        shift 2 ;;
    --name)     EXPORT_NAME="$2";    shift 2 ;;
    --no-lxc)   INCLUDE_LXC=0;       shift   ;;
    --no-data)  INCLUDE_DATA=0;      shift   ;;
    --help|-h)  usage ;;
    *) err "Unknown argument: $1" ;;
  esac
done

# ── Setup ─────────────────────────────────────────────────────────
mkdir -p "$OUT_DIR"
WORK_DIR=$(mktemp -d /tmp/c3box-export-XXXXXX)
EXPORT_DIR="${WORK_DIR}/export"
PRESEED_FILE="${OUT_DIR}/${EXPORT_NAME}-preseed.tar.gz"
MANIFEST_FILE="${OUT_DIR}/${EXPORT_NAME}-manifest.txt"

# Build SSH command
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -p ${C3BOX_PORT}"
[ -n "$SSH_KEY" ] && SSH_OPTS+=" -i $SSH_KEY"
SSH_CMD="ssh ${SSH_OPTS} ${C3BOX_USER}@${C3BOX_HOST}"
SCP_CMD="scp ${SSH_OPTS}"

cleanup() {
  rm -rf "${WORK_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

log "══════════════════════════════════════════════════════════"
log "Exporting C3Box Configuration"
log "Host       : ${C3BOX_USER}@${C3BOX_HOST}:${C3BOX_PORT}"
log "Output     : ${PRESEED_FILE}"
log "Include LXC: $([[ $INCLUDE_LXC -eq 1 ]] && echo "yes" || echo "no")"
log "Include Data: $([[ $INCLUDE_DATA -eq 1 ]] && echo "yes" || echo "no")"
log "══════════════════════════════════════════════════════════"

# ── Test connection ───────────────────────────────────────────────
log "Testing SSH connection..."
if ! $SSH_CMD "echo 'Connection OK'" &>/dev/null; then
  err "Cannot connect to ${C3BOX_USER}@${C3BOX_HOST}:${C3BOX_PORT}"
fi
ok "Connection established"

# ── Create export structure ───────────────────────────────────────
mkdir -p "${EXPORT_DIR}"/{etc/secubox,network,users,services,ssl,packages,lxc,data}

# ── Export metadata ───────────────────────────────────────────────
log "Creating export metadata..."

REMOTE_HOSTNAME=$($SSH_CMD "hostname" 2>/dev/null || echo "c3box")
REMOTE_DATE=$(date -Iseconds)

cat > "${EXPORT_DIR}/preseed.meta" <<EOF
# C3Box Clone Export Metadata
export_hostname="${REMOTE_HOSTNAME}"
export_date="${REMOTE_DATE}"
export_type="full-clone"
source_host="${C3BOX_HOST}"
source_port="${C3BOX_PORT}"
EOF

echo "# C3Box Clone Manifest - ${REMOTE_DATE}" > "$MANIFEST_FILE"
echo "# Source: ${REMOTE_HOSTNAME} (${C3BOX_HOST}:${C3BOX_PORT})" >> "$MANIFEST_FILE"
echo "" >> "$MANIFEST_FILE"

# ── 1. Export SecuBox configuration ───────────────────────────────
log "[1/8] Exporting SecuBox configuration..."

# /etc/secubox/
$SSH_CMD "tar -czf - -C /etc secubox 2>/dev/null" | tar -xzf - -C "${EXPORT_DIR}/etc/" 2>/dev/null || warn "No /etc/secubox"

# Hostname
$SSH_CMD "cat /etc/hostname" > "${EXPORT_DIR}/etc/hostname" 2>/dev/null || true
$SSH_CMD "cat /etc/hosts" > "${EXPORT_DIR}/etc/hosts" 2>/dev/null || true

# Timezone
$SSH_CMD "cat /etc/timezone" > "${EXPORT_DIR}/etc/timezone" 2>/dev/null || true

echo "## SecuBox Configuration" >> "$MANIFEST_FILE"
ls -la "${EXPORT_DIR}/etc/secubox/" 2>/dev/null >> "$MANIFEST_FILE" || true
echo "" >> "$MANIFEST_FILE"

ok "SecuBox configuration exported"

# ── 2. Export network configuration ───────────────────────────────
log "[2/8] Exporting network configuration..."

# Netplan
$SSH_CMD "tar -czf - -C /etc netplan 2>/dev/null" | tar -xzf - -C "${EXPORT_DIR}/network/" 2>/dev/null || warn "No netplan"

# WireGuard
$SSH_CMD "[ -d /etc/wireguard ] && tar -czf - -C /etc wireguard 2>/dev/null || true" | tar -xzf - -C "${EXPORT_DIR}/network/" 2>/dev/null || true

# nftables
$SSH_CMD "cat /etc/nftables.conf" > "${EXPORT_DIR}/services/nftables.conf" 2>/dev/null || true

echo "## Network Configuration" >> "$MANIFEST_FILE"
ls -la "${EXPORT_DIR}/network/" 2>/dev/null >> "$MANIFEST_FILE" || true
echo "" >> "$MANIFEST_FILE"

ok "Network configuration exported"

# ── 3. Export user accounts ───────────────────────────────────────
log "[3/8] Exporting user accounts..."

# Get non-system users (UID >= 1000 or root)
$SSH_CMD "awk -F: '\$3 >= 1000 || \$1 == \"root\" {print}' /etc/passwd" > "${EXPORT_DIR}/users/passwd" 2>/dev/null || true
$SSH_CMD "awk -F: '\$3 >= 1000 || \$1 == \"root\" {print}' /etc/shadow" > "${EXPORT_DIR}/users/shadow" 2>/dev/null || true

# Root password separately
$SSH_CMD "grep '^root:' /etc/shadow" > "${EXPORT_DIR}/users/root-shadow" 2>/dev/null || true

# SSH authorized keys
for user in root $($SSH_CMD "awk -F: '\$3 >= 1000 {print \$1}' /etc/passwd" 2>/dev/null); do
  if [ "$user" = "root" ]; then
    home="/root"
  else
    home="/home/$user"
  fi

  mkdir -p "${EXPORT_DIR}/users/ssh/$user"
  $SSH_CMD "cat ${home}/.ssh/authorized_keys 2>/dev/null || true" > "${EXPORT_DIR}/users/ssh/$user/authorized_keys" 2>/dev/null || true
done

echo "## User Accounts" >> "$MANIFEST_FILE"
cat "${EXPORT_DIR}/users/passwd" 2>/dev/null >> "$MANIFEST_FILE" || true
echo "" >> "$MANIFEST_FILE"

ok "User accounts exported"

# ── 4. Export service configurations ──────────────────────────────
log "[4/8] Exporting service configurations..."

# nginx
$SSH_CMD "[ -d /etc/nginx/sites-enabled ] && tar -czf - -C /etc/nginx sites-enabled 2>/dev/null || true" | tar -xzf - -C "${EXPORT_DIR}/services/" 2>/dev/null || true
mv "${EXPORT_DIR}/services/sites-enabled" "${EXPORT_DIR}/services/nginx-sites" 2>/dev/null || true

$SSH_CMD "[ -d /etc/nginx/secubox.d ] && tar -czf - -C /etc/nginx secubox.d 2>/dev/null || true" | tar -xzf - -C "${EXPORT_DIR}/services/" 2>/dev/null || true
mv "${EXPORT_DIR}/services/secubox.d" "${EXPORT_DIR}/services/nginx-conf" 2>/dev/null || true

# HAProxy
$SSH_CMD "cat /etc/haproxy/haproxy.cfg 2>/dev/null || true" > "${EXPORT_DIR}/services/haproxy.cfg" 2>/dev/null || true

# CrowdSec
$SSH_CMD "[ -d /etc/crowdsec ] && tar -czf - -C /etc crowdsec 2>/dev/null || true" | tar -xzf - -C "${EXPORT_DIR}/services/" 2>/dev/null || true

echo "## Service Configurations" >> "$MANIFEST_FILE"
ls -la "${EXPORT_DIR}/services/" 2>/dev/null >> "$MANIFEST_FILE" || true
echo "" >> "$MANIFEST_FILE"

ok "Service configurations exported"

# ── 5. Export SSL certificates ────────────────────────────────────
log "[5/8] Exporting SSL certificates..."

# Let's Encrypt
$SSH_CMD "[ -d /etc/letsencrypt ] && tar -czf - -C /etc letsencrypt 2>/dev/null || true" | tar -xzf - -C "${EXPORT_DIR}/ssl/" 2>/dev/null || true

# Custom certs
$SSH_CMD "[ -d /etc/ssl/secubox ] && tar -czf - -C /etc/ssl secubox 2>/dev/null || true" | tar -xzf - -C "${EXPORT_DIR}/ssl/" 2>/dev/null || true

echo "## SSL Certificates" >> "$MANIFEST_FILE"
ls -la "${EXPORT_DIR}/ssl/" 2>/dev/null >> "$MANIFEST_FILE" || true
echo "" >> "$MANIFEST_FILE"

ok "SSL certificates exported"

# ── 6. Export package list ────────────────────────────────────────
log "[6/8] Exporting package list..."

# Get installed SecuBox packages
$SSH_CMD "dpkg -l | grep secubox | awk '{print \$2, \$3}'" > "${EXPORT_DIR}/packages/secubox-packages.list" 2>/dev/null || true

# Get all manually installed packages
$SSH_CMD "apt-mark showmanual" > "${EXPORT_DIR}/packages/manual-packages.list" 2>/dev/null || true

echo "## Installed Packages" >> "$MANIFEST_FILE"
cat "${EXPORT_DIR}/packages/secubox-packages.list" 2>/dev/null >> "$MANIFEST_FILE" || true
echo "" >> "$MANIFEST_FILE"

ok "Package list exported"

# ── 7. Export LXC containers ──────────────────────────────────────
if [[ $INCLUDE_LXC -eq 1 ]]; then
  log "[7/8] Exporting LXC containers..."

  # Get list of LXC containers
  LXC_LIST=$($SSH_CMD "ls /srv/lxc 2>/dev/null || ls /var/lib/lxc 2>/dev/null || true" 2>/dev/null)

  if [ -n "$LXC_LIST" ]; then
    mkdir -p "${EXPORT_DIR}/lxc"

    for container in $LXC_LIST; do
      log "  Exporting LXC: $container..."

      # Export container config (not full rootfs - too large)
      $SSH_CMD "cat /srv/lxc/${container}/config 2>/dev/null || cat /var/lib/lxc/${container}/config 2>/dev/null || true" \
        > "${EXPORT_DIR}/lxc/${container}.config" 2>/dev/null || true

      # Export container metadata
      echo "$container" >> "${EXPORT_DIR}/lxc/containers.list"
    done

    echo "## LXC Containers" >> "$MANIFEST_FILE"
    cat "${EXPORT_DIR}/lxc/containers.list" 2>/dev/null >> "$MANIFEST_FILE" || true
    echo "" >> "$MANIFEST_FILE"

    ok "LXC container configs exported"
  else
    warn "No LXC containers found"
  fi
else
  log "[7/8] Skipping LXC containers (--no-lxc)"
fi

# ── 8. Export data partition ──────────────────────────────────────
if [[ $INCLUDE_DATA -eq 1 ]]; then
  log "[8/8] Exporting /data partition contents..."

  # Check if /data exists and has content
  DATA_SIZE=$($SSH_CMD "du -sh /data 2>/dev/null | cut -f1" 2>/dev/null || echo "0")

  if [ -n "$DATA_SIZE" ] && [ "$DATA_SIZE" != "0" ]; then
    # Export small files from /data (skip large files like LXC rootfs)
    $SSH_CMD "find /data -maxdepth 2 -type f -size -10M 2>/dev/null | tar -czf - -T - 2>/dev/null || true" \
      > "${EXPORT_DIR}/data/data-small.tar.gz" 2>/dev/null || true

    # List of directories in /data
    $SSH_CMD "ls -la /data 2>/dev/null || true" > "${EXPORT_DIR}/data/data-listing.txt" 2>/dev/null || true

    echo "## Data Partition" >> "$MANIFEST_FILE"
    echo "Size: $DATA_SIZE" >> "$MANIFEST_FILE"
    cat "${EXPORT_DIR}/data/data-listing.txt" 2>/dev/null >> "$MANIFEST_FILE" || true
    echo "" >> "$MANIFEST_FILE"

    ok "Data partition contents exported"
  else
    warn "No /data partition or empty"
  fi
else
  log "[8/8] Skipping /data partition (--no-data)"
fi

# ── Create preseed archive ────────────────────────────────────────
log "Creating preseed archive..."

# Remove empty files and directories
find "${EXPORT_DIR}" -type f -empty -delete 2>/dev/null || true
find "${EXPORT_DIR}" -type d -empty -delete 2>/dev/null || true

# Create compressed archive
tar -czf "$PRESEED_FILE" -C "$EXPORT_DIR" .

PRESEED_SIZE=$(du -sh "$PRESEED_FILE" | cut -f1)

ok "Preseed archive created: ${PRESEED_FILE} (${PRESEED_SIZE})"

echo ""
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  C3Box Clone Export Complete!${NC}"
echo ""
echo -e "  Source:   ${REMOTE_HOSTNAME} (${C3BOX_HOST}:${C3BOX_PORT})"
echo -e "  Preseed:  ${PRESEED_FILE} (${PRESEED_SIZE})"
echo -e "  Manifest: ${MANIFEST_FILE}"
echo ""
echo -e "  ${BOLD}To create a cloned installer ISO:${NC}"
echo -e "    sudo bash image/build-installer-iso.sh --preseed ${PRESEED_FILE}"
echo ""
echo -e "  ${BOLD}Or build with all local packages:${NC}"
echo -e "    sudo bash image/build-installer-iso.sh --preseed ${PRESEED_FILE} --slipstream"
echo ""
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════════${NC}"
