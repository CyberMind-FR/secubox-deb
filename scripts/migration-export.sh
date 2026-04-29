#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  scripts/migration-export.sh — Export SecuBox-OpenWrt → Migration Archive
#
#  SecuBox-DEB :: Migration Data Saver
#  CyberMind — https://cybermind.fr
#  Author: Gérald Kerma <gandalf@gk2.net>
#
#  Usage:
#    bash scripts/migration-export.sh -h 192.168.255.1 -o /tmp/migration.tar.gz
#    bash scripts/migration-export.sh -h 192.168.255.1 -i ~/.ssh/secubox-openwrt -o /tmp/migration.tar.gz
#    bash scripts/migration-export.sh -h 192.168.255.1 --encrypt -o /tmp/migration.tar.gz.enc
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly VERSION="2.1.0"
readonly TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

# ── Colors ──
CYAN='\033[0;36m'; GREEN='\033[0;32m'; GOLD='\033[0;33m'
RED='\033[0;31m'; PURPLE='\033[0;35m'; NC='\033[0m'

log()     { echo -e "${CYAN}[export]${NC} $*"; }
ok()      { echo -e "${GREEN}[   OK ]${NC} $*"; }
warn()    { echo -e "${GOLD}[ WARN ]${NC} $*"; }
err()     { echo -e "${RED}[ FAIL ]${NC} $*" >&2; exit 1; }
section() { echo -e "\n${PURPLE}══════════════════════════════════════════════════════════════════${NC}"; echo -e "${PURPLE}  $*${NC}"; echo -e "${PURPLE}══════════════════════════════════════════════════════════════════${NC}"; }

# ── Default values ──
HOST=""
SSH_KEY=""
OUTPUT=""
ENCRYPT=0
PASSPHRASE=""
SSH_PORT=22
WORKDIR=""
MODULES="all"
EXCLUDE_SERVICES=""

usage() {
  cat <<EOF
SecuBox Migration Export — Version $VERSION

Export configurations and data from SecuBox-OpenWrt to migration archive.

Usage:
  $(basename "$0") -h HOST [-i SSH_KEY] [-o OUTPUT] [OPTIONS]

Required:
  -h, --host HOST       OpenWrt host (IP or hostname)
  -o, --output FILE     Output archive path (default: ./secubox-migration-TIMESTAMP.tar.gz)

Options:
  -i, --identity FILE   SSH private key file
  -p, --port PORT       SSH port (default: 22)
  -e, --encrypt         Encrypt archive with AES-256
  --passphrase PASS     Encryption passphrase (prompts if not provided)
  -m, --modules LIST    Comma-separated module list (default: all)
                        Available: network,firewall,wireguard,crowdsec,dhcp,
                                   haproxy,nginx,certs,content,vhosts,users,
                                   git,media,mail,accounts,dns,databases,scripts
  --exclude-services    Comma-separated list of /srv/* services to skip
                        Example: nextcloud,peertube,gitea
  --help                Show this help

Examples:
  # Basic export
  $(basename "$0") -h 192.168.255.1 -o /tmp/migration.tar.gz

  # With SSH key
  $(basename "$0") -h 192.168.255.1 -i ~/.ssh/secubox-openwrt -o /tmp/migration.tar.gz

  # Encrypted archive
  $(basename "$0") -h 192.168.255.1 -e --passphrase "secret" -o /tmp/migration.tar.gz.enc

  # Specific modules only
  $(basename "$0") -h 192.168.255.1 -m wireguard,crowdsec,certs -o /tmp/migration.tar.gz

EOF
  exit 0
}

# ── Parse arguments ──
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--host)      HOST="$2"; shift 2 ;;
    -i|--identity)  SSH_KEY="$2"; shift 2 ;;
    -o|--output)    OUTPUT="$2"; shift 2 ;;
    -p|--port)      SSH_PORT="$2"; shift 2 ;;
    -e|--encrypt)   ENCRYPT=1; shift ;;
    --passphrase)   PASSPHRASE="$2"; shift 2 ;;
    -m|--modules)   MODULES="$2"; shift 2 ;;
    --exclude-services) EXCLUDE_SERVICES="$2"; shift 2 ;;
    --help)         usage ;;
    *)              err "Unknown option: $1" ;;
  esac
done

# ── Validate required arguments ──
[[ -z "$HOST" ]] && err "Host required. Use -h/--host"
[[ -z "$OUTPUT" ]] && OUTPUT="./secubox-migration-${TIMESTAMP}.tar.gz"

# ── Build SSH command ──
SSH_CMD="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p $SSH_PORT"
SCP_CMD="scp -o StrictHostKeyChecking=no -P $SSH_PORT"
[[ -n "$SSH_KEY" ]] && {
  [[ -f "$SSH_KEY" ]] || err "SSH key not found: $SSH_KEY"
  SSH_CMD="$SSH_CMD -i $SSH_KEY"
  SCP_CMD="$SCP_CMD -i $SSH_KEY"
}

ssh_run() { $SSH_CMD "root@$HOST" "$@"; }
scp_get() { $SCP_CMD "root@$HOST:$1" "$2"; }

# ── Test SSH connection ──
section "Testing SSH connection to $HOST"
ssh_run "echo 'Connection OK'" 2>/dev/null || err "Cannot connect to $HOST via SSH"
ok "SSH connection established"

# ── Create work directory ──
WORKDIR=$(mktemp -d -t secubox-migration-XXXXXX)
trap 'rm -rf "$WORKDIR"' EXIT

mkdir -p "$WORKDIR"/{configs,secrets,content,state}

# ── Detect OpenWrt version ──
section "Detecting SecuBox-OpenWrt version"
OWRT_VERSION=$(ssh_run "cat /etc/openwrt_release 2>/dev/null | grep DISTRIB_RELEASE | cut -d= -f2 | tr -d \"'\"" || echo "unknown")
SECUBOX_VERSION=$(ssh_run "cat /etc/secubox-version 2>/dev/null || echo 'unknown'")
log "OpenWrt: $OWRT_VERSION"
log "SecuBox: $SECUBOX_VERSION"

# ── Create manifest ──
cat > "$WORKDIR/manifest.json" <<EOF
{
  "version": "$VERSION",
  "timestamp": "$TIMESTAMP",
  "source": {
    "host": "$HOST",
    "type": "openwrt",
    "openwrt_version": "$OWRT_VERSION",
    "secubox_version": "$SECUBOX_VERSION"
  },
  "modules": [],
  "checksums": {}
}
EOF

# ── Module export functions ──

export_network() {
  section "Exporting: Network Configuration (UCI)"
  local dst="$WORKDIR/configs/network"
  mkdir -p "$dst"

  # UCI network config
  ssh_run "cat /etc/config/network" > "$dst/network.uci" 2>/dev/null || warn "No /etc/config/network"

  # Interfaces info
  ssh_run "ip addr show" > "$dst/interfaces.txt" 2>/dev/null || true
  ssh_run "ip route show" > "$dst/routes.txt" 2>/dev/null || true

  ok "Network config exported"
}

export_firewall() {
  section "Exporting: Firewall Rules (UCI)"
  local dst="$WORKDIR/configs/firewall"
  mkdir -p "$dst"

  # UCI firewall config
  ssh_run "cat /etc/config/firewall" > "$dst/firewall.uci" 2>/dev/null || warn "No /etc/config/firewall"

  # Current iptables rules (for reference)
  ssh_run "iptables-save 2>/dev/null" > "$dst/iptables.rules" || true
  ssh_run "ip6tables-save 2>/dev/null" > "$dst/ip6tables.rules" || true

  # Custom nftables if present
  ssh_run "cat /etc/nftables.conf 2>/dev/null" > "$dst/nftables.conf" || true

  ok "Firewall rules exported"
}

export_wireguard() {
  section "Exporting: WireGuard Configuration"
  local dst="$WORKDIR/configs/wireguard"
  local secrets_dst="$WORKDIR/secrets/wireguard"
  mkdir -p "$dst" "$secrets_dst"

  # UCI wireguard config
  ssh_run "cat /etc/config/wireguard 2>/dev/null" > "$dst/wireguard.uci" || true

  # WireGuard configs (contains private keys - goes to secrets)
  ssh_run "ls /etc/wireguard/*.conf 2>/dev/null" | while read -r f; do
    local name=$(basename "$f")
    ssh_run "cat $f" > "$secrets_dst/$name"
    log "  Exported: $name (secrets)"
  done || warn "No WireGuard configs found"

  # Interface status
  ssh_run "wg show all 2>/dev/null" > "$dst/wg-status.txt" || true

  ok "WireGuard exported"
}

export_crowdsec() {
  section "Exporting: CrowdSec Configuration"
  local dst="$WORKDIR/configs/crowdsec"
  mkdir -p "$dst"

  # Main config
  ssh_run "cat /etc/crowdsec/config.yaml 2>/dev/null" > "$dst/config.yaml" || warn "No CrowdSec config"

  # Acquis configs
  ssh_run "tar -czf - /etc/crowdsec/acquis.d 2>/dev/null" | tar -xzf - -C "$dst" --strip-components=2 || true

  # Local parsers/scenarios
  for subdir in parsers scenarios postoverflows; do
    ssh_run "tar -czf - /etc/crowdsec/$subdir 2>/dev/null" | tar -xzf - -C "$dst" --strip-components=2 || true
  done

  # Local API creds (secrets)
  mkdir -p "$WORKDIR/secrets/crowdsec"
  ssh_run "cat /etc/crowdsec/local_api_credentials.yaml 2>/dev/null" > "$WORKDIR/secrets/crowdsec/local_api_credentials.yaml" || true

  ok "CrowdSec exported"
}

export_dhcp() {
  section "Exporting: DHCP/DNS Configuration (UCI)"
  local dst="$WORKDIR/configs/dhcp"
  mkdir -p "$dst"

  # UCI dhcp config
  ssh_run "cat /etc/config/dhcp" > "$dst/dhcp.uci" 2>/dev/null || warn "No /etc/config/dhcp"

  # Static leases
  ssh_run "cat /tmp/dhcp.leases 2>/dev/null" > "$dst/leases.txt" || true

  # Custom dnsmasq config
  ssh_run "cat /etc/dnsmasq.conf 2>/dev/null" > "$dst/dnsmasq.conf" || true
  ssh_run "ls /etc/dnsmasq.d/*.conf 2>/dev/null | xargs cat" > "$dst/dnsmasq.d.conf" || true

  ok "DHCP/DNS exported"
}

export_haproxy() {
  section "Exporting: HAProxy Configuration (Full)"
  local dst="$WORKDIR/configs/haproxy"
  local secrets_dst="$WORKDIR/secrets/haproxy"
  mkdir -p "$dst" "$secrets_dst"

  # Main config
  ssh_run "cat /etc/haproxy/haproxy.cfg 2>/dev/null" > "$dst/haproxy.cfg" || warn "No HAProxy config"

  # conf.d directory (backend definitions, ACLs, routing)
  if ssh_run "[ -d '/etc/haproxy/conf.d' ]" 2>/dev/null; then
    log "  Exporting HAProxy conf.d..."
    mkdir -p "$dst/conf.d"
    ssh_run "tar -czf - /etc/haproxy/conf.d 2>/dev/null" | tar -xzf - -C "$dst/conf.d" --strip-components=3 || true
    local conf_count=$(ls "$dst/conf.d"/*.cfg 2>/dev/null | wc -l || echo "0")
    log "    Found $conf_count config snippets"
  fi

  # HAProxy certificates (secrets)
  if ssh_run "[ -d '/etc/haproxy/certs' ]" 2>/dev/null; then
    log "  Exporting HAProxy certificates..."
    mkdir -p "$secrets_dst/certs"
    ssh_run "tar -czf - /etc/haproxy/certs 2>/dev/null" | tar -xzf - -C "$secrets_dst/certs" --strip-components=3 || true
    local cert_count=$(ssh_run "ls /etc/haproxy/certs/*.pem 2>/dev/null | wc -l" || echo "0")
    log "    Found $cert_count certificate files"
  fi

  # HAProxy maps (domain → backend mappings)
  if ssh_run "[ -d '/etc/haproxy/maps' ]" 2>/dev/null; then
    log "  Exporting HAProxy maps..."
    mkdir -p "$dst/maps"
    ssh_run "tar -czf - /etc/haproxy/maps 2>/dev/null" | tar -xzf - -C "$dst/maps" --strip-components=3 || true
  fi

  # HAProxy errors directory (custom error pages)
  if ssh_run "[ -d '/etc/haproxy/errors' ]" 2>/dev/null; then
    log "  Exporting HAProxy error pages..."
    mkdir -p "$dst/errors"
    ssh_run "tar -czf - /etc/haproxy/errors 2>/dev/null" | tar -xzf - -C "$dst/errors" --strip-components=3 || true
  fi

  # ACME/Let's Encrypt HAProxy integration
  if ssh_run "[ -f '/etc/haproxy/acme.cfg' ]" 2>/dev/null; then
    ssh_run "cat /etc/haproxy/acme.cfg 2>/dev/null" > "$dst/acme.cfg" || true
  fi

  # HAProxy Lua scripts
  if ssh_run "[ -d '/etc/haproxy/lua' ]" 2>/dev/null; then
    log "  Exporting HAProxy Lua scripts..."
    mkdir -p "$dst/lua"
    ssh_run "tar -czf - /etc/haproxy/lua 2>/dev/null" | tar -xzf - -C "$dst/lua" --strip-components=3 || true
  fi

  # mitmproxy routes mapping (SecuBox specific)
  if ssh_run "[ -f '/srv/mitmproxy/haproxy-routes.json' ]" 2>/dev/null; then
    log "  Exporting mitmproxy routes..."
    ssh_run "cat /srv/mitmproxy/haproxy-routes.json 2>/dev/null" > "$dst/mitmproxy-routes.json" || true
  fi

  local size=$(du -sh "$dst" 2>/dev/null | cut -f1 || echo "0")
  ok "HAProxy exported ($size)"
}

export_nginx() {
  section "Exporting: Nginx Configuration"
  local dst="$WORKDIR/configs/nginx"
  mkdir -p "$dst"

  # Main config
  ssh_run "cat /etc/nginx/nginx.conf 2>/dev/null" > "$dst/nginx.conf" || true

  # Sites
  ssh_run "tar -czf - /etc/nginx/sites-enabled 2>/dev/null" | tar -xzf - -C "$dst" --strip-components=2 || true
  ssh_run "tar -czf - /etc/nginx/sites-available 2>/dev/null" | tar -xzf - -C "$dst" --strip-components=2 || true

  # Conf.d
  ssh_run "tar -czf - /etc/nginx/conf.d 2>/dev/null" | tar -xzf - -C "$dst" --strip-components=2 || true

  ok "Nginx exported"
}

export_certs() {
  section "Exporting: SSL Certificates"
  local secrets_dst="$WORKDIR/secrets/certs"
  mkdir -p "$secrets_dst"

  # Let's Encrypt certificates
  ssh_run "tar -czf - /etc/letsencrypt 2>/dev/null" | tar -xzf - -C "$secrets_dst" --strip-components=1 || true

  # Custom SSL certs
  ssh_run "ls /etc/ssl/private/*.key 2>/dev/null" | while read -r f; do
    local name=$(basename "$f")
    ssh_run "cat $f" > "$secrets_dst/$name"
  done || true

  ssh_run "ls /etc/ssl/certs/*.pem 2>/dev/null" | while read -r f; do
    local name=$(basename "$f")
    ssh_run "cat $f" > "$secrets_dst/$name"
  done || true

  ok "Certificates exported"
}

export_content() {
  section "Exporting: Web Content"
  local dst="$WORKDIR/content"

  # /srv/www
  ssh_run "tar -czf - /srv/www 2>/dev/null" | tar -xzf - -C "$dst" --strip-components=1 || true

  # /var/www
  ssh_run "tar -czf - /var/www 2>/dev/null" | tar -xzf - -C "$dst" --strip-components=1 || true

  # Calculate size
  local size=$(du -sh "$dst" 2>/dev/null | cut -f1)
  ok "Web content exported ($size)"
}

export_vhosts() {
  section "Exporting: Virtual Hosts (UCI)"
  local dst="$WORKDIR/configs/vhosts"
  mkdir -p "$dst"

  # UCI vhost config
  ssh_run "cat /etc/config/vhost 2>/dev/null" > "$dst/vhost.uci" || warn "No /etc/config/vhost"

  # SecuBox vhost configs
  ssh_run "tar -czf - /etc/secubox/vhosts 2>/dev/null" | tar -xzf - -C "$dst" --strip-components=3 || true

  ok "Virtual hosts exported"
}

export_users() {
  section "Exporting: User Accounts"
  local dst="$WORKDIR/configs/users"
  local secrets_dst="$WORKDIR/secrets/users"
  mkdir -p "$dst" "$secrets_dst"

  # Filter system users - only export secubox-related users
  ssh_run "grep -E '^(root|secubox|admin)' /etc/passwd 2>/dev/null" > "$dst/passwd.filtered" || true
  ssh_run "grep -E '^(root|secubox|admin)' /etc/shadow 2>/dev/null" > "$secrets_dst/shadow.filtered" || true

  # SSH authorized keys
  ssh_run "cat /root/.ssh/authorized_keys 2>/dev/null" > "$secrets_dst/authorized_keys" || true

  # SecuBox auth config
  ssh_run "cat /etc/secubox/auth.toml 2>/dev/null" > "$dst/auth.toml" || true

  ok "Users exported"
}

export_state() {
  section "Exporting: Service State Data"
  local dst="$WORKDIR/state"

  # CrowdSec decisions DB
  mkdir -p "$dst/crowdsec"
  ssh_run "cat /var/lib/crowdsec/data/crowdsec.db 2>/dev/null" > "$dst/crowdsec/crowdsec.db" || true

  # SecuBox state
  mkdir -p "$dst/secubox"
  ssh_run "tar -czf - /var/lib/secubox 2>/dev/null" | tar -xzf - -C "$dst/secubox" --strip-components=3 || true

  ok "State data exported"
}

export_git() {
  section "Exporting: Git Repositories"
  local dst="$WORKDIR/content/git"
  mkdir -p "$dst"

  # Common Git repository locations
  local git_dirs="/srv/git /var/lib/git /home/git /root/repos"
  local total_size=0
  local repo_count=0

  for git_base in $git_dirs; do
    if ssh_run "[ -d '$git_base' ]" 2>/dev/null; then
      log "  Scanning: $git_base"

      # Find all .git directories (bare repos)
      ssh_run "find '$git_base' -maxdepth 3 -name '*.git' -type d 2>/dev/null" | while read -r repo; do
        local repo_name=$(basename "$repo")
        local repo_path=$(dirname "$repo")
        log "    Found: $repo_name"

        # Export as bare repo tarball
        ssh_run "tar -czf - '$repo' 2>/dev/null" > "$dst/${repo_name}.tar.gz" || true
        ((repo_count++))
      done || true

      # Also find non-bare repos (containing .git subdirectory)
      ssh_run "find '$git_base' -maxdepth 4 -type d -name '.git' 2>/dev/null" | while read -r dotgit; do
        local repo=$(dirname "$dotgit")
        local repo_name=$(basename "$repo")
        log "    Found: $repo_name (working tree)"

        # Export entire repo including working tree
        ssh_run "tar -czf - '$repo' 2>/dev/null" > "$dst/${repo_name}-full.tar.gz" || true
        ((repo_count++))
      done || true
    fi
  done

  # Gitea/Gogs/GitLab data if present
  for git_app in gitea gogs gitlab; do
    local app_data="/var/lib/$git_app"
    if ssh_run "[ -d '$app_data' ]" 2>/dev/null; then
      log "  Exporting $git_app data..."
      mkdir -p "$dst/$git_app"
      ssh_run "tar -czf - '$app_data/repositories' 2>/dev/null" | tar -xzf - -C "$dst/$git_app" --strip-components=3 || true
      ssh_run "cat '$app_data/conf/app.ini' 2>/dev/null" > "$dst/$git_app/app.ini" || true
      ssh_run "cat /etc/$git_app/app.ini 2>/dev/null" >> "$dst/$git_app/app.ini" || true
    fi
  done

  local size=$(du -sh "$dst" 2>/dev/null | cut -f1 || echo "0")
  ok "Git repositories exported ($size)"
}

export_media() {
  section "Exporting: Media Files (Videos, Images, Audio)"
  local dst="$WORKDIR/content/media"
  mkdir -p "$dst"

  # Common media locations
  local media_dirs="/srv/media /var/lib/media /home/media /srv/videos /var/lib/jellyfin/data /var/lib/plex"

  for media_base in $media_dirs; do
    if ssh_run "[ -d '$media_base' ]" 2>/dev/null; then
      log "  Exporting: $media_base"
      local base_name=$(echo "$media_base" | tr '/' '_' | sed 's/^_//')
      mkdir -p "$dst/$base_name"

      # Export media files (with progress indicator for large files)
      ssh_run "tar -czf - '$media_base' 2>/dev/null" | tar -xzf - -C "$dst/$base_name" --strip-components=2 || true
    fi
  done

  # PeerTube data
  if ssh_run "[ -d '/var/www/peertube/storage' ]" 2>/dev/null; then
    log "  Exporting PeerTube storage..."
    mkdir -p "$dst/peertube"
    ssh_run "tar -czf - /var/www/peertube/storage/videos 2>/dev/null" | tar -xzf - -C "$dst/peertube" --strip-components=4 || true
  fi

  # Jellyfin metadata + library
  if ssh_run "[ -d '/var/lib/jellyfin' ]" 2>/dev/null; then
    log "  Exporting Jellyfin library..."
    mkdir -p "$dst/jellyfin"
    ssh_run "tar -czf - /var/lib/jellyfin/data/library 2>/dev/null" | tar -xzf - -C "$dst/jellyfin" --strip-components=4 || true
    ssh_run "cat /etc/jellyfin/system.xml 2>/dev/null" > "$dst/jellyfin/system.xml" || true
  fi

  # Nextcloud data (files, not database)
  if ssh_run "[ -d '/var/www/nextcloud/data' ]" 2>/dev/null; then
    log "  Exporting Nextcloud user files..."
    mkdir -p "$dst/nextcloud"
    ssh_run "tar -czf - /var/www/nextcloud/data 2>/dev/null" | tar -xzf - -C "$dst/nextcloud" --strip-components=4 || warn "Nextcloud export partial"
  fi

  local size=$(du -sh "$dst" 2>/dev/null | cut -f1 || echo "0")
  ok "Media files exported ($size)"
}

export_mail() {
  section "Exporting: Email Data"
  local dst="$WORKDIR/content/mail"
  local secrets_dst="$WORKDIR/secrets/mail"
  mkdir -p "$dst" "$secrets_dst"

  # Maildir format (Dovecot, Postfix)
  local mail_dirs="/var/mail /var/vmail /home/vmail"
  for mail_base in $mail_dirs; do
    if ssh_run "[ -d '$mail_base' ]" 2>/dev/null; then
      log "  Exporting Maildir: $mail_base"
      local base_name=$(echo "$mail_base" | tr '/' '_' | sed 's/^_//')
      mkdir -p "$dst/$base_name"
      ssh_run "tar -czf - '$mail_base' 2>/dev/null" | tar -xzf - -C "$dst/$base_name" --strip-components=2 || true
    fi
  done

  # Postfix configuration
  if ssh_run "[ -d '/etc/postfix' ]" 2>/dev/null; then
    log "  Exporting Postfix config..."
    mkdir -p "$dst/postfix"
    ssh_run "tar -czf - /etc/postfix 2>/dev/null" | tar -xzf - -C "$dst/postfix" --strip-components=2 || true
  fi

  # Dovecot configuration
  if ssh_run "[ -d '/etc/dovecot' ]" 2>/dev/null; then
    log "  Exporting Dovecot config..."
    mkdir -p "$dst/dovecot"
    ssh_run "tar -czf - /etc/dovecot 2>/dev/null" | tar -xzf - -C "$dst/dovecot" --strip-components=2 || true
  fi

  # OpenDKIM keys (secrets)
  if ssh_run "[ -d '/etc/opendkim/keys' ]" 2>/dev/null; then
    log "  Exporting DKIM keys..."
    mkdir -p "$secrets_dst/opendkim"
    ssh_run "tar -czf - /etc/opendkim 2>/dev/null" | tar -xzf - -C "$secrets_dst/opendkim" --strip-components=2 || true
  fi

  # Mail aliases
  ssh_run "cat /etc/aliases 2>/dev/null" > "$dst/aliases" || true
  ssh_run "cat /etc/mailname 2>/dev/null" > "$dst/mailname" || true

  # Mail account database (if using virtual users)
  ssh_run "cat /etc/postfix/vmailbox 2>/dev/null" > "$dst/vmailbox" || true
  ssh_run "cat /etc/dovecot/users 2>/dev/null" > "$secrets_dst/dovecot-users" || true

  local size=$(du -sh "$dst" 2>/dev/null | cut -f1 || echo "0")
  ok "Email data exported ($size)"
}

export_accounts() {
  section "Exporting: Complete User Accounts"
  local dst="$WORKDIR/content/accounts"
  local secrets_dst="$WORKDIR/secrets/accounts"
  mkdir -p "$dst" "$secrets_dst"

  # Get list of real users (UID >= 1000 or specific system users)
  log "  Discovering user accounts..."
  ssh_run "awk -F: '\$3 >= 1000 || \$1 ~ /^(admin|secubox|git|nextcloud|peertube)/ {print \$1}' /etc/passwd 2>/dev/null" > "$dst/users.list" || true

  # Export home directories
  while read -r user; do
    [[ -z "$user" ]] && continue
    local home_dir=$(ssh_run "getent passwd '$user' | cut -d: -f6" 2>/dev/null)
    [[ -z "$home_dir" ]] && continue

    if ssh_run "[ -d '$home_dir' ]" 2>/dev/null; then
      log "    Exporting home: $user ($home_dir)"
      mkdir -p "$dst/homes/$user"

      # Export home directory (excluding large cache/trash dirs)
      ssh_run "tar -czf - --exclude='.cache' --exclude='.local/share/Trash' --exclude='node_modules' --exclude='.npm' '$home_dir' 2>/dev/null" | \
        tar -xzf - -C "$dst/homes/$user" --strip-components=2 || true
    fi
  done < "$dst/users.list"

  # Export passwd/shadow/group for these users (to secrets)
  log "  Exporting user credentials..."
  while read -r user; do
    [[ -z "$user" ]] && continue
    ssh_run "grep '^${user}:' /etc/passwd" >> "$secrets_dst/passwd" 2>/dev/null || true
    ssh_run "grep '^${user}:' /etc/shadow" >> "$secrets_dst/shadow" 2>/dev/null || true
    ssh_run "grep -E '(^${user}:|:${user},|,${user},|,${user}\$|:${user}\$)' /etc/group" >> "$secrets_dst/group" 2>/dev/null || true
  done < "$dst/users.list"

  # Export sudo rules
  ssh_run "cat /etc/sudoers.d/* 2>/dev/null" > "$dst/sudoers.d" || true
  ssh_run "grep -v '^#' /etc/sudoers 2>/dev/null | grep -v '^\$'" > "$dst/sudoers" || true

  # Crontabs
  mkdir -p "$dst/crontabs"
  ssh_run "ls /var/spool/cron/crontabs 2>/dev/null" | while read -r cron_user; do
    ssh_run "cat /var/spool/cron/crontabs/$cron_user 2>/dev/null" > "$dst/crontabs/$cron_user" || true
    log "    Exported crontab: $cron_user"
  done || true

  # System-wide cron
  ssh_run "tar -czf - /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null" | \
    tar -xzf - -C "$dst" --strip-components=1 || true

  local user_count=$(wc -l < "$dst/users.list" 2>/dev/null || echo "0")
  local size=$(du -sh "$dst" 2>/dev/null | cut -f1 || echo "0")
  ok "User accounts exported ($user_count users, $size)"
}

export_dns() {
  section "Exporting: DNS Services (BIND, Vortex, AdGuard)"
  local dst="$WORKDIR/configs/dns"
  local secrets_dst="$WORKDIR/secrets/dns"
  mkdir -p "$dst" "$secrets_dst"

  # BIND/named configuration
  if ssh_run "[ -d '/etc/bind' ]" 2>/dev/null; then
    log "  Exporting BIND configuration..."
    mkdir -p "$dst/bind"
    ssh_run "tar -czf - /etc/bind 2>/dev/null" | tar -xzf - -C "$dst/bind" --strip-components=2 || true

    # Zones directory separately (may be large)
    if ssh_run "[ -d '/etc/bind/zones' ]" 2>/dev/null; then
      log "  Exporting DNS zones..."
      mkdir -p "$dst/bind/zones"
      ssh_run "tar -czf - /etc/bind/zones 2>/dev/null" | tar -xzf - -C "$dst/bind/zones" --strip-components=3 || true
      local zone_count=$(ls "$dst/bind/zones"/*.zone 2>/dev/null | wc -l || echo "0")
      log "    Found $zone_count zone files"
    fi

    # RNDC key (secret)
    ssh_run "cat /etc/bind/rndc.key 2>/dev/null" > "$secrets_dst/rndc.key" || true
  fi

  # Unbound configuration
  if ssh_run "[ -d '/etc/unbound' ]" 2>/dev/null; then
    log "  Exporting Unbound configuration..."
    mkdir -p "$dst/unbound"
    ssh_run "tar -czf - /etc/unbound 2>/dev/null" | tar -xzf - -C "$dst/unbound" --strip-components=2 || true
  fi

  # Vortex DNS (dnsmasq-based blocklists)
  if ssh_run "[ -d '/etc/dnsmasq.d/vortex' ]" 2>/dev/null; then
    log "  Exporting Vortex DNS blocklists..."
    mkdir -p "$dst/vortex"
    ssh_run "tar -czf - /etc/dnsmasq.d/vortex 2>/dev/null" | tar -xzf - -C "$dst/vortex" --strip-components=3 || true
    ssh_run "cat /etc/dnsmasq.d/vortex*.conf 2>/dev/null" > "$dst/vortex/vortex-main.conf" || true
  fi

  # Vortex RPZ zone (Response Policy Zone for blocking)
  if ssh_run "[ -f '/etc/bind/zones/rpz.vortex.zone' ]" 2>/dev/null; then
    log "  Exporting Vortex RPZ zone (blocklist)..."
    ssh_run "cat /etc/bind/zones/rpz.vortex.zone 2>/dev/null" > "$dst/bind/zones/rpz.vortex.zone" || true
    local rpz_size=$(ssh_run "du -h /etc/bind/zones/rpz.vortex.zone 2>/dev/null | cut -f1" || echo "0")
    log "    RPZ zone size: $rpz_size"
  fi

  # AdGuard Home
  if ssh_run "[ -f '/etc/adguardhome/AdGuardHome.yaml' ]" 2>/dev/null; then
    log "  Exporting AdGuard Home configuration..."
    mkdir -p "$dst/adguardhome"
    ssh_run "cat /etc/adguardhome/AdGuardHome.yaml 2>/dev/null" > "$dst/adguardhome/AdGuardHome.yaml" || true

    # AdGuard Home data (filters, stats)
    if ssh_run "[ -d '/var/lib/adguardhome/data' ]" 2>/dev/null; then
      mkdir -p "$dst/adguardhome/data"
      ssh_run "tar -czf - /var/lib/adguardhome/data 2>/dev/null" | tar -xzf - -C "$dst/adguardhome/data" --strip-components=4 || true
    fi
  fi

  # Pi-hole (if present)
  if ssh_run "[ -d '/etc/pihole' ]" 2>/dev/null; then
    log "  Exporting Pi-hole configuration..."
    mkdir -p "$dst/pihole"
    ssh_run "tar -czf - /etc/pihole 2>/dev/null" | tar -xzf - -C "$dst/pihole" --strip-components=2 || true
  fi

  # Additional dnsmasq configs
  ssh_run "cat /etc/dnsmasq.d/*.conf 2>/dev/null" > "$dst/dnsmasq.d.conf" || true

  local size=$(du -sh "$dst" 2>/dev/null | cut -f1 || echo "0")
  ok "DNS services exported ($size)"
}

export_databases() {
  section "Exporting: Databases (SQLite, MySQL dumps)"
  local dst="$WORKDIR/state/databases"
  mkdir -p "$dst"

  # SQLite databases from common locations
  local db_paths="/var/lib/*.db /srv/*.db /var/lib/*/data/*.db /var/lib/*/*/*.db"
  local db_count=0

  for db_pattern in $db_paths; do
    ssh_run "ls $db_pattern 2>/dev/null" | while read -r db_file; do
      [[ -z "$db_file" ]] && continue
      local db_name=$(basename "$db_file")
      local db_dir=$(dirname "$db_file" | tr '/' '_' | sed 's/^_//')
      mkdir -p "$dst/$db_dir"
      log "  Exporting: $db_file"
      ssh_run "cat '$db_file' 2>/dev/null" > "$dst/$db_dir/$db_name" || true
      ((db_count++))
    done || true
  done

  # MySQL/MariaDB dump (if mysqldump available)
  if ssh_run "which mysqldump >/dev/null 2>&1"; then
    log "  Creating MySQL dump..."
    mkdir -p "$dst/mysql"
    ssh_run "mysqldump --all-databases --single-transaction 2>/dev/null" > "$dst/mysql/all-databases.sql" || warn "MySQL dump failed"
  fi

  # PostgreSQL dump (if pg_dumpall available)
  if ssh_run "which pg_dumpall >/dev/null 2>&1"; then
    log "  Creating PostgreSQL dump..."
    mkdir -p "$dst/postgresql"
    ssh_run "su - postgres -c 'pg_dumpall' 2>/dev/null" > "$dst/postgresql/all-databases.sql" || warn "PostgreSQL dump failed"
  fi

  # Redis dump
  if ssh_run "[ -f '/var/lib/redis/dump.rdb' ]" 2>/dev/null; then
    log "  Exporting Redis dump..."
    mkdir -p "$dst/redis"
    ssh_run "cat /var/lib/redis/dump.rdb 2>/dev/null" > "$dst/redis/dump.rdb" || true
  fi

  local size=$(du -sh "$dst" 2>/dev/null | cut -f1 || echo "0")
  ok "Databases exported ($size)"
}

export_scripts() {
  section "Exporting: Custom Scripts and Systemd Units"
  local dst="$WORKDIR/configs/scripts"
  mkdir -p "$dst"

  # Custom scripts from common locations
  local script_dirs="/usr/local/bin /usr/local/sbin /root/scripts /root/bin /opt/scripts"
  for script_dir in $script_dirs; do
    if ssh_run "[ -d '$script_dir' ]" 2>/dev/null; then
      log "  Exporting: $script_dir"
      local dir_name=$(echo "$script_dir" | tr '/' '_' | sed 's/^_//')
      mkdir -p "$dst/$dir_name"
      ssh_run "tar -czf - '$script_dir' 2>/dev/null" | tar -xzf - -C "$dst/$dir_name" --strip-components=3 || true
    fi
  done

  # Systemd unit overrides
  if ssh_run "[ -d '/etc/systemd/system' ]" 2>/dev/null; then
    log "  Exporting systemd unit overrides..."
    mkdir -p "$dst/systemd"
    ssh_run "find /etc/systemd/system -name '*.service' -o -name '*.d' -type d 2>/dev/null" | while read -r unit; do
      [[ -z "$unit" ]] && continue
      local unit_name=$(basename "$unit")
      if [[ -d "$unit" ]]; then
        ssh_run "tar -czf - '$unit' 2>/dev/null" | tar -xzf - -C "$dst/systemd" --strip-components=3 || true
      else
        ssh_run "cat '$unit' 2>/dev/null" > "$dst/systemd/$unit_name" || true
      fi
    done || true
  fi

  # Init.d scripts (OpenWrt style)
  if ssh_run "[ -d '/etc/init.d' ]" 2>/dev/null; then
    log "  Exporting init.d scripts..."
    mkdir -p "$dst/init.d"
    ssh_run "tar -czf - /etc/init.d 2>/dev/null" | tar -xzf - -C "$dst/init.d" --strip-components=2 || true
  fi

  # RC.local
  ssh_run "cat /etc/rc.local 2>/dev/null" > "$dst/rc.local" || true

  # Environment files
  mkdir -p "$dst/environment"
  ssh_run "cat /etc/environment 2>/dev/null" > "$dst/environment/environment" || true
  ssh_run "cat /etc/default/* 2>/dev/null" > "$dst/environment/defaults" || true

  local size=$(du -sh "$dst" 2>/dev/null | cut -f1 || echo "0")
  ok "Scripts and units exported ($size)"
}

export_services() {
  section "Exporting: Application Services (/srv/*)"
  local dst="$WORKDIR/content/services"
  mkdir -p "$dst"

  # List of service directories to export from /srv/
  local services="
    streamlit
    gitea
    metablogizer
    metabolizer
    metacatalog
    mitmproxy
    mitmproxy-in
    mitmproxy-out
    secubox
    config-vault
    saas-relay
    hexojs
    gotosocial
    nextcloud
    peertube
    matrix
    simplex
    voip
    webradio
    zigbee2mqtt
    domoticz
    photoprism
    rezapp
    haproxy
    crowdsec
    dns
    dns-master
    lxc
    jabber
    jitsi
    localai
    sherlock
    maltego
  "

  # Build exclusion array
  local -a excluded_list
  IFS=',' read -ra excluded_list <<< "$EXCLUDE_SERVICES"

  for svc in $services; do
    svc=$(echo "$svc" | tr -d ' ')
    [[ -z "$svc" ]] && continue

    # Check if service is in exclusion list
    local skip=0
    for excl in "${excluded_list[@]}"; do
      excl=$(echo "$excl" | tr -d ' ')
      [[ "$svc" == "$excl" ]] && { skip=1; break; }
    done
    [[ $skip -eq 1 ]] && { warn "  Skipping excluded: /srv/$svc"; continue; }

    if ssh_run "[ -d '/srv/$svc' ]" 2>/dev/null; then
      log "  Exporting: /srv/$svc"
      mkdir -p "$dst/$svc"

      # Export service directory (excluding large binary/cache dirs)
      ssh_run "tar -czf - \
        --exclude='*.log' \
        --exclude='node_modules' \
        --exclude='__pycache__' \
        --exclude='.cache' \
        --exclude='cache' \
        --exclude='*.pyc' \
        --exclude='.venv' \
        --exclude='venv' \
        /srv/$svc 2>/dev/null" | tar -xzf - -C "$dst/$svc" --strip-components=2 || warn "Partial export: $svc"
    fi
  done

  # Export Streamlit apps specifically
  if ssh_run "[ -d '/srv/streamlit/apps' ]" 2>/dev/null; then
    log "  Exporting Streamlit apps..."
    mkdir -p "$dst/streamlit-apps"
    ssh_run "tar -czf - /srv/streamlit/apps 2>/dev/null" | tar -xzf - -C "$dst/streamlit-apps" --strip-components=3 || true
    local app_count=$(ssh_run "ls -d /srv/streamlit/apps/*/ 2>/dev/null | wc -l" || echo "0")
    log "    Found $app_count Streamlit apps"
  fi

  # Export Git repositories (full repos with history)
  log "  Discovering Git repositories..."
  ssh_run "find /srv -maxdepth 4 -name '.git' -type d 2>/dev/null" | while read -r git_dir; do
    [[ -z "$git_dir" ]] && continue
    local repo_path=$(dirname "$git_dir")
    local repo_name=$(echo "$repo_path" | sed 's|/srv/||' | tr '/' '_')
    log "    Exporting repo: $repo_name"
    mkdir -p "$dst/git-repos"
    ssh_run "tar -czf - '$repo_path' 2>/dev/null" > "$dst/git-repos/${repo_name}.tar.gz" || true
  done || true

  # Export Docker/Podman compose files
  log "  Exporting Docker compose files..."
  mkdir -p "$dst/docker-compose"
  ssh_run "find /srv -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' 2>/dev/null" | while read -r compose_file; do
    [[ -z "$compose_file" ]] && continue
    local compose_name=$(echo "$compose_file" | tr '/' '_' | sed 's/^_srv_//')
    ssh_run "cat '$compose_file' 2>/dev/null" > "$dst/docker-compose/$compose_name" || true
  done || true

  # Export LXC container configs
  if ssh_run "[ -d '/srv/lxc' ]" 2>/dev/null; then
    log "  Exporting LXC container configs..."
    mkdir -p "$dst/lxc"
    ssh_run "ls /srv/lxc 2>/dev/null" | while read -r container; do
      [[ -z "$container" ]] && continue
      ssh_run "cat /srv/lxc/$container/config 2>/dev/null" > "$dst/lxc/${container}.config" || true
    done || true
  fi

  local size=$(du -sh "$dst" 2>/dev/null | cut -f1 || echo "0")
  local svc_count=$(ls -d "$dst"/*/ 2>/dev/null | wc -l || echo "0")
  ok "Services exported ($svc_count services, $size)"
}

# ── Module selection ──
declare -A MODULE_FUNCS=(
  [network]=export_network
  [firewall]=export_firewall
  [wireguard]=export_wireguard
  [crowdsec]=export_crowdsec
  [dhcp]=export_dhcp
  [haproxy]=export_haproxy
  [nginx]=export_nginx
  [certs]=export_certs
  [content]=export_content
  [vhosts]=export_vhosts
  [users]=export_users
  [state]=export_state
  [git]=export_git
  [media]=export_media
  [mail]=export_mail
  [accounts]=export_accounts
  [dns]=export_dns
  [databases]=export_databases
  [scripts]=export_scripts
  [services]=export_services
)

ALL_MODULES="network,firewall,wireguard,crowdsec,dhcp,haproxy,nginx,certs,content,vhosts,users,state,git,media,mail,accounts,dns,databases,scripts,services"

if [[ "$MODULES" == "all" ]]; then
  MODULES="$ALL_MODULES"
fi

# ── Execute exports ──
section "Starting Migration Export"
log "Target: $HOST"
log "Modules: $MODULES"
log "Output: $OUTPUT"

IFS=',' read -ra MOD_ARRAY <<< "$MODULES"
EXPORTED_MODULES=()

for mod in "${MOD_ARRAY[@]}"; do
  mod=$(echo "$mod" | tr -d ' ')
  if [[ -n "${MODULE_FUNCS[$mod]:-}" ]]; then
    ${MODULE_FUNCS[$mod]}
    EXPORTED_MODULES+=("$mod")
  else
    warn "Unknown module: $mod"
  fi
done

# ── Update manifest with exported modules ──
section "Creating Archive"

# Add modules to manifest
MODULES_JSON=$(printf '"%s",' "${EXPORTED_MODULES[@]}" | sed 's/,$//')
sed -i "s/\"modules\": \[\]/\"modules\": [$MODULES_JSON]/" "$WORKDIR/manifest.json"

# Generate checksums
log "Generating checksums..."
(cd "$WORKDIR" && find . -type f ! -name 'manifest.json' -exec sha256sum {} \; > checksums.sha256)

# ── Create archive ──
log "Creating tar archive..."
ARCHIVE_TMP="${OUTPUT%.enc}"
tar -czf "$ARCHIVE_TMP" -C "$WORKDIR" .

# ── Encrypt if requested ──
if [[ $ENCRYPT -eq 1 ]]; then
  section "Encrypting Archive"

  if [[ -z "$PASSPHRASE" ]]; then
    read -sp "Enter encryption passphrase: " PASSPHRASE
    echo
    read -sp "Confirm passphrase: " PASSPHRASE2
    echo
    [[ "$PASSPHRASE" != "$PASSPHRASE2" ]] && err "Passphrases do not match"
  fi

  openssl enc -aes-256-cbc -salt -pbkdf2 -in "$ARCHIVE_TMP" -out "${OUTPUT}" -pass pass:"$PASSPHRASE"
  rm -f "$ARCHIVE_TMP"
  ok "Archive encrypted: $OUTPUT"
else
  [[ "$ARCHIVE_TMP" != "$OUTPUT" ]] && mv "$ARCHIVE_TMP" "$OUTPUT"
fi

# ── Summary ──
section "Export Complete"
ARCHIVE_SIZE=$(du -h "$OUTPUT" | cut -f1)
log "Archive: $OUTPUT ($ARCHIVE_SIZE)"
log "Modules exported: ${EXPORTED_MODULES[*]}"
log "Encrypted: $([ $ENCRYPT -eq 1 ] && echo 'Yes (AES-256)' || echo 'No')"
echo
ok "Migration export completed successfully"
echo
log "To import on SecuBox-DEB target:"
log "  bash scripts/migration-import.sh -f $OUTPUT --dry-run"
log "  bash scripts/migration-import.sh -f $OUTPUT"
