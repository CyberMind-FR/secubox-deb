#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  scripts/migration-import.sh — Import Migration Archive → SecuBox-DEB
#
#  SecuBox-DEB :: Migration Data Saver
#  CyberMind — https://cybermind.fr
#  Author: Gérald Kerma <gandalf@gk2.net>
#
#  Usage:
#    bash scripts/migration-import.sh -f /tmp/migration.tar.gz --dry-run
#    bash scripts/migration-import.sh -f /tmp/migration.tar.gz
#    bash scripts/migration-import.sh -f /tmp/migration.tar.gz.enc --passphrase "secret"
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly VERSION="1.0.0"
readonly TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

# ── Colors ──
CYAN='\033[0;36m'; GREEN='\033[0;32m'; GOLD='\033[0;33m'
RED='\033[0;31m'; PURPLE='\033[0;35m'; NC='\033[0m'

log()     { echo -e "${CYAN}[import]${NC} $*"; }
ok()      { echo -e "${GREEN}[   OK ]${NC} $*"; }
warn()    { echo -e "${GOLD}[ WARN ]${NC} $*"; }
err()     { echo -e "${RED}[ FAIL ]${NC} $*" >&2; exit 1; }
section() { echo -e "\n${PURPLE}══════════════════════════════════════════════════════════════════${NC}"; echo -e "${PURPLE}  $*${NC}"; echo -e "${PURPLE}══════════════════════════════════════════════════════════════════${NC}"; }

# ── Default values ──
ARCHIVE=""
PASSPHRASE=""
DRY_RUN=0
FORCE=0
SKIP_BACKUP=0
MODULES="all"
WORKDIR=""
TRANSFORM_DIR=""

# ── Target directories ──
SECUBOX_CONF="/etc/secubox"
NETPLAN_DIR="/etc/netplan"
NFTABLES_CONF="/etc/nftables.conf"
WIREGUARD_DIR="/etc/wireguard"
CROWDSEC_DIR="/etc/crowdsec"
HAPROXY_DIR="/etc/haproxy"
NGINX_DIR="/etc/nginx"
LETSENCRYPT_DIR="/etc/letsencrypt"
WWW_DIR="/srv/www"
VAR_LIB_SECUBOX="/var/lib/secubox"
ROLLBACK_DIR="/var/lib/secubox/rollback"

usage() {
  cat <<EOF
SecuBox Migration Import — Version $VERSION

Import migration archive to SecuBox-DEB system.

Usage:
  $(basename "$0") -f ARCHIVE [OPTIONS]

Required:
  -f, --file ARCHIVE    Migration archive (.tar.gz or .tar.gz.enc)

Options:
  --dry-run             Preview changes without applying
  --force               Apply without confirmation
  --skip-backup         Skip pre-import rollback snapshot (not recommended)
  --passphrase PASS     Decryption passphrase (prompts if encrypted)
  -m, --modules LIST    Comma-separated module list (default: all)
                        Available: network,firewall,wireguard,crowdsec,dhcp,
                                   haproxy,nginx,certs,content,vhosts,users,state
  --help                Show this help

Examples:
  # Preview import (dry-run)
  $(basename "$0") -f /tmp/migration.tar.gz --dry-run

  # Full import
  $(basename "$0") -f /tmp/migration.tar.gz

  # Import specific modules only
  $(basename "$0") -f /tmp/migration.tar.gz -m wireguard,crowdsec

  # Import encrypted archive
  $(basename "$0") -f /tmp/migration.tar.gz.enc --passphrase "secret"

EOF
  exit 0
}

# ── Parse arguments ──
while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--file)       ARCHIVE="$2"; shift 2 ;;
    --dry-run)       DRY_RUN=1; shift ;;
    --force)         FORCE=1; shift ;;
    --skip-backup)   SKIP_BACKUP=1; shift ;;
    --passphrase)    PASSPHRASE="$2"; shift 2 ;;
    -m|--modules)    MODULES="$2"; shift 2 ;;
    --help)          usage ;;
    *)               err "Unknown option: $1" ;;
  esac
done

# ── Validate required arguments ──
[[ -z "$ARCHIVE" ]] && err "Archive required. Use -f/--file"
[[ -f "$ARCHIVE" ]] || err "Archive not found: $ARCHIVE"

# ── Dry-run prefix ──
run() {
  if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "${GOLD}[DRY-RUN]${NC} $*"
  else
    eval "$@"
  fi
}

# ── Create work directory ──
WORKDIR=$(mktemp -d -t secubox-import-XXXXXX)
TRANSFORM_DIR=$(mktemp -d -t secubox-transform-XXXXXX)
trap 'rm -rf "$WORKDIR" "$TRANSFORM_DIR"' EXIT

# ── Extract archive ──
section "Extracting Migration Archive"
log "Archive: $ARCHIVE"

# Check if encrypted
if [[ "$ARCHIVE" == *.enc ]]; then
  log "Archive is encrypted"

  if [[ -z "$PASSPHRASE" ]]; then
    read -sp "Enter decryption passphrase: " PASSPHRASE
    echo
  fi

  DECRYPTED_ARCHIVE="${WORKDIR}/migration.tar.gz"
  openssl enc -aes-256-cbc -d -pbkdf2 -in "$ARCHIVE" -out "$DECRYPTED_ARCHIVE" -pass pass:"$PASSPHRASE" || err "Decryption failed"
  ARCHIVE="$DECRYPTED_ARCHIVE"
  ok "Archive decrypted"
fi

# Extract
tar -xzf "$ARCHIVE" -C "$WORKDIR"
ok "Archive extracted"

# ── Validate manifest ──
section "Validating Migration Archive"
MANIFEST="$WORKDIR/manifest.json"
[[ -f "$MANIFEST" ]] || err "Invalid archive: manifest.json not found"

# Parse manifest (basic parsing without jq)
SOURCE_HOST=$(grep -o '"host": "[^"]*"' "$MANIFEST" | cut -d'"' -f4 || echo "unknown")
SOURCE_TYPE=$(grep -o '"type": "[^"]*"' "$MANIFEST" | cut -d'"' -f4 || echo "unknown")
ARCHIVE_VERSION=$(grep -o '"version": "[^"]*"' "$MANIFEST" | head -1 | cut -d'"' -f4 || echo "unknown")

log "Source: $SOURCE_HOST ($SOURCE_TYPE)"
log "Archive version: $ARCHIVE_VERSION"

# Verify checksums
if [[ -f "$WORKDIR/checksums.sha256" ]]; then
  log "Verifying checksums..."
  (cd "$WORKDIR" && sha256sum -c checksums.sha256 --quiet 2>/dev/null) || warn "Some checksums failed"
  ok "Checksums verified"
fi

# ── Transform configs ──
section "Transforming UCI Configs"
python3 "$SCRIPT_DIR/migration-transform.py" transform-all "$WORKDIR" "$TRANSFORM_DIR"
ok "Configs transformed"

# ── Create rollback snapshot ──
if [[ $SKIP_BACKUP -eq 0 && $DRY_RUN -eq 0 ]]; then
  section "Creating Pre-Import Rollback Snapshot"

  ROLLBACK_SNAPSHOT="${ROLLBACK_DIR}/pre-migration-${TIMESTAMP}"
  mkdir -p "$ROLLBACK_SNAPSHOT"

  # Backup current configs
  [[ -d "$SECUBOX_CONF" ]] && cp -a "$SECUBOX_CONF" "$ROLLBACK_SNAPSHOT/" || true
  [[ -d "$NETPLAN_DIR" ]] && cp -a "$NETPLAN_DIR" "$ROLLBACK_SNAPSHOT/" || true
  [[ -f "$NFTABLES_CONF" ]] && cp -a "$NFTABLES_CONF" "$ROLLBACK_SNAPSHOT/" || true
  [[ -d "$WIREGUARD_DIR" ]] && cp -a "$WIREGUARD_DIR" "$ROLLBACK_SNAPSHOT/" || true
  [[ -d "$CROWDSEC_DIR" ]] && cp -a "$CROWDSEC_DIR" "$ROLLBACK_SNAPSHOT/" || true

  ok "Rollback snapshot created: $ROLLBACK_SNAPSHOT"
fi

# ── Confirmation ──
if [[ $DRY_RUN -eq 0 && $FORCE -eq 0 ]]; then
  section "Confirmation Required"
  echo -e "${GOLD}The following changes will be applied to this system:${NC}"
  echo "  - Network: netplan config"
  echo "  - Firewall: nftables rules"
  echo "  - Services: WireGuard, CrowdSec, HAProxy, Nginx"
  echo "  - Content: Web files, certificates"
  echo
  read -p "Continue? [y/N] " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || { log "Aborted."; exit 0; }
fi

# ── Module import functions ──

import_network() {
  section "Importing: Network Configuration"

  local src="$TRANSFORM_DIR/netplan/00-secubox.yaml"
  if [[ -f "$src" ]]; then
    run "mkdir -p '$NETPLAN_DIR'"
    run "cp '$src' '$NETPLAN_DIR/00-secubox.yaml'"
    run "chmod 600 '$NETPLAN_DIR/00-secubox.yaml'"

    if [[ $DRY_RUN -eq 0 ]]; then
      log "Applying netplan..."
      netplan apply 2>/dev/null || warn "netplan apply failed (may need reboot)"
    fi

    ok "Network config imported"
  else
    warn "No network config to import"
  fi
}

import_firewall() {
  section "Importing: Firewall Rules"

  local src="$TRANSFORM_DIR/nftables.conf"
  if [[ -f "$src" ]]; then
    run "cp '$src' '$NFTABLES_CONF'"
    run "chmod 644 '$NFTABLES_CONF'"

    if [[ $DRY_RUN -eq 0 ]]; then
      log "Applying nftables rules..."
      nft -f "$NFTABLES_CONF" 2>/dev/null || warn "nftables apply failed"
      systemctl enable nftables 2>/dev/null || true
    fi

    ok "Firewall rules imported"
  else
    warn "No firewall config to import"
  fi
}

import_wireguard() {
  section "Importing: WireGuard Configuration"

  local secrets_src="$WORKDIR/secrets/wireguard"
  if [[ -d "$secrets_src" && -n "$(ls -A "$secrets_src" 2>/dev/null)" ]]; then
    run "mkdir -p '$WIREGUARD_DIR'"

    for conf in "$secrets_src"/*.conf; do
      [[ -f "$conf" ]] || continue
      local name=$(basename "$conf")
      run "cp '$conf' '$WIREGUARD_DIR/$name'"
      run "chmod 600 '$WIREGUARD_DIR/$name'"
      log "  Imported: $name"

      # Enable interface
      local iface="${name%.conf}"
      if [[ $DRY_RUN -eq 0 ]]; then
        systemctl enable "wg-quick@${iface}" 2>/dev/null || true
      fi
    done

    ok "WireGuard configs imported"
  else
    warn "No WireGuard configs to import"
  fi
}

import_crowdsec() {
  section "Importing: CrowdSec Configuration"

  local src="$WORKDIR/configs/crowdsec"
  if [[ -d "$src" && -n "$(ls -A "$src" 2>/dev/null)" ]]; then
    run "mkdir -p '$CROWDSEC_DIR'"

    # Main config
    [[ -f "$src/config.yaml" ]] && run "cp '$src/config.yaml' '$CROWDSEC_DIR/'"

    # Acquis configs
    if [[ -d "$src/acquis.d" ]]; then
      run "mkdir -p '$CROWDSEC_DIR/acquis.d'"
      run "cp -r '$src/acquis.d/'* '$CROWDSEC_DIR/acquis.d/' 2>/dev/null || true"
    fi

    # Local parsers/scenarios
    for subdir in parsers scenarios postoverflows; do
      if [[ -d "$src/$subdir" ]]; then
        run "mkdir -p '$CROWDSEC_DIR/$subdir'"
        run "cp -r '$src/$subdir/'* '$CROWDSEC_DIR/$subdir/' 2>/dev/null || true"
      fi
    done

    # API credentials from secrets
    local creds="$WORKDIR/secrets/crowdsec/local_api_credentials.yaml"
    if [[ -f "$creds" ]]; then
      run "cp '$creds' '$CROWDSEC_DIR/'"
      run "chmod 600 '$CROWDSEC_DIR/local_api_credentials.yaml'"
    fi

    if [[ $DRY_RUN -eq 0 ]]; then
      systemctl restart crowdsec 2>/dev/null || warn "CrowdSec restart failed"
    fi

    ok "CrowdSec configs imported"
  else
    warn "No CrowdSec configs to import"
  fi
}

import_dhcp() {
  section "Importing: DHCP/DNS Configuration"

  local src="$TRANSFORM_DIR/dnsmasq.conf"
  if [[ -f "$src" ]]; then
    run "cp '$src' '/etc/dnsmasq.d/secubox.conf'"
    run "chmod 644 '/etc/dnsmasq.d/secubox.conf'"

    if [[ $DRY_RUN -eq 0 ]]; then
      systemctl restart dnsmasq 2>/dev/null || warn "dnsmasq restart failed"
    fi

    ok "DHCP/DNS config imported"
  else
    warn "No DHCP config to import"
  fi
}

import_haproxy() {
  section "Importing: HAProxy Configuration"

  local src="$WORKDIR/configs/haproxy"
  if [[ -d "$src" && -n "$(ls -A "$src" 2>/dev/null)" ]]; then
    run "mkdir -p '$HAPROXY_DIR'"

    # Main config
    [[ -f "$src/haproxy.cfg" ]] && run "cp '$src/haproxy.cfg' '$HAPROXY_DIR/'"

    # Additional configs
    if [[ -d "$src/conf.d" ]]; then
      run "mkdir -p '$HAPROXY_DIR/conf.d'"
      run "cp -r '$src/conf.d/'* '$HAPROXY_DIR/conf.d/' 2>/dev/null || true"
    fi

    if [[ $DRY_RUN -eq 0 ]]; then
      # Validate config first
      haproxy -c -f "$HAPROXY_DIR/haproxy.cfg" 2>/dev/null && \
        systemctl restart haproxy 2>/dev/null || warn "HAProxy restart failed"
    fi

    ok "HAProxy configs imported"
  else
    warn "No HAProxy configs to import"
  fi
}

import_nginx() {
  section "Importing: Nginx Configuration"

  local src="$WORKDIR/configs/nginx"
  if [[ -d "$src" && -n "$(ls -A "$src" 2>/dev/null)" ]]; then
    # Sites
    if [[ -d "$src/sites-available" ]]; then
      run "mkdir -p '$NGINX_DIR/sites-available'"
      for site in "$src/sites-available"/*; do
        [[ -f "$site" ]] || continue
        local name=$(basename "$site")
        run "cp '$site' '$NGINX_DIR/sites-available/$name'"
        log "  Imported site: $name"
      done
    fi

    if [[ -d "$src/sites-enabled" ]]; then
      run "mkdir -p '$NGINX_DIR/sites-enabled'"
      for site in "$src/sites-enabled"/*; do
        [[ -f "$site" ]] || continue
        local name=$(basename "$site")
        # Create symlink if available site exists
        if [[ -f "$NGINX_DIR/sites-available/$name" ]]; then
          run "ln -sf '../sites-available/$name' '$NGINX_DIR/sites-enabled/$name'"
        else
          run "cp '$site' '$NGINX_DIR/sites-enabled/$name'"
        fi
      done
    fi

    if [[ $DRY_RUN -eq 0 ]]; then
      nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || warn "Nginx reload failed"
    fi

    ok "Nginx configs imported"
  else
    warn "No Nginx configs to import"
  fi
}

import_certs() {
  section "Importing: SSL Certificates"

  local src="$WORKDIR/secrets/certs"
  if [[ -d "$src" && -n "$(ls -A "$src" 2>/dev/null)" ]]; then
    # Let's Encrypt
    if [[ -d "$src/letsencrypt" ]]; then
      run "mkdir -p '$LETSENCRYPT_DIR'"
      run "cp -r '$src/letsencrypt/'* '$LETSENCRYPT_DIR/' 2>/dev/null || true"
      run "chmod -R 600 '$LETSENCRYPT_DIR/'"
      log "  Imported: Let's Encrypt certificates"
    fi

    # Custom certs
    local key_count=0
    for key in "$src"/*.key; do
      [[ -f "$key" ]] || continue
      run "mkdir -p '/etc/ssl/private'"
      run "cp '$key' '/etc/ssl/private/'"
      run "chmod 600 '/etc/ssl/private/$(basename "$key")'"
      ((key_count++))
    done
    [[ $key_count -gt 0 ]] && log "  Imported: $key_count private keys"

    local cert_count=0
    for cert in "$src"/*.pem "$src"/*.crt; do
      [[ -f "$cert" ]] || continue
      run "mkdir -p '/etc/ssl/certs'"
      run "cp '$cert' '/etc/ssl/certs/'"
      ((cert_count++))
    done
    [[ $cert_count -gt 0 ]] && log "  Imported: $cert_count certificates"

    ok "Certificates imported"
  else
    warn "No certificates to import"
  fi
}

import_content() {
  section "Importing: Web Content"

  local src="$WORKDIR/content"
  if [[ -d "$src" && -n "$(ls -A "$src" 2>/dev/null)" ]]; then
    run "mkdir -p '$WWW_DIR'"
    run "cp -r '$src/'* '$WWW_DIR/' 2>/dev/null || true"

    # Fix ownership
    if [[ $DRY_RUN -eq 0 ]]; then
      chown -R www-data:www-data "$WWW_DIR" 2>/dev/null || true
    fi

    local size=$(du -sh "$src" 2>/dev/null | cut -f1)
    ok "Web content imported ($size)"
  else
    warn "No web content to import"
  fi
}

import_vhosts() {
  section "Importing: Virtual Hosts"

  local src="$TRANSFORM_DIR/vhosts"
  if [[ -d "$src" && -n "$(ls -A "$src" 2>/dev/null)" ]]; then
    run "mkdir -p '$SECUBOX_CONF/vhosts'"

    for vhost in "$src"/*; do
      [[ -f "$vhost" ]] || continue
      local name=$(basename "$vhost")
      run "cp '$vhost' '$SECUBOX_CONF/vhosts/$name'"
      log "  Imported: $name"
    done

    ok "Virtual hosts imported"
  else
    warn "No virtual hosts to import"
  fi
}

import_users() {
  section "Importing: User Accounts"

  local src="$WORKDIR/configs/users"
  local secrets_src="$WORKDIR/secrets/users"

  # Import SecuBox auth.toml
  if [[ -f "$src/auth.toml" ]]; then
    run "mkdir -p '$SECUBOX_CONF'"
    run "cp '$src/auth.toml' '$SECUBOX_CONF/auth.toml'"
    run "chmod 600 '$SECUBOX_CONF/auth.toml'"
    ok "SecuBox auth config imported"
  fi

  # Import SSH authorized keys
  if [[ -f "$secrets_src/authorized_keys" ]]; then
    run "mkdir -p '/root/.ssh'"
    # Append rather than replace
    if [[ $DRY_RUN -eq 0 ]]; then
      cat "$secrets_src/authorized_keys" >> /root/.ssh/authorized_keys
      sort -u /root/.ssh/authorized_keys -o /root/.ssh/authorized_keys
      chmod 600 /root/.ssh/authorized_keys
    else
      log "Would append SSH keys to /root/.ssh/authorized_keys"
    fi
    ok "SSH authorized keys imported"
  fi

  # Note: We don't import system users (/etc/passwd, /etc/shadow)
  # Those should be created by package installation
  warn "System users not imported (use package installation)"
}

import_state() {
  section "Importing: Service State Data"

  local src="$WORKDIR/state"
  if [[ -d "$src" && -n "$(ls -A "$src" 2>/dev/null)" ]]; then
    # CrowdSec decisions
    if [[ -f "$src/crowdsec/crowdsec.db" ]]; then
      run "mkdir -p '/var/lib/crowdsec/data'"
      run "cp '$src/crowdsec/crowdsec.db' '/var/lib/crowdsec/data/'"
      run "chown crowdsec:crowdsec '/var/lib/crowdsec/data/crowdsec.db' 2>/dev/null || true"
      log "  Imported: CrowdSec decisions database"
    fi

    # SecuBox state
    if [[ -d "$src/secubox" && -n "$(ls -A "$src/secubox" 2>/dev/null)" ]]; then
      run "mkdir -p '$VAR_LIB_SECUBOX'"
      run "cp -r '$src/secubox/'* '$VAR_LIB_SECUBOX/' 2>/dev/null || true"
      log "  Imported: SecuBox state data"
    fi

    ok "State data imported"
  else
    warn "No state data to import"
  fi
}

# ── Module selection ──
declare -A MODULE_FUNCS=(
  [network]=import_network
  [firewall]=import_firewall
  [wireguard]=import_wireguard
  [crowdsec]=import_crowdsec
  [dhcp]=import_dhcp
  [haproxy]=import_haproxy
  [nginx]=import_nginx
  [certs]=import_certs
  [content]=import_content
  [vhosts]=import_vhosts
  [users]=import_users
  [state]=import_state
)

ALL_MODULES="network,firewall,wireguard,crowdsec,dhcp,haproxy,nginx,certs,content,vhosts,users,state"

if [[ "$MODULES" == "all" ]]; then
  MODULES="$ALL_MODULES"
fi

# ── Execute imports ──
section "Starting Migration Import"
log "Archive: $ARCHIVE"
log "Modules: $MODULES"
[[ $DRY_RUN -eq 1 ]] && log "Mode: DRY-RUN (no changes will be made)"

IFS=',' read -ra MOD_ARRAY <<< "$MODULES"
IMPORTED_MODULES=()
FAILED_MODULES=()

for mod in "${MOD_ARRAY[@]}"; do
  mod=$(echo "$mod" | tr -d ' ')
  if [[ -n "${MODULE_FUNCS[$mod]:-}" ]]; then
    if ${MODULE_FUNCS[$mod]}; then
      IMPORTED_MODULES+=("$mod")
    else
      FAILED_MODULES+=("$mod")
    fi
  else
    warn "Unknown module: $mod"
  fi
done

# ── Summary ──
section "Import Complete"

if [[ $DRY_RUN -eq 1 ]]; then
  log "DRY-RUN completed — no changes were made"
  log "To apply changes, run without --dry-run"
else
  log "Modules imported: ${IMPORTED_MODULES[*]:-none}"
  [[ ${#FAILED_MODULES[@]} -gt 0 ]] && warn "Modules with issues: ${FAILED_MODULES[*]}"

  if [[ $SKIP_BACKUP -eq 0 ]]; then
    log "Rollback available at: $ROLLBACK_SNAPSHOT"
    log "To rollback: bash scripts/migration-rollback.sh $ROLLBACK_SNAPSHOT"
  fi
fi

echo
ok "Migration import completed"

# ── Post-import recommendations ──
section "Recommended Next Steps"
echo "1. Verify network connectivity:"
echo "   ip addr show"
echo "   ping -c 3 8.8.8.8"
echo
echo "2. Check service status:"
echo "   systemctl status secubox-* --no-pager"
echo
echo "3. Test WireGuard (if imported):"
echo "   wg show"
echo
echo "4. Test CrowdSec (if imported):"
echo "   cscli decisions list"
echo
echo "5. Verify firewall rules:"
echo "   nft list ruleset"
