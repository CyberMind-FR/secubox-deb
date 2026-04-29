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
readonly VERSION="2.1.0"
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
GIT_DIR="/srv/git"
MEDIA_DIR="/srv/media"
MAIL_DIR="/var/vmail"
POSTFIX_DIR="/etc/postfix"
DOVECOT_DIR="/etc/dovecot"
BIND_DIR="/etc/bind"
UNBOUND_DIR="/etc/unbound"
ADGUARD_DIR="/etc/adguardhome"

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
                                   haproxy,nginx,certs,content,vhosts,users,state,
                                   git,media,mail,accounts,dns,databases,scripts
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

import_git() {
  section "Importing: Git Repositories"

  local src="$WORKDIR/content/git"
  if [[ -d "$src" && -n "$(ls -A "$src" 2>/dev/null)" ]]; then
    run "mkdir -p '$GIT_DIR'"

    local repo_count=0

    # Import bare repos
    for repo_tar in "$src"/*.git.tar.gz; do
      [[ -f "$repo_tar" ]] || continue
      local repo_name=$(basename "$repo_tar" .tar.gz)
      log "  Importing bare repo: $repo_name"
      run "tar -xzf '$repo_tar' -C '$GIT_DIR/' --strip-components=2 2>/dev/null || true"
      ((repo_count++))
    done

    # Import full repos (with working trees)
    for repo_tar in "$src"/*-full.tar.gz; do
      [[ -f "$repo_tar" ]] || continue
      local repo_name=$(basename "$repo_tar" -full.tar.gz)
      log "  Importing repo with worktree: $repo_name"
      run "mkdir -p '$GIT_DIR/$repo_name'"
      run "tar -xzf '$repo_tar' -C '$GIT_DIR/$repo_name' --strip-components=2 2>/dev/null || true"
      ((repo_count++))
    done

    # Import Gitea/Gogs/GitLab repos
    for git_app in gitea gogs gitlab; do
      if [[ -d "$src/$git_app" ]]; then
        log "  Importing $git_app repositories..."
        run "mkdir -p '/var/lib/$git_app/repositories'"
        run "cp -r '$src/$git_app/'* '/var/lib/$git_app/repositories/' 2>/dev/null || true"

        # Import config if present
        if [[ -f "$src/$git_app/app.ini" ]]; then
          run "mkdir -p '/etc/$git_app'"
          run "cp '$src/$git_app/app.ini' '/etc/$git_app/'"
        fi

        if [[ $DRY_RUN -eq 0 ]]; then
          systemctl restart "$git_app" 2>/dev/null || warn "$git_app restart failed"
        fi
      fi
    done

    # Fix ownership
    if [[ $DRY_RUN -eq 0 ]]; then
      chown -R git:git "$GIT_DIR" 2>/dev/null || true
    fi

    local size=$(du -sh "$src" 2>/dev/null | cut -f1 || echo "0")
    ok "Git repositories imported ($repo_count repos, $size)"
  else
    warn "No git repositories to import"
  fi
}

import_media() {
  section "Importing: Media Files"

  local src="$WORKDIR/content/media"
  if [[ -d "$src" && -n "$(ls -A "$src" 2>/dev/null)" ]]; then
    run "mkdir -p '$MEDIA_DIR'"

    # Import general media directories
    for media_sub in "$src"/srv_* "$src"/var_*; do
      [[ -d "$media_sub" ]] || continue
      local sub_name=$(basename "$media_sub")
      log "  Importing media: $sub_name"
      run "cp -r '$media_sub/'* '$MEDIA_DIR/' 2>/dev/null || true"
    done

    # Import PeerTube videos
    if [[ -d "$src/peertube" ]]; then
      log "  Importing PeerTube videos..."
      run "mkdir -p '/var/www/peertube/storage/videos'"
      run "cp -r '$src/peertube/'* '/var/www/peertube/storage/videos/' 2>/dev/null || true"
      if [[ $DRY_RUN -eq 0 ]]; then
        chown -R peertube:peertube /var/www/peertube/storage 2>/dev/null || true
      fi
    fi

    # Import Jellyfin library
    if [[ -d "$src/jellyfin" ]]; then
      log "  Importing Jellyfin library..."
      run "mkdir -p '/var/lib/jellyfin/data/library'"
      run "cp -r '$src/jellyfin/'* '/var/lib/jellyfin/data/library/' 2>/dev/null || true"
      if [[ -f "$src/jellyfin/system.xml" ]]; then
        run "mkdir -p '/etc/jellyfin'"
        run "cp '$src/jellyfin/system.xml' '/etc/jellyfin/'"
      fi
      if [[ $DRY_RUN -eq 0 ]]; then
        chown -R jellyfin:jellyfin /var/lib/jellyfin 2>/dev/null || true
        systemctl restart jellyfin 2>/dev/null || warn "Jellyfin restart failed"
      fi
    fi

    # Import Nextcloud user files
    if [[ -d "$src/nextcloud" ]]; then
      log "  Importing Nextcloud files..."
      run "mkdir -p '/var/www/nextcloud/data'"
      run "cp -r '$src/nextcloud/'* '/var/www/nextcloud/data/' 2>/dev/null || true"
      if [[ $DRY_RUN -eq 0 ]]; then
        chown -R www-data:www-data /var/www/nextcloud/data 2>/dev/null || true
        # Run Nextcloud file scan
        sudo -u www-data php /var/www/nextcloud/occ files:scan --all 2>/dev/null || warn "Nextcloud scan failed"
      fi
    fi

    local size=$(du -sh "$src" 2>/dev/null | cut -f1 || echo "0")
    ok "Media files imported ($size)"
  else
    warn "No media files to import"
  fi
}

import_mail() {
  section "Importing: Email Data"

  local src="$WORKDIR/content/mail"
  local secrets_src="$WORKDIR/secrets/mail"

  if [[ -d "$src" && -n "$(ls -A "$src" 2>/dev/null)" ]]; then
    # Import Maildir
    for mail_dir in "$src"/var_* "$src"/home_*; do
      [[ -d "$mail_dir" ]] || continue
      local dir_name=$(basename "$mail_dir")
      log "  Importing maildir: $dir_name"

      if [[ "$dir_name" == "var_vmail" || "$dir_name" == "var_mail" ]]; then
        run "mkdir -p '$MAIL_DIR'"
        run "cp -r '$mail_dir/'* '$MAIL_DIR/' 2>/dev/null || true"
      fi
    done

    # Import Postfix config
    if [[ -d "$src/postfix" ]]; then
      log "  Importing Postfix configuration..."
      run "mkdir -p '$POSTFIX_DIR'"
      run "cp -r '$src/postfix/'* '$POSTFIX_DIR/' 2>/dev/null || true"
      if [[ $DRY_RUN -eq 0 ]]; then
        postmap /etc/postfix/virtual 2>/dev/null || true
        postmap /etc/postfix/vmailbox 2>/dev/null || true
        systemctl restart postfix 2>/dev/null || warn "Postfix restart failed"
      fi
    fi

    # Import Dovecot config
    if [[ -d "$src/dovecot" ]]; then
      log "  Importing Dovecot configuration..."
      run "mkdir -p '$DOVECOT_DIR'"
      run "cp -r '$src/dovecot/'* '$DOVECOT_DIR/' 2>/dev/null || true"
    fi

    # Import DKIM keys from secrets
    if [[ -d "$secrets_src/opendkim" ]]; then
      log "  Importing DKIM keys..."
      run "mkdir -p '/etc/opendkim'"
      run "cp -r '$secrets_src/opendkim/'* '/etc/opendkim/' 2>/dev/null || true"
      run "chmod 600 /etc/opendkim/keys/*/*.private 2>/dev/null || true"
      if [[ $DRY_RUN -eq 0 ]]; then
        chown -R opendkim:opendkim /etc/opendkim 2>/dev/null || true
      fi
    fi

    # Import mail aliases
    if [[ -f "$src/aliases" ]]; then
      run "cp '$src/aliases' '/etc/aliases'"
      if [[ $DRY_RUN -eq 0 ]]; then
        newaliases 2>/dev/null || warn "newaliases failed"
      fi
    fi

    if [[ -f "$src/mailname" ]]; then
      run "cp '$src/mailname' '/etc/mailname'"
    fi

    # Import virtual mailbox config
    if [[ -f "$src/vmailbox" ]]; then
      run "cp '$src/vmailbox' '/etc/postfix/vmailbox'"
    fi

    # Import Dovecot users from secrets
    if [[ -f "$secrets_src/dovecot-users" ]]; then
      run "mkdir -p '/etc/dovecot'"
      run "cp '$secrets_src/dovecot-users' '/etc/dovecot/users'"
      run "chmod 600 '/etc/dovecot/users'"
    fi

    # Restart mail services
    if [[ $DRY_RUN -eq 0 ]]; then
      systemctl restart dovecot 2>/dev/null || warn "Dovecot restart failed"
      systemctl restart opendkim 2>/dev/null || true
    fi

    # Fix maildir ownership
    if [[ $DRY_RUN -eq 0 ]]; then
      chown -R vmail:vmail "$MAIL_DIR" 2>/dev/null || true
    fi

    local size=$(du -sh "$src" 2>/dev/null | cut -f1 || echo "0")
    ok "Email data imported ($size)"
  else
    warn "No email data to import"
  fi
}

import_accounts() {
  section "Importing: User Accounts"

  local src="$WORKDIR/content/accounts"
  local secrets_src="$WORKDIR/secrets/accounts"

  if [[ -d "$src" && -n "$(ls -A "$src" 2>/dev/null)" ]]; then
    local user_count=0

    # Create users from passwd/shadow (interactive - requires confirmation)
    if [[ -f "$secrets_src/passwd" && -f "$secrets_src/shadow" ]]; then
      log "  Importing user accounts..."

      while IFS=: read -r username x uid gid gecos home shell; do
        [[ -z "$username" ]] && continue

        # Check if user exists
        if ! id "$username" &>/dev/null; then
          log "    Creating user: $username (UID: $uid)"
          if [[ $DRY_RUN -eq 0 ]]; then
            # Create user with same UID/GID
            useradd -m -u "$uid" -s "$shell" -c "$gecos" "$username" 2>/dev/null || \
              useradd -m -s "$shell" -c "$gecos" "$username" 2>/dev/null || \
              warn "Failed to create user: $username"

            # Set password from shadow
            local shadow_entry=$(grep "^${username}:" "$secrets_src/shadow" 2>/dev/null)
            if [[ -n "$shadow_entry" ]]; then
              echo "$shadow_entry" | chpasswd -e 2>/dev/null || true
            fi
          fi
          ((user_count++))
        else
          log "    User exists: $username (skipping)"
        fi
      done < "$secrets_src/passwd"
    fi

    # Import home directories
    if [[ -d "$src/homes" ]]; then
      for user_home in "$src/homes"/*; do
        [[ -d "$user_home" ]] || continue
        local username=$(basename "$user_home")
        local target_home="/home/$username"

        # Get actual home from passwd if user exists
        if id "$username" &>/dev/null; then
          target_home=$(getent passwd "$username" | cut -d: -f6)
        fi

        log "    Importing home directory: $username → $target_home"
        run "mkdir -p '$target_home'"
        run "cp -r '$user_home/'* '$target_home/' 2>/dev/null || true"

        if [[ $DRY_RUN -eq 0 ]]; then
          chown -R "$username:$username" "$target_home" 2>/dev/null || true
        fi
      done
    fi

    # Import group memberships
    if [[ -f "$secrets_src/group" ]]; then
      log "  Importing group memberships..."
      while IFS=: read -r groupname x gid members; do
        [[ -z "$groupname" ]] && continue
        [[ -z "$members" ]] && continue

        # Create group if it doesn't exist
        if ! getent group "$groupname" &>/dev/null; then
          if [[ $DRY_RUN -eq 0 ]]; then
            groupadd -g "$gid" "$groupname" 2>/dev/null || \
              groupadd "$groupname" 2>/dev/null || true
          fi
        fi

        # Add members to group
        IFS=',' read -ra MEMBERS <<< "$members"
        for member in "${MEMBERS[@]}"; do
          if id "$member" &>/dev/null; then
            if [[ $DRY_RUN -eq 0 ]]; then
              usermod -aG "$groupname" "$member" 2>/dev/null || true
            fi
          fi
        done
      done < "$secrets_src/group"
    fi

    # Import sudoers
    if [[ -f "$src/sudoers.d" && -s "$src/sudoers.d" ]]; then
      log "  Importing sudoers rules..."
      run "cp '$src/sudoers.d' '/etc/sudoers.d/migrated'"
      run "chmod 440 '/etc/sudoers.d/migrated'"
      # Validate sudoers
      if [[ $DRY_RUN -eq 0 ]]; then
        visudo -c -f /etc/sudoers.d/migrated 2>/dev/null || {
          warn "Invalid sudoers rules - removing"
          rm -f /etc/sudoers.d/migrated
        }
      fi
    fi

    # Import crontabs
    if [[ -d "$src/crontabs" ]]; then
      log "  Importing user crontabs..."
      for crontab_file in "$src/crontabs"/*; do
        [[ -f "$crontab_file" ]] || continue
        local cron_user=$(basename "$crontab_file")
        if id "$cron_user" &>/dev/null; then
          run "mkdir -p '/var/spool/cron/crontabs'"
          run "cp '$crontab_file' '/var/spool/cron/crontabs/$cron_user'"
          run "chmod 600 '/var/spool/cron/crontabs/$cron_user'"
          run "chown '$cron_user:crontab' '/var/spool/cron/crontabs/$cron_user' 2>/dev/null || true"
          log "    Imported crontab: $cron_user"
        fi
      done
    fi

    # Import system cron jobs
    for cron_dir in cron.d cron.daily cron.weekly cron.monthly; do
      if [[ -d "$src/$cron_dir" ]]; then
        run "cp -r '$src/$cron_dir/'* '/etc/$cron_dir/' 2>/dev/null || true"
      fi
    done

    ok "User accounts imported ($user_count new users)"
  else
    warn "No user accounts to import"
  fi
}

import_dns() {
  section "Importing: DNS Services"

  local src="$WORKDIR/configs/dns"
  local secrets_src="$WORKDIR/secrets/dns"

  if [[ -d "$src" && -n "$(ls -A "$src" 2>/dev/null)" ]]; then
    # BIND/named
    if [[ -d "$src/bind" ]]; then
      log "  Importing BIND configuration..."
      run "mkdir -p '$BIND_DIR'"
      run "cp -r '$src/bind/'* '$BIND_DIR/' 2>/dev/null || true"

      # Import zones
      if [[ -d "$src/bind/zones" ]]; then
        run "mkdir -p '$BIND_DIR/zones'"
        run "cp -r '$src/bind/zones/'* '$BIND_DIR/zones/' 2>/dev/null || true"
        local zone_count=$(ls "$src/bind/zones"/*.zone 2>/dev/null | wc -l || echo "0")
        log "    Imported $zone_count zone files"
      fi

      # Import RNDC key from secrets
      if [[ -f "$secrets_src/rndc.key" ]]; then
        run "cp '$secrets_src/rndc.key' '$BIND_DIR/'"
        run "chmod 600 '$BIND_DIR/rndc.key'"
      fi

      if [[ $DRY_RUN -eq 0 ]]; then
        chown -R bind:bind "$BIND_DIR" 2>/dev/null || true
        systemctl restart named 2>/dev/null || systemctl restart bind9 2>/dev/null || warn "BIND restart failed"
      fi
    fi

    # Unbound
    if [[ -d "$src/unbound" ]]; then
      log "  Importing Unbound configuration..."
      run "mkdir -p '$UNBOUND_DIR'"
      run "cp -r '$src/unbound/'* '$UNBOUND_DIR/' 2>/dev/null || true"
      if [[ $DRY_RUN -eq 0 ]]; then
        systemctl restart unbound 2>/dev/null || warn "Unbound restart failed"
      fi
    fi

    # Vortex DNS (dnsmasq blocklists)
    if [[ -d "$src/vortex" ]]; then
      log "  Importing Vortex DNS blocklists..."
      run "mkdir -p '/etc/dnsmasq.d/vortex'"
      run "cp -r '$src/vortex/'* '/etc/dnsmasq.d/vortex/' 2>/dev/null || true"
    fi

    # AdGuard Home
    if [[ -d "$src/adguardhome" ]]; then
      log "  Importing AdGuard Home configuration..."
      run "mkdir -p '$ADGUARD_DIR'"
      run "cp '$src/adguardhome/AdGuardHome.yaml' '$ADGUARD_DIR/' 2>/dev/null || true"
      if [[ -d "$src/adguardhome/data" ]]; then
        run "mkdir -p '/var/lib/adguardhome/data'"
        run "cp -r '$src/adguardhome/data/'* '/var/lib/adguardhome/data/' 2>/dev/null || true"
      fi
      if [[ $DRY_RUN -eq 0 ]]; then
        systemctl restart AdGuardHome 2>/dev/null || warn "AdGuard Home restart failed"
      fi
    fi

    # Pi-hole
    if [[ -d "$src/pihole" ]]; then
      log "  Importing Pi-hole configuration..."
      run "mkdir -p '/etc/pihole'"
      run "cp -r '$src/pihole/'* '/etc/pihole/' 2>/dev/null || true"
      if [[ $DRY_RUN -eq 0 ]]; then
        pihole restartdns 2>/dev/null || warn "Pi-hole restart failed"
      fi
    fi

    local size=$(du -sh "$src" 2>/dev/null | cut -f1 || echo "0")
    ok "DNS services imported ($size)"
  else
    warn "No DNS configuration to import"
  fi
}

import_databases() {
  section "Importing: Databases"

  local src="$WORKDIR/state/databases"

  if [[ -d "$src" && -n "$(ls -A "$src" 2>/dev/null)" ]]; then
    # SQLite databases - restore to original locations
    for db_dir in "$src"/var_lib_*; do
      [[ -d "$db_dir" ]] || continue
      local original_path=$(echo "$db_dir" | sed 's/_/\//g' | sed 's/.*var/\/var/')
      log "  Restoring databases to: $original_path"
      run "mkdir -p '$original_path'"
      run "cp -r '$db_dir/'* '$original_path/' 2>/dev/null || true"
    done

    # MySQL restore
    if [[ -f "$src/mysql/all-databases.sql" ]]; then
      log "  Restoring MySQL databases..."
      if [[ $DRY_RUN -eq 0 ]]; then
        mysql < "$src/mysql/all-databases.sql" 2>/dev/null || warn "MySQL restore failed"
      else
        log "    Would restore MySQL from all-databases.sql"
      fi
    fi

    # PostgreSQL restore
    if [[ -f "$src/postgresql/all-databases.sql" ]]; then
      log "  Restoring PostgreSQL databases..."
      if [[ $DRY_RUN -eq 0 ]]; then
        su - postgres -c "psql < $src/postgresql/all-databases.sql" 2>/dev/null || warn "PostgreSQL restore failed"
      else
        log "    Would restore PostgreSQL from all-databases.sql"
      fi
    fi

    # Redis restore
    if [[ -f "$src/redis/dump.rdb" ]]; then
      log "  Restoring Redis dump..."
      run "mkdir -p '/var/lib/redis'"
      run "cp '$src/redis/dump.rdb' '/var/lib/redis/'"
      if [[ $DRY_RUN -eq 0 ]]; then
        chown redis:redis /var/lib/redis/dump.rdb 2>/dev/null || true
        systemctl restart redis 2>/dev/null || warn "Redis restart failed"
      fi
    fi

    local size=$(du -sh "$src" 2>/dev/null | cut -f1 || echo "0")
    ok "Databases imported ($size)"
  else
    warn "No databases to import"
  fi
}

import_scripts() {
  section "Importing: Custom Scripts and Units"

  local src="$WORKDIR/configs/scripts"

  if [[ -d "$src" && -n "$(ls -A "$src" 2>/dev/null)" ]]; then
    # Custom scripts
    for script_dir in "$src"/usr_local_*; do
      [[ -d "$script_dir" ]] || continue
      local target="/usr/local/bin"
      log "  Importing scripts to: $target"
      run "mkdir -p '$target'"
      run "cp -r '$script_dir/'* '$target/' 2>/dev/null || true"
      run "chmod +x '$target/'* 2>/dev/null || true"
    done

    for script_dir in "$src"/root_*; do
      [[ -d "$script_dir" ]] || continue
      local target="/root/scripts"
      log "  Importing scripts to: $target"
      run "mkdir -p '$target'"
      run "cp -r '$script_dir/'* '$target/' 2>/dev/null || true"
      run "chmod +x '$target/'* 2>/dev/null || true"
    done

    # Systemd unit overrides
    if [[ -d "$src/systemd" ]]; then
      log "  Importing systemd unit overrides..."
      for unit in "$src/systemd"/*; do
        [[ -e "$unit" ]] || continue
        local unit_name=$(basename "$unit")
        if [[ -d "$unit" ]]; then
          run "mkdir -p '/etc/systemd/system/$unit_name'"
          run "cp -r '$unit/'* '/etc/systemd/system/$unit_name/' 2>/dev/null || true"
        else
          run "cp '$unit' '/etc/systemd/system/$unit_name'"
        fi
        log "    Imported: $unit_name"
      done
      if [[ $DRY_RUN -eq 0 ]]; then
        systemctl daemon-reload 2>/dev/null || true
      fi
    fi

    # RC.local
    if [[ -f "$src/rc.local" && -s "$src/rc.local" ]]; then
      log "  Importing rc.local..."
      run "cp '$src/rc.local' '/etc/rc.local'"
      run "chmod +x '/etc/rc.local'"
    fi

    # Environment files
    if [[ -d "$src/environment" ]]; then
      if [[ -f "$src/environment/environment" && -s "$src/environment/environment" ]]; then
        log "  Importing /etc/environment..."
        run "cp '$src/environment/environment' '/etc/environment'"
      fi
    fi

    local size=$(du -sh "$src" 2>/dev/null | cut -f1 || echo "0")
    ok "Scripts and units imported ($size)"
  else
    warn "No scripts to import"
  fi
}

import_services() {
  section "Importing: Application Services"

  local src="$WORKDIR/content/services"

  if [[ -d "$src" && -n "$(ls -A "$src" 2>/dev/null)" ]]; then
    # Import service directories to /srv/
    for svc_dir in "$src"/*/; do
      [[ -d "$svc_dir" ]] || continue
      local svc_name=$(basename "$svc_dir")

      # Skip special directories
      [[ "$svc_name" == "git-repos" || "$svc_name" == "docker-compose" || "$svc_name" == "lxc" || "$svc_name" == "streamlit-apps" ]] && continue

      log "  Importing service: $svc_name"
      run "mkdir -p '/srv/$svc_name'"
      run "cp -r '$svc_dir'* '/srv/$svc_name/' 2>/dev/null || true"
    done

    # Import Streamlit apps
    if [[ -d "$src/streamlit-apps" ]]; then
      log "  Importing Streamlit apps..."
      run "mkdir -p '/srv/streamlit/apps'"
      run "cp -r '$src/streamlit-apps/'* '/srv/streamlit/apps/' 2>/dev/null || true"
    fi

    # Import Git repositories
    if [[ -d "$src/git-repos" ]]; then
      log "  Importing Git repositories..."
      run "mkdir -p '/srv/repos'"
      for repo_tar in "$src/git-repos"/*.tar.gz; do
        [[ -f "$repo_tar" ]] || continue
        local repo_name=$(basename "$repo_tar" .tar.gz)
        log "    Importing repo: $repo_name"
        run "mkdir -p '/srv/repos/$repo_name'"
        run "tar -xzf '$repo_tar' -C '/srv/repos/$repo_name' --strip-components=2 2>/dev/null || true"
      done
    fi

    # Import Docker compose files
    if [[ -d "$src/docker-compose" ]]; then
      log "  Importing Docker compose files..."
      for compose in "$src/docker-compose"/*; do
        [[ -f "$compose" ]] || continue
        local compose_name=$(basename "$compose")
        local target_path=$(echo "$compose_name" | sed 's/_/\//g' | sed 's/^srv/\/srv/')
        local target_dir=$(dirname "$target_path")
        run "mkdir -p '$target_dir'"
        run "cp '$compose' '$target_path'"
        log "    Imported: $compose_name"
      done
    fi

    # Import LXC configs
    if [[ -d "$src/lxc" ]]; then
      log "  Importing LXC container configs..."
      run "mkdir -p '/srv/lxc'"
      for lxc_config in "$src/lxc"/*.config; do
        [[ -f "$lxc_config" ]] || continue
        local container=$(basename "$lxc_config" .config)
        run "mkdir -p '/srv/lxc/$container'"
        run "cp '$lxc_config' '/srv/lxc/$container/config'"
        log "    Imported: $container"
      done
    fi

    # Fix ownership
    if [[ $DRY_RUN -eq 0 ]]; then
      chown -R root:root /srv/* 2>/dev/null || true
      # Fix specific service ownership
      chown -R www-data:www-data /srv/nextcloud 2>/dev/null || true
      chown -R gitea:gitea /srv/gitea 2>/dev/null || true
    fi

    local size=$(du -sh "$src" 2>/dev/null | cut -f1 || echo "0")
    local svc_count=$(ls -d "$src"/*/ 2>/dev/null | wc -l || echo "0")
    ok "Services imported ($svc_count services, $size)"
  else
    warn "No services to import"
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
  [git]=import_git
  [media]=import_media
  [mail]=import_mail
  [accounts]=import_accounts
  [dns]=import_dns
  [databases]=import_databases
  [scripts]=import_scripts
  [services]=import_services
)

ALL_MODULES="network,firewall,wireguard,crowdsec,dhcp,haproxy,nginx,certs,content,vhosts,users,state,git,media,mail,accounts,dns,databases,scripts,services"

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
