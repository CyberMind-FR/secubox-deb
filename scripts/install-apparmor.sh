#!/bin/bash
# Install SecuBox AppArmor profiles
# Run as root

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APPARMOR_DIR="$SCRIPT_DIR/../common/apparmor"

# Check root
[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }

# Check AppArmor
if ! aa-status >/dev/null 2>&1; then
    echo "AppArmor not running, installing..."
    apt-get install -y apparmor apparmor-utils
fi

echo "Installing SecuBox AppArmor profiles..."

# Install base abstractions
mkdir -p /etc/apparmor.d/local
cp "$APPARMOR_DIR/secubox-base" /etc/apparmor.d/local/secubox-base

# Install service profiles
for profile in "$APPARMOR_DIR"/usr.lib.secubox.*; do
    if [ -f "$profile" ]; then
        name=$(basename "$profile")
        echo "Installing profile: $name"
        cp "$profile" /etc/apparmor.d/"$name"
    fi
done

# Reload AppArmor profiles
echo "Reloading AppArmor profiles..."
systemctl reload apparmor || apparmor_parser -r /etc/apparmor.d/usr.lib.secubox.* 2>/dev/null || true

# Show status
echo ""
echo "Installed profiles:"
aa-status 2>/dev/null | grep secubox || echo "Profiles installed (need service restart to apply)"

echo ""
echo "To apply profiles, restart SecuBox services:"
echo "  systemctl restart secubox-hub secubox-mail secubox-wireguard secubox-crowdsec"
echo ""
echo "To check a profile is working:"
echo "  aa-status | grep secubox"
