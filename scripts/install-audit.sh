#!/bin/bash
# Install SecuBox audit rules
# Run as root

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUDIT_RULES="$SCRIPT_DIR/../common/audit/50-secubox.rules"

# Check root
[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }

# Install auditd if not present
if ! command -v auditctl &>/dev/null; then
    echo "Installing auditd..."
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Copy rules
echo "Installing SecuBox audit rules..."
cp "$AUDIT_RULES" /etc/audit/rules.d/50-secubox.rules

# Configure auditd for security
cat > /etc/audit/auditd.conf.d/secubox.conf 2>/dev/null || true << 'EOF'
# SecuBox auditd configuration
log_file = /var/log/audit/audit.log
log_format = ENRICHED
max_log_file = 50
num_logs = 10
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
EOF

# Reload audit rules
echo "Reloading audit rules..."
augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/50-secubox.rules

# Enable and start auditd
systemctl enable auditd
systemctl restart auditd

echo ""
echo "Audit rules installed. View logs with:"
echo "  ausearch -k secubox_config"
echo "  ausearch -k wireguard_config"
echo "  aureport --summary"
