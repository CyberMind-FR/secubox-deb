#!/bin/bash
# SecuBox Eye Remote - Deploy to SD Card
# Copies agent, icons, and config to mounted SD card

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROUND_DIR="$(dirname "$SCRIPT_DIR")"
PIROOT="${1:-/mnt/piroot}"

echo "=== SecuBox Eye Remote - Deploy to SD Card ==="
echo "Source: $SCRIPT_DIR"
echo "Target: $PIROOT"

# Check if SD card is mounted
if [ ! -d "$PIROOT/usr" ]; then
    echo "ERROR: $PIROOT does not appear to be a mounted root filesystem"
    echo "Usage: $0 /path/to/mounted/rootfs"
    exit 1
fi

# Target directories
TARGET_LIB="$PIROOT/usr/lib/secubox-eye"
TARGET_AGENT="$TARGET_LIB/agent"
TARGET_ASSETS="$TARGET_LIB/assets"
TARGET_ICONS="$TARGET_ASSETS/icons"
TARGET_SBIN="$PIROOT/usr/local/sbin"
TARGET_SYSTEMD="$PIROOT/etc/systemd/system"

# Create directories
echo ""
echo "Creating directories..."
mkdir -p "$TARGET_AGENT"
mkdir -p "$TARGET_ICONS"
mkdir -p "$TARGET_SBIN"
mkdir -p "$TARGET_SYSTEMD"

# Copy Python files
echo "Copying agent files..."
cp -v "$SCRIPT_DIR"/*.py "$TARGET_AGENT/"

# Make main_standalone.py executable
chmod +x "$TARGET_AGENT/main_standalone.py"

# Copy icons
echo "Copying icons..."
if [ -d "$ROUND_DIR/assets/icons" ]; then
    cp -v "$ROUND_DIR/assets/icons/"*.png "$TARGET_ICONS/"
    echo "  $(ls "$TARGET_ICONS/"*.png 2>/dev/null | wc -l) icons copied"
else
    echo "WARNING: No icons found at $ROUND_DIR/assets/icons"
fi

# Create wrapper script
echo "Creating wrapper script..."
cat > "$TARGET_SBIN/eye-agent-wrapper.sh" << 'WRAPPER'
#!/bin/bash
# SecuBox Eye Agent Wrapper - Crash logging
exec 2>&1
echo "=== Eye Agent Starting: $(date) ===" >> /var/log/eye-crash.log
cd /usr/lib/secubox-eye/agent
exec python3 main_standalone.py 2>&1 | tee -a /var/log/eye-crash.log
WRAPPER
chmod +x "$TARGET_SBIN/eye-agent-wrapper.sh"

# Create systemd service
echo "Creating systemd service..."
cat > "$TARGET_SYSTEMD/secubox-eye-agent.service" << 'SERVICE'
[Unit]
Description=SecuBox Eye Remote Agent
After=local-fs.target
DefaultDependencies=no

[Service]
Type=simple
ExecStart=/usr/local/sbin/eye-agent-wrapper.sh
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE

# Enable service
echo "Enabling service..."
ln -sf "$TARGET_SYSTEMD/secubox-eye-agent.service" "$PIROOT/etc/systemd/system/multi-user.target.wants/secubox-eye-agent.service" 2>/dev/null || true

# Fix rc.local
echo "Fixing rc.local..."
cat > "$PIROOT/etc/rc.local" << 'RCLOCAL'
#!/bin/sh -e
# SecuBox Eye Remote - First boot configuration
exit 0
RCLOCAL
chmod +x "$PIROOT/etc/rc.local"

# Summary
echo ""
echo "=== Deployment Complete ==="
echo "Agent:   $TARGET_AGENT"
echo "Icons:   $TARGET_ICONS ($(ls "$TARGET_ICONS/"*.png 2>/dev/null | wc -l) files)"
echo "Service: $TARGET_SYSTEMD/secubox-eye-agent.service"
echo ""
echo "Next: Unmount SD card and test on Pi"
