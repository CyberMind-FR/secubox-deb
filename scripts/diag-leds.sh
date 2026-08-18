#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox LED Diagnostic Script
# Run on MOCHAbin to diagnose IS31FL3199 LED controller issues
#
# Usage: ./diag-leds.sh [--fix]

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_info()  { echo -e "[INFO] $1"; }

FIX_MODE=false
[[ "${1:-}" == "--fix" ]] && FIX_MODE=true

echo "=========================================="
echo "SecuBox LED Diagnostic - IS31FL3199"
echo "=========================================="
echo

# 1. Check kernel modules
echo "=== Kernel Modules ==="
if lsmod | grep -q leds_is31fl319x; then
    log_ok "leds-is31fl319x module loaded"
else
    log_warn "leds-is31fl319x module NOT loaded"
    if $FIX_MODE; then
        log_info "Attempting to load module..."
        modprobe leds-is31fl319x 2>&1 || log_err "Failed to load module"
    fi
fi

if lsmod | grep -q i2c_mv64xxx; then
    log_ok "i2c-mv64xxx module loaded"
else
    log_warn "i2c-mv64xxx module NOT loaded"
fi
echo

# 2. Check I2C bus
echo "=== I2C Bus ==="
if [[ -e /dev/i2c-1 ]]; then
    log_ok "/dev/i2c-1 exists"
else
    log_err "/dev/i2c-1 does not exist!"
fi

log_info "Scanning I2C bus 1..."
i2cdetect -y 1 2>&1 || log_err "i2cdetect failed"

# Check for device at 0x64
if i2cdetect -y 1 2>/dev/null | grep -q "64"; then
    log_ok "IS31FL3199 detected at address 0x64"
else
    log_err "IS31FL3199 NOT detected at address 0x64"
fi
echo

# 3. Check GPIO state
echo "=== GPIO State (MPP30/GPIO62) ==="
GPIO_DEBUG="/sys/kernel/debug/gpio"
if [[ -f "$GPIO_DEBUG" ]]; then
    log_info "GPIO debug info for cp0-gpio1:"
    cat "$GPIO_DEBUG" 2>/dev/null | grep -A10 "cp0-gpio1" | head -15 || log_warn "Could not read GPIO debug"
else
    log_warn "GPIO debug not available (need debugfs mounted)"
fi

# Check if GPIO62 is exported (conflict!)
if [[ -d /sys/class/gpio/gpio62 ]]; then
    log_err "GPIO62 is exported via sysfs - this conflicts with the LED driver!"
    if $FIX_MODE; then
        log_info "Unexporting GPIO62..."
        echo 62 > /sys/class/gpio/unexport 2>/dev/null || log_warn "Could not unexport"
    fi
fi
echo

# 4. Check LED sysfs entries
echo "=== LED Sysfs Entries ==="
if ls /sys/class/leds/ 2>/dev/null | grep -q "led"; then
    log_ok "LED entries found:"
    ls -la /sys/class/leds/ | grep -E "led[123]|:led" || true
else
    log_warn "No LED entries found in /sys/class/leds/"
fi
echo

# 5. Check I2C device binding
echo "=== I2C Device Binding ==="
I2C_DEV="/sys/bus/i2c/devices/1-0064"
if [[ -d "$I2C_DEV" ]]; then
    log_ok "I2C device 1-0064 exists"
    log_info "Device info:"
    cat "$I2C_DEV/name" 2>/dev/null || log_warn "No name file"
    ls -la "$I2C_DEV" 2>/dev/null | head -10
else
    log_err "I2C device 1-0064 not found"
fi
echo

# 6. Check dmesg for errors
echo "=== Recent dmesg Errors ==="
dmesg | grep -iE "is31|i2c|mv64xxx|led" | tail -20 || log_info "No relevant dmesg entries"
echo

# 7. Check DTB
echo "=== Device Tree Info ==="
DTB_PATH="/sys/firmware/devicetree/base/cp0/config-space@f2000000/i2c@701100/leds@64"
if [[ -d "$DTB_PATH" ]]; then
    log_ok "IS31FL3199 node found in device tree"
    log_info "shutdown-gpios property:"
    xxd "$DTB_PATH/shutdown-gpios" 2>/dev/null | head -2 || log_warn "Could not read shutdown-gpios"
else
    log_err "IS31FL3199 node NOT found in device tree"
fi
echo

# 8. Test LED write
echo "=== LED Write Test ==="
GREEN_LED="/sys/class/leds/green:led1/brightness"
if [[ -f "$GREEN_LED" ]]; then
    log_info "Testing write to $GREEN_LED..."
    for i in 1 2 3; do
        if echo 255 > "$GREEN_LED" 2>&1; then
            log_ok "Write $i: ON success"
        else
            log_err "Write $i: ON failed"
        fi
        sleep 0.2
        if echo 0 > "$GREEN_LED" 2>&1; then
            log_ok "Write $i: OFF success"
        else
            log_err "Write $i: OFF failed"
        fi
        sleep 0.2
    done
else
    log_warn "Green LED sysfs not available for test"
fi
echo

# 9. Recommendations
echo "=== Recommendations ==="
if ! i2cdetect -y 1 2>/dev/null | grep -q "64"; then
    echo "1. IS31FL3199 not responding on I2C. Check:"
    echo "   - GPIO shutdown pin state (should be HIGH)"
    echo "   - DTB shutdown-gpios polarity (should be GPIO_ACTIVE_HIGH)"
    echo "   - I2C controller driver (kernel/initrd mismatch?)"
    echo
    echo "2. Try rebinding I2C controller:"
    echo "   echo 'f2701000.i2c' > /sys/bus/platform/drivers/mv64xxx_i2c/unbind"
    echo "   sleep 1"
    echo "   echo 'f2701000.i2c' > /sys/bus/platform/drivers/mv64xxx_i2c/bind"
fi

if [[ -d /sys/class/gpio/gpio62 ]]; then
    echo "3. GPIO62 conflict detected. Run:"
    echo "   echo 62 > /sys/class/gpio/unexport"
fi

echo
echo "=========================================="
echo "Diagnostic complete"
echo "=========================================="
