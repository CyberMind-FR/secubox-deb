#!/bin/bash
#
# SecuBox VM Network Setup
#
# Creates libvirt networks that simulate MOCHAbin's network topology:
# - secubox-wan: Primary WAN (NAT mode for dev, bridge mode for prod)
# - secubox-lan: LAN switch (isolated, SecuBox provides DHCP)
# - secubox-switch: Internal switch uplink (isolated)
#
# Usage:
#   ./setup-networks.sh create   - Create and start all networks
#   ./setup-networks.sh destroy  - Stop and remove all networks
#   ./setup-networks.sh status   - Show network status
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORKS_DIR="$SCRIPT_DIR/networks"

NETWORKS=(
    "secubox-wan"
    "secubox-lan"
    "secubox-switch"
)

create_networks() {
    echo "Creating SecuBox VM networks..."

    for net in "${NETWORKS[@]}"; do
        xml_file="$NETWORKS_DIR/${net}.xml"

        if [ ! -f "$xml_file" ]; then
            echo "ERROR: Network definition not found: $xml_file"
            exit 1
        fi

        # Check if network already exists
        if virsh net-info "$net" &>/dev/null; then
            echo "  Network '$net' already exists, skipping..."
        else
            echo "  Creating network '$net'..."
            virsh net-define "$xml_file"
        fi

        # Start if not running
        if ! virsh net-info "$net" 2>/dev/null | grep -q "Active:.*yes"; then
            echo "  Starting network '$net'..."
            virsh net-start "$net"
        fi

        # Set autostart
        virsh net-autostart "$net"
    done

    echo ""
    echo "Networks created successfully!"
    echo ""
    show_status
}

destroy_networks() {
    echo "Destroying SecuBox VM networks..."

    for net in "${NETWORKS[@]}"; do
        if virsh net-info "$net" &>/dev/null; then
            echo "  Stopping network '$net'..."
            virsh net-destroy "$net" 2>/dev/null || true
            echo "  Removing network '$net'..."
            virsh net-undefine "$net"
        else
            echo "  Network '$net' not found, skipping..."
        fi
    done

    echo "Networks destroyed."
}

show_status() {
    echo "SecuBox VM Network Status:"
    echo "=========================="
    echo ""

    for net in "${NETWORKS[@]}"; do
        if virsh net-info "$net" &>/dev/null; then
            echo "Network: $net"
            virsh net-info "$net" | grep -E "(Name|UUID|Active|Persistent|Autostart|Bridge)"
            echo ""
        else
            echo "Network: $net (not defined)"
            echo ""
        fi
    done

    echo "Bridge Status:"
    echo "--------------"
    for br in virbr-sbwan virbr-sblan virbr-sbsw; do
        if ip link show "$br" &>/dev/null; then
            echo "$br: UP"
            ip addr show "$br" | grep -E "inet|link/ether" | head -2
        else
            echo "$br: DOWN"
        fi
        echo ""
    done
}

case "${1:-status}" in
    create)
        create_networks
        ;;
    destroy)
        destroy_networks
        ;;
    status)
        show_status
        ;;
    *)
        echo "Usage: $0 {create|destroy|status}"
        exit 1
        ;;
esac
