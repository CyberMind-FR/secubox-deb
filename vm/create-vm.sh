#!/bin/bash
#
# SecuBox VM Creation Script
#
# Creates a SecuBox VM with MOCHAbin-like network topology.
#
# Prerequisites:
#   - Debian 12 (Bookworm) ISO or cloud image
#   - libvirt/QEMU installed
#   - Networks created (./setup-networks.sh create)
#
# Usage:
#   ./create-vm.sh                    # Interactive mode
#   ./create-vm.sh --iso /path/to.iso # Use ISO for installation
#   ./create-vm.sh --cloud            # Use Debian cloud image
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_NAME="secubox-mochabin"
VM_RAM="4096"  # MB
VM_CPUS="4"
DISK_SIZE="40G"
DATA_DISK_SIZE="20G"

IMAGES_DIR="/var/lib/libvirt/images"
SYSTEM_DISK="$IMAGES_DIR/${VM_NAME}.qcow2"
DATA_DISK="$IMAGES_DIR/${VM_NAME}-data.qcow2"

# Debian 12 cloud image URL
CLOUD_IMAGE_URL="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2"
CLOUD_IMAGE_FILE="$IMAGES_DIR/debian-12-generic-amd64.qcow2"

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --iso PATH      Use ISO image for installation"
    echo "  --cloud         Use Debian cloud image (default)"
    echo "  --ram MB        RAM size in MB (default: 4096)"
    echo "  --cpus N        Number of CPUs (default: 4)"
    echo "  --disk SIZE     System disk size (default: 40G)"
    echo "  --name NAME     VM name (default: secubox-mochabin)"
    echo "  --destroy       Destroy existing VM first"
    echo "  -h, --help      Show this help"
    echo ""
}

# Parse arguments
MODE="cloud"
DESTROY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --iso)
            MODE="iso"
            ISO_PATH="$2"
            shift 2
            ;;
        --cloud)
            MODE="cloud"
            shift
            ;;
        --ram)
            VM_RAM="$2"
            shift 2
            ;;
        --cpus)
            VM_CPUS="$2"
            shift 2
            ;;
        --disk)
            DISK_SIZE="$2"
            shift 2
            ;;
        --name)
            VM_NAME="$2"
            SYSTEM_DISK="$IMAGES_DIR/${VM_NAME}.qcow2"
            DATA_DISK="$IMAGES_DIR/${VM_NAME}-data.qcow2"
            shift 2
            ;;
        --destroy)
            DESTROY=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Check prerequisites
check_prerequisites() {
    echo "Checking prerequisites..."

    if ! command -v virsh &>/dev/null; then
        echo "ERROR: libvirt (virsh) not found. Install with: apt install libvirt-daemon-system"
        exit 1
    fi

    if ! command -v qemu-img &>/dev/null; then
        echo "ERROR: qemu-img not found. Install with: apt install qemu-utils"
        exit 1
    fi

    # Check networks exist
    for net in secubox-wan secubox-lan secubox-switch; do
        if ! virsh net-info "$net" &>/dev/null; then
            echo "ERROR: Network '$net' not found. Run: ./setup-networks.sh create"
            exit 1
        fi
    done

    echo "Prerequisites OK."
}

# Destroy existing VM
destroy_vm() {
    if virsh dominfo "$VM_NAME" &>/dev/null; then
        echo "Destroying existing VM '$VM_NAME'..."
        virsh destroy "$VM_NAME" 2>/dev/null || true
        virsh undefine "$VM_NAME" --remove-all-storage 2>/dev/null || true
    fi
}

# Download cloud image
download_cloud_image() {
    if [ ! -f "$CLOUD_IMAGE_FILE" ]; then
        echo "Downloading Debian 12 cloud image..."
        curl -L -o "$CLOUD_IMAGE_FILE" "$CLOUD_IMAGE_URL"
    else
        echo "Using existing cloud image: $CLOUD_IMAGE_FILE"
    fi
}

# Create disks
create_disks() {
    echo "Creating VM disks..."

    if [ -f "$SYSTEM_DISK" ]; then
        if [ "$DESTROY" = true ]; then
            rm -f "$SYSTEM_DISK"
        else
            echo "ERROR: System disk exists: $SYSTEM_DISK"
            echo "Use --destroy to remove existing VM first"
            exit 1
        fi
    fi

    if [ "$MODE" = "cloud" ]; then
        # Create disk from cloud image
        qemu-img create -f qcow2 -F qcow2 -b "$CLOUD_IMAGE_FILE" "$SYSTEM_DISK" "$DISK_SIZE"
    else
        # Create empty disk for ISO installation
        qemu-img create -f qcow2 "$SYSTEM_DISK" "$DISK_SIZE"
    fi

    # Create data disk
    if [ ! -f "$DATA_DISK" ] || [ "$DESTROY" = true ]; then
        qemu-img create -f qcow2 "$DATA_DISK" "$DATA_DISK_SIZE"
    fi

    echo "Disks created:"
    echo "  System: $SYSTEM_DISK ($DISK_SIZE)"
    echo "  Data:   $DATA_DISK ($DATA_DISK_SIZE)"
}

# Create cloud-init ISO for initial configuration
create_cloud_init() {
    echo "Creating cloud-init configuration..."

    CLOUD_INIT_DIR=$(mktemp -d)
    CLOUD_INIT_ISO="$IMAGES_DIR/${VM_NAME}-cloud-init.iso"

    # meta-data
    cat > "$CLOUD_INIT_DIR/meta-data" << EOF
instance-id: ${VM_NAME}
local-hostname: ${VM_NAME}
EOF

    # user-data
    cat > "$CLOUD_INIT_DIR/user-data" << 'EOF'
#cloud-config
hostname: secubox
fqdn: secubox.local
manage_etc_hosts: true

users:
  - name: secubox
    groups: sudo, adm, systemd-journal
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    # Password: secubox (change immediately!)
    passwd: $6$rounds=4096$saltsalt$aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefghijklmnopqrstuvwxyz

ssh_pwauth: true
disable_root: false

# Network configuration will be done via netplan
write_files:
  - path: /etc/netplan/50-secubox.yaml
    permissions: '0600'
    content: |
      # SecuBox Network Configuration - MOCHAbin Topology
      network:
        version: 2
        renderer: networkd
        ethernets:
          # eth0: WAN Primary (10G equivalent)
          eth0:
            dhcp4: true
            dhcp6: true
            optional: true

          # eth1: Switch Uplink (internal)
          eth1:
            dhcp4: false
            optional: true

          # eth2: WAN Secondary / Management (NAT)
          eth2:
            dhcp4: true
            optional: true

          # eth3-eth6: LAN ports (will be bridged)
          eth3:
            dhcp4: false
            optional: true
          eth4:
            dhcp4: false
            optional: true
          eth5:
            dhcp4: false
            optional: true
          eth6:
            dhcp4: false
            optional: true

        bridges:
          # LAN bridge (equivalent to MOCHAbin DSA bridge)
          br-lan:
            interfaces: [eth3, eth4, eth5, eth6]
            addresses:
              - 10.55.1.1/24
            dhcp4: false
            parameters:
              stp: false
              forward-delay: 0

  - path: /etc/sysctl.d/99-secubox.conf
    content: |
      # Enable IP forwarding
      net.ipv4.ip_forward = 1
      net.ipv6.conf.all.forwarding = 1

      # Security hardening
      net.ipv4.conf.all.rp_filter = 1
      net.ipv4.conf.default.rp_filter = 1
      net.ipv4.conf.all.accept_redirects = 0
      net.ipv4.conf.default.accept_redirects = 0
      net.ipv4.conf.all.send_redirects = 0
      net.ipv4.conf.default.send_redirects = 0
      net.ipv4.icmp_ignore_bogus_error_responses = 1
      net.ipv4.icmp_echo_ignore_broadcasts = 1
      net.ipv4.tcp_syncookies = 1

runcmd:
  - netplan apply
  - sysctl --system
  - systemctl enable systemd-networkd
  - echo "SecuBox VM initialized at $(date)" >> /var/log/secubox-init.log

final_message: |
  SecuBox VM initialization complete!

  Network Interfaces (MOCHAbin topology):
    eth0: WAN Primary (DHCP)
    eth1: Switch Uplink (internal)
    eth2: WAN Secondary (DHCP/NAT)
    eth3-eth6: LAN ports (bridged to br-lan)
    br-lan: 10.55.1.1/24

  Login: secubox / secubox

  Next steps:
    1. Change password: passwd
    2. Install SecuBox packages
    3. Configure services
EOF

    # network-config (cloud-init v2 network config)
    cat > "$CLOUD_INIT_DIR/network-config" << 'EOF'
version: 2
ethernets:
  eth0:
    dhcp4: true
  eth2:
    dhcp4: true
EOF

    # Create ISO
    if command -v genisoimage &>/dev/null; then
        genisoimage -output "$CLOUD_INIT_ISO" -volid cidata -joliet -rock \
            "$CLOUD_INIT_DIR/user-data" "$CLOUD_INIT_DIR/meta-data" "$CLOUD_INIT_DIR/network-config"
    elif command -v mkisofs &>/dev/null; then
        mkisofs -output "$CLOUD_INIT_ISO" -volid cidata -joliet -rock \
            "$CLOUD_INIT_DIR/user-data" "$CLOUD_INIT_DIR/meta-data" "$CLOUD_INIT_DIR/network-config"
    else
        echo "WARNING: genisoimage/mkisofs not found, skipping cloud-init ISO"
        rm -rf "$CLOUD_INIT_DIR"
        return
    fi

    rm -rf "$CLOUD_INIT_DIR"
    echo "Cloud-init ISO created: $CLOUD_INIT_ISO"
}

# Define and start VM
define_vm() {
    echo "Defining VM..."

    # Update domain XML with actual paths
    DOMAIN_XML=$(mktemp)
    sed -e "s|/var/lib/libvirt/images/secubox-mochabin.qcow2|$SYSTEM_DISK|g" \
        -e "s|/var/lib/libvirt/images/secubox-mochabin-data.qcow2|$DATA_DISK|g" \
        -e "s|<name>secubox-mochabin</name>|<name>$VM_NAME</name>|g" \
        "$SCRIPT_DIR/secubox-mochabin.xml" > "$DOMAIN_XML"

    # Add cloud-init ISO if exists
    CLOUD_INIT_ISO="$IMAGES_DIR/${VM_NAME}-cloud-init.iso"
    if [ -f "$CLOUD_INIT_ISO" ]; then
        # Insert CD-ROM source
        sed -i "s|<disk type=\"file\" device=\"cdrom\">|<disk type=\"file\" device=\"cdrom\">\n      <source file=\"$CLOUD_INIT_ISO\"/>|" "$DOMAIN_XML"
    fi

    # Define the VM
    virsh define "$DOMAIN_XML"
    rm -f "$DOMAIN_XML"

    echo "VM '$VM_NAME' defined."
}

# Start VM
start_vm() {
    echo "Starting VM..."
    virsh start "$VM_NAME"

    echo ""
    echo "=========================================="
    echo "SecuBox VM '$VM_NAME' is starting!"
    echo "=========================================="
    echo ""
    echo "Network Interfaces:"
    echo "  eth0 (WAN):     Connected to secubox-wan (NAT)"
    echo "  eth1 (Switch):  Connected to secubox-switch (isolated)"
    echo "  eth2 (WAN2):    Connected to default (NAT)"
    echo "  eth3-6 (LAN):   Connected to secubox-lan (isolated)"
    echo ""
    echo "Access:"
    echo "  Console:  virsh console $VM_NAME"
    echo "  VNC:      virt-viewer $VM_NAME"
    echo "  SSH:      ssh secubox@<IP>"
    echo ""
    echo "Default credentials: secubox / secubox"
    echo ""
    echo "Get IP address:"
    echo "  virsh domifaddr $VM_NAME"
    echo ""
}

# Main
main() {
    echo "========================================"
    echo "SecuBox VM Creation - MOCHAbin Topology"
    echo "========================================"
    echo ""

    check_prerequisites

    if [ "$DESTROY" = true ]; then
        destroy_vm
    fi

    if [ "$MODE" = "cloud" ]; then
        download_cloud_image
    fi

    create_disks

    if [ "$MODE" = "cloud" ]; then
        create_cloud_init
    fi

    define_vm
    start_vm
}

main
