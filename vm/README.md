# SecuBox VM - MOCHAbin Network Topology

This directory contains libvirt/QEMU configuration for running SecuBox in a VM with network interfaces matching the Globalscale MOCHAbin hardware.

## Network Topology

```
                    ┌─────────────────────────────────────────────────┐
                    │              SecuBox VM                          │
                    │                                                  │
   Internet ────────┤ eth0 (WAN)      ┌────────────────────────┐      │
   (NAT/Bridge)     │ 10G equiv       │      br-lan            │      │
                    │                 │   192.168.255.1/24     │      │
   Management ──────┤ eth2 (WAN2)     │                        │      │
   (NAT)            │ 1G equiv        │  ┌───┐┌───┐┌───┐┌───┐ │      │
                    │                 │  │e3 ││e4 ││e5 ││e6 │ │      │
                    │ eth1 (Switch)───┤  └───┘└───┘└───┘└───┘ │      │
                    │ 2.5G uplink     │  lan0 lan1 lan2 lan3  │      │
                    │                 └────────────────────────┘      │
                    └─────────────────────────────────────────────────┘
                                              │
                                      ┌───────┴───────┐
                                      │  secubox-lan  │
                                      │   (isolated)  │
                                      └───────────────┘
                                              │
                                      ┌───────┴───────┐
                                      │  Test VMs /   │
                                      │  Containers   │
                                      └───────────────┘
```

## Interface Mapping

| VM Interface | MOCHAbin Equivalent | Purpose | libvirt Network |
|--------------|---------------------|---------|-----------------|
| eth0 | cp0_eth0 (10G SFP+) | WAN Primary | secubox-wan |
| eth1 | cp0_eth1 (2.5G) | Switch Uplink | secubox-switch |
| eth2 | cp0_eth2 (1G SFP/RJ45) | WAN Secondary | default (NAT) |
| eth3 | swport1 (lan0) | LAN Port 1 | secubox-lan |
| eth4 | swport2 (lan1) | LAN Port 2 | secubox-lan |
| eth5 | swport3 (lan2) | LAN Port 3 | secubox-lan |
| eth6 | swport4 (lan3) | LAN Port 4 | secubox-lan |

## Quick Start

### 1. Prerequisites

```bash
# Install required packages
sudo apt install libvirt-daemon-system qemu-kvm qemu-utils virtinst genisoimage

# Add user to libvirt group
sudo usermod -aG libvirt $USER
newgrp libvirt
```

### 2. Create Networks

```bash
./setup-networks.sh create
```

### 3. Create VM

```bash
# Using Debian cloud image (recommended)
./create-vm.sh --cloud

# Or using ISO for manual installation
./create-vm.sh --iso /path/to/debian-12-netinst.iso
```

### 4. Access VM

```bash
# Console access
virsh console secubox-mochabin

# VNC viewer
virt-viewer secubox-mochabin

# Get IP address
virsh domifaddr secubox-mochabin

# SSH (once running)
ssh secubox@<IP>
```

## Default Credentials

- **Username**: secubox
- **Password**: secubox

**Change immediately after first login!**

## Network Configuration Inside VM

The VM is pre-configured with netplan:

```yaml
# /etc/netplan/50-secubox.yaml
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true      # WAN - gets IP from secubox-wan
    eth2:
      dhcp4: true      # Management - gets IP from default NAT
  bridges:
    br-lan:
      interfaces: [eth3, eth4, eth5, eth6]
      addresses:
        - 192.168.255.1/24
```

## Testing LAN Connectivity

1. Create a test VM attached to `secubox-lan`:

```bash
virt-install \
  --name test-client \
  --ram 512 \
  --vcpus 1 \
  --disk size=4 \
  --network network=secubox-lan \
  --cdrom /path/to/alpine-virt.iso
```

2. The test VM should get DHCP from SecuBox (192.168.255.x)

## Production Mode

For production, modify `networks/secubox-wan.xml` to bridge to a physical interface:

```xml
<!-- Change from NAT mode -->
<forward mode="bridge"/>
<bridge name="br0"/>  <!-- Your physical bridge -->
```

## VM Management

```bash
# Start VM
virsh start secubox-mochabin

# Stop VM
virsh shutdown secubox-mochabin

# Force stop
virsh destroy secubox-mochabin

# Delete VM
virsh undefine secubox-mochabin --remove-all-storage

# Snapshot
virsh snapshot-create-as secubox-mochabin snap1 "Initial setup"

# List snapshots
virsh snapshot-list secubox-mochabin

# Revert to snapshot
virsh snapshot-revert secubox-mochabin snap1
```

## Files

| File | Description |
|------|-------------|
| `secubox-mochabin.xml` | libvirt domain definition |
| `networks/secubox-wan.xml` | WAN network (NAT/bridge) |
| `networks/secubox-lan.xml` | LAN network (isolated) |
| `networks/secubox-switch.xml` | Switch uplink (isolated) |
| `setup-networks.sh` | Create/destroy networks |
| `create-vm.sh` | Create VM from cloud image or ISO |

## Hardware Comparison

| Feature | MOCHAbin | VM |
|---------|----------|-----|
| CPU | ARM Cortex-A72 | x86_64 (host-passthrough) |
| RAM | Up to 16GB DDR4 | 4GB (configurable) |
| 10G Port | Yes (SFP+) | Virtio (simulated) |
| 1G Ports | 4x (Topaz switch) | 4x Virtio (bridged) |
| DSA Switch | Marvell 88E6141 | Linux bridge |
| Storage | SATA/NVMe | Virtio (qcow2) |
