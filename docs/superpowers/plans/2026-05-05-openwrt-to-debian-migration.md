<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# OpenWrt to Debian Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate from OpenWrt C3BOX (192.168.255.1) to SecuBox-DEB Debian (192.168.255.10), making target the primary internet gateway with Mail, NextCloud, Matrix, and Gitea in LXC containers.

**Architecture:** Big Bang migration with 4 phases — Prepare (LXC/storage setup), Build (containers + services), Sync (data migration), Cutover (network swap). All LXC containers on /data SSD. Host runs gateway services (HAProxy, CrowdSec, nftables). Containers run apps.

**Tech Stack:** Debian 12, LXC 5.0, HAProxy, CrowdSec, nftables, Postfix/Dovecot, NextCloud, Matrix Synapse, Gitea, netplan

**Source:** 192.168.255.1 (OpenWrt C3BOX)
**Target:** 192.168.255.10 (SecuBox-DEB MOCHAbin)

---

## File Structure

### Host Configuration Files (Target)

| Path | Purpose |
|------|---------|
| `/etc/lxc/lxc.conf` | LXC global config (storage path) |
| `/etc/lxc/default.conf` | LXC default container config |
| `/etc/netplan/10-lxc-bridge.yaml` | LXC network bridge |
| `/etc/netplan/01-secubox-gateway.yaml` | Gateway netplan (WAN+LAN) |
| `/etc/nftables.conf` | Firewall + NAT rules |
| `/etc/haproxy/haproxy.cfg` | HAProxy main config |
| `/etc/dnsmasq.d/secubox.conf` | DHCP + DNS config |

### LXC Container Configs

| Path | Purpose |
|------|---------|
| `/data/lxc/mail/config` | Mail container LXC config |
| `/data/lxc/nextcloud/config` | NextCloud container LXC config |
| `/data/lxc/matrix/config` | Matrix container LXC config |
| `/data/lxc/gitea/config` | Gitea container LXC config |

### Data Volumes

| Path | Purpose |
|------|---------|
| `/data/volumes/mail/` | Mail data (vmail, config, ssl) |
| `/data/volumes/nextcloud/` | NextCloud data (files, config, db) |
| `/data/volumes/matrix/` | Matrix data (synapse, db) |
| `/data/volumes/gitea/` | Gitea data (repos, data, db) |
| `/data/haproxy/certs/` | SSL certificates (94 certs) |
| `/data/haproxy/config/` | HAProxy configs |
| `/data/crowdsec/` | CrowdSec data |

---

## Phase 1: Prepare

### Task 1: Create Directory Structure

**Files:**
- Create: `/data/lxc/`
- Create: `/data/volumes/{mail,nextcloud,matrix,gitea}/`
- Create: `/data/haproxy/{certs,config}/`
- Create: `/data/crowdsec/`
- Create: `/data/backups/`

- [ ] **Step 1: SSH to target and create directories**

```bash
ssh root@192.168.255.10
```

```bash
mkdir -p /data/lxc
mkdir -p /data/volumes/mail/{vmail,config,ssl}
mkdir -p /data/volumes/nextcloud/{data,config,db}
mkdir -p /data/volumes/matrix/{data,db}
mkdir -p /data/volumes/gitea/{repos,data,db}
mkdir -p /data/haproxy/{certs,config}
mkdir -p /data/crowdsec
mkdir -p /data/backups
mkdir -p /data/music
```

- [ ] **Step 2: Verify structure**

```bash
tree -L 2 /data/
```

Expected:
```
/data/
├── backups
├── crowdsec
├── haproxy
│   ├── certs
│   └── config
├── lxc
├── music
└── volumes
    ├── gitea
    ├── mail
    ├── matrix
    └── nextcloud
```

- [ ] **Step 3: Set ownership**

```bash
chown -R root:root /data/lxc
chown -R 100000:100000 /data/volumes
chmod 755 /data/lxc /data/volumes
```

---

### Task 2: Configure LXC Storage Path

**Files:**
- Modify: `/etc/lxc/lxc.conf`

- [ ] **Step 1: Backup existing config**

```bash
cp /etc/lxc/lxc.conf /etc/lxc/lxc.conf.bak 2>/dev/null || true
```

- [ ] **Step 2: Configure LXC path**

```bash
cat > /etc/lxc/lxc.conf << 'EOF'
# LXC system-wide configuration
lxc.lxcpath = /data/lxc
EOF
```

- [ ] **Step 3: Verify config**

```bash
cat /etc/lxc/lxc.conf
lxc-config lxc.lxcpath
```

Expected: `/data/lxc`

---

### Task 3: Configure LXC Default Container Settings

**Files:**
- Modify: `/etc/lxc/default.conf`

- [ ] **Step 1: Configure default container settings**

```bash
cat > /etc/lxc/default.conf << 'EOF'
# Default container configuration
lxc.net.0.type = veth
lxc.net.0.link = br-lxc
lxc.net.0.flags = up

# Unprivileged container mappings
lxc.idmap = u 0 100000 65536
lxc.idmap = g 0 100000 65536

# AppArmor (Debian default)
lxc.apparmor.profile = generated
lxc.apparmor.allow_nesting = 1
EOF
```

- [ ] **Step 2: Configure subuid/subgid for root**

```bash
grep -q "^root:" /etc/subuid || echo "root:100000:65536" >> /etc/subuid
grep -q "^root:" /etc/subgid || echo "root:100000:65536" >> /etc/subgid
```

- [ ] **Step 3: Verify mappings**

```bash
cat /etc/subuid
cat /etc/subgid
```

Expected: Both contain `root:100000:65536`

---

### Task 4: Create LXC Network Bridge

**Files:**
- Create: `/etc/netplan/10-lxc-bridge.yaml`

- [ ] **Step 1: Create LXC bridge netplan**

```bash
cat > /etc/netplan/10-lxc-bridge.yaml << 'EOF'
# LXC container network bridge
network:
  version: 2
  bridges:
    br-lxc:
      addresses:
        - 10.100.0.1/24
      mtu: 1500
      parameters:
        stp: false
        forward-delay: 0
EOF
```

- [ ] **Step 2: Apply netplan**

```bash
netplan apply
```

- [ ] **Step 3: Verify bridge exists**

```bash
ip addr show br-lxc
```

Expected: Shows `10.100.0.1/24` address

- [ ] **Step 4: Enable IP forwarding for containers**

```bash
grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p
```

---

### Task 5: Prepare Gateway Netplan (for Cutover)

**Files:**
- Create: `/etc/netplan/01-secubox-gateway.yaml.ready`

- [ ] **Step 1: Create gateway netplan (not applied yet)**

```bash
cat > /etc/netplan/01-secubox-gateway.yaml.ready << 'EOF'
# SecuBox Gateway Configuration
# Applied during cutover - target becomes 192.168.255.1
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: true
      dhcp4-overrides:
        use-dns: false
        use-routes: true
    eth2:
      dhcp4: true
      optional: true
      dhcp4-overrides:
        use-dns: false
    lan0:
      optional: true
    lan1:
      optional: true
    lan2:
      optional: true
    lan3:
      optional: true
  bridges:
    br-lan:
      interfaces: [lan0, lan1, lan2, lan3]
      addresses:
        - 192.168.255.1/24
      mtu: 1500
      parameters:
        stp: false
        forward-delay: 0
    br-lxc:
      addresses:
        - 10.100.0.1/24
      mtu: 1500
      parameters:
        stp: false
        forward-delay: 0
EOF
```

- [ ] **Step 2: Verify file created**

```bash
ls -la /etc/netplan/01-secubox-gateway.yaml.ready
```

Note: This file will be renamed to `.yaml` during cutover.

---

### Task 6: Prepare nftables Rules

**Files:**
- Create: `/etc/nftables.conf.gateway`

- [ ] **Step 1: Create gateway nftables ruleset**

```bash
cat > /etc/nftables.conf.gateway << 'EOF'
#!/usr/sbin/nft -f
# SecuBox Gateway Firewall Rules
# Applied during cutover

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow established/related
        ct state established,related accept

        # Allow loopback
        iif lo accept

        # Allow ICMP
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        # Allow SSH from LAN
        iifname "br-lan" tcp dport 22 accept

        # Allow DHCP/DNS from LAN
        iifname "br-lan" udp dport { 53, 67, 68 } accept
        iifname "br-lan" tcp dport 53 accept

        # Allow HTTP/HTTPS (HAProxy)
        tcp dport { 80, 443 } accept

        # Allow mail ports
        tcp dport { 25, 465, 587, 993, 995 } accept

        # Allow Matrix federation
        tcp dport 8448 accept

        # Allow from LXC bridge
        iifname "br-lxc" accept

        # Log dropped packets (optional, comment for production)
        # log prefix "[SECUBOX-DROP] " counter drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;

        # Allow established/related
        ct state established,related accept

        # Allow LAN to WAN
        iifname "br-lan" oifname { "eth0", "eth2" } accept

        # Allow LXC to WAN
        iifname "br-lxc" oifname { "eth0", "eth2" } accept

        # Allow LAN to LXC
        iifname "br-lan" oifname "br-lxc" accept

        # Allow DNAT traffic
        ct status dnat accept
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}

table inet nat {
    chain prerouting {
        type nat hook prerouting priority -100;

        # Mail ports -> mail LXC
        tcp dport { 25, 465, 587, 993, 995 } dnat to 10.100.0.10

        # Gitea SSH -> gitea LXC
        tcp dport 2222 dnat to 10.100.0.40:22
    }

    chain postrouting {
        type nat hook postrouting priority 100;

        # Masquerade outbound traffic
        oifname { "eth0", "eth2" } masquerade

        # Masquerade LXC to LAN
        iifname "br-lxc" oifname "br-lan" masquerade
    }
}
EOF
```

- [ ] **Step 2: Verify syntax**

```bash
nft -c -f /etc/nftables.conf.gateway
```

Expected: No output (syntax OK)

---

### Task 7: Commit Phase 1 Configuration

- [ ] **Step 1: Create a backup of all configs**

```bash
mkdir -p /data/backups/phase1-config
cp /etc/lxc/lxc.conf /data/backups/phase1-config/
cp /etc/lxc/default.conf /data/backups/phase1-config/
cp /etc/netplan/10-lxc-bridge.yaml /data/backups/phase1-config/
cp /etc/netplan/01-secubox-gateway.yaml.ready /data/backups/phase1-config/
cp /etc/nftables.conf.gateway /data/backups/phase1-config/
```

- [ ] **Step 2: Verify LXC is ready**

```bash
lxc-checkconfig | grep -E "enabled|missing"
```

Expected: All critical features "enabled"

---

## Phase 2: Build

### Task 8: Create Mail LXC Container

**Files:**
- Create: `/data/lxc/mail/config`
- Create: `/data/lxc/mail/rootfs/` (via lxc-create)

- [ ] **Step 1: Create Debian container**

```bash
lxc-create -n mail -t download -- -d debian -r bookworm -a arm64
```

Expected: Container created in `/data/lxc/mail/`

- [ ] **Step 2: Configure container**

```bash
cat > /data/lxc/mail/config << 'EOF'
# Mail container configuration
lxc.include = /usr/share/lxc/config/debian.common.conf

lxc.arch = linux64
lxc.rootfs.path = dir:/data/lxc/mail/rootfs
lxc.uts.name = mail

# Network
lxc.net.0.type = veth
lxc.net.0.link = br-lxc
lxc.net.0.flags = up
lxc.net.0.ipv4.address = 10.100.0.10/24
lxc.net.0.ipv4.gateway = 10.100.0.1
lxc.net.0.name = eth0

# Unprivileged mappings
lxc.idmap = u 0 100000 65536
lxc.idmap = g 0 100000 65536

# Bind mounts for persistent data
lxc.mount.entry = /data/volumes/mail/vmail var/vmail none bind,create=dir 0 0
lxc.mount.entry = /data/volumes/mail/config etc/mail-config none bind,create=dir 0 0
lxc.mount.entry = /data/volumes/mail/ssl etc/ssl/mail none bind,create=dir 0 0

# Resource limits
lxc.cgroup2.memory.max = 1G
lxc.cgroup2.cpu.max = 100000 100000

# Start settings
lxc.start.auto = 1
lxc.start.delay = 5
EOF
```

- [ ] **Step 3: Start container**

```bash
lxc-start -n mail
sleep 5
lxc-ls -f
```

Expected: mail container RUNNING with IP 10.100.0.10

- [ ] **Step 4: Install mail packages**

```bash
lxc-attach -n mail -- bash << 'EOF'
apt-get update
apt-get install -y postfix dovecot-imapd dovecot-pop3d dovecot-lmtpd \
    opendkim opendkim-tools spamassassin procmail
EOF
```

- [ ] **Step 5: Verify network connectivity**

```bash
lxc-attach -n mail -- ping -c 3 8.8.8.8
```

Expected: Ping successful

---

### Task 9: Create NextCloud LXC Container

**Files:**
- Create: `/data/lxc/nextcloud/config`

- [ ] **Step 1: Create Debian container**

```bash
lxc-create -n nextcloud -t download -- -d debian -r bookworm -a arm64
```

- [ ] **Step 2: Configure container**

```bash
cat > /data/lxc/nextcloud/config << 'EOF'
# NextCloud container configuration
lxc.include = /usr/share/lxc/config/debian.common.conf

lxc.arch = linux64
lxc.rootfs.path = dir:/data/lxc/nextcloud/rootfs
lxc.uts.name = nextcloud

# Network
lxc.net.0.type = veth
lxc.net.0.link = br-lxc
lxc.net.0.flags = up
lxc.net.0.ipv4.address = 10.100.0.20/24
lxc.net.0.ipv4.gateway = 10.100.0.1
lxc.net.0.name = eth0

# Unprivileged mappings
lxc.idmap = u 0 100000 65536
lxc.idmap = g 0 100000 65536

# Bind mounts
lxc.mount.entry = /data/volumes/nextcloud/data var/www/nextcloud/data none bind,create=dir 0 0
lxc.mount.entry = /data/volumes/nextcloud/config var/www/nextcloud/config none bind,create=dir 0 0
lxc.mount.entry = /data/volumes/nextcloud/db var/lib/mysql none bind,create=dir 0 0

# Resource limits
lxc.cgroup2.memory.max = 2G
lxc.cgroup2.cpu.max = 200000 100000

# Start settings
lxc.start.auto = 1
lxc.start.delay = 10
EOF
```

- [ ] **Step 3: Start container**

```bash
lxc-start -n nextcloud
sleep 5
lxc-ls -f
```

- [ ] **Step 4: Install NextCloud packages**

```bash
lxc-attach -n nextcloud -- bash << 'EOF'
apt-get update
apt-get install -y apache2 libapache2-mod-php php-gd php-json php-mysql \
    php-curl php-mbstring php-intl php-imagick php-xml php-zip php-apcu \
    php-redis redis-server mariadb-server unzip wget
a2enmod rewrite headers env dir mime ssl
systemctl enable apache2 mariadb redis-server
EOF
```

- [ ] **Step 5: Verify container**

```bash
lxc-attach -n nextcloud -- systemctl status apache2
```

---

### Task 10: Create Matrix LXC Container

**Files:**
- Create: `/data/lxc/matrix/config`

- [ ] **Step 1: Create Debian container**

```bash
lxc-create -n matrix -t download -- -d debian -r bookworm -a arm64
```

- [ ] **Step 2: Configure container**

```bash
cat > /data/lxc/matrix/config << 'EOF'
# Matrix Synapse container configuration
lxc.include = /usr/share/lxc/config/debian.common.conf

lxc.arch = linux64
lxc.rootfs.path = dir:/data/lxc/matrix/rootfs
lxc.uts.name = matrix

# Network
lxc.net.0.type = veth
lxc.net.0.link = br-lxc
lxc.net.0.flags = up
lxc.net.0.ipv4.address = 10.100.0.30/24
lxc.net.0.ipv4.gateway = 10.100.0.1
lxc.net.0.name = eth0

# Unprivileged mappings
lxc.idmap = u 0 100000 65536
lxc.idmap = g 0 100000 65536

# Bind mounts
lxc.mount.entry = /data/volumes/matrix/data var/lib/matrix-synapse none bind,create=dir 0 0
lxc.mount.entry = /data/volumes/matrix/db var/lib/postgresql none bind,create=dir 0 0

# Resource limits
lxc.cgroup2.memory.max = 2G
lxc.cgroup2.cpu.max = 200000 100000

# Start settings
lxc.start.auto = 1
lxc.start.delay = 15
EOF
```

- [ ] **Step 3: Start container**

```bash
lxc-start -n matrix
sleep 5
lxc-ls -f
```

- [ ] **Step 4: Install Matrix packages**

```bash
lxc-attach -n matrix -- bash << 'EOF'
apt-get update
apt-get install -y matrix-synapse postgresql postgresql-contrib
systemctl enable matrix-synapse postgresql
EOF
```

---

### Task 11: Create Gitea LXC Container

**Files:**
- Create: `/data/lxc/gitea/config`

- [ ] **Step 1: Create Debian container**

```bash
lxc-create -n gitea -t download -- -d debian -r bookworm -a arm64
```

- [ ] **Step 2: Configure container**

```bash
cat > /data/lxc/gitea/config << 'EOF'
# Gitea container configuration
lxc.include = /usr/share/lxc/config/debian.common.conf

lxc.arch = linux64
lxc.rootfs.path = dir:/data/lxc/gitea/rootfs
lxc.uts.name = gitea

# Network
lxc.net.0.type = veth
lxc.net.0.link = br-lxc
lxc.net.0.flags = up
lxc.net.0.ipv4.address = 10.100.0.40/24
lxc.net.0.ipv4.gateway = 10.100.0.1
lxc.net.0.name = eth0

# Unprivileged mappings
lxc.idmap = u 0 100000 65536
lxc.idmap = g 0 100000 65536

# Bind mounts
lxc.mount.entry = /data/volumes/gitea/repos var/lib/gitea/repositories none bind,create=dir 0 0
lxc.mount.entry = /data/volumes/gitea/data var/lib/gitea none bind,create=dir 0 0

# Resource limits
lxc.cgroup2.memory.max = 1G
lxc.cgroup2.cpu.max = 100000 100000

# Start settings
lxc.start.auto = 1
lxc.start.delay = 20
EOF
```

- [ ] **Step 3: Start container**

```bash
lxc-start -n gitea
sleep 5
lxc-ls -f
```

- [ ] **Step 4: Install Gitea**

```bash
lxc-attach -n gitea -- bash << 'EOF'
apt-get update
apt-get install -y git sqlite3 wget

# Download Gitea ARM64
GITEA_VERSION="1.21.5"
wget -O /usr/local/bin/gitea \
    "https://dl.gitea.io/gitea/${GITEA_VERSION}/gitea-${GITEA_VERSION}-linux-arm64"
chmod +x /usr/local/bin/gitea

# Create gitea user
useradd --system --shell /bin/bash --create-home --home-dir /var/lib/gitea gitea

# Create directories
mkdir -p /var/lib/gitea/{custom,data,log,repositories}
chown -R gitea:gitea /var/lib/gitea

# Create systemd service
cat > /etc/systemd/system/gitea.service << 'UNIT'
[Unit]
Description=Gitea
After=network.target

[Service]
User=gitea
Group=gitea
WorkingDirectory=/var/lib/gitea
ExecStart=/usr/local/bin/gitea web --config /var/lib/gitea/custom/conf/app.ini
Restart=always
Environment=USER=gitea HOME=/var/lib/gitea

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable gitea
EOF
```

---

### Task 12: Verify All Containers Running

- [ ] **Step 1: List all containers**

```bash
lxc-ls -f
```

Expected:
```
NAME       STATE   AUTOSTART GROUPS IPV4         IPV6 UNPRIVILEGED
gitea      RUNNING 1         -      10.100.0.40  -    true
mail       RUNNING 1         -      10.100.0.10  -    true
matrix     RUNNING 1         -      10.100.0.30  -    true
nextcloud  RUNNING 1         -      10.100.0.20  -    true
```

- [ ] **Step 2: Test connectivity from host**

```bash
ping -c 2 10.100.0.10
ping -c 2 10.100.0.20
ping -c 2 10.100.0.30
ping -c 2 10.100.0.40
```

Expected: All respond

---

## Phase 3: Sync

### Task 13: Sync SSL Certificates

**Files:**
- Sync: Source `/opt/haproxy/certs/` → Target `/data/haproxy/certs/`

- [ ] **Step 1: Sync certificates from source**

```bash
rsync -avz --progress \
    root@192.168.255.1:/opt/haproxy/certs/*.pem \
    /data/haproxy/certs/
```

- [ ] **Step 2: Verify certificate count**

```bash
ls /data/haproxy/certs/*.pem | wc -l
```

Expected: 94 (or close to it)

- [ ] **Step 3: Test a certificate**

```bash
openssl x509 -in /data/haproxy/certs/*.gk2.secubox.in.pem -noout -subject -dates | head -5
```

Expected: Shows valid certificate info

---

### Task 14: Configure HAProxy

**Files:**
- Create: `/etc/haproxy/haproxy.cfg`

- [ ] **Step 1: Get domain list from source**

```bash
ssh root@192.168.255.1 "cat /opt/haproxy/certs/certs.list" > /tmp/domains.txt
cat /tmp/domains.txt | head -20
```

- [ ] **Step 2: Create HAProxy config**

```bash
cat > /etc/haproxy/haproxy.cfg << 'EOF'
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

    # SSL settings
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11
    tune.ssl.default-dh-param 2048

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    option  forwardfor
    timeout connect 5000
    timeout client  50000
    timeout server  50000
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http

frontend http_front
    bind *:80
    mode http
    redirect scheme https code 301 if !{ ssl_fc }

frontend https_front
    bind *:443 ssl crt /data/haproxy/certs/ alpn h2,http/1.1
    mode http

    # ACLs for routing
    acl host_nextcloud hdr(host) -i nextcloud.gk2.secubox.in
    acl host_gitea hdr(host) -i gitea.gk2.secubox.in git.gk2.secubox.in
    acl host_matrix hdr(host) -i matrix.gk2.secubox.in
    acl host_element hdr(host) -i element.gk2.secubox.in chat.gk2.secubox.in

    # Route to backends
    use_backend nextcloud if host_nextcloud
    use_backend gitea if host_gitea
    use_backend matrix if host_matrix
    use_backend matrix if host_element

    # Default to SecuBox dashboard
    default_backend secubox

# Matrix federation port
frontend matrix_federation
    bind *:8448 ssl crt /data/haproxy/certs/
    mode http
    default_backend matrix_federation_back

backend secubox
    mode http
    server local 127.0.0.1:443 ssl verify none

backend nextcloud
    mode http
    server nextcloud 10.100.0.20:80 check

backend gitea
    mode http
    server gitea 10.100.0.40:3000 check

backend matrix
    mode http
    server matrix 10.100.0.30:8008 check

backend matrix_federation_back
    mode http
    server matrix 10.100.0.30:8008 check
EOF
```

- [ ] **Step 3: Test HAProxy config**

```bash
haproxy -c -f /etc/haproxy/haproxy.cfg
```

Expected: "Configuration file is valid"

- [ ] **Step 4: Reload HAProxy**

```bash
systemctl reload haproxy
systemctl status haproxy
```

---

### Task 15: Sync CrowdSec Data

**Files:**
- Sync: Source `/srv/crowdsec/` → Target `/data/crowdsec/`

- [ ] **Step 1: Stop CrowdSec on target**

```bash
systemctl stop crowdsec
```

- [ ] **Step 2: Sync data from source**

```bash
rsync -avz --progress \
    root@192.168.255.1:/srv/crowdsec/ \
    /data/crowdsec/
```

- [ ] **Step 3: Update CrowdSec config paths**

```bash
# Backup original config
cp /etc/crowdsec/config.yaml /etc/crowdsec/config.yaml.bak

# Update data directory if needed
sed -i 's|/var/lib/crowdsec|/data/crowdsec|g' /etc/crowdsec/config.yaml
```

- [ ] **Step 4: Restart CrowdSec**

```bash
systemctl start crowdsec
systemctl status crowdsec
cscli decisions list | head -10
```

---

### Task 16: Sync Gitea Data

**Files:**
- Sync: Source `/srv/gitea/` → Target `/data/volumes/gitea/`

- [ ] **Step 1: Stop Gitea in container**

```bash
lxc-attach -n gitea -- systemctl stop gitea
```

- [ ] **Step 2: Sync repositories**

```bash
rsync -avz --progress \
    root@192.168.255.1:/srv/gitea/git/repositories/ \
    /data/volumes/gitea/repos/
```

- [ ] **Step 3: Sync Gitea data**

```bash
rsync -avz --progress \
    root@192.168.255.1:/srv/gitea/gitea/ \
    /data/volumes/gitea/data/
```

- [ ] **Step 4: Fix permissions**

```bash
chown -R 100000:100000 /data/volumes/gitea/
```

- [ ] **Step 5: Start Gitea**

```bash
lxc-attach -n gitea -- systemctl start gitea
lxc-attach -n gitea -- systemctl status gitea
```

---

### Task 17: Sync NextCloud Data

**Files:**
- Sync: Source `/srv/nextcloud/` → Target `/data/volumes/nextcloud/`

- [ ] **Step 1: Stop services in container**

```bash
lxc-attach -n nextcloud -- systemctl stop apache2
```

- [ ] **Step 2: Dump database on source**

```bash
ssh root@192.168.255.1 "docker exec nextcloud-db mysqldump -u nextcloud -p'password' nextcloud" > /tmp/nextcloud.sql
```

Note: Adjust credentials as needed from source config.

- [ ] **Step 3: Sync data files**

```bash
rsync -avz --progress --exclude='*.log' \
    root@192.168.255.1:/srv/nextcloud/html/data/ \
    /data/volumes/nextcloud/data/
```

- [ ] **Step 4: Sync config**

```bash
rsync -avz \
    root@192.168.255.1:/srv/nextcloud/html/config/ \
    /data/volumes/nextcloud/config/
```

- [ ] **Step 5: Import database**

```bash
lxc-attach -n nextcloud -- mysql -u root nextcloud < /tmp/nextcloud.sql
```

- [ ] **Step 6: Update config.php**

```bash
lxc-attach -n nextcloud -- bash << 'EOF'
cd /var/www/nextcloud/config
# Update trusted domains
php -r "
\$config = include 'config.php';
\$config['trusted_domains'] = ['nextcloud.gk2.secubox.in', '10.100.0.20'];
\$config['overwrite.cli.url'] = 'https://nextcloud.gk2.secubox.in';
file_put_contents('config.php', '<?php return ' . var_export(\$config, true) . ';');
"
EOF
```

- [ ] **Step 7: Fix permissions and start**

```bash
chown -R 100000:100000 /data/volumes/nextcloud/
lxc-attach -n nextcloud -- chown -R www-data:www-data /var/www/nextcloud/data
lxc-attach -n nextcloud -- systemctl start apache2
```

---

### Task 18: Sync Matrix Data

**Files:**
- Sync: Source `/srv/matrix/` → Target `/data/volumes/matrix/`

- [ ] **Step 1: Stop Matrix in container**

```bash
lxc-attach -n matrix -- systemctl stop matrix-synapse
```

- [ ] **Step 2: Dump database on source**

```bash
ssh root@192.168.255.1 "docker exec matrix-db pg_dump -U synapse synapse" > /tmp/matrix.sql
```

- [ ] **Step 3: Sync Synapse data**

```bash
rsync -avz --progress \
    root@192.168.255.1:/srv/matrix/synapse/ \
    /data/volumes/matrix/data/
```

- [ ] **Step 4: Import database**

```bash
lxc-attach -n matrix -- bash << 'EOF'
sudo -u postgres createdb synapse 2>/dev/null || true
sudo -u postgres createuser synapse 2>/dev/null || true
sudo -u postgres psql synapse < /tmp/matrix.sql
EOF
```

- [ ] **Step 5: Fix permissions and start**

```bash
chown -R 100000:100000 /data/volumes/matrix/
lxc-attach -n matrix -- systemctl start matrix-synapse
```

---

### Task 19: Sync Mail Data

**Files:**
- Sync: Source `/srv/mailserver/` → Target `/data/volumes/mail/`

- [ ] **Step 1: Stop mail services in container**

```bash
lxc-attach -n mail -- systemctl stop postfix dovecot
```

- [ ] **Step 2: Sync mailboxes (CRITICAL)**

```bash
rsync -avz --progress \
    root@192.168.255.1:/srv/mailserver/mail-data/ \
    /data/volumes/mail/vmail/
```

- [ ] **Step 3: Sync mail config**

```bash
rsync -avz \
    root@192.168.255.1:/srv/mailserver/mail-state/ \
    /data/volumes/mail/config/
```

- [ ] **Step 4: Sync mail SSL**

```bash
rsync -avz \
    root@192.168.255.1:/srv/mailserver/ssl/ \
    /data/volumes/mail/ssl/
```

- [ ] **Step 5: Fix permissions**

```bash
chown -R 100000:100000 /data/volumes/mail/
```

- [ ] **Step 6: Configure Postfix/Dovecot paths**

```bash
lxc-attach -n mail -- bash << 'EOF'
# Link config from bind mount
ln -sf /etc/mail-config/postfix/* /etc/postfix/
ln -sf /etc/mail-config/dovecot/* /etc/dovecot/

# Start services
systemctl start postfix dovecot
systemctl status postfix dovecot
EOF
```

---

## Phase 4: Cutover

### Task 20: Pre-Cutover Verification

- [ ] **Step 1: Verify all containers running**

```bash
lxc-ls -f
```

Expected: All 4 containers RUNNING

- [ ] **Step 2: Verify HAProxy**

```bash
haproxy -c -f /etc/haproxy/haproxy.cfg
systemctl status haproxy
```

- [ ] **Step 3: Verify CrowdSec**

```bash
systemctl status crowdsec
cscli bouncers list
```

- [ ] **Step 4: Verify nftables ready**

```bash
nft -c -f /etc/nftables.conf.gateway
```

- [ ] **Step 5: Verify netplan ready**

```bash
ls -la /etc/netplan/01-secubox-gateway.yaml.ready
```

- [ ] **Step 6: Test services via /etc/hosts override**

On local machine, add to /etc/hosts:
```
192.168.255.10 nextcloud.gk2.secubox.in gitea.gk2.secubox.in matrix.gk2.secubox.in
```

Test each URL in browser.

---

### Task 21: Final Data Sync

- [ ] **Step 1: Stop services on source (minimize writes)**

```bash
ssh root@192.168.255.1 << 'EOF'
/etc/init.d/haproxy stop
# Note: Don't stop all services yet, just reduce writes
EOF
```

- [ ] **Step 2: Final rsync for all data**

```bash
# Mail
rsync -avz --delete \
    root@192.168.255.1:/srv/mailserver/mail-data/ \
    /data/volumes/mail/vmail/

# NextCloud
rsync -avz --delete \
    root@192.168.255.1:/srv/nextcloud/html/data/ \
    /data/volumes/nextcloud/data/

# Matrix
rsync -avz --delete \
    root@192.168.255.1:/srv/matrix/synapse/ \
    /data/volumes/matrix/data/

# Gitea
rsync -avz --delete \
    root@192.168.255.1:/srv/gitea/git/repositories/ \
    /data/volumes/gitea/repos/
```

- [ ] **Step 3: Final database dumps and import**

```bash
# NextCloud
ssh root@192.168.255.1 "docker exec nextcloud-db mysqldump nextcloud" > /tmp/nc-final.sql
lxc-attach -n nextcloud -- mysql -u root nextcloud < /tmp/nc-final.sql

# Matrix
ssh root@192.168.255.1 "docker exec matrix-db pg_dump -U synapse synapse" > /tmp/matrix-final.sql
lxc-attach -n matrix -- sudo -u postgres psql synapse < /tmp/matrix-final.sql
```

---

### Task 22: Execute Network Cutover

- [ ] **Step 1: Stop all source services**

```bash
ssh root@192.168.255.1 << 'EOF'
/etc/init.d/haproxy stop
/etc/init.d/postfix stop
/etc/init.d/dovecot stop
/etc/init.d/nginx stop
# Stop other services as needed
EOF
```

- [ ] **Step 2: Physical cable swap**

```
MANUAL ACTION:
1. Unplug WAN cable from source (192.168.255.1)
2. Plug WAN cable into target (192.168.255.10)
```

- [ ] **Step 3: Apply gateway netplan**

```bash
# On target
cp /etc/netplan/01-secubox-gateway.yaml.ready /etc/netplan/01-secubox-gateway.yaml

# Remove the old .10 config if exists
rm -f /etc/netplan/00-installer-config.yaml 2>/dev/null

# Apply
netplan apply
```

- [ ] **Step 4: Verify network**

```bash
# Check WAN got DHCP IP
ip addr show eth0

# Check LAN is .1
ip addr show br-lan
```

- [ ] **Step 5: Apply nftables**

```bash
cp /etc/nftables.conf.gateway /etc/nftables.conf
systemctl restart nftables
nft list ruleset | head -30
```

---

### Task 23: Start All Services

- [ ] **Step 1: Restart LXC containers**

```bash
lxc-stop -n mail && lxc-start -n mail
lxc-stop -n nextcloud && lxc-start -n nextcloud
lxc-stop -n matrix && lxc-start -n matrix
lxc-stop -n gitea && lxc-start -n gitea
sleep 10
lxc-ls -f
```

- [ ] **Step 2: Restart HAProxy**

```bash
systemctl restart haproxy
systemctl status haproxy
```

- [ ] **Step 3: Verify CrowdSec**

```bash
systemctl status crowdsec
```

- [ ] **Step 4: Restart dnsmasq for DHCP**

```bash
systemctl restart dnsmasq
systemctl status dnsmasq
```

---

### Task 24: Verify All Services

- [ ] **Step 1: Test from external network (4G/phone)**

```
MANUAL TESTS:
- [ ] Mail: Send email TO hosted address, verify delivery
- [ ] Mail: Send email FROM hosted address, verify delivery
- [ ] NextCloud: Login, upload file, download file
- [ ] Matrix: Login to Element, send message
- [ ] Gitea: Clone repo via HTTPS
- [ ] Gitea: Clone repo via SSH (port 2222)
- [ ] All HTTPS domains load with valid SSL
```

- [ ] **Step 2: Check container logs**

```bash
lxc-attach -n mail -- journalctl -u postfix -n 20
lxc-attach -n nextcloud -- journalctl -u apache2 -n 20
lxc-attach -n matrix -- journalctl -u matrix-synapse -n 20
lxc-attach -n gitea -- journalctl -u gitea -n 20
```

- [ ] **Step 3: Check HAProxy stats**

```bash
echo "show stat" | socat /run/haproxy/admin.sock stdio | cut -d, -f1,2,18 | head -20
```

---

### Task 25: Post-Cutover - Mount MUSIC Drive

- [ ] **Step 1: Shutdown for drive install**

```bash
shutdown -h now
```

```
MANUAL ACTION:
1. Power off target
2. Connect MUSIC drive (previously on source)
3. Power on target
```

- [ ] **Step 2: Find drive**

```bash
lsblk
blkid | grep -v mmcblk
```

- [ ] **Step 3: Mount drive**

```bash
# Replace sdX1 with actual device
mount /dev/sdX1 /data/music

# Verify
ls /data/music | head -10
df -h /data/music
```

- [ ] **Step 4: Add to fstab**

```bash
# Get UUID
UUID=$(blkid -s UUID -o value /dev/sdX1)
echo "UUID=${UUID} /data/music ext4 defaults 0 2" >> /etc/fstab

# Test fstab
mount -a
```

---

### Task 26: Final Verification & Cleanup

- [ ] **Step 1: Verify all services after reboot**

```bash
reboot
# Wait for reboot
ssh root@192.168.255.1  # Now target is .1
```

```bash
lxc-ls -f
systemctl status haproxy crowdsec nftables dnsmasq
```

- [ ] **Step 2: Remove /etc/hosts overrides**

On local machine, remove test entries from /etc/hosts.

- [ ] **Step 3: Monitor for 24h**

```bash
# Watch logs
journalctl -f -u haproxy -u crowdsec

# Check mail queue
lxc-attach -n mail -- postqueue -p
```

- [ ] **Step 4: Keep source available for 1 week**

Don't decommission source yet. Keep it available for rollback if issues found.

---

## Rollback Procedure

If critical issues occur at any point:

```bash
# 1. Unplug WAN from target
# 2. Plug WAN back into source

# 3. Start source services
ssh root@192.168.255.1 << 'EOF'
/etc/init.d/haproxy start
/etc/init.d/postfix start
/etc/init.d/dovecot start
/etc/init.d/nginx start
EOF

# 4. Debug target
# 5. Re-attempt cutover when fixed
```

---

## Summary Checklist

### Phase 1: Prepare
- [ ] Task 1: Directory structure
- [ ] Task 2: LXC storage path
- [ ] Task 3: LXC default config
- [ ] Task 4: LXC network bridge
- [ ] Task 5: Gateway netplan (ready)
- [ ] Task 6: nftables rules (ready)
- [ ] Task 7: Commit Phase 1

### Phase 2: Build
- [ ] Task 8: Mail LXC container
- [ ] Task 9: NextCloud LXC container
- [ ] Task 10: Matrix LXC container
- [ ] Task 11: Gitea LXC container
- [ ] Task 12: Verify all containers

### Phase 3: Sync
- [ ] Task 13: SSL certificates
- [ ] Task 14: HAProxy config
- [ ] Task 15: CrowdSec data
- [ ] Task 16: Gitea data
- [ ] Task 17: NextCloud data
- [ ] Task 18: Matrix data
- [ ] Task 19: Mail data

### Phase 4: Cutover
- [ ] Task 20: Pre-cutover verification
- [ ] Task 21: Final data sync
- [ ] Task 22: Network cutover
- [ ] Task 23: Start services
- [ ] Task 24: Verify services
- [ ] Task 25: Mount MUSIC drive
- [ ] Task 26: Final verification
