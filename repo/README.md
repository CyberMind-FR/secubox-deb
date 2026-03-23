# SecuBox APT Repository — apt.secubox.in

Configuration and scripts for the SecuBox APT repository.

## Quick Install (for users)

```bash
curl -fsSL https://apt.secubox.in/install.sh | sudo bash
sudo apt install secubox-full
```

## Structure

```
repo/
├── conf/
│   ├── distributions         # reprepro config (bookworm, trixie)
│   └── options               # reprepro options
├── scripts/
│   ├── export-secrets.sh     # Export secrets for GitHub Actions
│   ├── generate-gpg-key.sh   # Generate GPG signing key
│   ├── local-publish.sh      # Local testing server
│   ├── repo-manage.sh        # Repository management (add, remove, sync)
│   └── setup-repo-server.sh  # Full server setup
├── install.sh                # User installation script
├── nginx-apt.secubox.in.conf # nginx config with SSL
└── README.md
```

## Installation côté utilisateur

```bash
# Ajouter la clé GPG
curl -fsSL https://apt.secubox.in/secubox-keyring.gpg | \
  sudo tee /usr/share/keyrings/secubox.gpg > /dev/null

# Ajouter le repository
echo "deb [signed-by=/usr/share/keyrings/secubox.gpg] https://apt.secubox.in bookworm main" | \
  sudo tee /etc/apt/sources.list.d/secubox.list

# Installer
sudo apt update
sudo apt install secubox-full   # ou secubox-lite
```

## Setup serveur

```bash
# Sur le serveur apt.secubox.in
sudo bash repo/scripts/setup-repo-server.sh
```

## Gestion des packages

```bash
# Initialiser le repo local
bash repo/scripts/repo-manage.sh init

# Ajouter des packages
bash repo/scripts/repo-manage.sh add bookworm packages/*.deb

# Lister les packages
bash repo/scripts/repo-manage.sh list bookworm

# Synchroniser vers le serveur
bash repo/scripts/repo-manage.sh sync deploy@apt.secubox.in:/var/www/apt.secubox.in/
```

## Local Testing

Test the repository locally before deploying:

```bash
# Build all packages first
bash scripts/build-all.sh

# Create local repo and serve on port 8888
bash repo/scripts/local-publish.sh --serve

# On VM/target machine
curl -fsSL http://<host-ip>:8888/install-local.sh | bash
sudo apt install secubox-full
```

## CI/CD

The `.github/workflows/publish-packages.yml` workflow:
1. Builds packages for arm64 and amd64
2. Signs with GPG
3. Publishes to apt.secubox.in

### GitHub Secrets Configuration

| Secret | Description |
|--------|-------------|
| `GPG_PRIVATE_KEY` | GPG private key (armored) |
| `DEPLOY_SSH_KEY` | SSH private key for rsync |
| `DEPLOY_KNOWN_HOSTS` | Server known_hosts entry |

### Exporting Secrets

```bash
# Generate GPG key and export all secrets
bash repo/scripts/export-secrets.sh --output ./secrets

# Files created:
#   secrets/GPG_PRIVATE_KEY.txt    → GitHub secret: GPG_PRIVATE_KEY
#   secrets/deploy_key             → GitHub secret: DEPLOY_SSH_KEY
#   secrets/deploy_key.pub         → Add to server authorized_keys
#   secrets/GITHUB_SECRETS_INSTRUCTIONS.md
```

### Server-Side Setup

1. Add deploy public key to server:
```bash
# On apt.secubox.in
cat secrets/deploy_key.pub >> /home/deploy/.ssh/authorized_keys
```

2. Get known_hosts entry:
```bash
ssh-keyscan -H apt.secubox.in
# Copy output to GitHub secret: DEPLOY_KNOWN_HOSTS
```

## Packages disponibles (41 packages)

### Metapackages
| Package | Description |
|---------|-------------|
| `secubox-full` | All 39 modules (4GB+ RAM recommended) |
| `secubox-lite` | Essential modules only (1-2GB RAM) |

### Core Infrastructure
| Package | Description |
|---------|-------------|
| `secubox-core` | Shared Python library |
| `secubox-hub` | Central dashboard |
| `secubox-portal` | Login portal |
| `secubox-system` | System management |

### Security
| Package | Description |
|---------|-------------|
| `secubox-crowdsec` | CrowdSec integration |
| `secubox-waf` | Web Application Firewall (300+ rules) |
| `secubox-mitmproxy` | MITM proxy with WAF inspection |
| `secubox-auth` | Authentication |
| `secubox-nac` | Network Access Control |
| `secubox-hardening` | Kernel and system hardening |

### Networking
| Package | Description |
|---------|-------------|
| `secubox-wireguard` | WireGuard VPN |
| `secubox-netmodes` | Network modes |
| `secubox-dpi` | Deep Packet Inspection |
| `secubox-qos` | Quality of Service |
| `secubox-traffic` | TC/CAKE traffic shaping |
| `secubox-vhost` | Virtual hosts |
| `secubox-haproxy` | HAProxy management |
| `secubox-cdn` | CDN cache |
| `secubox-tor` | Tor circuits and hidden services |
| `secubox-exposure` | Unified exposure (Tor, SSL, DNS, Mesh) |

### Applications
| Package | Description |
|---------|-------------|
| `secubox-mail` | Mail server (Postfix/Dovecot + DKIM + SpamAssassin + ClamAV) |
| `secubox-mail-lxc` | Mail LXC container |
| `secubox-webmail` | Roundcube webmail |
| `secubox-webmail-lxc` | Webmail LXC container |
| `secubox-gitea` | Gitea Git server (LXC) |
| `secubox-nextcloud` | Nextcloud file sync (LXC) |
| `secubox-dns` | DNS/BIND management |
| `secubox-users` | Unified identity (7 services) |

### Publishing
| Package | Description |
|---------|-------------|
| `secubox-droplet` | File publisher |
| `secubox-streamlit` | Streamlit apps |
| `secubox-streamforge` | Streamlit app manager |
| `secubox-metablogizer` | Static site generator |
| `secubox-publish` | Unified publishing |

### Monitoring & Infrastructure
| Package | Description |
|---------|-------------|
| `secubox-netdata` | Netdata integration |
| `secubox-mediaflow` | Media flow analysis |
| `secubox-c3box` | Services portal |
| `secubox-watchdog` | Container/service/endpoint monitoring |
| `secubox-backup` | System and container backups |
| `secubox-repo` | APT repository management |
