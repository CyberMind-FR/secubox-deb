# SecuBox APT Repository — apt.secubox.in

Configuration et scripts pour le repository APT SecuBox.

## Structure

```
repo/
├── conf/
│   ├── distributions    # Configuration reprepro (bookworm, trixie)
│   └── options          # Options reprepro
├── scripts/
│   ├── generate-gpg-key.sh   # Génération clé GPG
│   ├── repo-manage.sh        # Gestion du repo (add, remove, list, sync)
│   └── setup-repo-server.sh  # Installation serveur complet
├── nginx-apt.secubox.in.conf # Config nginx avec SSL
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

## CI/CD

Le workflow `.github/workflows/publish-packages.yml` :
1. Build les packages pour arm64 et amd64
2. Signe avec GPG
3. Publie sur apt.secubox.in

### Secrets GitHub requis

| Secret | Description |
|--------|-------------|
| `GPG_PRIVATE_KEY` | Clé GPG privée (armor export) |
| `DEPLOY_SSH_KEY` | Clé SSH pour rsync vers le serveur |
| `DEPLOY_KNOWN_HOSTS` | known_hosts du serveur |

### Export de la clé GPG pour CI

```bash
gpg --armor --export-secret-keys packages@secubox.in > gpg-private.key
# Ajouter le contenu dans GitHub Secrets > GPG_PRIVATE_KEY
```

## Packages disponibles

| Package | Description |
|---------|-------------|
| `secubox-full` | Tous les modules (4GB+ RAM) |
| `secubox-lite` | Modules essentiels (1-2GB RAM) |
| `secubox-core` | Bibliothèque partagée |
| `secubox-hub` | Dashboard central |
| `secubox-crowdsec` | Intégration CrowdSec |
| `secubox-netdata` | Monitoring Netdata |
| `secubox-wireguard` | VPN WireGuard |
| `secubox-dpi` | Deep Packet Inspection |
| `secubox-netmodes` | Modes réseau |
| `secubox-nac` | Network Access Control |
| `secubox-auth` | Authentification |
| `secubox-qos` | Quality of Service |
| `secubox-mediaflow` | Media Flow Analysis |
| `secubox-cdn` | CDN Cache |
| `secubox-vhost` | Virtual Hosts |
| `secubox-system` | System Hub |
