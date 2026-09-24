# SecuBox-DEB APT Repository

Configuration files for the SecuBox APT package repository.

## Repository Structure

```
/srv/apt/
├── conf/
│   ├── distributions    # Repository distributions config
│   ├── options          # Global reprepro options
│   └── incoming         # Incoming packages config
├── db/                  # Reprepro database
├── dists/               # Distribution metadata
│   ├── bookworm/        # Stable releases
│   └── bookworm-testing/ # Testing releases
├── pool/                # Package files
│   ├── main/            # Main component
│   └── contrib/         # Contrib component
├── incoming/            # Incoming packages drop
└── tmp/                 # Temporary files
```

## Setup

### Initialize Repository

```bash
# Create directory structure
sudo mkdir -p /srv/apt/{conf,db,dists,pool,incoming,tmp}

# Copy configuration
sudo cp apt/conf/* /srv/apt/conf/

# Set ownership
sudo chown -R $(whoami) /srv/apt

# Initialize
cd /srv/apt
reprepro export
```

### Clé de signature (état réel, #1366)

apt.secubox.in est hébergé **et signé sur gk2** (`/srv/apt → /data/apt`,
servi par `/var/www/apt.secubox.in/dists → /data/apt/dists`).

| | |
|---|---|
| Empreinte | `219B A872 E393 3EAA C348  6A13 44E5 0F01 78E8 BC7E` |
| Identité | SecuBox APT Repository `<apt@secubox.in>`, rsa4096, créée 2026-05-11 |
| Clé privée | **une seule copie** : `/root/.gnupg` sur gk2 (celle de reprepro, `conf/options` sans `gnupghome`) |
| Révocation | `/root/.gnupg/openpgp-revocs.d/219BA872….rev` + copie hors ligne |

- **Ne jamais générer de nouvelle clé** : tous les clients font confiance à
  celle-ci. `31848880…6DB9` (packages@secubox.in, 2026-05-12) est une clé
  de mise en scène jamais publiée ; elle ne signe rien.
- La copie de `/data/secubox-repo/gpg` (lisible par le compte `secubox`) a
  été détruite : l'API `secubox-repo` ne peut plus signer. Signer se fait
  en root, en attendant la session de signature du Coffre (#1367, P2).
- Aucun secret GPG sur GitHub : la CI construit, gk2 signe.

```bash
# Signer après une mise à jour (root sur gk2)
GPG_TTY=$(tty) reprepro -b /srv/apt export bookworm
```

## Usage

### Publishing Packages

```bash
# Publish a single package
./scripts/apt-publish.sh packages/secubox-core/*.deb

# Publish to testing
./scripts/apt-publish.sh -c bookworm-testing packages/*/*.deb

# Skip lintian (not recommended)
./scripts/apt-publish.sh --skip-lintian packages/*/*.deb

# Dry run
./scripts/apt-publish.sh -n packages/*/*.deb
```

### Syncing to Remote

```bash
# Preview sync
./scripts/apt-sync.sh --dry-run

# Full sync
./scripts/apt-sync.sh

# Verbose sync
./scripts/apt-sync.sh --verbose
```

### Manual reprepro Commands

```bash
cd /srv/apt

# Add package
reprepro -C main includedeb bookworm /path/to/package.deb

# Remove package
reprepro remove bookworm package-name

# List packages
reprepro list bookworm

# Check repository
reprepro check
```

## Client Configuration

### Adding Repository

```bash
# Add GPG key
curl -fsSL https://apt.secubox.in/secubox.gpg | sudo gpg --dearmor -o /usr/share/keyrings/secubox.gpg

# Add repository
echo "deb [signed-by=/usr/share/keyrings/secubox.gpg] https://apt.secubox.in bookworm main" | \
    sudo tee /etc/apt/sources.list.d/secubox.list

# Update and install
sudo apt update
sudo apt install secubox-core
```

## Distributions

| Codename | Description | Use Case |
|----------|-------------|----------|
| bookworm | Stable releases | Production |
| bookworm-testing | Testing releases | Pre-release testing |

## Components

| Component | Description |
|-----------|-------------|
| main | Core SecuBox packages |
| contrib | Community contributions |

## Architectures

- `arm64` - Primary target (MOCHAbin, ESPRESSObin, RPi)
- `amd64` - VMs and x64 hardware
- `all` - Architecture-independent packages
