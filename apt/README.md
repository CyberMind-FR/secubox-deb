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

### GPG Key Setup

```bash
# Generate signing key (if not exists)
gpg --gen-key

# Export public key for clients
gpg --armor --export your@email.com > /srv/apt/secubox.gpg
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
