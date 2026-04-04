# secubox-ksm

Kernel Same-page Merging (KSM) management module for SecuBox.

## Overview

KSM is a Linux kernel feature that enables memory deduplication by merging identical memory pages across processes. This is particularly useful for:

- **Virtual Machines**: Multiple VMs running similar operating systems can share common memory pages
- **Containers**: Docker/LXC containers with similar base images benefit from KSM
- **Memory Optimization**: Reduce overall memory footprint on systems running multiple similar workloads

## Features

- **Real-time Status**: View KSM enabled/disabled state
- **Memory Savings**: See how much memory is being saved by deduplication
- **Statistics**: Monitor pages shared, scanning progress, deduplication efficiency
- **Configuration**: Tune KSM parameters (pages to scan, sleep interval)
- **P31 Phosphor Theme**: CRT-style green interface matching SecuBox aesthetic

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Health check |
| `/status` | GET | No | KSM enabled/disabled status |
| `/stats` | GET | No | Detailed statistics |
| `/summary` | GET | No | Dashboard widget summary |
| `/enable` | POST | JWT | Enable KSM |
| `/disable` | POST | JWT | Disable KSM |
| `/config` | GET | JWT | Get configuration |
| `/config` | POST | JWT | Update configuration |

## Statistics Explained

- **pages_shared**: Number of unique memory pages being shared
- **pages_sharing**: Total number of page slots using shared pages
- **pages_unshared**: Pages scanned but not mergeable
- **full_scans**: Number of complete memory scans performed
- **memory_saved**: Actual RAM saved (`(pages_sharing - pages_shared) * 4KB`)

## Configuration Parameters

| Parameter | Default | Range | Description |
|-----------|---------|-------|-------------|
| `pages_to_scan` | 100 | 1-10000 | Pages to scan per iteration |
| `sleep_millisecs` | 20 | 10-1000 | Sleep time between scans (ms) |

### Tuning Guidelines

- **High Activity**: Lower `sleep_millisecs` (10-20ms), higher `pages_to_scan` (500-1000)
- **Low CPU Impact**: Higher `sleep_millisecs` (100-200ms), lower `pages_to_scan` (50-100)
- **Balanced**: Default values work well for most deployments

## System Requirements

- Linux kernel with KSM support (most modern kernels)
- `/sys/kernel/mm/ksm/` must be accessible
- Root access required for enable/disable operations

## Frontend

The web interface is available at `/ksm/` and provides:

- Status card with enable/disable toggle
- Memory savings display with progress bar
- Statistics panel with deduplication metrics
- Configuration form for tuning parameters

## Installation

```bash
apt install secubox-ksm
systemctl enable --now secubox-ksm
```

## Manual KSM Control

```bash
# Check if KSM is enabled
cat /sys/kernel/mm/ksm/run

# Enable KSM manually
echo 1 > /sys/kernel/mm/ksm/run

# View memory saved
cat /sys/kernel/mm/ksm/pages_sharing
cat /sys/kernel/mm/ksm/pages_shared
```

## License

Proprietary - CyberMind SecuBox
ANSSI CSPN certification candidate
