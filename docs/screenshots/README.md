<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox UI Module Screenshots

Automated screenshots of all 120+ SecuBox web UI modules for documentation and compliance testing.

## Directory Structure

```
docs/screenshots/
├── vm/                      # Full-size screenshots (1920x1080)
│   ├── hub.png
│   ├── soc.png
│   ├── crowdsec.png
│   └── ...
├── thumbnails/              # Thumbnails (400x225) for wiki
│   ├── hub-thumb.png
│   └── ...
├── capture-manifest.json    # Capture results metadata
└── README.md
```

## Capture Screenshots

### Prerequisites

```bash
# Install dependencies
pip install -r scripts/requirements-screenshot.txt

# Install browser
playwright install chromium
```

### Usage

```bash
# Capture all modules from SecuBox instance
python scripts/capture-screenshots.py --base-url https://192.168.1.200

# Capture specific modules
python scripts/capture-screenshots.py --modules hub,soc,crowdsec

# Generate thumbnails only (from existing screenshots)
python scripts/capture-screenshots.py --thumbnails-only

# Run with visible browser for debugging
python scripts/capture-screenshots.py --headed

# Use custom credentials
SECUBOX_PASSWORD=mypassword python scripts/capture-screenshots.py
```

## Generate Documentation

```bash
# Generate wiki pages with screenshots
python scripts/generate-docs.py --include-screenshots

# Generate for specific language
python scripts/generate-docs.py --include-screenshots --lang fr
```

## Module Count

| Category | Count |
|----------|-------|
| Dashboard | 5 |
| Security | 19 |
| Network | 11 |
| DNS | 6 |
| VPN & Privacy | 9 |
| Monitoring | 8 |
| Access | 3 |
| Services | 3 |
| AI | 6 |
| Email | 4 |
| Media | 7 |
| Publishing | 6 |
| Apps | 3 |
| IoT | 4 |
| Communication | 4 |
| System | 8 |
| **Total** | **106** |

## Captured

- **Date**: 2026-05-09
- **Version**: 1.8.0
- **Source**: QEMU ARM64 / VirtualBox

## Integration

Screenshots are integrated into:
- Package READMEs: `packages/secubox-*/README.md`
- Wiki pages: `docs/wiki/MODULES-*.md`
- GitHub wiki

## License

MIT License - CyberMind © 2024-2026
