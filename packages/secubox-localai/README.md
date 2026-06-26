# 🤖 LocalAI

OpenAI-compatible local API

**Category:** AI

## Screenshot

![LocalAI](../../docs/screenshots/vm/localai.png)

## Features

- OpenAI API
- Multiple models
- Embeddings
- Image generation

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-localai
```

## Configuration

Configuration file: `/etc/secubox/localai.toml`

## API Endpoints

- `GET /api/v1/localai/status` - Module status
- `GET /api/v1/localai/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
