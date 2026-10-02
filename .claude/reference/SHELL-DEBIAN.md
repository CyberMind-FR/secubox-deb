<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.

  Extrait À L'IDENTIQUE de l'ancien CLAUDE.md racine (master 8af868a51), #1863.
  Lu sur demande seulement : AGENTS.md renvoie ici.
-->

## 🐧 Debian Shell Scripting Guidelines

### Différences avec OpenWrt

| Commande | OpenWrt | Debian |
|----------|---------|--------|
| JSON parsing | `jsonfilter` | `jq` |
| Timeout | Non disponible | `timeout` |
| Socket check | `netstat -tln` | `ss -tlnp` |
| Service | `/etc/init.d/X restart` | `systemctl restart X` |
| Logs | `logread` | `journalctl` |
| Config | UCI | TOML + netplan |

### Bonnes pratiques Bash sur Debian

```bash
#!/bin/bash
set -euo pipefail  # Strict mode

# Utiliser jq pour JSON (installé sur Debian)
value=$(jq -r '.field' /path/to/file.json)

# Vérifier port ouvert avec ss
ss -tlnp | grep -q ":8080 " && echo "Port 8080 open"

# Logs avec journalctl
journalctl -u secubox-dpi --since "1 hour ago" --no-pager

# Timeout disponible
timeout 5 curl -s http://localhost:8080/health || echo "Timeout"

# Netplan au lieu de UCI
netplan generate && netplan apply
```

### Detection de processus

```bash
# Sur Debian, pgrep -x fonctionne
pgrep -x ndpid >/dev/null && echo "nDPId running"

# Ou utiliser systemctl
systemctl is-active --quiet secubox-dpi && echo "Active"
```

---

