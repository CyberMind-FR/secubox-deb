# SecuBox-DEB — Remote UI

Interfaces utilisateur déportées pour SecuBox.

---

## Modules

| Module | Description | Hardware |
|--------|-------------|----------|
| **round/** | Eye Remote Dashboard | HyperPixel 2.1 Round + Pi Zero W |

---

## Round Edition

Dashboard kiosk circulaire 480×480 pour monitoring SecuBox.

### Features

- 6 anneaux de status (AUTH, WALL, BOOT, MIND, ROOT, MESH)
- Transport OTG prioritaire, WiFi fallback
- Mode simulation intégré
- USB gadget composite (ECM + ACM + mass_storage)

### Documentation

Voir [round/README.md](round/README.md) pour la documentation complète.

---

## Build Scripts

| Script | Description |
|--------|-------------|
| `round/build-eye-remote-image.sh` | Build image Pi Zero W |
| `round/build-storage-img.sh` | Build storage ESPRESSObin |
| `round/install_zerow.sh` | Flash et config SD |
| `round/deploy.sh` | Déployer dashboard |

### Pipeline complet

```bash
# Build complet (depuis racine du repo)
sudo bash build-eye-remote-full.sh
```

Cela exécute :
1. Build des packages SecuBox (.deb)
2. Build de storage.img ESPRESSObin
3. Build de l'image Pi Zero W

---

## Architecture

```
remote-ui/
├── round/                      ← Eye Remote Dashboard
│   ├── agent/                  ← Agent multi-SecuBox (v2.0)
│   ├── files/                  ← Fichiers système à installer
│   ├── host-install/           ← Scripts côté host SecuBox
│   ├── scripts/                ← Utilitaires
│   ├── build-eye-remote-image.sh
│   ├── build-storage-img.sh
│   ├── deploy.sh
│   ├── install_zerow.sh
│   ├── CLAUDE.md              ← Instructions Claude Code
│   └── README.md              ← Documentation complète
└── README.md                  ← Ce fichier
```

---

## Planned Modules

| Module | Status | Description |
|--------|--------|-------------|
| `square/` | Planned | Dashboard rectangulaire 800×480 |
| `web/` | Planned | WebUI responsive |
| `console/` | Planned | TUI ncurses |

---

## See Also

- [docs/TOOLS.md](../docs/TOOLS.md) — Référence des outils
- [docs/eye-remote/](docs/eye-remote/) — Documentation Eye Remote

---

## Author

Gerald KERMA <devel@cybermind.fr>
