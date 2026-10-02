<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.

  Extrait À L'IDENTIQUE de l'ancien CLAUDE.md racine (master 8af868a51), #1863.
  Lu sur demande seulement : AGENTS.md renvoie ici.
-->

## 🛠️ Commandes usuelles

```bash
# Build un paquet .deb localement (cross arm64)
cd packages/secubox-dpi
dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b

# Déployer sur le MOCHAbin
bash scripts/deploy.sh secubox-dpi root@192.168.1.1

# Construire l'image complète
bash image/build-image.sh --board mochabin --out /tmp/secubox-deb.img

# Porter le frontend d'un module depuis le repo source
bash scripts/port-frontend.sh dpi-dashboard

# Réécrire les appels XHR d'un module
python3 scripts/rewrite-xhr.py packages/secubox-dpi/www/

# Lancer l'API d'un module en dev local
cd packages/secubox-dpi && uvicorn api.main:app --reload --uds /tmp/dpi.sock
```

---

