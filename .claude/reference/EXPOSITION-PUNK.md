<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.

  Extrait À L'IDENTIQUE de l'ancien CLAUDE.md racine (master 8af868a51), #1863.
  Lu sur demande seulement : AGENTS.md renvoie ici.
-->

## 🚀 Punk Exposure Engine — Directive Architecturale

Héritée de `secubox-openwrt/package/secubox/PUNK-EXPOSURE.md`.
Le modèle trois-verbes **Peek / Poke / Emancipate** s'applique identiquement
sur base Debian — seuls les transports changent.

### Trois canaux d'exposition

| Canal    | OpenWrt              | Debian                          |
|----------|----------------------|---------------------------------|
| Tor      | secubox-app-tor      | tor.service + secubox-exposure  |
| DNS/SSL  | HAProxy + ACME + UCI | HAProxy TLS1.3 + certbot + TOML |
| Mesh     | secubox-p2p (à porter) | secubox-p2p-deb (à porter)    |

### Règles invariantes (Debian = OpenWrt)

* **Join par port, jamais par nom** — cross-référencer scan ↔ Tor/SSL/Mesh
  via le numéro de port backend uniquement
* **Jamais d'auto-exposition de 127.0.0.1** — seuls les services sur
  `0.0.0.0` ou IP LAN spécifique sont éligibles à l'exposition externe
* **Emancipate est multi-canal** — un service peut activer Tor + DNS + Mesh
  dans un seul workflow ; chaque canal est indépendamment toggleable

### CLI Debian (cible)
```bash
# Port depuis OpenWrt — même interface, backend Debian
secubox-exposure emancipate <service> <port> <domain> --all
secubox-exposure emancipate secret 8888 --tor
secubox-exposure revoke myapp --all
```

---

