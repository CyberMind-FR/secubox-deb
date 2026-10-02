<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.

  Extrait À L'IDENTIQUE de l'ancien CLAUDE.md racine (master 8af868a51), #1863.
  Lu sur demande seulement : AGENTS.md renvoie ici.
-->

## 🔑 Règles impératives

### Réseau / Sécurité
- **JAMAIS** de bypass WAF hand-edité ni de port ouvert inutile (seul le
  `waf_bypass = true` déclaratif du `haproxy.toml` est autorisé — cf. §WAF Bypass)
- nftables DEFAULT DROP — ouvrir explicitement seulement ce qui est nécessaire
- HAProxy en frontal TLS 1.3 pour toute exposition externe
- AppArmor profile enforce pour chaque service

### Pattern FastAPI (RPCD → API)
- Chaque méthode RPCD `luci.<module>/<method>` → `GET /api/v1/<module>/<method>`
- Les méthodes d'action (set_*, apply, ban...) → `POST /api/v1/<module>/<method>`
- Authentification JWT **obligatoire** sur tous les endpoints via `Depends(auth.require_jwt)`
- Socket Unix `/run/secubox/<module>.sock` — jamais de port TCP direct

### Packaging Debian
- Versioning : `1.0.0-1~bookworm1`
- `debian/postinst` : `systemctl enable --now secubox-<module>`
- `debian/prerm` : `systemctl stop secubox-<module>`
- Toujours `debian/compat` = 13, `Standards-Version: 4.6.2`

### Frontend (htdocs conservé)
- **Ne pas modifier** le JS/CSS/HTML des vues LuCI
- Le script `scripts/rewrite-xhr.py` remplace les appels ubus par des appels REST
- URL pattern : `rpc.declare({object: 'luci.X', method: 'Y'})` → `fetch('/api/v1/X/Y')`

### Mise à jour des fichiers de suivi
Après chaque module complété :
- Cocher `✅` dans `.claude/MIGRATION-MAP.md`
- Mettre à jour `.claude/WIP.md` (déplacer vers "Fait", pointer le suivant)
- Appender à `.claude/HISTORY.md` avec la date

---

