<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.

  Extrait À L'IDENTIQUE de l'ancien CLAUDE.md racine (master 8af868a51), #1863.
  Lu sur demande seulement : AGENTS.md renvoie ici.
-->

## 🔒 Security Policies — Héritées de secubox-openwrt, adaptées Debian

### WAF Bypass — Interdit par défaut, exception déclarative uniquement

* **Défaut : JAMAIS de bypass** — tout le trafic DOIT passer par `sbxwaf`
  (moteur Go, écoute 127.0.0.1:8085, unité `secubox-waf-ng`) pour inspection.
  Quand tu ajoutes un nouveau vhost, route systématiquement via le backend
  `sbxwaf_inspector` dans HAProxy.
* Si un service nécessite WebSocket ou long-polling, configure d'abord
  `sbxwaf` pour forward correctement — n'atteins le bypass qu'en dernier recours.
* **Seule exception sanctionnée : `waf_bypass = true` déclaratif par-vhost** dans
  `/etc/secubox/haproxy.toml`, honoré par `haproxyctl` (backend `nginx_vhosts`,
  droit vers nginx). Réservé aux services que la chaîne d'inspection casse
  prouvablement — gros uploads / WebDAV / streaming média Range / fédération
  (ex. `nc`, `photoprism`, `matrix`, `torrent`). Opt-in explicite, déclaratif,
  auditable, versionné — **jamais un hand-edit du `haproxy.cfg` généré** (qui
  serait écrasé au prochain `haproxyctl generate`) et jamais un défaut silencieux.
* Après ajout d'un backend HAProxy, mettre à jour la table de routes unique
  `/etc/secubox/waf/haproxy-routes.json` (lue par `sbxwaf --routes`) :
```json
  "domain.example.com": ["127.0.0.1", PORT]
```
* `sbxwaf` recharge les routes à chaud ; au besoin : `systemctl reload secubox-waf-ng`

### sbxwaf Route Configuration (complet)

Quand tu ajoutes un nouveau service qui passe par HAProxy → sbxwaf :

1. Ajouter le vhost HAProxy :
   ```bash
   haproxyctl vhost add <domain>
   ```

2. Le backend sera par défaut `sbxwaf_inspector` (correct)

3. Ajouter la route dans la table unique `sbxwaf` :
   ```bash
   # Éditer /etc/secubox/waf/haproxy-routes.json
   ```
   ```json
   {
     "domain.example.com": ["127.0.0.1", PORT]
   }
   ```

4. `sbxwaf` recharge la table à chaud ; au besoin :
   ```bash
   systemctl reload secubox-waf-ng
   ```

5. Tester :
   ```bash
   curl -k https://domain.example.com/
   journalctl -u secubox-waf-ng -f  # Voir les logs sbxwaf
   ```

---

