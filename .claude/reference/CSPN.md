<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.

  Extrait À L'IDENTIQUE de l'ancien CLAUDE.md racine (master 8af868a51), #1863.
  Lu sur demande seulement : AGENTS.md renvoie ici.
-->

## 🛡️ Règles CSPN / Sécurité formelle

*(Critiques pour certification ANSSI)*

* **Double-buffer PARAMETERS** : toute modification de config sensible passe
  par un buffer shadow → validation → swap atomique. Rollback 4R obligatoire
  (Read → Write → Validate → Rollback-or-Commit)
* **Journalisation immuable** : chaque décision de sécurité (ban, unban,
  changement de règle WAF) écrite dans `/var/log/secubox/audit.log`
  (append-only, rotation sans truncate)
* **Séparation de privilèges** : chaque daemon tourne sous `secubox-<module>`
  (user/group dédié créé dans `debian/postinst`), jamais root
* **Secrets hors code** : `/etc/secubox/secrets/` chmod 600, owner
  `secubox-<module>`. Aucun secret dans le code ni dans TOML versionné
* **AppArmor enforce** : profil obligatoire pour chaque service, livré dans
  `debian/` et activé dans `postinst`

---

