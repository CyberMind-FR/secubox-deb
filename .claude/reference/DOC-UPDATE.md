<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.

  Extrait À L'IDENTIQUE de l'ancien CLAUDE.md racine (master 8af868a51), #1863.
  Lu sur demande seulement : AGENTS.md renvoie ici.
-->

## 📝 Documentation Update Workflow (identique OpenWrt)

Après chaque modification de code :

1. **`.claude/HISTORY.md`** — ajouter entrée datée
2. **`.claude/WIP.md`** — déplacer "fait", pointer le suivant
3. **`.claude/MIGRATION-MAP.md`** — cocher `✅` si module complété
4. **`packages/<module>/README.md`** — mettre à jour si CLI ou API change

Format de commit :
```
git commit -m "docs: Update tracking files for <feature>"
```

Déclencheurs obligatoires de mise à jour README :
* Nouvel endpoint FastAPI ajouté
* Modèle Pydantic modifié (= contrat API changé)
* Options TOML ajoutées ou renommées
* Dépendance Debian ajoutée dans `debian/control`

---

