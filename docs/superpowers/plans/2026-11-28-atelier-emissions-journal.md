<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
See LICENCE-CMSD-1.0.md for terms.
-->
# Atelier des émissions — journal des décisions (#4058)

## Vague 1

- **Task 4** — Décision : `amorcer` lit les réponses de `GET /rapports/{genre}/{id}` et retient celles dont
  `ia.etat == "fait"` (« ia » aussi accepté) et non `perimee` — parce que gk2 (`rapports.rediger`) écrit
  `etat: "fait"`, jamais `"ia"` comme l'écrit le plan — coût si faux : amorçage vide, à corriger d'un mot.
- **Task 4** — Décision : `statut` gk2 « retenue » devient « verifiee » ; les retirées ne sont jamais stockées ;
  `Magasin` prend un `maintenant` facultatif (tests) — parce que le schéma du plan n'admet que
  `verifiee|hypothese` — coût si faux : nul (paramètre facultatif).
- **Task 4** — Décision : empreinte = sha256 du JSON trié tronqué à 16 caractères, comme `rapports.signature` —
  parce que le plan dit « signature-like » — coût si faux : comparaison d'empreinte avec gk2 à adapter.
