<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Comparaison TV — avant / après filtrage DNS

> **POC non validé sur flux Freebox réel.** Ce fichier est le modèle ; il est écrit par `tools/tv-before-after.py rapport` à partir de mesures réelles.
> Il ne contient volontairement aucun chiffre tant que la procédure (`docs/poc-dns-adblock-tv.md` §7) n'a pas été jouée sur une Freebox TV.
> Formulation : **réduction des domaines publicitaires/tracking résolus par DNS** — ce n'est pas une suppression de publicités.

| Phase | Mode | Requêtes DNS | Domaines uniques | Advertising (résolus) | Tracking (résolus) | Bloqués (requêtes) | Domaines bloqués | Erreurs amont |
|---|---|---|---|---|---|---|---|---|
| A | DNS habituel de la Freebox | non mesurable côté box | – | – | – | – | – | – |
| B | OBSERVE | _à mesurer_ | | | | | | |
| C | BLOCK | _à mesurer_ | | | | | | |

## À renseigner par l'opérateur
- Domaines **nécessaires** au fonctionnement du service : …
- Faux positifs constatés : …
- Fonctions cassées en phase C : …
