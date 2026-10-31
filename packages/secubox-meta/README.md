<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-meta — l'arbre des métapaquets

`arbre.yaml` est la source unique ; `gen-meta.py` en tire `debian/control`
(`gen-meta.py --check` échoue si le control a divergé). Racines `sbxos` et
`secubox`, puis fonctions (`secubox-fonction-*`), puis services
(`secubox-service-*`), puis les paquets réels. Chaque paquet du dépôt est
rangé une seule fois dans l'arbre, ou listé hors-arbre.

## Maître du parc (#3337)

    apt install secubox-fonction-maitre

pose tout ce qu'un maître de parc porte, en plus de la box elle-même :

| Nœud | Contenu |
|---|---|
| `secubox-service-pilotage` | requiert `secubox-pilotage` (contrôleur, vhosts `admin.<box>`) et `secubox-autoload` (jetons, abonnements par box, droits du maillage) ; recommande `secubox-kiosque` (webapp kiosque distant) |
| `secubox-service-mesh` | `secubox-annuaire` (Flotte, annuaire), `secubox-p2p` (maillage, enrôlement) |
| `secubox-service-administration` | `secubox-profiles`, `secubox-appstore`, `secubox-certs` ; `secubox-repo` (dépôt apt) seulement recommandé |

`secubox` ne fait que le suggérer : une box ordinaire ne le reçoit jamais sans
le demander. L'agent `secubox-pilotage-agent` reste hors-arbre : toute box l'a
déjà, maître compris.
