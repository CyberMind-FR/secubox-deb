<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->
# secubox-kiosque — kiosque distant (PWA)

Webapp tactile servie par le **maître** sous `https://admin.<maître>/kiosque/` (#3330), sur le modèle Squeezebox/Jive : les box ne
servent que leurs API, l'interface tourne ailleurs. Première version : téléphone (PWA installable) et écran 800×480.

- **Onglets** : Accueil (état, mémoire, durée de marche), Sécurité (requêtes bloquées par le WAF), Réseau (sortie Internet,
  adresse LAN, mode), Médias (radio en cours), Box (box du maillage, état, « Ouvrir l'administration »). Veille après 60 s.
- **Données** : API existantes du maître en lecture seule (`/api/v1/pilotage/boxes`, `/api/v1/hub/{system_health,memory,uptime,
  network_summary}`, `/api/v1/waf/stats`, `/api/v1/radio/current`). Une valeur absente reste « — » ; ce qui n'existe pas encore
  est marqué « Bientôt » (bans récents, protection renforcée, appareils et débit, lecteur Lyrion, charge).
- **Pastilles (0.2.0)** : « le maître » (ses API hub, WAF, radio en direct) puis chaque box du maillage. Une box choisie
  affiche SES données, lues dans l'inventaire du pilotage (`GET /api/v1/pilotage/boxes/<box>`, relevé toutes les 60 s) :
  en ligne, services en échec, mémoire (`Device.DeviceInfo.MemoryStatus.Total/Free`), charge processeur si relevée
  (`…ProcessStatus.CPUUsage`), durée de marche (`…UpTime`), interface, mains liées, version de l'agent. Sécurité, réseau
  et médias en direct restent ceux du maître (« — » pour une box).
- **Session** : jeton `sbx_token` de l'administrateur du maître (même origine) ; sans jeton → `/login.html?redirect=/kiosque/`.
  Appairage par QR ou code depuis le maître : version suivante.
- **Sécurité** : CSP stricte (aucun script ni style intégré, `default-src 'none'`), en-têtes posés dans la location nginx
  `/etc/nginx/secubox-routes.d/kiosque.conf`, derrière HAProxy → sbxwaf → nginx comme le reste. Le service worker ne met en cache
  que les fichiers statiques de `/kiosque/`, jamais une réponse d'API.
- **Ouvrir une box** : même chemin que la Flotte (box distante : `connexion-vhost` du maître ; box locale : son admin relayé).
