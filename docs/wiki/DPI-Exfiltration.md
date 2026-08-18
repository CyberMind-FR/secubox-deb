<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# DPI Exfiltration & le rapport Netrunner

**CyberMind · Gondwana · Savoie** | [Home](Home) | [kbin](Kbin-Toolbox) | [Modules](Modules)

> Voir *qui*, parmi tes appareils derrière le tunnel R3, **envoie des données vers des
> clouds externes** — et lire le tout dans une **fiche de joueur cyberpunk**.

---

## Pipeline DPI (paquet `secubox-dpi`)

```
wg-toolbox (tap R3)
  └─ ndpiReader -C  (fenêtres 60 s)            ← producteur  : secubox-dpi-flowcap
       └─ secubox-dpi-collector (Go, stdlib)   ← scoreur
            ├─ device = sha256(wg_pubkey)[:16]  (wg-peers.json)
            ├─ SNI → catégorie : cloud · filehost · messaging · ai ·
            │                     media · game · social · adult
            └─ scénarios exfil :
                 • exfil_volume         (≥5 Mo ↑ vers cloud, ↑>↓)
                 • new_cloud            (1ʳᵉ sortie vers un cloud)
                 • beaconing            (cadence 1 s–1 h, CV ≤ 0,25)
                 • unclassified_external
       └─ /var/lib/secubox/dpi/state.json        (fenêtre live, dashboard)
       └─ /var/lib/secubox/dpi/cumulative.json    (rollup 7 j, rapport)
            └─ GET /api/v1/dpi/exfil
```

- **state.json** = la dernière fenêtre de 60 s (vue *live* du dashboard `/dpi/`).
- **cumulative.json** = rollup glissant **7 jours** par device (utilisé par le rapport
  kbin, sinon un appareil inactif afficherait des zéros).
- Catégories *exfil-relevant* (cloud/filehost/messaging/ai) = celles qui déclenchent une
  alerte ; media/game/social/adult sont affichées mais jamais alertées (c'est de la
  navigation, pas de l'exfiltration).

### Services
| Unit | Rôle |
|------|------|
| `secubox-dpi-flowcap.service` | boucle ndpiReader → collector (Nice 15, MemoryMax 256M) |
| `secubox-dpi.service` | API FastAPI (`/api/v1/dpi/*`, dont `/exfil`) |

Dépend de `libndpi-bin` (fournit `ndpiReader`).

---

## Le rapport kbin — fiche Netrunner

`https://kbin.gk2.secubox.in/report/me/html?mh=<hash>` (HTML) et `/report/me` (PDF).

La même donnée live (exposition, traceurs, DPI cumulatif, pubs bloquées, protections
actives) est réhabillée en **fiche de personnage cyberpunk** :

- **Persona** — classe + emoji depuis le *User-Agent de la requête* (l'appareil qui
  consulte), niveau **R3** auto pour un pair wg-toolbox, alignement selon l'exposition.
- **Barres** — 🧬 ICE/intégrité (100 − exposition), ☣️ Exposition, ✦ XP (Ko échangés 7 j).
- **Caractéristiques** (pip bars) — 🛡️ Défense · 👁️ Discrétion · ⚔️ Riposte (pubs tuées) ·
  🧠 Intel (diversité DPI).
- **Inventaire** — Tor / Cert MITM / WireGuard / Ad-blocker (✓/✗).
- **Bestiaire** — top traceurs. **Quêtes** — alertes exfil.
- **Onglets** (HTML) : Pistage / DPI-Exfil / Overall.

### PDF
Le PDF reprend tout (fiche Netrunner + « En un coup d'œil » + grille de donuts
DPI/MITM/Certs/Pubs + **carto** réseau + tables emoji Traceurs/Pays/DPI). Les graphiques
sont rendus en **PNG matplotlib** embarqués (les donuts vectoriels fpdf2 s'affichaient
en blanc sur iOS/Chrome) ; la grille est **une seule image 2×2**.

---

## Exploitation

```bash
# état live
curl -s --unix-socket /run/secubox/dpi.sock http://localhost/api/v1/dpi/exfil | jq .
# le moteur R3 = Go sbxmitm (PAS la mitmproxy Python)
systemctl status secubox-toolbox-ng-worker@{1,2,3,4}   # 10.99.1.1:8091-8094
```

> ⚠️ Le tap DPI ne voit que le trafic R3 (wg-toolbox). Un device doit surfer via le
> tunnel 🧅/🛰️ pour apparaître. SNI absent (IP-only/QUIC) ⇒ non classé (enrichissement
> ASN prévu en Phase 3).

---

*Réf. issues : #687 (pipeline), #707 (fiche Netrunner), #714/#716 (rendu PDF). Voir
[HISTORY 2026-06-22](../../.claude/HISTORY.md).*
