<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-webos — SBXOS, le Hall

**SBXOS** est le bureau web de la box : un **Hall** unique qui rassemble tous
les services SecuBox en cartes vivantes, et par lequel on lit, écoute, regarde
et surfe — sans jamais le quitter.

Ce n'est pas un portail de liens. Chaque service **habite** le Hall : il y sert
sa propre carte (`/micro`), ou s'y montre en aperçu vivant, ou s'y embarque en
pleine page. Le Hall prend toujours le degré d'intégration le plus élevé
disponible et bascule seul quand un service apprend à se résumer.

## Ce que le Hall porte

| | |
|---|---|
| **Mosaïque de cartes** | une carte par service, réordonnable (glisser), avec une bande de **favoris** en tête |
| **Barre média** | un rang par flux qui joue (radio, podcast, PeerTube…) — volume/muet **persistants**, pli par flux, pastilles ; une seule instance par service, la vidéo fait taire l'audio |
| **Mégabarre** | Accueil / Services / Système, recherche — **ou barre d'adresse** (une adresse tapée se surfe) |
| **Menu profil** | identités détectées (registre RGPD), thème, « ordre actuel = défaut », connexion SecuBox |
| **Le BiB** | voir ci-dessous |

## Le BiB — *Browser in Browser*

Le **BiB** est le navigateur de relais **surf** de SBXOS. On tape une adresse
et le site s'ouvre **à travers la box** (`secubox-surf`, hors chaîne
d'inspection) : origine par site `surf-<hôte-aplati>.gk2.secubox.in`, **pisteurs
coupés**, pubs et Taboola masqués, popups et notifications interceptées, cookies
neutralisés, portails de consentement contournés. Une barre de metrics dit ce
qui a été coupé : 🎯 traqueurs · 📢 pubs · 🍪 cookies · 🔔 notifs · 🚫 popups ·
🛡️ % pisté.

Ce **n'est pas un « MITM proxy »** : c'est un navigateur de relais **par-origine,
opt-in, en lecture**. Détail et mesures : [`docs/POC-SURF.md`](../../docs/POC-SURF.md).

**La matrice SBXOS** : dans le Hall, *tout lien reste dans le Hall*. Un lien vers
un service de la box s'embarque à la bonne référence ; un lien externe passe par
la gateway surf. Hors du Hall (service ouvert seul), les liens restent directs.

## Architecture

```
Navigateur ─▶ hall.gk2.net / hall.gk2.secubox.in
                    │
   ┌────────────────┼─────────────────────────────┐
   │ www/hall/      │ api/ (FastAPI, socket unix)  │
   │  index.html    │  registry, cardlets, acces,  │
   │  cardlets/     │  actions, jeton              │
   │  surf.html     │                              │
   └────────────────┴─────────────────────────────┘
                    │
        nginx (hall.vhost.conf) ─▶ services, /pt/ (PeerTube), /cardlets/
```

- **`www/hall/index.html`** — le Hall (mosaïque, barre média, mégabarre, overlay surf).
- **`www/hall/cardlets/`** — cartes servies par le Hall (peertube, quick, delegue, surf…).
- **`api/`** — registre normalisé des services, cartes publiques, **accès délégués**
  (`acces.py` : demande → validation manuelle → secret 0600, jamais de mot de
  passe en transit), **actions** de modules, relais de jeton cross-domaine.

## Contrat d'une carte

Une carte **résume**, elle ne rétrécit pas. Règles et pièges (CSP, cookies
tiers, thème, zone morte temporelle, etc.) :
[`docs/CARDLET-GUIDELINES.md`](../../docs/CARDLET-GUIDELINES.md) et
[`docs/WEBOS-DESIGN.md`](../../docs/WEBOS-DESIGN.md).

## Build & déploiement

```bash
cd packages/secubox-webos
dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b -d
# puis, sur la box : dpkg -i --force-confold secubox-webos_*.deb
```

Le service tourne en `secubox-webos.service` (uvicorn, socket
`/run/secubox/webos.sock`), derrière nginx puis HAProxy TLS 1.3.

## Voir aussi

- [`docs/WEBOS-DESIGN.md`](../../docs/WEBOS-DESIGN.md) — pourquoi le Hall est fait ainsi.
- [`docs/CARDLET-GUIDELINES.md`](../../docs/CARDLET-GUIDELINES.md) — ce qui casse en construisant une carte.
- [`docs/POC-SURF.md`](../../docs/POC-SURF.md) — le BiB, mesures et décision.
- `packages/secubox-surf/` — le relais surf.
