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

## Les cartes du Hall

Chaque carte est un aperçu **vivant** d'un service — elle ne peint rien qu'elle
n'ait lu, de même origine que le Hall. Ce catalogue est aussi rendu dans la vue
**Aide** du Hall et sur le [wiki](https://github.com/CyberMind-FR/secubox-deb/wiki/Cartes-du-Hall).

| Carte | En une ligne |
|---|---|
| 🧭 **Surf & Viewer** | Rappel en slices : favoris (se partage / se répète), propositions au parc (se propose / se cumule ×N), liens collés. |
| 🛰️ **DevWatch** | Pouls d'un dépôt GitHub en temps réel : cadence, flèches d'efficience, temps cumulé, coût, carbone, campagne, évolutions des versions. |
| 📹 **PeerTube** | Dernières vidéos du catalogue, lecture souveraine en place, agrandissement dans le viewer. |
| 🎙️ **Podcaster** | Abonnements, épisodes téléchargés localement, lecteur intégré qui reprend au refresh. |
| 📻 **Radio** | Flux en direct, lecteur souverain qui suit le thème et l'état du Hall. |
| 💬 **BBS** | Derniers fils et salons ; les liens média deviennent un objet souverain (voir / garder / diffuser). |
| 🎟️ **Billets** | Dernières publications ; objet média embarqué, titre et détails enrichis. |
| 🗞️ **MetaNews** | Topics clusterisés et leurs sources, ouverts en profondeur dans le Hall. |
| 🌐 **Surf (BiB)** | Navigateur de relais : surfe une adresse à travers la box, pisteurs coupés, 🎬 pour rapatrier un média croisé. |
| ✋ **Qui frappe ?** | Tentatives d'accès en cours vues par le WAF — donnée de sécurité, session requise. |
| ☁️ **Délégués** | Cloud, Photos, Social, Mail : aperçu authentifié + validation d'accès souveraine. |
| 📊 **Cumul (groupe)** | Carte de groupe : santé et activité d'un ensemble de services (sécurité, contenu, cloud…) d'un coup d'œil. |
| ⚡ **Accès rapide** | Saut direct vers un service (Dépôt, YTSaS, Torrent) avec son état en direct. |

> Source unique : la liste vit dans `www/hall/index.html` (`CARDLETS_INFO`), reprise
> ici et dans le wiki. Mettre à jour les trois ensemble en ajoutant une carte.

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
