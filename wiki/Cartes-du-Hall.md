<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Les cartes du Hall (SBXOS)

Le **Hall** de SBXOS réunit les services souverains de la box en un seul bureau.
Chaque **carte** (*cardlet*) est un aperçu **vivant** d'un service — elle ne peint
rien qu'elle n'ait lu, toujours de **même origine** que le Hall (aucun tiers
chargé, aucun secret dans le navigateur).

Ce catalogue est la **source unique** : il est aussi rendu dans la vue **Aide**
du Hall (`www/hall/index.html`, tableau `CARDLETS_INFO`) et dans le
[README de secubox-webos](https://github.com/CyberMind-FR/secubox-deb/blob/master/packages/secubox-webos/README.md).
En ajoutant une carte, mettre à jour les **trois** ensemble.

## Catalogue

| Carte | En une ligne |
|---|---|
| 🧭 **Surf & Viewer** | Rappel en slices : favoris (se partage / se répète), propositions au parc (se propose / se cumule ×N), liens collés. |
| 🛰️ **DevWatch** | Pouls d'un dépôt GitHub en temps réel : cadence, flèches d'efficience, temps cumulé, coût, carbone, campagne, évolutions des versions. |
| 📹 **PeerTube** | Dernières vidéos du catalogue, lecture souveraine en place, agrandissement dans le viewer. |
| 🎙️ **Podcaster** | Abonnements, épisodes téléchargés localement, lecteur intégré qui reprend au refresh. |
| 📻 **Radio** | Flux en direct, lecteur souverain qui suit le thème et l'état du Hall. |
| 💬 **BBS** | Derniers fils et salons ; les liens média deviennent un objet souverain (voir / garder / diffuser). |
| 🎟️ **Billets** | Dernières publications ; objet média embarqué, titre et détails enrichis. |
| 💬 **Messagerie** | Mur public + messages privés de la box ; chat radio et commentaires Billets centralisés, y répondre publie à la source. |
| 🗝️ **Mes comptes** | Les comptes liés de la personne (courriel, Nextcloud, PeerTube, BBS) et leur lien ; un mot de passe pour tous, le forum ouvert d'office. |
| 🗞️ **MetaNews** | Topics clusterisés et leurs sources, ouverts en profondeur dans le Hall. |
| 🌐 **Surf (BiB)** | Navigateur de relais : surfe une adresse à travers la box, pisteurs coupés, 🎬 pour rapatrier un média croisé. |
| ✋ **Qui frappe ?** | Tentatives d'accès en cours vues par le WAF — donnée de sécurité, session requise. |
| ☁️ **Délégués** | Cloud, Photos, Social, Mail : aperçu authentifié + validation d'accès souveraine. |
| 📊 **Cumul (groupe)** | Carte de groupe : santé et activité d'un ensemble de services (sécurité, contenu, cloud…) d'un coup d'œil. |
| ⚡ **Accès rapide** | Saut direct vers un service (Dépôt, YTSaS, Torrent) avec son état en direct. |
| 🔬 **DPI · Trafic** | Trafic **vivant** classé par nDPI 5.x (protocoles / applications / talkers / risques), tranché à la barre à bullets. Sans PII. |
| 🎚️ **Lyrion** | Client Squeezebox/LMS : now-playing, transport, volume, power. 📡 **diffuse** l'audio du parc vers un lecteur ; 🎧 écoute un lecteur web dans le navigateur. |

## Slices & nouveautés (2026-08)

Plusieurs cartes se **tranchent** désormais à une **barre à bullets doubles** en
bas (pilule active en dégradé) — on choisit la vue, la rotation continue dedans :

* **DPI · Trafic** — 🌐 Protocoles · 📱 Applications · 🗣️ Talkers · ⚠️ Risques,
  sur des **données réelles** (moteur nDPI 5.x émancipé en Go, `sbxdpi`).
* **PeerTube** — 🆕 Récentes · 🔥 Populaires · 📂 Catégories · 📺 Chaînes · 🎞️ Playlists.
* **MetaNews** — 🌍 Une + les **sections** (catégories de sources).
* **Radio** — 💬 Messages · 🔁 Playlist · 🗳️ Propositions.

Autres : **Nextcloud** gagne un onglet **📅 Agenda** (CalDAV, lecture seule) ; les
**diffusions du parc** sont gardées par profil et listées **au survol** du menu
profil (badge de non-vues sur l'avatar) ; le **viewer** garde sa pastille sur la
barre média tant qu'il joue.

## Prise en main

* **Voir un média** — collez son lien dans la barre du viewer (en bas) : une vidéo
  ouvre le **lecteur souverain** (rapatriée via ytsas, sans pub ni Google) ; une
  page part dans le navigateur de relais.
* **Le viewer survit au rafraîchissement** — il rouvre là où vous en étiez,
  position comprise.
* **⭐ Favori** — se **partage** (copie du lien) et se **répète** (re-vu d'un clic).
* **📡 Proposition** — diffuser au parc, c'est proposer : ça se **cumule** (×N) et
  se rejoue en un clic.
* **🧭 Surf** — tapez une adresse dans la recherche du haut : la box la relaie,
  pisteurs coupés, métriques à l'appui.
* **Mini** — repliez le viewer dans un coin pour regarder tout en naviguant.

## FAQ

**Mes données partent-elles chez un tiers ?**
Non. Aucun cookie tiers, aucun secret dans le navigateur. Tout passe par la box
(même origine) ; les flux média sont rapatriés en souverain, et le surf coupe les
pisteurs.

**Pourquoi une vidéo YouTube met un instant à démarrer ?**
La box la rapatrie (ytsas) pour vous la servir sans pub ni Google. Une fois en
cache local, la lecture est immédiate — et souveraine.

**Que veut dire « proposer au parc » (📡) ?**
Diffuser un flux à tout le parc (📡 direct). Re-proposer le même n'ajoute pas de
doublon : ça incrémente son compteur, et le journal garde la trace.

**Une carte affiche « hors ligne » ?**
Le service est arrêté ou injoignable. La santé est sondée en direct
(*socket-aware*) ; réessayez, ou ouvrez le module pour voir son état.

**Comment revenir à l'accueil ?**
Le logo **SbX** en haut à gauche. Vos favoris du jour reviennent en tête de la
mosaïque.

---

Voir aussi : [[MODULES-FR]] · [[Architecture]] · [[WAF-FR]]
