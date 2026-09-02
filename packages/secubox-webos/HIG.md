<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
Source-Disclosed License — All rights reserved except as expressly granted.
See LICENCE-CMSD-1.0.md for terms.
-->

# SBXOS — Human Interface Guidelines du WebOS (le « Hall »)

> Le WebOS de SecuBox (nom d'usage **SBXOS**, surface publique « le Hall ») est un
> **bureau numérique souverain** : une page-hôte (`www/hall/index.html`) qui
> encadre des **cardlets** (vues `/micro`) et des **vues pleines** (`/mega`),
> reliées par un **protocole de messages `sbx`** et deux **bibliothèques
> partagées** (`SBXSliceBar`, `SBXAide`).
>
> Ce document est la **source de vérité** du design system : il décrit ce qui
> EXISTE (le réel) et ce qui est VISÉ (le possible). Tout nouveau cardlet ou
> service doit s'y conformer. Objectif : **zéro écart**, cohérence de bout en bout.

Sommaire :
1. [Philosophie](#1-philosophie)
2. [Le modèle cardlet : /micro, /mega, mega=admin](#2-le-modèle-cardlet)
3. [Le chrome du Hall](#3-le-chrome-du-hall)
4. [Le protocole `sbx` (référence complète)](#4-le-protocole-sbx)
5. [Les bibliothèques partagées](#5-les-bibliothèques-partagées)
6. [Partage de la lib entre paquets](#6-partage-de-la-lib-entre-paquets)
7. [Couches de visibilité](#7-couches-de-visibilité)
8. [Checklist d'un nouveau cardlet](#8-checklist-dun-nouveau-cardlet)
9. [Écarts connus & audit](#9-écarts-connus--audit)
10. [Roadmap « en possible »](#10-roadmap--en-possible-)

---

## 1. Philosophie

- **Même origine, souveraineté.** La CSP du Hall impose `connect-src 'self'` et une
  liste fermée de `frame-src` (nos vhosts uniquement). Tout appel d'un cardlet est
  de même origine ; les données viennent de la box, jamais d'un tiers.
- **On annote, on ne cache pas.** L'aide « reverse-design » pose des anneaux et des
  pastilles numérotées SUR le contenu réel, sans voile — le service reste lisible.
- **Le contenu est vivant.** Les cardlets tournent (slices), se rafraîchissent en
  place (`relis`), et se mettent en pause au survol. Un rafraîchissement ne doit
  jamais casser un choix de l'utilisateur (slice figée, thème, ordre des cartes).
- **Réel ET possible.** Cette HIG documente l'implémenté ET trace la cible : les
  deux doivent rester cohérents ; on n'introduit pas d'écart « en attendant ».

---

## 2. Le modèle cardlet

Trois formes de carte, choisies par `featCardHTML()` selon le service (par ordre) :

| Forme | Classe | Quand | Contenu |
|------|--------|-------|---------|
| **Cardlet vive** | `.fcard.fcard-vive` | service avec `micro` ou `carte` | iframe `data-micro` → `/cardlets/x.html` (local) ou `https://<hôte>/micro` (distant) |
| **Aperçu** | `.fcard.fcard-apercu` | `EMBEDDABLE` sans `/micro` | iframe `data-apercu` = capture vivante mise à l'échelle (1280×900 → 174px) |
| **Descriptif** | `.fcard.clic` | fallback | icône, nom, état, description, bouton « Ouvrir » |

### /micro vs /mega

- **/micro** = la cardlet, dans la grille du Hall. Rotation de slices, aide,
  pause au survol. C'est la vue de coup d'œil.
- **/mega** = la vue pleine, ouverte par l'agrandissement (`setMode`). Un iframe
  par mode (`tab` / `admin` / `embed`), on ne fait que basculer `display`.

`modeURL(mode)` décide de la cible du /mega, dans cet ordre :

1. **`megaAdmin:true`** → `https://admin.gk2.secubox.in<path>?theme=…`
   La /micro reste la cardlet vivante, le /mega ouvre la **console admin**.
   **Règle HIG : `megaAdmin` quand le service n'a pas de vhost public riche**
   (ex. **DPI** — sa vue pleine EST le dashboard admin : Sessions/Learning/Pays/
   Exfil ; **Surf**). Les services de contenu qui ONT une page publique riche
   (metanews, peertube…) gardent leur **vhost** en /mega ; l'admin reste sur ⚙️.
2. **`noVhost`** (a `carte`, pas d'`url`) → pseudo-/mega : `carte?embed=1&mega=1&theme=…`
   (on agrandit la cardlet elle-même, même origine).
3. **`mode==='admin'`** → `https://admin…<path>?theme=…`.
4. défaut **embed** → `https://<url>/?embed=1&theme=…`.

Côté cardlet, `/mega` se détecte par `?mega=1` (+`embed=1`) et bascule d'un
**slicer** (une slice + rotation) à une **page empilée multi-colonnes** (`html.mega`).

---

## 3. Le chrome du Hall

### 3.1 Boutons haut-droite (`.mast-actions`, ibtn 38×38)
- **Pastilles de flux** `#pastilles` / `#pastilles-direct` — n'apparaissent que
  pendant une lecture ; clic → viewer/zoom/embed.
- **Thème** `#theme` (◐) — cycle clair↔nuit, persisté (`localStorage`), propagé à
  tous les iframes par `{sbx:'theme'}`.
- **Profil** `.who#who` (🧙) — menu : connexion, ordre des cartes (⭐/↺), revoir
  l'accueil, **aide du Hall**, identités, diffusions.

### 3.2 Barre de service (`#nav-embed`)
Titre du service = déclencheur de sa nav (`ctx-btn`), ⟳ recharge, et le groupe
**`#modesw`** : **⧉ onglet réel · ⚙️ admin · ▦ embed** (défaut). Voir §2.

### 3.3 Barre du bas des cardlets (slicer)
`SBXSliceBar` (§5.1) : puces à gauche, libellé au centre, pastille d'hôte à
droite. Rotation auto ralentie (défaut **9 s**), pause au survol, **clic = fige +
pause persistante** (re-clic = reprend).

### 3.4 Mini-popup d'aide (bulle de légendes)
Le `?` de chaque carte (`.cl-aide`) :
- **survol** → bulle texte courte (mode `hover`).
- **clic sur une carte à iframe** → `montreDiag()` : envoie `{sbx:'aide',on}` +
  `{sbx:'aide?'}` au cardlet, qui répond `{sbx:'aide-zones',…}`. La bulle
  (`#carte-bulle`) liste les **légendes numérotées** (mêmes numéros que les
  pastilles in-card) et affiche le **nom de la slice** en cours.
- **clic sur une carte descriptive** → texte + mode inspection.

### 3.5 Dock média
`{sbx:'media',…}` d'un cardlet ajoute une ligne au dock + une pastille. `type:'video'`
obtient l'exclusivité (les autres reçoivent `{sbx:'cmd',action:'pause'}`) et le zoom.

### 3.6 Megamenu & favoris
Deux entrées : **🗂️ Services** / **🗄️ Système** (mosaïque de modules du parc,
groupés par catégorie). L'**étoile ★** ne fait que **réordonner** (favoris en
tête) ; la **poignée ⠿** permet le glisser-déposer ; l'ordre est persisté par
profil. Ordre par défaut : `['radio','metanews','podcaster','peertube']`.

---

## 4. Le protocole `sbx`

Tous les messages sont `postMessage({sbx:'<nom>', …})`. **Direction** : P→C = Hall
vers cardlet ; C→P = cardlet vers Hall ; C→child = cardlet-relais vers son iframe.

> **Sécurité des origines** : les signaux d'UI (thème, survol) partent en
> `targetOrigin:'*'` ; les **commandes** vers un iframe de confiance utilisent
> l'origine précise ; les handlers entrants **filtrent sur `ev.source`** quand
> l'authenticité compte. Tout nouveau message de commande DOIT suivre cette règle.

### 4.1 Hall → Cardlet (P→C)

| Message | Payload | Effet |
|---|---|---|
| `theme` | `{theme:'dark'\|'light'}` | Bascule de palette (tous les iframes). |
| `relis` | — | « Relis, ne recharge pas » : rafraîchir les données en place (retour de focus). |
| `contexte-demande` | — | Republier la nav du service dans le panneau de droite. |
| `contexte-choix` | `{cle}` | Renvoie le choix de source poussée aux frames candidats. |
| `cmd` | `{action:'pause'\|'toggle'\|'prev'\|'next'\|'stop'\|'vol'\|'muet', v?}` | Transport média. |
| `aide` | `{on:true\|false}` | Active/désactive l'annotation reverse-design in-card. |
| `aide?` | — | « Rapporte tes zones maintenant » → réponse `aide-zones`. |
| `survol` / `pause` | — | Pause de la rotation (souris au-dessus de la carte). |
| `quitte` / `reprend` | — | Reprise de la rotation. |
| `cast` | `{url, titre}` | (Lyrion) jouer un flux sur la Squeezebox physique. |

### 4.2 Cardlet → Hall (C→P)

| Message | Payload | Effet |
|---|---|---|
| `aide-zones` | `{slice, vw, vh, zones:[{label,x,y,w,h}]}` | Alimente la bulle de légendes (par slice). |
| `aide-ferme` | — | Ferme la bulle d'aide épinglée. |
| `media` | `{id, type?, titre, sous, joue, t, d, fin?, href?, vignette?, zoomable?}` | Déclare un flux en lecture → dock + pastille. `fin:true` retire la ligne. |
| `voir` | `{url, titre?}` | Ouvre une URL/média dans le viewer du Hall. |
| `diffuser` | `{url, titre}` | Diffuse un média au parc (résolu via ytsas). |
| `souverain` | `{url}` | Rapatrie/miroir une vidéo sur la box. |
| `ouvre` | `{id, url?}` | Embarque un service, deep-link si même origine (gated `ev.source`). |
| `ouvre-hote` | `{hote, url?}` | Ouvre un service par hôte (deep-links inter-services). |
| `connexion` | — | Ouvre le popup de login SecuBox. |
| `valider` | `{id}` | Ouvre `/acces.html?svc=<id>` (octroi d'accès, gated `ev.source`). |
| `zoom` | `{id}` | Agrandit la carte dans le mini-viewer. |
| `carte-haut` | `{id, h}` | La /micro distante rapporte sa hauteur (clamp 120–360px). |
| `contexte` | `{id, titre, items[]}` | Pousse des sources dynamiques dans la megabar. |
| `broadcast-on` | — | Réveille la sonde des pastilles direct/diffusion. |
| `surf` | `{url}` | Ouvre l'overlay surf sur une URL. |
| `surf-catch` | `{url, titre}` | La page surfée est un média → viewer souverain. |
| `surf-hote` | `{hote}` | Met à jour l'hôte affiché dans l'overlay surf. |
| `surf-close` / `surf-vide` | — | Ferme l'overlay surf. |
| `surf-stats-up` | `{stats:{trackers,pubs,cookies,notifs,popups,total}}` | Compteurs bloqués dans l'overlay. |

> `cumul.html` est un **relais** : il applique `theme` et le reforwarde à son
> iframe imbriqué, convertit `ouvre`→`ouvre-hote`, et ne remonte au Hall qu'une
> **liste blanche** : `ouvre-hote, surf, surf-close, surf-vide, surf-hote, voir,
> valider, connexion, contexte`. Modèle à suivre pour tout cardlet-conteneur.

---

## 5. Les bibliothèques partagées

Emplacement : `packages/secubox-webos/www/hall/` — `slicebar.js` (+`slicebar.css`),
`aide.js`, `spicy.css` (skin).

### 5.1 `SBXSliceBar(container, opts)`
Barre de pied + rotation entre slices. Le cardlet reste maître de son contenu.

```js
SBXSliceBar(el('slbar'), {
  autoMs: 9000,                 // rotation ralentie (0 = pas de rotation ; jamais sous reduced-motion)
  key: location.pathname,       // clé de persistance de la PAUSE (défaut = pathname)
  onShow: function(i, slice){}, // appelé à chaque changement de slice
  slices: [{ label, host, tone, href, open }]
});
// retour : { el, show(i), manual(i), count(), current(), setInfo(html) }
```

Comportement : puces bleues = **auto**, puces vertes = **manuel** (figé + pause).
**Un clic** fige une slice et met en pause ; l'état survit aux rafraîchissements
et aux visites (`localStorage` `sbx-slice:<key>`). **Re-cliquer la même puce**
reprend l'auto. Le survol de toute la carte met en pause temporairement.

### 5.2 `SBXAide(opts)` — aide reverse-design
Dessine anneaux + pastilles numérotées in-card (sans voile) ET rapporte les zones
au Hall pour la bulle de légendes.

```js
SBXAide({
  root:  document.querySelector('.mw'),   // conteneur annoté
  slice: function(){ return 'Protocoles'; }, // nom de la slice active (pour la bulle)
  zones: function(){ return [               // zones RICHES, par contexte/slice
    { el: el('kpis'),        label: 'KPIs — flux · débit · risques' },
    { el: el('s-'+courante), label: DESCRIPTIONS[courante] },
    { el: el('slbar'),       label: 'Slices — tournent seules ; clic pour figer' }
  ]; }
});
// écoute {sbx:'aide',on} et {sbx:'aide?'} ; répond {sbx:'aide-zones',…}
```

> **Standard obligatoire (§8) :** tout cardlet DOIT passer un `zones()` **riche et
> contextuel** (labels utiles, qui changent avec la slice) et `slice()`. Le
> fallback `autoZones()` (5 sélecteurs génériques) est un filet, **pas** une cible.

---

## 6. Partage de la lib entre paquets

`aide.js` / `slicebar.js` vivent dans **secubox-webos** et sont servis sous
`/cardlets/../*.js` — même origine que le Hall. **Un module servi par un AUTRE
vhost** (ex. `secubox-radio` sous `radio.gk2.secubox.in/static/`) **ne peut pas**
les inclure (origine + chemin différents, CSP). Aujourd'hui `radio` a donc une
**aide inline** minimale — c'est l'écart type à résorber.

**Cible (à trancher, cf. §10) :** faire de `sbx` une lib **distribuable** :
- soit un paquet `secubox-sbxui` (Depends commun) posant `slicebar.js`/`aide.js`/
  `spicy.css` sous un chemin canonique servi par chaque vhost de module ;
- soit un **vendoring** synchronisé par script (`scripts/sync-sbxui.sh`) copiant
  la lib de référence dans chaque paquet, avec vérif de dérive en CI.

Tant que ce n'est pas tranché, **une source unique** (le fichier de
secubox-webos) fait foi ; toute copie est un vendoring temporaire à noter.

---

## 7. Couches de visibilité

Le Hall masque/révèle les cartes par CSS, selon deux couches :

| Couche | Marqueur carte | Attribut DOM | CSS | Levé par |
|--------|----------------|--------------|-----|----------|
| **Authentifié** | `auth:true` | `data-auth="1"` | `.non-connecte .fcard[data-auth]{display:none}` | session box (`_moi`) |
| **LAN** | `lan:true` | `data-lan="1"` | `.non-lan .fcard[data-lan]{display:none}` | nginx (`$lan_client`) retire `non-lan` |

- `<html class="non-connecte non-lan">` par défaut (tout masqué → révélé).
- **Widgets sensibles = `auth:true`** : Sécurité, **DPI**, Cloud/Cloud+ …
- **LAN-only = `lan:true`** : Lyrion (service + relais API refusés côté serveur aux
  clients WAN, cf. `hall.vhost.conf`).
- Le gating côté client (CSS) est un confort ; **la vraie barrière est côté
  serveur** (JWT sur l'API, `if ($lan_client=0)` sur les relais).

**À venir — administration des privilèges** (cf. §10) : une UI pour visualiser et
piloter ces couches (public / LAN / authentifié / rôles), à définir ultérieurement,
**mockup au préalable**.

---

## 8. Checklist d'un nouveau cardlet

1. **Structure** `.mw` racine ; `.kpis` ; contenu en slices `.slice` (ou `.dsec`
   en /mega) ; `#slbar` pour la barre.
2. **Slicer** : `SBXSliceBar(el('slbar'), {autoMs:9000, onShow:montre, slices:[…]})`.
3. **/mega** : lire `?mega=1` → `html.mega`, empiler les sections multi-colonnes,
   masquer `#slbar` et l'aide.
4. **Aide RICHE** : `SBXAide({root, slice, zones})` avec des labels contextuels par
   slice — **jamais** `SBXAide({})` seul (fallback générique interdit comme cible).
5. **Thème** : appliquer `?theme=` au chargement ET écouter `{sbx:'theme'}`.
6. **Pause au survol** : gérée par `SBXSliceBar` (ne pas réimplémenter).
7. **Média** (si lecture) : émettre `{sbx:'media',…}` (+`fin:true` à l'arrêt) et
   obéir à `{sbx:'cmd',…}`.
8. **Sécurité** : messages de commande vers l'origine précise ; handlers entrants
   filtrés sur `ev.source`.
9. **Visibilité** : déclarer `auth:true`/`lan:true` si sensible/local, ET poser la
   vraie barrière serveur.
10. **Affichage progressif** : listes longues en **top-5 + « voir plus »** (état
    déplié conservé au rafraîchissement).

---

## 9. Écarts connus & audit

Suivi (objectif « zéro écart » — auditer à chaque tour) :

| Écart | Fichier | État |
|-------|---------|------|
| Aide **inline** (n'utilise pas `SBXAide`) | `cardlets/dpi.html` | ✅ **Résorbé (2026-09-02)** — migré sur `SBXAide`, `zones()` riche par slice conservé. |
| Aide **mixte** (SBXAide + inline) | `cardlets/lyrion.html` | ✅ **Résorbé** — `zones()` enrichi ; le CSS `.sbxaide-ring` en `var(--accent)` est une surcharge de teinte VOLONTAIRE (conservée). |
| **9 cardlets** en `SBXAide({})` générique | cumul, delegue, lyrion, nextcloud-super, peertube, quick, quifrappe, surf, surfviewer | ✅ **Résorbé** — chacun passe un `zones()` contextuel (surfviewer aussi `slice()`). |
| **radio** : aide inline minimale (`slice:''`), lib non partagée | `secubox-radio/internal/web/static/` | ⏳ **Lane B** — nécessite la lib partagée entre paquets (§6) avant d'émanciper + compléter. |

> Audit initial (2026-09-02) : DPI était le SEUL cardlet à aide riche par contexte.
> **Après lane A : les 10 cardlets du Hall ont une aide contextuelle** (plus aucun
> `SBXAide({})` nu). Reste **radio** (lane B), bloqué par le partage inter-paquets.

---

## 10. Roadmap « en possible »

Cohérence à pousser plus loin (documenté ici pour ne pas diverger en chemin) :

- **Slices favorites** : dépliage/repliage de slices épinglées (multi-slices
  visibles au choix), au-delà du figeage simple actuel.
- **Multi-cardlet** : composer plusieurs cardlets dans une même vue orchestrée.
- **/mega = fenêtre zoomée** dans le **bureau virtuel** du WebOS : l'agrandi n'est
  pas une page à part mais un **zoom spatial** dans l'espace de travail (retour
  fluide à la grille).
- **Administration des privilèges** : UI de gestion des couches de visibilité
  (public / LAN / authentifié / rôles) + attribution par service et par identité.
  **À définir & détailler ultérieurement — design + mockup au préalable.**
- **Lib `sbx` distribuable** (§6) : paquet `secubox-sbxui` ou vendoring synchronisé,
  pour que tout module (radio & co) partage exactement le même chrome et la même aide.
