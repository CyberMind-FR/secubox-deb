<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Média intégré souverain dans le BBS — conception (#1056)

Date : 2026-08-19 · Statut : conception approuvée (approche 1) · Portée : `secubox-ytsas` + `secubox-bbs`

## 1. Objectif

Intégrer un média WAN (YouTube d'abord) dans un fil/tuile du BBS avec
**souveraineté progressive** : externe une seule fois, local et inspecté ensuite.
Le navigateur ne contacte le tiers **qu'à la toute première vue** (choix produit :
embed direct instantané) ; dès que le média est caché puis miroité, toutes les
vues suivantes sont servies localement.

Décision produit (validée) : **première vue = embed `youtube-nocookie` direct**
(instantané, un seul contact Google), backfill ytsas en tâche de fond, bascule
locale ensuite.

## 2. Principe — le tuyau à rebond

Pour une URL YouTube donnée, la résolution rend la **meilleure source locale
disponible**, dans cet ordre, l'original restant le dernier recours :

1. **miroir PeerTube** (déjà conservé) → `<iframe>` PeerTube — souverain.
2. **cache ytsas** (téléchargé, pas encore miroité) → `<video src=ytsas/stream>` — souverain.
3. **WAN** (`pending`/`none`) → `<iframe youtube-nocookie>` — première vue seulement ;
   déclenche en tâche de fond `POST /add` + `POST /conserve`.
4. **failover** : si la source locale choisie échoue au moment de la lecture,
   le lecteur redescend la chaîne jusqu'à l'original WAN.

L'**URL d'origine n'est JAMAIS jetée** : conservée comme failover et comme
**tag de provenance**. Le join se fait **par identifiant vidéo**, jamais par titre.

## 3. Architecture

Deux unités, un contrat JSON entre elles.

```
[BBS gateway.Resolveur]                 [secubox-ytsas LXC :8091]
  connecteur youtube  --- GET /resolve?url= --->  résout l'état local
  (Go, rendu + tags)  <--- {state, src} ----      + enfile add/conserve
        |                                              |
        | rend selon state                             | (déjà existant)
        v                                     /add /stream /list /conserve
   iframe PeerTube | <video> ytsas | iframe youtube-nocookie
                                          conserve.timer --> peertubectl upload --> PeerTube
```

### 3.1 `secubox-ytsas` — nouvel endpoint `GET /resolve`

Unité : la résolution d'état vit dans ytsas, seul détenteur de la vérité
cache+conserve (fichiers cachés via `/list`, résultats de conserve via
`.conserve-results`).

Contrat :

```
GET /resolve?url=<url-youtube>
200 {
  "video_id":  "<id yt canonique>",
  "state":     "mirror" | "cache" | "pending" | "unsupported",
  "peertube_url": "<url embed peertube>",   // si state=mirror
  "stream_url":   "/stream/<id>",           // si state=cache
  "title":     "<titre si connu>",
  "thumbnail": "/files/<id>/poster.jpg"      // vignette proxifiée si connue
}
```

Comportement :
- Extrait le `video_id` (youtube.com/watch?v=, youtu.be/, /shorts/).
- `mirror` si un résultat de conserve existe pour ce `video_id`.
- sinon `cache` si le fichier est dans `/list`.
- sinon **enfile** `add` (+ `conserve`) et répond `pending` (idempotent : un
  `video_id` déjà en file n'est pas ré-enfilé — l'unicité est portée par la file,
  pas par une vérification préalable).
- `unsupported` si l'URL n'est pas reconnue (le connecteur laissera la carte générique).
- **Ne bloque jamais** sur un téléchargement : `resolve` est en chemin de requête,
  le fetch réel est asynchrone (file + timer existants).

Sécurité : endpoint en lecture, derrière le socket/vhost ytsas existant ; pas de
secret PeerTube sur le LXC (le conserve reste médié par l'hôte). Cookies YouTube :
réutilise le coffre existant (cf. #1048) ; un 403 (#1051) laisse l'état à
`pending`/`cache` selon ce qui a pu être obtenu — jamais d'erreur dure côté BBS.

### 3.2 `secubox-bbs` — connecteur `youtube` réel

Rend réels les fakes de `internal/gateway/resolveur_test.go`. Le connecteur
implémente l'interface `Connecteur` existante (motifs d'URL + `Resoudre`).

- **Motifs** : `youtube\.com/watch`, `youtu\.be/`, `youtube\.com/shorts/`.
- **Resoudre(url)** : appelle ytsas `GET /resolve`, mappe `state` → un `Contenu`
  portant : le genre (vidéo), la source de rendu, la **vignette** (proxifiée), les
  **tags de provenance** (`source=youtube`, `video_id`, `origine=<url>`), et
  l'**URL de failover** (= l'original).
- **Rendu** (gabarit) :
  - `mirror` → `<iframe>` PeerTube (origine déjà dans `FrameOrigines`).
  - `cache` → `<video>` pointant `ytsas/stream` (media-src board/ytsas).
  - `pending`/`none` → `<iframe youtube-nocookie>` (première vue WAN) + badge
    « rapatriement en cours ».
  - Data-attributs de failover pour que le lecteur redescende la chaîne si la
    source locale 404/erreur.
- **Réseau** : timeouts courts vers ytsas ; en cas d'indisponibilité ytsas, le
  connecteur retombe directement sur l'embed WAN (jamais d'échec de rendu du fil).

### 3.3 CSP

`internal/web/server.go` (`frameSrc`, en-têtes) :
- `frame-src` gagne `https://www.youtube-nocookie.com` (première vue) — les
  origines PeerTube y sont déjà.
- `media-src` gagne l'origine ytsas servie localement (pour `<video>`).
- Aucune ouverture vers `youtube.com` scripté/JS ; uniquement l'iframe nocookie.

## 4. Flux de données (séquence)

```
1er accès à un fil portant une URL YouTube :
  BBS.Resoudre(url) -> ytsas GET /resolve
    -> ytsas: pas de cache/miroir -> enfile add+conserve -> {state:pending}
  BBS rend <iframe youtube-nocookie> + tags provenance + failover=url
  (tâche de fond ytsas) add -> cache -> conserve.timer -> peertubectl -> PeerTube

Nième accès (après miroir) :
  BBS.Resoudre(url) -> ytsas GET /resolve -> {state:mirror, peertube_url}
  BBS rend <iframe peertube>  (souverain)

Miroir/cache HS au moment de lire :
  lecteur bascule sur la source suivante -> ... -> WAN (failover)
```

## 5. Gestion d'erreurs

- ytsas injoignable → embed WAN direct (dégradé mais fonctionnel), log.
- 403 YouTube (#1051) → reste `pending` ; réessais portés par le coffre cookies / la file.
- URL non reconnue → `unsupported` → carte générique existante (pas de régression).
- Un média défectueux n'interrompt pas le rendu du fil (best-effort, comme l'ingest).

## 6. Tests (TDD)

`secubox-ytsas` (pytest) :
- extraction `video_id` (watch, youtu.be, shorts, invalides).
- `/resolve` : mappe `list`/`conserve-results` → `mirror`/`cache`/`pending` ;
  idempotence de l'enfilement ; `unsupported` sur URL inconnue ; ne bloque pas.

`secubox-bbs` (go test) :
- connecteur `youtube` : motifs reconnus ; `Resoudre` mappe chaque `state` au bon
  rendu ; tags de provenance + failover posés ; ytsas HS → embed WAN.
- CSP : `frame-src` contient `youtube-nocookie` et PeerTube ; `media-src` l'origine ytsas
  (étendre `csp_test.go`/`frame_test.go`).
- rendu : `mirror`→iframe peertube, `cache`→video ytsas, `pending`→iframe nocookie.

## 7. Hors périmètre (YAGNI)

- Autres fournisseurs que YouTube (Vimeo…) : l'interface `Connecteur` le permettra
  plus tard ; pas dans cette tranche.
- Transcodage/qualité adaptative : délégué à PeerTube une fois miroité.
- Purge/quotas de cache ytsas : gérés par ytsas existant, pas ici.
- Réécriture des liens `bbs.gk2/b/` mal hôtés : ticket distinct (billets).

## 8. Dépendances / liens

- #1049 (mosaïque — la tuile relaie la vignette).
- #1048 (coffre cookies ytsas — écriture à authentifier) et #1051 (403 YouTube) :
  la robustesse du fetch en dépend ; le design dégrade proprement en attendant.
- Réutilise `secubox-ytsas-conserve` (déjà livré) pour le miroir PeerTube.
