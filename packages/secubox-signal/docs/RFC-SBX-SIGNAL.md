<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# RFC — SBX-SIGNAL : passerelle Signal pour SecuBox-Deb

| | |
|---|---|
| **Statut** | Proposition |
| **Issue** | [#1309](https://github.com/CyberMind-FR/secubox-deb/issues/1309) |
| **Module SBX** | `MESH` (transport), consommateur de `MIND` (Sentinel) |
| **Auteur** | CyberMind — Gérald Kerma |
| **Cibles** | **amd64** : bookworm et trixie. **arm64** : trixie seulement — voir §3.1 |

---

## 1. Pourquoi ce module

SecuBox sait détecter. Il sait mal **prévenir**. Les alertes de `sbx-sentinel`
finissent dans un journal que personne ne lit à 3 h du matin, et le courriel —
seul canal sortant actuel, via le conteneur `mail` — arrive quand il arrive.

Signal apporte trois choses qu'aucun autre canal du parc ne réunit :
la **confidentialité de bout en bout**, une **notification poussée** sur un
téléphone déjà dans la poche de l'exploitant, et un **canal de retour** — on
peut répondre à la box, pas seulement l'écouter.

Ce module n'est donc pas une messagerie de plus. C'est le **chemin de sortie
privé** du parc, et accessoirement une messagerie.

## 2. Ce que le module n'est pas

Poser les limites d'abord évite d'y revenir :

- **Pas un client Signal complet.** Pas d'appels, pas de stories, pas de
  réactions riches. Envoyer, recevoir, joindre un fichier.
- **Pas un archiveur.** Voir §7 — la rétention par défaut est courte et la
  raison est réglementaire, pas technique.
- **Pas un relais tiers.** La box parle pour elle-même, avec le numéro de son
  exploitant. Elle ne devient pas une passerelle pour autrui.

## 3. Contrainte fondatrice : `signal-cli` n'est pas dans Debian

Vérifié sur `api.ftp-master.debian.org` : `signal-cli` est absent de stable,
testing et unstable. C'est une application JVM distribuée en archive depuis
GitHub.

Le parc a déjà rencontré ce cas exact avec `ndpid`, et y a répondu par un
paquet `-engine` qui embarque le moteur absent. **On suit cette convention**,
pour trois raisons :

1. La dépendance devient **explicite** et vérifiable par `apt`, au lieu d'être
   découverte au premier démarrage — la leçon coûteuse de #1308.
2. Le backend se met à jour **sans toucher au démon**, et inversement.
3. L'architecture diffère : `signal-cli` est `all` (JVM), le démon est `any`.

| paquet | contenu | arch |
|---|---|---|
| `secubox-signal-engine` | `signal-cli` + JRE headless, `Provides: signal-cli` | `all` |
| `secubox-signal` | `sbx-signald`, API, WebUI, vhost, unité systemd | `any` |

### 3.1 arm64 exige Trixie — et cette contrainte n'est pas negociable

Cette RFC affirmait d'abord « compatible ARM64 et AMD64 (Debian Bookworm) ».
**C'etait faux**, et le deploiement sur gk2 l'a montre. La chaine de
contraintes se referme ainsi :

| suite | JVM max | signal-cli possible | libsignal exigee | binaire aarch64 |
|---|---|---|---|---|
| bookworm | Java 17 | ≤ 0.12.8 | 0.36.1 | **n'existe pas** |
| trixie | Java 25 | 0.13.24 / 0.14.x | 0.87.0 | publie |

Deux faits mesures, pas deduits :

1. La distribution JVM de `signal-cli` embarque un `libsignal_jni.so`
   **x86-64 uniquement**. Un paquet `Architecture: all` ne pouvait donc pas
   convenir — il transportait un binaire d'une seule architecture.
2. `exquo/signal-libs-build` publie des `libsignal_jni.so` aarch64 de
   **0.72.1 a 0.103.0**. La 0.36.1 qu'exige signal-cli 0.12.8 — la derniere
   version compatible Java 17 — n'y figure pas et n'y figurera pas.

**Sur bookworm arm64, aucune combinaison ne fonctionne** sans construire
libsignal soi-meme, en Rust, dans une version que l'amont ne maintient plus.

Le module vise donc **arm64 sur trixie**, ce qui s'aligne sur le portage deja
engage (#1294, #1295). Le paquet moteur passe en `Architecture: any` et
embarque la bibliotheque native de sa cible.

## 4. Architecture

```
                    ┌──────────────────────────────┐
   Hall / WebOS ───▶│  nginx  signal.gk2.secubox.in│
   (cardlet /micro) │         vhost + CSP          │
                    └──────────────┬───────────────┘
                                   │ proxy_pass unix:
                    ┌──────────────▼───────────────┐
                    │      sbx-signald  (Go)       │
                    │  /run/secubox/signal.sock    │
                    │                              │
                    │  api/   REST + JWT           │
                    │  ws/    WebSocket (événements)│
                    │  store/ SQLite (métadonnées) │
                    │  pairing/ QR d'appairage     │
                    │  sentinel/ alertes → Signal  │
                    └──────────────┬───────────────┘
                                   │ JSON-RPC (stdio)
                    ┌──────────────▼───────────────┐
                    │   signal-cli --output=json   │
                    │   (JVM, secubox-signal-engine)│
                    │   état : /var/lib/secubox/    │
                    │          signal/cli          │
                    └──────────────────────────────┘
```

### 4.1 Pourquoi un démon devant `signal-cli`

`signal-cli` en mode `daemon` expose déjà du JSON-RPC. On pourrait l'exposer
directement. On ne le fait pas :

- Il ne connaît **ni JWT ni les sessions du Hall** ; le placer derrière nginx
  sans médiation, c'est publier une messagerie authentifiée par rien.
- Il **redémarre** — mise à jour, appairage, expiration de session. Un démon
  Go maintient l'état, la file d'attente et les WebSockets ouvertes à travers
  ces redémarrages.
- Il parle JSON-RPC, pas REST. Le Hall attend du REST et du WebSocket comme
  tous les autres modules.

### 4.2 Pourquoi Go, et sans framework

Le parc a déjà cinq démons Go (`sbxwaf`, `sbxmitm`, `sbxdpi`, `sbx-actord`,
`secubox-socialrelayd`). Tous utilisent `net/http` et la bibliothèque
standard. Une passerelle qui multiplexe un processus enfant, une base SQLite
et des WebSockets n'a besoin de rien d'autre. Le `vendor/` restera sous cinq
entrées.

## 5. Surface d'API

Préfixe `/api/v1/signal`. Routes d'administration sous JWT
(`Depends(require_jwt)` côté nginx-Hall, vérification du jeton côté démon).

| Méthode | Route | Auth | Rôle |
|---|---|---|---|
| `GET` | `/healthz` | — | vivacité, pour systemd et le Hall |
| `GET` | `/micro` | session Hall | cardlet HTML |
| `GET` | `/status` | JWT | compte lié, état du backend, file |
| `POST` | `/link/start` | JWT | démarre l'appairage, rend un QR |
| `GET` | `/link/status` | JWT | progression de l'appairage |
| `DELETE` | `/link` | JWT | délie le compte, efface l'état local |
| `GET` | `/contacts` | JWT | liste des contacts |
| `GET` | `/groups` | JWT | liste des groupes |
| `POST` | `/messages` | JWT | envoi (texte et/ou pièces jointes) |
| `GET` | `/messages` | JWT | historique paginé (selon rétention) |
| `POST` | `/attachments` | JWT | dépôt d'une pièce jointe, rend un id |
| `GET` | `/attachments/{id}` | JWT | récupération |
| `WS` | `/ws` | JWT | flux d'événements temps réel |

Le contrat complet est dans [`openapi.yaml`](./openapi.yaml).

### 5.1 Événements WebSocket

Un seul type d'enveloppe, discriminé par `type` :

```json
{ "type": "message.received", "ts": "...", "data": { } }
{ "type": "message.sent",     "ts": "...", "data": { } }
{ "type": "link.progress",    "ts": "...", "data": { } }
{ "type": "backend.state",    "ts": "...", "data": { } }
```

## 6. Appairage

L'appairage Signal lie la box comme **appareil secondaire** d'un compte
existant. La box ne s'enregistre jamais comme appareil primaire : cela
demanderait de recevoir un SMS, donc un numéro dédié, et rendrait la box
responsable d'une identité — ce qu'elle ne doit pas être.

1. `POST /link/start` lance `signal-cli link -n "SecuBox <hostname>"`.
2. `signal-cli` émet une URI `sgnl://linkdevice?uuid=…&pub_key=…`.
3. Le démon la rend en **QR** (SVG, tracé côté serveur — aucune bibliothèque
   JS, aucune donnée d'appairage dans le navigateur au-delà de l'image).
4. L'exploitant scanne depuis Signal → *Appareils liés*.
5. `GET /link/status` suit la progression ; le WebSocket émet `link.progress`.

L'URI d'appairage est un **secret de courte durée**. Elle n'est jamais
journalisée, jamais persistée, et expire avec le processus qui l'a produite.

## 7. Données, rétention et posture CSPN

| donnée | emplacement | mode | rétention |
|---|---|---|---|
| état `signal-cli` (clés, sessions) | `/var/lib/secubox/signal/cli` | `0700 secubox-signal` | vie du lien |
| métadonnées de messages | `/var/lib/secubox/signal/signal.db` | `0600` | **24 h par défaut** |
| pièces jointes | `/var/lib/secubox/signal/attachments` | `0700` | 24 h |
| journal applicatif | `/var/log/secubox/signal/` | `0750` | rotation usuelle |

**Le contenu des messages n'est pas stocké par défaut.** La base ne retient
qu'un horodatage, un expéditeur haché, une taille et un identifiant. Le
paramètre `retention.store_body` existe, vaut `false`, et son commentaire
explique pourquoi : une box qui archive des conversations chiffrées de bout en
bout devient une cible d'un intérêt tout autre, et déplace la responsabilité
juridique de son exploitant.

Conformément à la doctrine du parc, chaque décision de sécurité — appairage,
déliaison, envoi automatique — est journalisée en append-only dans
`/var/log/secubox/audit.log`.

## 8. Relais Sentinel → Signal

`sbx-sentinel` produit des événements. Trois entrées possibles ont été pesées :

| voie | pour | contre |
|---|---|---|
| suivi de fichier journal | aucun couplage | latence, analyse fragile, rotation |
| socket d'abonnement | temps réel, typé | demande une modification de sentinel |
| appel HTTP sortant de sentinel | simple | inverse la dépendance, sentinel connaîtrait signal |

**Retenu : socket d'abonnement.** `sbx-signald` se connecte à
`/run/secubox/sentinel-events.sock` en lecteur. Si la socket est absente, le
relais est simplement inactif — le module reste utilisable comme messagerie.
C'est la seule voie qui ne fait pas dépendre le détecteur de son notificateur.

Un **garde-fou anti-avalanche** est non négociable : au-delà de
`sentinel.max_per_hour` (défaut 20), les alertes sont agrégées en un seul
message de synthèse. Une tempête d'événements ne doit pas devenir une tempête
de notifications, ni épuiser le quota Signal du compte lié.

## 9. Sécurité

- Utilisateur dédié `secubox-signal`, jamais root.
- Unité systemd sur le gabarit de `secubox-waf-ng` : `ProtectSystem=strict`,
  `PrivateDevices`, `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service`
  moins `@privileged` et `@resources`, `CapabilityBoundingSet=` **vide** — le
  module n'a besoin d'aucune capacité.
- `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` — pas de `AF_NETLINK`,
  contrairement au WAF qui bannit.
- Socket Unix uniquement ; nginx est le seul à parler au démon.
- Le sous-processus JVM hérite du bac à sable de l'unité.
- CSP stricte sur le vhost, avec `frame-ancestors 'self' https://hall.…` —
  sans quoi le cardlet encadré hérite du `'none'` serveur et n'affiche rien.

## 10. Intégration Hall / WebOS

- Entrée `menu.d/27-signal.json`, catégorie `mesh`.
- `/micro` sert le **cardlet** : état du lien, dernier message, compteur non-lus.
- `/` sert la page **`/mega`** : conversations, contacts, groupes, appairage.
- Les helpers partagés du Hall — `slicebar.js`, `aide.js`, `spicy.css` — sont
  consommés, jamais recopiés.

## 11. Ce qui reste ouvert

- **Multi-comptes.** `signal-cli` le permet ; l'UI s'en complique
  sensiblement. Proposition : un seul compte en v1, la base prévoit la colonne.
- **Réception en arrière-plan.** `signal-cli daemon` doit tourner en continu
  pour recevoir. Cela contredit `RuntimeMaxSec` — à trancher entre réception
  fiable et redémarrage périodique.
- **Quota Signal.** Le service impose des limites non documentées. Le garde-fou
  du §8 les respecte par construction, mais sans les connaître.

## 12. Étapes

| phase | contenu |
|---|---|
| **1** | paquets, démon, appairage, envoi texte, cardlet |
| **2** | réception, WebSocket, contacts, groupes |
| **3** | pièces jointes, relais Sentinel |
| **4** | multi-comptes, durcissement AppArmor |
