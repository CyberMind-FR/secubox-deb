<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.

  Dossier technique déposé par l'auteur (2026-08-21) — « note for later ».
  NON implémenté : référence de conception pour un futur module.
-->

# Dossier technique — `secubox-avatar`

**Module d'avatarisation SecuBox** — identité numérique unifiée, coffre de sessions, profils navigateur persistants, miroir & barre SSO.

Cible : Debian bookworm arm64, intégration SecuBox-Deb. Périmètre CSPN : le cœur (daemon, vault, API) est dans le périmètre ; le sous-module navigateur (`avatar-browser`) est **hors périmètre, documenté comme tel** dans la cible de sécurité.

---

## 1. Vue d'ensemble

L'avatar est le **profil numérique unique** de la box : un personnage complet, avec ses identités par service (locales et externes), ses secrets et ses sessions vivantes. Tout consommateur (gateway BBS, miroir, mosaïque, barre SSO) s'adresse à l'avatar — jamais directement aux secrets.

```
┌─────────────────────────────────────────────────────┐
│                    sbx-avatard                       │
│  ┌───────────┐  ┌────────────┐  ┌────────────────┐   │
│  │ Identity  │  │  Session   │  │ Browser Pool   │   │
│  │ Registry  │  │  Vault     │  │ (hors CSPN)    │   │
│  └───────────┘  └────────────┘  └────────────────┘   │
│  socket /run/secubox/avatar.sock (varlink/JSON)      │
└──────┬───────────────┬─────────────────┬─────────────┘
       │               │                 │
 sbx-bbs-gatewayd   UI mosaïque    barre SSO (JS servi)
```

## 2. Composants et fichiers

| Élément | Chemin |
|---|---|
| Daemon | `sbx-avatard` (systemd `secubox-avatard.service`) |
| CLI | `sbx-avatar` |
| Socket | `/run/secubox/avatar.sock` (0660, groupe `secubox-avatar`) |
| Conf | `/etc/secubox/avatar.toml` |
| Vault | `/var/lib/secubox/avatar/vault/` (extension du vault gateway, même format) |
| Profils navigateur | `/var/lib/secubox/avatar/browsers/<service_id>/` |
| État | `/var/lib/secubox/avatar/state.db` (SQLite, WAL) |
| Assets barre | `/usr/share/secubox/avatar/bar/` (bundle JS/CSS) |

## 3. Modèle objet

### 3.1 `SbxIdentity`
```toml
[identity]
id          = "gandalf"            # un seul avatar en v1, schéma prêt pour n
display     = "Gandalf"
brands      = ["gondwana", "cybermind"]
```

### 3.2 `SbxServiceAccount` — un enregistrement par service
```
id            : slug unique ("facebook-perso", "signal", "peertube-gk2", "nextcloud")
kind          : oidc | api_token | cookies | signal_device | local
endpoint      : URL de base du service
auth_state    : VALID | EXPIRING | EXPIRED | LOCKED | UNKNOWN
expires_at    : datetime | null
last_check    : datetime
secrets_ref   : clé dans le vault (jamais le secret en clair dans state.db)
browser_bound : bool  # true → profil navigateur dédié, sous-module hors CSPN
cspn_scope    : bool  # false → exclu du périmètre certifié, flag affiché en UI
policy        : { renew: auto|manual, healthcheck_interval: "15m" }
```

### 3.3 Vault
- Réutilise le format du vault gateway (chiffrement au repos, clé dérivée du secret machine ; **pas** de second coffre).
- Espace de noms `avatar/<service_id>/…` : tokens, refresh tokens, clés signal-cli, exports de cookies si nécessaires.
- Les profils navigateur ne sont **pas** dans le vault (trop volumineux, mutables) : répertoire dédié, chiffré au niveau du volume, permissions 0700 `sbx-avatar:sbx-avatar`.

## 4. Sessions & healthchecks

- Timer systemd `secubox-avatar-health.timer` (défaut 15 min, par-service surchargeable).
- Healthcheck par `kind` :
  - `oidc` / `api_token` : appel léger authentifié (ex. `/api/v1/me`), refresh si `EXPIRING`.
  - `cookies` : requête GET sur une page authentifiée du service via le profil navigateur, détection de redirection login → `EXPIRED`.
  - `signal_device` : `signal-cli` JSON-RPC `listAccounts` / receive à vide.
- Transitions d'état émises sur le socket (événements) → la mosaïque met à jour les pastilles en direct.
- `LOCKED` (checkpoint Facebook, MFA requis…) : jamais de retry automatique, notification à l'humain.

## 5. Browser Pool (sous-module `avatar-browser`, hors CSPN)

- Paquet séparé `secubox-avatar-browser` (dépendance optionnelle, `Suggests:`), pour que le paquet cœur reste dans le périmètre certifié.
- Un profil Chromium persistant **par service** (`browsers/<service_id>/`), piloté par Playwright (Node ou Python, aligner sur le gateway).
- Deux modes :
  1. **Reconnexion assistée** : `sbx-avatar login <service_id>` ouvre une fenêtre (Xvfb + noVNC exposé sur l'UI locale) ; l'humain s'authentifie ; le profil garde tout. Aucune manipulation manuelle de cookies : le profil vit, l'avatar orchestre.
  2. **Actions** : les consommateurs (connecteur facebook-perso du gateway) demandent une action de haut niveau (`publish`, `fetch_saved`) ; le pool exécute dans le profil, cadence lente, jitter, un seul contexte à la fois par service.
- Verrou par profil (flock) : jamais deux automations simultanées sur la même session.
- Journalisation des actions (horodatage, service, action, résultat) — pas de contenu sensible.

## 6. API socket (varlink/JSON, même style que le gateway)

```
avatar.ListAccounts()            → [SbxServiceAccount sans secrets]
avatar.GetStatus(service_id)     → auth_state, expires_at, last_check
avatar.GetCredential(service_id) → secret (contrôle d'accès par groupe + policy)
avatar.RequestLogin(service_id)  → URL noVNC de reconnexion assistée
avatar.Invoke(service_id, action, payload)  → résultat (route vers browser pool ou API directe)
avatar.Watch()                   → flux d'événements d'état
```
- `GetCredential` : liste blanche des consommateurs (unités systemd identifiées par `SO_PEERCRED` + groupe), refus par défaut, journalisé.

## 7. UI — mosaïque & miroir

- Écran « Avatar » dans le portail SecuBox : grille des services, pastille **vert** (VALID) / **orange** (EXPIRING, LOCKED) / **rouge** (EXPIRED), badge « hors CSPN » sur les services `cspn_scope=false`.
- Bouton **Reconnecter** → `RequestLogin` → iframe noVNC.
- Le miroir (façade unifiée des services) consomme `ListAccounts` + `Watch` pour composer sa page.

## 8. Barre SSO personnelle

- **Barre** : bundle JS/CSS servi par la box (`/usr/share/secubox/avatar/bar/`), injecté :
  - via theming applicatif quand le service le permet (PeerTube plugin, Nextcloud theming),
  - sinon via le reverse-proxy de la box (sub_filter / injection `<script>` sur les vhosts internes).
  - Contenu : navigation commune, état avatar, lien mosaïque.
- **SSO réel** : ne PAS implémenter d'IdP maison. Intégrer **Kanidm** (ou Authelia) comme IdP OIDC de la box ; l'avatar provisionne les clients OIDC des services internes et stocke leurs secrets dans le vault. Le « SSO personnel développé maison » = la barre + l'orchestration avatar, pas le protocole.

## 9. Connecteurs gateway consommateurs (rappel de liaison)

- `signal` : `signal-cli` daemon JSON-RPC, device secondaire lié par QR (flux dans l'UI avatar), clés dans le vault. Push texte + pièces jointes.
- `facebook-page` : Graph API, token longue durée dans le vault, `cspn_scope=true`.
- `facebook-perso` : via Browser Pool, `cspn_scope=false`, `ownership=own` uniquement, publication cadencée.

## 10. Sécurité & durcissement

- Unité systemd : `DynamicUser=no`, user dédié `sbx-avatar`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/secubox/avatar`, `NoNewPrivileges`, `PrivateTmp`, `CapabilityBoundingSet=`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`.
- Browser pool dans une slice dédiée `sbx-avatar-browser.slice` avec limites mémoire/CPU ; candidat naturel à la jail cgroup+nft de `secubox-antirootkit` (binaire non-dpkg — cohérent avec l'anti-évasion).
- Cible de sécurité CSPN : chapitre explicite « fonctions hors périmètre » listant `secubox-avatar-browser` et les services `cspn_scope=false`, avec justification produit.
- Aucune donnée de session dans les logs ; rotation journald standard.

## 11. Plan d'implémentation TDD — 12 tâches

1. **T01** — Squelette paquet `secubox-avatar` (debhelper, unité systemd durcie, conf TOML, user/groupe). Test : installation propre, daemon démarre, socket présent.
2. **T02** — `state.db` SQLite + modèle `SbxServiceAccount` (CRUD, migrations). Tests unitaires modèle.
3. **T03** — Extension vault : espace `avatar/`, get/put chiffrés, tests de non-régression sur le vault gateway.
4. **T04** — API socket : `ListAccounts`, `GetStatus`, contrôle d'accès `SO_PEERCRED`. Tests d'intégration socket.
5. **T05** — `GetCredential` + liste blanche consommateurs + journalisation des accès. Tests refus par défaut.
6. **T06** — Healthchecks `oidc`/`api_token` + timer + transitions d'état + `Watch` (événements). Tests avec service OIDC mocké.
7. **T07** — Connecteur `signal` : liaison device (QR), vault, healthcheck, `Invoke(publish)`. Tests contre signal-cli en conteneur.
8. **T08** — Connecteur `facebook-page` : token Graph API, healthcheck `/me`, publish. Tests mock Graph.
9. **T09** — Paquet `secubox-avatar-browser` : pool Playwright, profils persistants, flock, Xvfb+noVNC, `RequestLogin`. Tests : création profil, verrou, session survit au restart.
10. **T10** — Healthcheck `cookies` + connecteur `facebook-perso` (`Invoke(publish)`, détection checkpoint → `LOCKED`). Tests sur site de test local mimant login/expiration.
11. **T11** — UI mosaïque : grille, pastilles temps réel via `Watch`, badge hors-CSPN, iframe noVNC. Tests e2e légers.
12. **T12** — Barre SSO : bundle JS, injection reverse-proxy + plugin PeerTube, provisioning clients OIDC Kanidm depuis l'avatar. Tests : barre visible sur deux services, login OIDC bout en bout.

**Ordre strict T01→T06 (cœur, périmètre CSPN), puis T07/T08 parallélisables, T09/T10 (hors CSPN), T11/T12.**

## 12. Critères d'acceptation v1

- [ ] Un consommateur autorisé obtient un credential valide sans jamais lire le vault directement.
- [ ] Pastilles d'état correctes après expiration forcée d'une session de test.
- [ ] Reconnexion assistée noVNC fonctionnelle sur un service `cookies`.
- [ ] Publication Signal et Facebook Page depuis le gateway via `Invoke`.
- [ ] `facebook-perso` publie un contenu `ownership=own`, refuse un contenu tiers.
- [ ] Paquet cœur installable sans `secubox-avatar-browser` ; tout `cspn_scope=false` clairement identifié en UI et dans la doc.

---

## WebOS Hall — intégration cookies/avatar (TODO, design-first)

Directives utilisateur (#1175, 2026-08-24) — **différé, design-first ; ne construire que ce dont l'injection WebOS-core a besoin** :

- **self-avatar = capteur de cookies côté serveur** : l'avatar « attrape » les sessions
  d'auth des services (admin webui, bbs, nextcloud, peertube, gitea, mail, …) et les
  **encapsule pour réemploi** dans un **cookies-catcher helper** (coffre serveur), jamais
  recopiées vers le navigateur client.
- **avatar reporter** : journalise/expose l'usage des sessions capturées (traçabilité,
  quels services activés pour quel avatar).
- **cookies profilés & activables** : par avatar, des cookies « personnalisés / profilés »
  qu'on **active** par service — le rejeu se fait DANS la box (pool navigateur headless),
  pas côté client (conforme brief §14 + CSPN, hors CSPN pour le pool).
- **sub-linings / encapsulation** : réutilisation encapsulée des sessions sous l'avatar.
- **Lien avec P6 (barre injectée)** : l'injection WebOS-core peut avoir besoin d'un minimum
  de contexte avatar pour relier/relayer (gateway linker). Ne construire ce minimum que
  si l'injection l'exige ; tout le reste (catcher complet, reporter, profils) reste TODO.

Rappel sécurité : **jamais de recopie de cookies vers le navigateur client**. Le rejeu
authentifié = coffre + pool navigateur souverain (dans la box).

## Avatar multi-utilisateur « famille » (émancipation depuis sessions captées)

TODO à créer/raffiner (capté 2026-08-24) : **émanciper l'avatar** à partir de
l'**agrégation des cookies/sessions captés** afin que **plusieurs utilisateurs d'un
foyer (famille)** bénéficient d'un **auth passif complet** par service, **sous contrôle
sysop** :
- un **avatar par membre** (ou par rôle), alimenté par le coffre de sessions ;
- **activation/révocation par service et par avatar** décidée par le sysop (allow-list) ;
- rejeu **DANS la box** (pool navigateur souverain), **jamais** de recopie de cookies
  vers le navigateur client (brief §14 / CSPN) ;
- traçabilité via l'**avatar reporter** (quel avatar a activé quel service, quand).
- Modèle mental : l'avatar **squatte** le nœud — session hôte consentie, invité borné
  par le périmètre sysop (« pas tout à fait chez lui, mais bien là »).

Lien : [`webos-sbx-hall-cardlets.md`] §24 (backlog WebOS realtime) — l'auth passive est
le mur derrière les embeds admin/services self-authentifiés du Hall.
