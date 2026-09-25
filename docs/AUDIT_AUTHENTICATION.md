# Audit — identifiants et authentification (SecuBox / SBX OS)

> #1405 · 2026-09-25 · lecture du code (worktree sur master `a5432d6`) + état vivant de gk2.
> Rien n'a été exécuté contre un compte réel ; les points non confirmés sont marqués **(à vérifier)**.
> Suite : [AUTH_V2.md](AUTH_V2.md) — le modèle cible.

## 0. En une page

**Le constat.** Une personne a aujourd'hui jusqu'à **six identités** qui ne se connaissent pas :
un compte `users.json`, un appareil `did:sbx`, un compte BBS (`handle`), un auteur Billets,
une identité Avatar, un pseudo Radio — plus un compte par service hébergé (Nextcloud,
PeerTube, Gitea, boîte mail), relié par le seul **nom**. Il existe **sept façons de se
connecter**, **quatre vérificateurs JWT** (dont trois ignorent la révocation) et **cinq
vocabulaires de rôles**.

**Ce qui est déjà bon, et que la refonte garde :**

- Aucun humain n'est un compte Linux (aucun UID ≥ 1000 sur gk2 ; aucune lecture de
  `/etc/passwd`, aucun PAM pour les humains). La séparation demandée existe *de fait*.
- L'appareil a une vraie clé : ECDSA P-256 WebCrypto **non exportable**, défi signé
  à usage unique (120 s), `did:sbx` dérivé de la clé.
- Le cœur (`secubox_core.auth`) révoque par `jti`, refuse les jetons à portée
  (`scope`), vérifie que le porteur existe encore.
- Le login complet (`secubox-auth`) : Argon2id, TOTP avec garde anti-rejeu, codes de
  secours, enrôlement TOTP forcé pour les admins.

**Ce qui doit disparaître :** la pile `secubox-portal` (SHA-256 non salé, secret de repli
`CHANGEME_INSECURE`), les jetons durables en `localStorage`, les vérificateurs JWT
recopiés en Go, les identités par en-tête ou par texte libre, les rôles lus dans le corps
d'une requête.

## 1. Inventaire vivant (gk2, 2026-09-25)

| Magasin | Contenu | Clé d'identité | Remarque |
|---|---|---|---|
| `/etc/secubox/users.json` (0640) | **3 comptes** : `admin`, `gk2` (admin, TOTP), `operator` (sans TOTP) | `username` | ce sont des comptes **système** (administration SecuBox) |
| `/etc/secubox/auth.toml` | `[users.admin]` mot de passe **en clair** | nom | repli si users.json illisible |
| `/etc/secubox/secubox.conf` `[auth.users.admin]` | mot de passe en clair (firstboot) | nom | écrit, **jamais lu** |
| `/var/lib/secubox/users/users.db` | **vide (0 octet)** | — | vestige |
| `/etc/secubox/appareils.json` (0640) | **12 appareils** : `compte` `sbx-…`, `did`, empreinte, profil, actif | `did:sbx` | registre des appareils admis |
| `/var/lib/secubox/acces/demandes.json` | **12 demandes** : clé publique, état, `compte` rattaché, `jtis` | `did:sbx` | file d'admission |
| `/etc/secubox/secrets/webos-acces/demandes.json` | 1 demande de **délégation de service** | `qui` (= `sub`) | même mot, autre concept |
| `/var/lib/secubox/auth/sessions.json` (**0644**) | **29 sessions** `{id=jti, username, ip, ua, expires}` | `jti` | **lisible par tous** |
| BBS `index.db` | **9 `users`** (`handle`, rôle sysop/member/guest, `auth_source`) + **37 sessions** propres (30 j) | entier + `handle` | lien SecuBox = égalité de chaînes |
| Billets `billets.db` | **1 `author`** avec son propre mot de passe et TOTP | `username` | aucun lien SecuBox |
| Avatar `identities.json` | 1 identité (uuid4) | `username` | parallèle, non reliée |
| Radio `radio.db` | pseudos de chat | entier choisi par le client | aucun lien |
| `/var/lib/secubox/identity/keys/identity.json` (**0666**) | identité **du nœud** (`did:plc`, Ed25519) | — | **inscriptible par tous** |
| `/etc/secubox/auth-runtime.json` (**0666**) | `require_admin_totp` | — | **inscriptible par tous** : désactiver le TOTP admin ? **(à vérifier)** |

## 2. Cookies et stockage navigateur

| Nom | Posé par | Attributs | Contenu | Lu par |
|---|---|---|---|---|
| `secubox_session` | `secubox_core.auth.set_session_cookie` (auth, acces) | HttpOnly, Secure, SameSite=**None**, Domain `.gk2.secubox.in` | JWT HS256 complet | tout le cœur, nginx `auth_request` (BBS), BBS, Billets |
| `secubox_token` | `secubox-portal` | HttpOnly, Secure, Strict | JWT portail **avec claim `role`** | portail seulement |
| `sbx_bbs` | BBS | HttpOnly, 30 jours | 32 octets aléatoires (haché en base) | BBS |
| `sbx_bbs_csrf`, `sbx_auto_non` | BBS | non HttpOnly | CSRF double-soumission, anti-boucle | BBS |
| `billets_session`, `billets_csrf`, `billets_visitor` | Billets | HttpOnly 12 h / — | `TimestampSigner(author_id)` | Billets |
| `sbx_radio`, `sbx_radio_nom` | JS Radio | lisible JS, 1 an | id et pseudo **choisis par le client** | Radio |
| `localStorage.sbx_token` | portail, relais Hall (`#sbx=`) | — | **jeton porteur 1 h à 24 h** | Hall, BBS admin, socialrelay, metablogizer, radio |
| `localStorage.secubox_role` | portail | — | `'admin'` **codé en dur pour tous** | UI |
| IndexedDB `sbx-acces/appareil` | `acces/appareil.js` | par **origine** | paire ECDSA non exportable | acces |

Le commentaire `auth.py:266` annonce SameSite=Lax ; le code pose `None`.

## 3. Jetons et sessions

- **Cœur** : HS256, `{sub, iat, exp, jti[, scope]}`, 24 h, **sans rôle** ; `jti` doit figurer
  dans `sessions.json` ; jetons à `scope` refusés ; porteur doit être actif.
- **Portail** : second émetteur (PyJWT), claim `role` cru tel quel, sessions en mémoire,
  secret de repli `CHANGEME_INSECURE`, `jti` jamais enregistré.
- **Hall** `POST /webos/jeton` : ré-émet 1 h **avec le même `jti`**, transporté dans le
  fragment d'URL (`#sbx=`) — rejouable 1 h, et **fixation de session** possible.
- **Acces** : session 7 jours par signature, 24 h par lien à usage unique ; défis et liens
  **en mémoire** (perdus au redémarrage).
- **Vérificateurs Go** recopiés (BBS `api.go:93`, socialrelay `jwt.go:20`, signal
  `jeton.go:104`) : signature + `exp` seulement — **ni `jti`, ni `scope`**, et Signal rend
  `exp` facultatif. Un jeton révoqué, ou un jeton pré-TOTP `mfa-challenge`, y passe.
- **Déconnexion** : ne supprime que le cookie ; le `jti` reste valide jusqu'à `exp`.

## 4. Rôles — cinq vocabulaires

| Où | Rôles |
|---|---|
| moteur users | admin / operator / viewer |
| RBAC `roles.json` | admin / operator / user / guest (**`viewer` absent** : un compte créé par l'API n'a aucune permission) |
| appareils (acces) | guest / user / admin |
| BBS | sysop / member / guest (`guest` jamais appliqué) — deux tables de correspondance **contradictoires** |
| ZIA | guest / registered / member / admin — **lu dans le corps de la requête** |

## 5. Appareils, admission, rattachement

Demande `POST /invitation/demande` (5/h/IP) → admin accepte (profil `guest`) →
défi signé → session. `rattacher` lie l'appareil à un compte humain : le `sub` du JWT
devient ce compte. `revoquer` coupe les `jti` connus.

Défauts : le serveur **ne lie pas le DID à la clé** (re-soumettre un DID remplace la clé
et rend l'ancien jeton de suivi) ; la session « par lien » n'est **pas** plafonnée à guest
et son `jti` n'est pas noté ; la clé vit **par origine** → un même téléphone peut avoir
plusieurs `did:sbx` (Hall, acces…).

## 6. Services hébergés

Aucun SSO. Lien par **nom** (Nextcloud, Gitea, BBS), nom avec `-`→`_` (PeerTube — bogue :
un nom à tiret devient introuvable), champ `email` (boîte mail), JID (Jabber). Création par
`secubox-usersctl-services` (sudo, JSON sur stdin) **et** par `secubox-user-sync` (autre
chemin). Mots de passe **sur la ligne de commande** pour Gitea, mail (`doveadm -p`),
Matrix, Jabber, GoToSocial ; **injection shell** possible au reset Nextcloud et Gitea.
Le Hall délègue Nextcloud (Login Flow v2) et Mastodon (OAuth — `state` non vérifié, CSRF).

## 7. Comptes système

`secubox` (utilisateur de service, sans shell) ; `secubox-<module>` dédiés ; comptes dans
les LXC. **Dangereux** : l'ISO d'installation et le multiboot créent `secubox` **avec un
shell et `NOPASSWD: ALL`** — le compte sous lequel tournent tous les modules.
`root:secubox` posé par tous les constructeurs d'image, `PermitRootLogin yes` jusqu'au
firstboot. ReelBox : **n'existe pas** dans le dépôt ; aucun abonnement de personne
(les « tiers » existants sont ceux d'une **box**, via le certificat fédéral).

## 8. Redondances — quoi garder, quoi supprimer

| # | Redondance | Décision |
|---|---|---|
| R1 | login complet (auth) / login hérité (47 modules) / portail / BBS local / Billets local / radio sysop / signature appareil / lien | **un** login humain (appareil → replay), **un** login système (auth, TOTP) ; le reste disparaît |
| R2 | deux piles JWT (cœur / portail) | supprimer le portail API |
| R3 | 4 vérificateurs JWT (Python + 3 Go) | un seul point de vérité : `/auth/verify` (révocation, capacités) ; les Go l'appellent |
| R4 | users.json / auth.toml / secubox.conf / users.db / avatar | users.json = **système** ; `sbx_users` = humains ; le reste supprimé |
| R5 | appareils.json + demandes.json (profil en double) | `sbx_devices` + `sbx_invites` |
| R6 | 5 vocabulaires de rôles | rôles SBX OS = profils de **capacités** (AUTH_V2 §3) |
| R7 | « demande d'accès » = admission d'appareil **et** délégation de service | deux noms, deux écrans |
| R8 | `sbx_token` / `secubox_token` / `secubox_user` / `secubox_role` en localStorage | aucun jeton durable côté navigateur |
| R9 | deux chemins de provisionnement (usersctl-services / user-sync) | un seul, sans mot de passe sur argv |
| R10 | `did:sbx` (P-256, appareils) et `did:plc` (Ed25519, nœuds) | gardés tous deux : l'un **signe** le certificat de l'autre |

## 9. Failles — par priorité

**Corrigée** : *P0 — contournement TOTP* (#1406, `secubox-core` 1.5.10, déployé) : la route
héritée `/api/v1/<module>/auth/login` ouvrait une session complète sur mot de passe seul,
joignable par le frontal public.

**P0 — exploitables maintenant, à corriger avant la refonte :**

| # | Faille | Preuve |
|---|---|---|
| S1 | `GET /users`, `/user/{u}`, `/export` rendent **hachés et secrets TOTP** à tout porteur de JWT (appareil guest compris) — `redact_user` jamais appelé | `users/main.py:473-493,1103-1112` |
| S2 | Les mutations de l'API users (créer, rôles, `revoke-all`…) n'exigent qu'un JWT : **un appareil guest peut se promouvoir** | `users/main.py` (routes `require_jwt`) |
| S3 | ZIA `POST /v1/chat` sans authentification, **rôle pris dans le corps** ; `POST /config` modifiable par tout JWT (URL du LLM) | `zia/api/main.py:191-246` |
| S4 | Radio : en-têtes `X-Sbx-Role: sysop` non filtrés et routes courtes admin atteignables par chemin | `radiod/main.go:172-218`, `web.go:125-150` **(à vérifier derrière sbxwaf)** |
| S5 | Vault : tourne en root, **tout secret lisible par tout JWT** | `vault/main.py:174-212` |
| S6 | `identity.json` et `auth-runtime.json` en **0666** | inventaire vivant §1 |
| S7 | Images ISO/multiboot : `secubox` avec shell et `NOPASSWD: ALL` | `build-installer-iso.sh:199-204` |

**P1 :** Signal partagé à tout utilisateur du Hall après un premier appairage ; Billets
`/admin/api/*` et metablogizer ouverts à tout JWT (guest compris) ; session BBS 30 j qui
survit à la révocation ; fixation de session par `#sbx=` ; `revoke-all` de l'API users
écrit un format qui casse le login ; `_SESSIONS_FILE` indéfini dans secubox-auth (sessions
expirées jamais purgées) ; comptes semés sans mot de passe réclamables par le premier venu
(pas le cas sur gk2 : les 3 comptes ont un haché) ; DID non lié à sa clé ; OAuth Mastodon
sans `state` vérifié.

**P2 :** mots de passe sur argv ; injection shell au reset Nextcloud/Gitea ; SameSite=None ;
`acces.toml` ignoré ; `PolicyError` en HTTP 500 ; README de secubox-identity trompeur
(SAML/OIDC annoncés, absents).

## 10. Sources

Trois audits de code parallèles (chaîne cœur ; Hall/BBS/Billets/apps ; services hébergés,
comptes système, ReelBox) et l'inventaire vivant de gk2. Chaque affirmation du détail
porte son `fichier:ligne` dans l'issue #1405.
