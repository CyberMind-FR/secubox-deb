<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Le fournisseur OpenID Connect de SecuBox

Référence à partager : comment une application tierce ouvre le compte d'une personne d'après sa session SecuBox, sans mot de
passe. Rédigée le 2026-10-25 d'après le code (`packages/secubox-auth/composants/oidc/`) et vérifiée sur gk2. Issues liées : #3154
(La Suite Meet), #3155 (écarts à combler).

## En une page

- Chaque box est son propre **émetteur** (issuer) : `https://hall.<domaine de la box>/oidc`. Exemple : `https://hall.gk2.secubox.in/oidc`.
- Flux **code d'autorisation + PKCE (S256)**, jetons signés **RS256** par une clé propre à la box, clé publique publiée en JWKS.
- L'identité vient de la **session SecuBox** (cookie `secubox_session`, valable sur tout le domaine de la box). Seule une session qui
  désigne une **personne** authentifie. Un appareil non rattaché, un compte système seul ou la lecture sans connexion du LAN
  n'ouvrent aucun compte ailleurs.
- Le fournisseur n'a **ni mot de passe, ni écran de connexion** à lui : il s'appuie sur la connexion du Hall.
- Livré par le paquet `secubox-auth` (composant `oidc` ; `secubox-oidc` n'est plus qu'un paquet de transition). Monté par
  l'agrégateur sous `/api/v1/oidc`, exposé par le Hall sous `/oidc/`.

## Points d'accès

Découverte : `GET <issuer>/.well-known/openid-configuration`.

| Point | Rôle |
|---|---|
| `GET /authorize` | Demande d'autorisation (navigateur). `response_type=code`, `scope` contenant `openid`, `client_id`, `redirect_uri` exacte, `state`, `nonce`, `code_challenge` + `code_challenge_method=S256`. |
| `POST /token` | Échange du code. Authentification du client par `client_secret_basic` ou `client_secret_post`. Renvoie `access_token`, `id_token`, `token_type=Bearer`, `expires_in`. |
| `GET\|POST /userinfo` | Revendications de la personne, avec `Authorization: Bearer <access_token>`. |
| `GET /jwks` | Clé publique de signature. |
| `GET /health` | État du fournisseur et présence de la clé. |

Valeurs publiées par la découverte : `response_types_supported=[code]`, `grant_types_supported=[authorization_code]`,
`id_token_signing_alg_values_supported=[RS256]`, `scopes_supported=[openid, profile, email]`,
`code_challenge_methods_supported=[S256]`.

## Ce que l'application apprend de la personne

| Revendication | Valeur |
|---|---|
| `sub` | identifiant stable de la personne (`user_uuid` de SBX ID) |
| `preferred_username` | le compte lié à l'application s'il existe, sinon le pseudo |
| `name`, `nickname` | le pseudo de la personne |
| `email` | la boîte liée à la personne si elle en a une, sinon `<pseudo>@<domaine de la box>` |
| `email_verified` | vrai seulement si la boîte est réellement liée ; faux pour l'adresse synthétique |
| `auth_time` | instant de l'authentification |

Rien d'autre n'est transmis : ni rôle, ni appartenance à une communauté, ni identifiant d'appareil.

## Durées et garanties

- **Code** : à usage unique (même après un échec), 60 s, lié au client, à la `redirect_uri` exacte et au défi PKCE.
- **Jeton d'accès** : 600 s. **id_token** : 300 s. Pas de jeton de rafraîchissement.
- Codes, jetons d'accès et secrets de clients ne sont gardés que **hachés** (SHA-256), dans `/var/lib/secubox/oidc/oidc.db` (SQLite).
- `redirect_uri` : **égalité stricte** avec une adresse enregistrée, vérifiée avant toute redirection (pas de redirecteur ouvert).
- L'émetteur vient de la configuration, **jamais de l'en-tête Host**.
- Clé de signature : `/etc/secubox/secrets/oidc/signing.pem` (RSA, mode 0600, jamais réécrite par une mise à jour).

## Enregistrer une application

Réservé à root. Le secret est imprimé **une seule fois** ; seule son empreinte reste sur la box.

```sh
secubox-oidcctl client-add visio \
    --name "Visio" \
    --redirect https://visio.<domaine>/api/v1.0/callback/     # exemple : l'adresse exacte est celle que l'application annonce
secubox-oidcctl client-ls          # liste, jamais de secret
secubox-oidcctl client-rm visio
```

`--app APP` relie le client à un compte d'application SBX ID pour `preferred_username`. Le registre est
`/etc/secubox/oidc/clients.json` (identifiants `[a-z0-9][a-z0-9_-]{1,40}`).

## Qui entre

Toute personne SBX ID authentifiée, **invités compris** (rôle `guest` : une invitation crée une personne, donc une identité).
Un compte système ou un appareil non rattaché n'entre pas. Une restriction par rôle ou capacité, par client, est prévue
(#3155, écart 2) ; sans elle, le comportement est celui-ci.

## Brancher une application (valeurs à saisir côté application)

| Réglage | Valeur |
|---|---|
| Émetteur | `https://hall.<domaine>/oidc` |
| Autorisation | `<issuer>/authorize` |
| Jeton | `<issuer>/token` |
| Infos utilisateur | `<issuer>/userinfo` |
| Clés | `<issuer>/jwks` |
| Algorithme | `RS256` |
| Portées | `openid email profile` |
| PKCE | `S256` (recommandé) |
| Identifiant et secret | ceux de `client-add` |

Application derrière Django (`mozilla-django-oidc`, c'est le cas de La Suite Meet) : `OIDC_OP_AUTHORIZATION_ENDPOINT`,
`OIDC_OP_TOKEN_ENDPOINT`, `OIDC_OP_USER_ENDPOINT`, `OIDC_OP_JWKS_ENDPOINT`, `OIDC_RP_SIGN_ALGO=RS256`, `OIDC_RP_SCOPES="openid email"`.

## Limites actuelles

À connaître avant de partager ce fournisseur avec d'autres (suivi : #3155) :

1. ~~Sans session, impasse.~~ **Corrigé (#3155).** Sans session, `/authorize` renvoie vers `/login.html?redirect=/oidc/authorize?…`
   et la personne revient seule sur sa demande. Une session valide sans personne rattachée (compte système, appareil non rattaché)
   reçoit une page explicative (403) au lieu de tourner en rond.
2. **Aucune politique d'accès par client.** Toute personne authentifiée de la box obtient un compte dans toute application
   enregistrée.
3. **Ni déconnexion ni rafraîchissement.** Pas de `end_session_endpoint`, pas de `refresh_token`. Se déconnecter de l'application
   ne ferme pas la session SecuBox.
4. **Adresse électronique synthétique** quand aucune boîte n'est liée (`email_verified=false`) : certaines applications la refusent.
5. **Un émetteur par box.** Une personne d'une autre box du maillage ne peut pas se connecter à une application hébergée ici.
6. **Un service en conteneur** doit joindre l'émetteur sous son nom public (l'`iss` des jetons est comparé tel quel).

## Partager avec une autre box ou un tiers

- **Un tiers sur la même box** (application, conteneur) : un `client-add` suffit, avec sa `redirect_uri` exacte.
- **Une autre box du maillage** qui veut faire confiance à cet émetteur : elle aurait besoin de l'URL de découverte et du JWKS
  de la box, puis d'un client enregistré ici pour son service. Ce n'est pas câblé : une confiance entre émetteurs (fédération
  d'identité par l'annuaire) reste à concevoir et ne fait pas partie de #3154.
- **Ne jamais** copier `signing.pem` d'une box à l'autre : chaque box signe avec sa propre clé.
