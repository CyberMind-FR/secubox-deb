<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-oidc

SecuBox OIDC — fournisseur OpenID Connect adossé à la session SecuBox.

Un service de la box (PhotoPrism, Mastodon…) ouvre le compte d'une personne d'après sa session SecuBox, sans mot de passe. Flux code + PKCE, id_token RS256, codes à usage unique ; seule une session qui désigne une personne authentifie. Clients enregistrés par secubox-oidcctl.

Paquet Debian : version `0.1.2-1~bookworm1`, architecture `all`.

## Contenu

- `api/` : API FastAPI
- `conf/` : configuration livrée
- `sbin/` : exécutables
- `tests/` : tests

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/health` | aucune |
| `GET` | `/.well-known/openid-configuration` | aucune |
| `GET` | `/jwks` | aucune |
| `GET` | `/authorize` | aucune |
| `POST` | `/token` | aucune |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-aggregator`, `secubox-core`.

## Tests

1 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-oidc`.
