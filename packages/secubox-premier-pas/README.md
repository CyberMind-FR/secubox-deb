<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-premier-pas

SecuBox Premier Pas — first-boot wizard engine and silent profile.

One engine, one profile (profil.toml), four faces: kiosk, console, master panel and silent. premier-pasctl validates a profile step by step (name, clock, admin, network and domain, services, mesh, updates), shows the exact plan, and applies it by driving the existing SecuBox tools (hostnamectl, timedatectl, secubox-users engine, secubox-net-detect, secubox-profilectl, sbx-mesh-join). An incomplete profile is never half-applied: the wizard resumes at the missing step. Never stores a plaintext password.

Also ships secubox-majauto: nightly unattended upgrade of the SecuBox packages only, from the signed apt.secubox.in repository.

Paquet Debian : version `0.4.9-1~bookworm1`, architecture `all`.

## Contenu

- `api/` : API FastAPI
- `exemples/` : fichiers du module
- `kiosque/` : fichiers du module
- `menu.d/` : entrée de menu
- `premier_pas/` : fichiers du module
- `sbin/` : exécutables
- `systemd/` : unités systemd
- `tests/` : tests
- `www/` : interface web

## Exécution

- `secubox-majauto.service` : SecuBox — mises à jour automatiques des paquets SecuBox (#1522), lance `secubox-majauto`
- `secubox-majauto.timer` : SecuBox — mises à jour automatiques, chaque nuit (#1522)
- `secubox-premier-pas-appliquer.path` : SecuBox Premier Pas — une face demande l'application du profil (#1522)
- `secubox-premier-pas-appliquer.service` : SecuBox Premier Pas — application du profil rempli par une face (#1522), lance `premier-pasctl`
- `secubox-premier-pas-console.service` : SecuBox Premier Pas — assistant du premier démarrage, face console (tty1) (#1522), lance `premier-pas-console`
- `secubox-premier-pas.service` : SecuBox — premier démarrage : profil prêt appliqué, sinon assistant (#1522), lance `premier-pasctl`

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/etat` | aucune |
| `GET` | `/choix` | aucune |
| `PUT` | `/etape/{etape}` | aucune |
| `POST` | `/appliquer` | aucune |
| `GET` | `/code` | aucune |
| `POST` | `/proposition` | aucune |
| `POST` | `/proposition/accepter` | aucune |
| `POST` | `/proposition/refuser` | aucune |
| `GET` | `/maitre/profils` | aucune |
| `GET` | `/maitre/profils/{nom}` | aucune |
| `PUT` | `/maitre/profils/{nom}` | aucune |
| `DELETE` | `/maitre/profils/{nom}` | aucune |
| `GET` | `/maitre/profils/{nom}/export` | aucune |
| `POST` | `/maitre/pousser` | aucune |
| `GET` | `/maitre/distant` | aucune |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-core`.

## Tests

4 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-premier-pas`.
