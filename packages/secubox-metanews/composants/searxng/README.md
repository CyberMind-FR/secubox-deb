<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SearXNG — métamoteur interne (composant de secubox-metanews)

Remplace YaCy (#3581). SearXNG interroge plusieurs moteurs et rend une page de résultats ; il tourne dans un conteneur
LXC et **n'est exposé nulle part** : ni vhost, ni nom public, ni route WAF. La page d'administration `/searxng/` et l'API
`/api/v1/searxng/` passent par le vhost d'administration.

## Architecture

| Couche | Où | Qui |
|---|---|---|
| Conteneur LXC `searxng` | `/data/lxc/searxng` (`lxc.path` du TOML), non privilégié (idmap 0 → 100000), Debian de l'hôte (trixie), `lxc.start.auto = 1`, mémoire 384 Mio | root |
| SearXNG | commit figé `3e95f6cd2a68` (2026.11.5+3e95f6c), venv `/usr/local/searxng/venv`, unité `searxng.service`, écoute **10.100.0.85:8888** seulement | utilisateur `searxng` du conteneur |
| API hôte | `secubox-searxng.service`, socket `/run/secubox/searxng.sock`, AppArmor `secubox-searxng-api` (enforce) | `secubox-searxng` (dédié) |
| Contrôleur | `/usr/sbin/searxngctl` | root (lectures : n'importe qui) |

Serveur d'application : celui que fournit `requirements-server.txt` (granian, sinon uwsgi), à défaut `python -m searx.webapp`
— choisi à l'installation, noté dans `/usr/local/searxng/.serveur` du conteneur.

## Installation sur une box

```bash
apt-get install secubox-metanews          # API, page, contrôleur ; ne crée PAS le conteneur
searxngctl install                        # root : conteneur, SearXNG, secret, settings.yml (long au premier passage)
searxngctl status                         # sans privilège
```

`searxngctl install` est idempotent : un second appel ne retélécharge rien et ne redémarre rien. Il exige le pont
`br-lxc` (secubox-netmodes / secubox-core) ; la sortie du conteneur vers Internet est celle de `secubox-lxc-reseau`.

## Configuration — `/etc/secubox/searxng.toml`

Modèle : `/usr/share/secubox/searxng/searxng.toml.example` (copié au premier passage). Sections `[lxc]` (nom, adresse,
passerelle, pont, chemin, mémoire, DNS) et `[searxng]` (port, nom de l'instance, langue, safe_search, délais sortants,
suspension des moteurs en échec, `moteurs_desactives`). Une clé inconnue est refusée.

`settings.yml` est **généré** (`use_default_settings: true`, `limiter: false`, `public_instance: false`, `image_proxy: false`,
`enable_metrics: false`, `formats: [html, json]`, `default_locale: fr`, `request_timeout` 3 s, `max_request_timeout` 6 s,
`ban_time_on_fail` 5 s → `max_ban_time_on_fail` 120 s). Aucune vérification anti-robot des moteurs n'est contournée.

**Secret** : `server.secret_key` n'est jamais dans le TOML ni dans `settings.yml`. `searxngctl install` le crée une fois dans
`/etc/secubox/secrets/searxng/secret_key` (root 0600) et l'écrit dans `/etc/searxng/searxng.env` du conteneur (0600), lu par
systemd (`SEARXNG_SECRET`).

Après une modification : `searxngctl reload` ou le bouton « Recharger la configuration » de la page. Double tampon :
`settings.yml.nouveau` écrit, relu et validé (YAML, clés attendues, aucun secret), l'ancien gardé en `settings.yml.precedent`,
remplacement atomique, relance, sonde `/healthz` (30 s) ; si SearXNG ne répond plus, l'ancien fichier revient. Chaque issue
(`applique`, `refuse`, `retour-arriere`, `echec`, `conteneur-arrete`) est une ligne JSON de `/var/log/secubox/audit.log`.

## API — `/api/v1/searxng/`

| Route | Garde | Rôle |
|---|---|---|
| `GET /health` | publique | sonde |
| `GET /status` | `require_lecture` | `overall` (green/yellow/red), `conteneur`, `service`, `api`, `adresse` |
| `GET /components` | `require_lecture` | `lxc`, `searxng`, `host-api` |
| `GET /engines` | `require_lecture` | moteurs actifs (`/config` de SearXNG), désactivés (TOML), sans réponse à la dernière recherche |
| `GET /rechercher?q=&page=` | `require_jwt` | `q` 1-256 caractères, `page` 1-50 ; au plus 20 `{titre, url, extrait, moteur}`, URL http(s) seulement |
| `POST /reload` | `require_jwt` | `searxngctl reload` (sudo + systemd-run, argv exact) ; 409 refusé/défait/occupé, 504 délai |

Les sondes ne demandent aucun privilège (connexion TCP vers le conteneur, `/healthz`), partent en parallèle et sont bornées
(< 5 s au total) ; une sonde en retard vaut `unknown`, jamais une 500. Le relevé est gardé 10 s (`/var/cache/secubox-searxng`).

## Tests

```bash
python3 -m pytest -q packages/secubox-metanews/composants/searxng/tests
```

Hors réseau (boucle locale seulement) ; la page est testée dans Chromium si Playwright est présent.

## Licence

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2026. Voir [LICENCE-CMSD-1.0.md](../../../../LICENCE-CMSD-1.0.md).
