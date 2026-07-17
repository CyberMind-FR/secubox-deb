# secubox-profiles

Inventaire et profils des modules SecuBox. **Phase 1 : lecture seule.**

## Commandes

    secubox-profilectl scan [--force]   # dérive les manifestes du réel
    secubox-profilectl status [--json]  # état, taxonomie et coût RAM par module
    secubox-profilectl diff --profile <nom> [--json]   # ce qu'un profil changerait

`apply` n'existe pas encore (Phase 3) : rien n'est jamais allumé ni éteint ici.

## Fichiers

| Chemin | Rôle |
|---|---|
| `/etc/secubox/modules.d/<id>.toml` | manifeste module (cycle de vie) |
| `/etc/secubox/profiles/<nom>.toml` | profil (état désiré, exhaustif) |
| `/etc/secubox/profiles/pins.toml` | surcharges individuelles persistantes |
| `/etc/secubox/profiles/active` | nom du profil actif |

`menu.d/` reste la source UI (path, ordre, icône) et n'est pas dupliqué ici.

## API web (`/profiles/`, socket dédié)

Service systemd propre (`secubox-profiles.service`, `/run/secubox/profiles.sock`)
— **jamais servi par l'aggregator** : le moteur de profils ne doit pas dépendre
de quelque chose qu'il pourrait plus tard redémarrer. JWT obligatoire sur
toutes les routes (`Depends(require_jwt)`).

| Méthode | Route | Rôle |
|---|---|---|
| GET | `/api/v1/profiles/status` | inventaire (état tri-state on/off/unknown, coût RAM, agrégats catégorie/runtime/exposure) |
| GET | `/api/v1/profiles/profiles` | liste des profils + profil actif |
| GET | `/api/v1/profiles/pins` | pins courants |
| GET | `/api/v1/profiles/diff?profile=<nom>` | plan de changements (**n'applique rien**) — 404 si profil inconnu, 409 si `ProtectedViolation` |
| POST | `/api/v1/profiles/profiles/{name}/members` | `{"id","on"}` — ajoute/retire un module de la liste `on` d'un profil (404 id/profil inconnu) |
| POST | `/api/v1/profiles/pins` | `{"id","pin":"on"\|"off"\|null}` — pose/lève un pin ; **409 et rien d'écrit** si `pin="off"` sur un module protégé |

Écritures limitées à `/etc/secubox/profiles/<nom>.toml` et `pins.toml`
(atomique : fichier temporaire + `os.replace`) — c'est ce qui rend Phase 1
sûre : rien ne lit ces fichiers pour agir avant Phase 3.

Panel webui : `/profiles/` (hybrid-dark, cf. `.claude/WEBUI-PANEL-GUIDELINES.md`).

## Manifeste

    id        = "peertube"
    category  = "media"     # media|security|network|infra|dev|mesh
    runtime   = "lxc"       # native|lxc
    exposure  = "public"    # public|lan|internal
    units     = ["secubox-peertube.service"]
    lxc       = "peertube"
    portal    = { domain = "peertube.gk2.secubox.in" }
    priority  = 40          # 0-100
    protected = false       # true = jamais éteignable
    needs     = ["auth"]

Un manifeste corrigé à la main fait autorité : `scan` ne l'écrase pas sans `--force`.

## Tests

    python3 -m pytest packages/secubox-profiles/tests -q
