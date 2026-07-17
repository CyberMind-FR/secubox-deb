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
