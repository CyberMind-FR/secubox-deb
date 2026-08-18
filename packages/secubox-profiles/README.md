<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-profiles

Inventaire et profils des modules SecuBox. **Phase 1 : lecture seule.**
**0.4.0+ : actuation (apply/rollback). 0.8.0 (ref #896) : scale-to-zero
(lifecycle/wake_class, waker, sleeper).**

## Commandes

    secubox-profilectl scan [--force]   # dérive les manifestes du réel
    secubox-profilectl status [--json]  # état, taxonomie et coût RAM par module
    secubox-profilectl diff --profile <nom> [--json]   # ce qu'un profil changerait
    secubox-profilectl export <nom> [--format pkglist|apt|json]  # paquets d'un profil

`apply` n'existe pas encore (Phase 3) : rien n'est jamais allumé ni éteint ici.
`export` aussi est lecture seule : il lit dpkg + la config, ne touche à rien.

## Profils & export

Quatre tiers livrés (seedés dans `/etc/secubox/profiles/` à l'install, sans
jamais écraser un fichier déjà édité par l'opérateur) :

| Profil | Usage |
|---|---|
| `full` | tous les modules |
| `lite` | socle minimal (sécurité + admin) |
| `secure-gateway` | passerelle durcie (firewall/WAF/IDS, pas de media) |
| `media-lab` | modules media (peertube, lyrion, photoprism…) en plus du socle |

**Piège pins** : un module pinné `off` reste listé par `diff` (le pin est une
surcharge d'état désiré, pas une suppression du module de l'inventaire) — il
n'apparaît simplement plus dans le futur état ON. Ne pas confondre "absent du
profil" et "pinné off" en lisant une sortie `diff`.

`export <nom>` résout l'ensemble ON du profil (profil + pins, comme `diff`),
mappe chaque module vers son paquet Debian (`dpkg -S` sur les units, repli
`secubox-<id>`), et imprime :

| `--format` | Sortie |
|---|---|
| `pkglist` (défaut) | un paquet par ligne, triés |
| `apt` | `apt-get install -y <pkg> <pkg> …` prêt à coller |
| `json` | `{profile, on_ids, packages, unresolved, rss_estimate_mo}` |

Un module dont le paquet reste introuvable part dans `unresolved` (imprimé sur
stderr, `⚠️`) — jamais silencieusement omis de l'installateur.

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
| POST | `/api/v1/profiles/active` | `{"name"}` — change le profil actif (fichier `active`, pas d'actuation) |
| POST | `/api/v1/profiles/apply` | applique le profil actif (webui→ctl : sudo `secubox-profilectl apply --yes --json`) — snapshot 4R + audit, rollback auto si échec |
| POST | `/api/v1/profiles/rollback` | recharge le dernier snapshot 4R (webui→ctl : `secubox-profilectl rollback --yes --json`) |
| POST | `/api/v1/profiles/wake` | `{"id"}` — réveille manuellement UN module on-demand (webui→ctl, **synchrone** : `secubox-wakectl wake <id> --json`) |
| POST | `/api/v1/profiles/sleep` | `{"id"}` — endort manuellement UN module sleepable (webui→ctl : `secubox-profilectl apply --only <id> --yes --json`) |

Écritures limitées à `/etc/secubox/profiles/<nom>.toml` et `pins.toml`
(atomique : fichier temporaire + `os.replace`) — c'est ce qui rend Phase 1
sûre : rien ne lit ces fichiers pour agir avant Phase 3.

Actuation is **observed-state-arbitrated**: a STOP/START succeeds only when the
module's real state (systemd unit, and the container for LXC) reaches the target
within a timeout derived from the unit's own systemd `TimeoutStop/StartUSec` — a
slow-but-successful transition is never mistaken for a failure.

Panel webui : `/profiles/` (hybrid-dark, cf. `.claude/WEBUI-PANEL-GUIDELINES.md`).

## Manifeste

    id         = "peertube"
    category   = "media"     # media|security|network|infra|dev|mesh
    runtime    = "lxc"       # native|lxc
    exposure   = "public"    # public|lan|internal
    units      = ["secubox-peertube.service"]
    lxc        = "peertube"
    portal     = { domain = "peertube.gk2.secubox.in" }
    priority   = 40          # 0-100
    protected  = false       # true = jamais éteignable
    needs      = ["auth"]
    lifecycle  = "on-demand" # always-on|eager|on-demand|manual (défaut: always-on)
    wake_class = "normal"    # normal|urgent (défaut: normal)

Un manifeste corrigé à la main fait autorité : `scan` ne l'écrase pas sans `--force`.

## Scale-to-zero — lifecycle, waker, sleeper (ref #896)

Chaque module déclare un `lifecycle` dans son manifeste
(`/etc/secubox/modules.d/<id>.toml`) :

| `lifecycle` | Démarre au boot ? | Rendormi si idle ? | Réveillé sur accès ? |
|---|---|---|---|
| `always-on` **(défaut)** | oui, toujours | jamais | — (jamais éteint) |
| `eager` | oui | oui (si idle et sans réponse `/idle`) | oui (déjà up en général) |
| `on-demand` | non | oui | oui — `sbxwaf` proxy vers le waker |
| `manual` | non | non | non — opérateur uniquement (`/wake` panel) |

Le défaut est `always-on`, pas `eager` : sur une flotte de 184 modules, un
manifeste sans opinion propre (donc la majorité) ne doit jamais devenir
sleep-eligible par accident. Le sommeil est un **opt-in explicite** —
`eager` ou `on-demand` doit être déclaré à la main dans le manifeste pour
qu'un module participe au sleeper/waker.

Un module `protected = true` est **toujours** `always-on`, quoi que déclare
son `lifecycle` (`effective_lifecycle`, `api/lifecycle.py`) — le cœur ne dort
jamais. `wake_class = "urgent"` multiplie le seuil d'inactivité avant sommeil
(×4) et réduit le budget de réveil affiché (15s au lieu de 45s) — pour les
modules qu'on préfère garder chauds plus longtemps mais réveiller vite s'ils
dorment quand même.

**Le sommeil (`secubox-sleeper.service`, daemon root, tick 30s)** — construit
un plan STOP pour chaque module `eager`/`on-demand` observé up, idle depuis
`idle_threshold()`, sans connexion active, et sans verrou de réveil en cours
(`/run/secubox/waker-active.json`) — et le confie à l'actionneur 0.7.0
(`apply_plan` : snapshot 4R, audit, timeout dérivé, rollback si échec). Ne
dort **jamais** sur un signal indéterminé (fichier de signaux absent/vide,
sonde `/idle` muette) — l'incertitude protège toujours l'état "up".

**Le réveil (`secubox-waker.service`, `User=secubox`, socket
`/run/secubox/waker.sock`)** — `sbxwaf` (Go, `packages/secubox-toolbox-ng`)
proxy une requête vers un vhost on-demand sans route active vers
`/_wake/<vhost>` au lieu de répondre 421. Le waker résout vhost→module, pose
un verrou par module (une requête déclenche le réveil, N requêtes
concurrentes attendent le même réveil), tire `sudo→systemd-run→
secubox-wakectl wake <id>` (fire-and-forget, webui→ctl — le waker ne pilote
jamais systemd/LXC en direct) et sert le splash `templates/waking.html`
(503 + `Retry-After`, palette hybrid-dark, auto-refresh) le temps du réveil.

**Config générée pour les consommateurs** (`secubox-wakectl waf-sync` /
`health-sync`, exécutés au postinst et re-exécutables à la main après un
`scan`) :

| Fichier | Consommateur | Contenu |
|---|---|---|
| `/etc/secubox/waf/on-demand-vhosts.json` | `sbxwaf` | domaines portail des modules `eager`/`on-demand` routés — décide "proxy vers le waker" vs 421 |
| `/etc/secubox/health/sleepable-modules.json` | `secubox-hub` (moniteur santé) | ids des modules sleepables — distingue "volontairement endormi" de "en panne" |

`api/nginxgen.py`/`nginx-sync` (Tâche 7) restent dans l'arbre mais **ne sont
plus câblés** — PIVOT (2026-07-20) : le déclencheur de réveil est `sbxwaf`,
pas un `location @waker` nginx.

**Procédure pilote** (un module `on-demand` à la fois, avant généralisation) :

1. Éditer `/etc/secubox/modules.d/<id>.toml` : `lifecycle = "on-demand"`
   (et `wake_class` si le module doit rester chaud plus longtemps).
2. `secubox-wakectl waf-sync && secubox-wakectl health-sync` (ou attendre le
   prochain postinst — mais après une simple édition manuelle du manifeste,
   régénérer à la main pour que `sbxwaf` voie le nouveau vhost tout de suite).
3. `secubox-profilectl apply --only <id> --yes --json` pour l'endormir une
   première fois (ou attendre le prochain tick idle du sleeper).
4. Visiter le vhost à froid : la première requête doit voir le splash 503
   puis, après `wake_budget()` secondes, le service réel.
5. Surveiller `/var/log/secubox/audit.log` (entrées `wake-on-access` /
   `idle-sleep`) et `journalctl -u secubox-waker -u secubox-sleeper`.
6. `lifecycle = "manual"` si le pilote révèle un réveil trop lent/fragile
   pour un accès non annoncé — le module reste éteignable/allumable
   seulement depuis le panel.

## Tests

    python3 -m pytest packages/secubox-profiles/tests -q
