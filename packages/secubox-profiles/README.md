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

    secubox-profilectl apply <nom> [--yes]       # applique un profil (dry-run par défaut)
    secubox-profilectl rollback <snapshot> [--yes]  # restaure un snapshot (R1..R4)

    secubox-profilectl releve [--json]   # relevé de validation de cette box (#3212)
    secubox-profilectl coupe <unité> [--json]   # rc 0 si le profil actif coupe secubox-<id>.service|.timer (#3218)

`scan`, `status`, `diff` et `export` sont en lecture seule : ils lisent dpkg et la
config, ne touchent à rien. `apply` et `rollback` n'agissent qu'avec `--yes` ; sans
lui, ils décrivent seulement ce qu'ils feraient. `apply` est le SEUL décideur de ce
qui est allumé ou éteint (voir `docs/dossiers/simplification-modules-beta.md`).

## Profils & export

Cinq profils livrés dans `/usr/share/secubox/profiles/`, copiés dans `/etc/secubox/profiles/` par le postinst
(`/usr/lib/secubox/profiles/maj-references.py`, #3218) : absent, le profil est installé ; identique à une version
déjà LIVRÉE (empreintes sha256 de l'historique git, `empreintes-livrees.txt`), il est **remplacé** par la nouvelle
référence ; modifié par l'opérateur ou réécrit par le panneau, il est **gardé** et la nouvelle référence posée à
côté en `<nom>.toml.dpkg-dist`. Avant #3218, une mise à jour ne changeait jamais `/etc/secubox/profiles/minimal.toml`.
Après avoir modifié un profil de référence : `python3 scripts/gen-empreintes-livrees.py` (un test le rappelle).

| Profil | Usage |
|---|---|
| `full` | tous les modules |
| `lite` | protections (pendant du méta-paquet `secubox-lite`) ; ni KSM, ni Centres, ni DPI/nDPId (#3218) |
| `isp` | `lite` + DPI (nDPI, nDPId), NetFlow (Media Flow) et cabine numérique (toolbox, intercepteur) ; décision du 2026-10-29 (#3258) : le reste de `secubox-isp` (courrier, publication, métriques…) est arrêté par l'apply |
| `minimal` | carte de 1 Go sans tête (pendant de `secubox-minimal`) : garde DNS, ad-guard, webfilter, NAC, Freebox, WireGuard, socle et maillage (#3218) ; le sleeper n'y est pas (livré désactivé) |
| `secure-gateway` | passerelle durcie (firewall/WAF/IDS, pas de media) |
| `media-lab` | modules media (peertube, lyrion, photoprism…) en plus du socle |

Clés d'un profil :

| Clé | Rôle |
|---|---|
| `on` | ids allumés ; **exhaustif** : un module absent est arrêté et désactivé par `apply` — y compris un sleeper activé par l'opérateur : pour le garder, l'épingler (`sleeper = "on"` dans `pins.toml`). N'y lister que des services durables ou des oneshot `RemainAfterExit` : un oneshot de minuterie y serait démarré, ne deviendrait jamais actif et ferait annuler tout l'apply |
| `menu_off` | entrées de menu masquées tant que le profil est actif (lu par le hub, #2897) |
| `minuteurs_off` | minuteries (`secubox-<id>.timer`) arrêtées et désactivées (#3218). L'ensemble géré est l'union des `minuteurs_off` de tous les profils : un profil qui ne la nomme pas la **rétablit** (activée, démarrée). N'y nommer que des minuteries activées par défaut par leur paquet ; une unité absente du disque n'est pas gérée. Dans le plan : pseudo-module `minuteur:<id>`, priorité 10 |
| `proteges_off` | protégés coupés par ce profil, limités à `PROTEGES_COUPABLES` (`profiles` seul : la CLI `secubox-profilectl` reste) ; tout autre id (auth, aggregator…) fait refuser le profil au chargement (#3218) |

Le panneau, quand il bascule un module d'un profil, réécrit le fichier en gardant `menu_off`, `minuteurs_off` et
`proteges_off`. Le postinst de ce paquet demande `secubox-profilectl coupe <unité>` avant de réactiver ses unités : ce que le
profil actif coupe n'est plus rallumé à chaque mise à jour (#3218). Le profil `minimal` coupant l'API du panneau, le
panneau refuse de l'appliquer (409, `POST /api/v1/profiles/apply`) ; on l'applique par la CLI :
`secubox-profilectl apply --profile minimal --yes`.

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

## Profil léger « distante » (#3126 L5, tâche 7)

Variante de `minimal` pour une carte de 1 Go **sans interface d'administration locale** : la box est administrée par le
maître (pilotage TR-369). L'agent de pilotage déclare alors `Device.X_SECUBOX_Pilotage.Interface = "distante"` et le
maître sert lui-même `admin.<box>.secubox.in` (basculement « locale ⇄ distante », R-L5-27) ; le panneau « Flotte » du
maître ouvre la box par l'émission d'un code à usage unique.

- **Allumés** : socle (core, agrégateur, auth, system, network-ready, runtime, firstboot, net-fallback, autoload-agent,
  premier-pas), maillage (p2p, meshname), **pilotage** (`pilotage-agent`, `pilotage-relais`), boîtier de garde
  (webfilter, webfilter-feed, nac, freebox, ipv6guard) et **un seul groupe** `group@distante`.
- **Groupe** `secubox-group@distante` (`groups/distante.conf`, livré sous `/usr/share/secubox/profiles/groups/` — jamais
  dans `/etc/secubox/groups.d`, où il couperait le groupe des modules déclarés des autres profils) : hub, hardening,
  dns-guard, ad-guard, wireguard dans un interpréteur ; drop-in `secubox-group@distante.service.d/distante.conf` :
  `--veille 600 --veille-modules hub,hardening` (les fonctions de filtrage et le tunnel ne dorment jamais). Aucun module
  à socket dédiée, root, polkit ou compte propre dans le groupe.
- **Éteints** : nginx d'administration, portal, haproxy, WAF, waker, kiosque, console, **annuaire et assist**
  (R-L5-28, #3292), `groupe-declares` (ad-guard est servi par le groupe : jamais deux serveurs sur une socket).
- **`front_web = "etat"`** (`api/front_web.py`, après un apply complet réussi, audit `profiles_front_web`) : chaque
  entrée de `/etc/nginx/sites-enabled` est mise de côté dans `/var/lib/secubox-profiles/allegement/` (root 0700, jamais
  effacée), le gabarit `nginx/etat.conf` devient le seul site (`sites-available/secubox-etat`), `nginx -t` valide (échec :
  tout est rendu, rien n'est rechargé). Tout autre profil rend les sites et `aggregator.toml` d'origine.
- **`agregateur = "relais"`** : `/etc/secubox/aggregator.toml` sauvegardé puis remplacé par `modules = []` : l'agrégateur
  ne monte plus rien et relaie vers les sockets (un module seulement monté n'est plus joignable, R-L5-7).

### Page d'état locale (`/etat`)

Page HTML statique écrite par l'agent de pilotage toutes les 60 s (`/run/secubox/pilotage/etat.html`) : nom, maître
joignable ou non, mains liées, mémoire, services en échec. Aucun secret ni donnée personnelle (ni adresse, ni clé, ni
jeton, ni nom d'utilisateur). Gabarit `etat` : port 80, **LAN seulement** (`allow` 127.0.0.1, ::1, 10/8, 172.16/12,
192.168/16, fc00::/7, fe80::/10 ; `deny all`), une seule page (`/` → 302 `/etat`, tout le reste 404), GET seulement,
aucun relais vers une API ; CSP `default-src 'none'` + `style-src` limité à l'empreinte de la feuille de style de la
page, `frame-ancestors 'none'`, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `no-store`.

### Limites connues (sans annuaire)

L'annuaire apportait à une box trois fonctions qui **ne sont plus appliquées localement** sous ce profil (rien n'est
réimplémenté ici ; suite à créer) :

1. **Bans fédérés** (`secubox-annuaire-bans-apply`) : l'union des bans du maillage n'est plus chargée dans nft. La box
   garde son pare-feu local (DEFAULT DROP) ; seuls les bans fédérés manquent. Piste : le maître pousse la liste par le
   canal du pilotage (Operate d'action vers un verbe borné du ctl root, `secubox-pilotagectl bans-appliquer`, ensemble
   nft dédié remplacé atomiquement), sans interpréteur résident.
2. **Noms `.lan` / `.mesh`** (`secubox-annuaire-noms`) : la box ne publie plus ces noms (Unbound local, Bonjour). Le
   relais de noms du maître lit déjà le plan d'exposition de l'agent (T6) pour les noms publics ; pour les noms locaux,
   piste : fichier de zone poussé par le maître par le même canal, chargé par `unbound-control` (verrou, #2979).
3. **Configuration répliquée 4R** (`secubox-annuaire-apply`) : plus de réplication gondwana. Piste : opération du
   pilotage « appliquer la configuration » (double tampon + rollback 4R côté ctl root), déclenchée par le maître.

Mesure à faire sur la carte (gk5) après installation : `scripts/bench/mesure-box.sh` (RAM disponible ≥ 250 Mo, swap
≤ 50 %, CPU au repos ≤ 25 %, aucun service en boucle, démarrage ≤ 3 min).

## Fichiers

| Chemin | Rôle |
|---|---|
| `/etc/secubox/modules.d/<id>.toml` | manifeste module (cycle de vie) |
| `/etc/secubox/profiles/<nom>.toml` | profil (état désiré, exhaustif) |
| `/etc/secubox/profiles/pins.toml` | surcharges individuelles persistantes |
| `/etc/secubox/profiles/active` | nom du profil actif |
| `/usr/share/secubox/profiles/*.toml` | profils de référence livrés |
| `/usr/share/secubox/profiles/empreintes-livrees.txt` | sha256 de toutes les versions livrées des profils (#3218) |
| `/usr/lib/secubox/profiles/maj-references.py` | mise à jour des profils non modifiés, appelée par le postinst en root : préparée dans un dossier root seul sous /etc, renommée par descripteur sans suivre de lien, FIFO et liens laissés (#3218, relecture #3248) |
| `/var/lib/secubox/profiles/validation/releve.json` | relevé de validation de la box (#3212), écrit toutes les 5 min par `secubox-profiles-releve.timer` (compte dédié `secubox-profiles`, profil AppArmor `secubox-profiles-releve`, fichier 0640 au groupe secubox) |

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
| GET | `/api/v1/profiles/comparatif` | contenu des profils (méta-paquets) + profil actif et modules installés ici (`require_lecture`, #2819) |
| GET | `/api/v1/profiles/validation` | relevé de validation de cette box (`require_lecture`, #3212) ; 503 tant que le minuteur n'a pas tourné |

Écritures limitées à `/etc/secubox/profiles/<nom>.toml` et `pins.toml`
(atomique : fichier temporaire + `os.replace`) — c'est ce qui rend Phase 1
sûre : rien ne lit ces fichiers pour agir avant Phase 3.

Actuation is **observed-state-arbitrated**: a STOP/START succeeds only when the
module's real state (systemd unit, and the container for LXC) reaches the target
within a timeout derived from the unit's own systemd `TimeoutStop/StartUSec` — a
slow-but-successful transition is never mistaken for a failure.

Panel webui : `/profiles/` (hybrid-dark, cf. `.claude/WEBUI-PANEL-GUIDELINES.md`).

## Validation du parc (#3212)

`/profiles/comparatif.html#parc` compare **l'état réel** des box du maillage, sans le confondre avec les métadonnées
des profils (onglet « Profils déclarés »). Une ligne par paquet SecuBox, une colonne par box, quatre niveaux :

1. **attendu** — le paquet est dans la fermeture des `Depends` du méta-paquet de profil installé le plus haut sur la box
   (`recommande` pour ses `Recommends`, `hors_profil` s'il est installé sans être demandé) ;
2. **paquet** — version et statut dpkg (`iF`, `iU`… : configuration inachevée, donc erreur) ;
3. **services** — unités livrées par le paquet (`/var/lib/dpkg/info/<paquet>.list`) et modules montés dans l'agrégateur
   (`/health`) ;
4. **ressources** — mémoire des unités actives (cgroup entier), CPU en % d'un cœur depuis le relevé précédent.

États : `fonctionnel`, `veille` (module à la demande endormi), `arrete`, `erreur` (unité en échec, paquet inachevé,
échec de chargement dans l'agrégateur), `manquant` (demandé, pas installé), `absent`, `inconnu` (sonde en échec).
Ne sont **jamais** « arrêtées » : une unité lancée par un minuteur, non activée au démarrage, dont la condition de
démarrage n'est pas remplie, un oneshot terminé avec succès, un module servi par l'agrégateur.

Chaîne : `secubox-profilectl releve` (ce paquet, sans privilège) → `sbx-fleetctl publish-modules` (secubox-annuaire,
signature Ed25519 de la box) → `GET /api/v1/annuaire/fleet/modules/self` sur l'écoute du maillage (:8799) →
`GET /api/v1/annuaire/fleet/modules` (JWT) rassemble les box et nomme celles sans relevé lisible. Une sonde en échec
rend le relevé **partiel**, annoncé dans l'en-tête de la colonne. Lecture seule.

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
