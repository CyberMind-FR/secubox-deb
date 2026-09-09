<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->

# Audit d'allègement gk2 — 2026-09-07

Croise **mesures live** (gk2, Armada 7040, 8 Go) et **inventaire dépôt** (184 paquets).
Complète `.claude/PHASE-6.P-MEMORY-OPTIMIZATION.md` (le plan chiffré préexistant).

## 1. Constat terrain (mesuré)

- RAM 6,1/7,9 Go utilisés, **~130-340 Mo libres**, **~3,5 Go de SWAP actif** → gk2
  **swappe en continu** = le `load ~5` + `kswapd0`. **Descendre sous la RAM physique
  supprime le swap → la charge s'effondre.** C'est L'objectif.
- **python3 ≈ 1,9 Go RSS** (le plus gros poste), 12 conteneurs LXC.
- 111 services secubox actifs ; côté `secubox-profiles` : **116 always-on**, 70 on-demand
  (65 endormis). `DEFAULT_LIFECYCLE="always-on"`.

## 2. Découvertes clés (corrigent l'intuition initiale)

1. **L'aggregator EST déjà actif et MOUNT ~40 modules en-process** (`secubox-aggregator`,
   `aggregator/main.py` = master ASGI, `app.mount()` par module listé dans
   `/etc/secubox/aggregator.toml`). nginx route `/api/v1/*` → **`aggregator.sock`**.
   → La consolidation ASGI n'est PAS à faire de zéro : elle est **à finir**.
2. **23 modules tournent EN DOUBLE** : montés dans l'aggregator ET encore actifs en
   unité standalone = RAM gaspillée pour rien (nginx ne tape même pas leur socket).
3. **Fuites mémoire** : `secubox-metrics` (285 Mo) et `secubox-devwatch` (284 Mo)
   grossissent dans le temps. Restart → **156 Mo / 53 Mo** (≈ **360 Mo reclaim**). Fuite
   réelle à corriger (band-aid immédiat = timer de restart).
4. Les « 21 Streamlit » (#946) sont des **apps hébergées** par `secubox-streamlit`
   (`streamlitctl … idle-check`), pas des paquets → plafonner/idle, pas supprimer.

## 3. Directions, par ROI

| # | Direction | Gain | Effort | Risque |
|---|---|---|---|---|
| 1 | **Finir la consolidation aggregator** : désactiver les unités standalone des modules déjà montés (pure-API) ; monter les gros standalone restants. | ~300-500 Mo | Faible-Moyen | Moyen (par module) |
| 2 | **Corriger/contenir les fuites** metrics + devwatch (fix, ou timer restart). | ~360 Mo | Faible | Faible |
| 3 | **Purge** morts/POC (voir §5). | RAM faible + code | Faible | ~0 |
| 4 | **On-demand** des résidents rares (~40, voir §6). | ~30-60 Mo/svc | Moyen | Moyen (fiabiliser réveil) |
| 5 | **Réécriture Go** des 3 chauds : toolbox(106-174 Mo)→toolbox-ng, auth, hub. | gros/svc | Élevé | Moyen |
| 6 | **LXC caps** (`memory.max`) + on-demand conteneurs rares ; **hygiène** (journald, KSM `secubox-ksm`, zram). | ~400-800 Mo | Faible | Faible |

## 4. Les 23 modules en DOUBLE (montés + standalone actif)

**Désactiver le standalone est sûr pour les modules PURE-API** (l'aggregator les sert,
nginx tape déjà l'aggregator) — vérifier au cas par cas l'absence de tâche de fond :

- **Sûrs (pure-API, désactiver le standalone)** : `admin`(4), `auth`(9), `hub`(40),
  `metacatalog`(23), `portal`(4), `repo`(14), `soc`(7), `users`(14), `vhost`(16),
  `vm`(5). → **~135 Mo**.
- **À VÉRIFIER (tâche de fond / collecteur ?)** : `metrics`(163) [collecteur — garder
  standalone, sert la boucle], `waf`(100) [dashboard], `streamlit`(26).
- **Fronts LXC (le standalone pilote le conteneur — NE PAS désactiver aveuglément)** :
  `nextcloud`(284), `gitea`(27), `lyrion`(24), `jellyfin`(9), `peertube`(4),
  `photoprism`(4), `zigbee`(4), `mqtt`(4), `yacy`(4), `dpi`(51, hybride).

> Procédure sûre par module : `systemctl disable --now secubox-<m>` → tester
> `GET /api/v1/<m>/health` via le Hall (doit répondre via l'aggregator) → si KO, réactiver.

## 5. Purge — état

| Paquet | Box | Dépôt | Note |
|---|---|---|---|
| mitmproxy | déjà non installé | **CONSERVÉ** | 6 paquets le déclarent en Depends (cookies, grafana, interceptor, lyrion, profils, yacy) — nettoyer ces `control` d'abord (#1054). |
| ndpid | non installé | **CONSERVÉ** | `secubox-dpi` le déclare en Depends — nettoyer d'abord. |
| dpi-engine | **purgé** ✅ | **supprimé** ✅ | nDPId écarté. |
| surf | **RÉACTIVÉ** ⚠️ | à restaurer au dépôt | ❌ PAS un POC mort : **metanews en dépend** pour les clics de liens sources (réécrits en `surf-<hôte>.gk2.secubox.in` → nginx `surf.conf` → uvicorn `127.0.0.1:9082`). Désactivé par erreur → clics = 502. Réactivé le 2026-09-09 (`enable --now secubox-surf`). Le retrait du dépôt était une erreur — à restaurer si future réinstall. |
| webradio | non installé | **supprimé** ✅ | doublon de `secubox-radio` (Go). |

## 6. Candidats ON-DEMAND (sleeper `secubox-profiles`)

Basculer `lifecycle=on-demand` (modèle `nextcloud`) — **après** fiabilisation du réveil
(échoue sous saturation, cf. #946 ; #1/#2 le résolvent indirectement) :
- Domotique/HW rare : domoticz, homeassistant, zigbee, mqtt, picobrew, smart-strip, meshtastic, fmrelay, rbs-sensor, sentinelle-gsm, modem.
- OSINT ponctuel : openclaw, spiderfoot, maigret, cve-triage, threat-analyst, device-intel.
- Média à la demande : freeboxtv, podcaster, newsbin, torrent, ytsas.
- Outillage : vm, redroid, rezapp, netboot, mirror, repo, release, cloner, vault, backup, reporter, saas-relay.
- Accès distant : rtty, console, rustdesk, eye-remote.

## 7. Réécriture Python→Go (déjà Go : toolbox-ng, metanews, bbs, radio, socialrelay, waf-ng, daemon)

Priorité : `toolbox`(106-174 Mo, migration vers `toolbox-ng` déjà amorcée) > `auth`
(JWT partout, simple) > `hub` (dashboard central). L'ASGI-consolidation (§4) supprime le
surcoût interpréteur SANS réécrire → réserver Go aux 3 plus chauds.

## 8. Plan par phases (cercle vertueux)

- **P1 (fait/immédiat, sûr)** : purge (§5) ; reclaim des fuites (restart metrics+devwatch) ;
  → **RAM dispo 130 → ~2000 Mo** cette session.
- **P2** : timer de restart hebdo metrics+devwatch (contenir la fuite) OU fix ; désactiver
  les 10 standalones pure-API sûrs (§4) → ~135 Mo, swap ↓.
- **P3** : LXC `memory.max` + on-demand conteneurs rares ; hygiène (journald, KSM, zram).
- **P4** : on-demand des ~40 résidents rares (§6), une fois le réveil fiable.
- **P5** : Go pour toolbox/auth/hub ; finir purge mitmproxy/ndpid (nettoyer les Depends).

## 9. Fait cette session (2026-09-07)

- **P1** : purgé `dpi-engine` (box+dépôt), désactivé `surf`, supprimé du dépôt
  `surf`+`webradio`. Reclaim ~360 Mo (restart des fuites metrics/devwatch).
- **P2 TERMINÉ** : les **10 standalones pure-API redondants** (montés dans
  l'aggregator, vérifiés 200 via le Hall) désactivés → **vhost, hub, admin, auth,
  portal, users, metacatalog, repo, vm, soc ≈ 128 Mo**. (Le `pre=000` initial sur 6
  d'entre eux était un TIMEOUT transitoire du probe socket direct — l'uvicorn unique
  de l'aggregator se bloque sous rafale ; la vérif via le Hall, chemin client réel,
  confirme 200.) L'aggregator monte **111 modules** ; 4 échecs bénins (glances,
  metalogizer, roadmap, torrent = pas de `api/main.py`).
  **⚠️ Durabilité** : `systemctl disable` survit au reboot mais PAS à un `apt upgrade`
  du module (le postinst réactive). Fix durable = `mask` OU postinst du module qui
  n'enable pas si aggregator-mounté (à packager). Reste **13 doubles (~772 Mo)** =
  fronts LXC + collecteurs (nextcloud 284, metrics 156, waf 100, gitea, lyrion,
  streamlit…) : le standalone y a un RÔLE DE FOND (pilote le conteneur / collecteur)
  → NE PAS couper à l'aveugle, traitement au cas par cas (P3/P4).
- **Verrou durable** : les 10 pure-API `systemctl mask`és (survit à `apt upgrade`).
- **🔥 secubox-ui-manager = SPINNER 100% CPU (2026-09-09).** L'unité lance une TUI
  **Textual** (`python3 -m textual run secubox_console.app`) en démon `Type=notify` :
  une TUI n'envoie jamais le READY sd_notify → l'unité reste `activating` à vie et
  sa **boucle de rendu spin à ~180% CPU** (2 threads), sans TTY, sans socket, sans
  route nginx, sans consommateur. C'est un **bug d'unité** (TUI packagée en daemon).
  Il avait été masqué par l'allègement (à raison) puis **réactivé par erreur** dans
  la reprise post-incident login (« unmask des 14 par sûreté »). **Re-masqué** →
  load 11 → 3,4. À corriger côté paquet (unité : soit retirer le service, soit
  l'attacher à un vrai TTY/console locale). Leçon : la reprise « par sûreté » a
  réactivé un service qui n'aurait pas dû — vérifier CONSOMMATEUR **et** santé
  (spin/activating) avant de (re)démarrer.
- **🔴 INCIDENT (2026-09-08) — le masquage a CASSÉ le login admin. Prémisse P2
  fausse pour hub+auth.** Symptôme : `admin.gk2.secubox.in` → `JSON.parse:
  unexpected character at line 1 column 1` au Sign In. Cause : le formulaire POST
  `/api/v1/hub/auth/login` ; or **nginx du panneau admin ne route PAS hub/auth vers
  l'aggregator** mais **en DIRECT** vers leur standalone : `hub` → `127.0.0.1:8001`
  (`secubox-routes.d/hub.conf`), `auth` → `auth.sock` (`webui.conf` location
  `/api/v1/auth/`). Masqués → 8001/auth.sock morts → nginx renvoie une page d'erreur
  HTML 502 → le front fait `JSON.parse` dessus → crash. Le mount aggregator de hub
  ne remplace PAS : sur admin, nginx ne l'utilise même pas (et le mount hub répond
  quand même, mais admin tape 8001). **Correctif** : `unmask + enable --now` hub+auth
  (login redevient 401 JSON = OK), puis **par sûreté unmask+restart des 14 masqués**
  (retour à l'état d'avant P2). Aggregator restart propre au passage (les « hang »
  des mounts hub/admin/soc/vhost/system étaient du **warm-up** ~30 s au montage de
  100+ modules, pas un bug ; après chauffe tous 200).
- **LEÇON (corrige la règle P2)** : « module monté dans l'aggregator ⇒ standalone
  masquable » est **FAUX** tant qu'on n'a pas vérifié le ROUTAGE NGINX RÉEL de CHAQUE
  vhost qui l'utilise. Un `location /api/v1/<m>/` peut pointer soit vers
  `aggregator.sock` (→ masquage OK) soit **en direct vers le socket/port du
  standalone** (→ masquage = panne). Avant tout `mask`, faire :
  `grep -rn "api/v1/<m>/\|<m>.sock\|127.0.0.1:<port>" /etc/nginx/{sites-enabled,secubox-routes.d,secubox.d}`
  et ne masquer que si TOUTES les routes vont à l'aggregator. hub (8001) et auth
  (auth.sock) sont routés en direct → **jamais masquables** tant que nginx pointe là.
  → P2 est donc **suspendu** : reprendre module par module avec cette vérif de routage,
  ou d'abord basculer les routes nginx vers `aggregator.sock` AVANT de masquer.
- **Analyse des 13** (2026-09-07) : leurs app-vhosts (nc.gk2, gitea.gk2, lyrion…)
  proxifient le **LXC directement** (`10.100.0.100:9000`), PAS le socket module ni
  l'aggregator. Le standalone restant = **API de gestion (contrôle scale-to-zero du
  conteneur) + collecteurs** (metrics/waf/dpi/streamlit). → **NON désactivables à
  l'aveugle** (casserait réveil scale-to-zero / collecte). Chacun exige une lecture
  du code (boucle de fond ? fuite ? double-collecte). Reste ~772 Mo, mais chaque
  coupe est un mini-chantier, pas un gain gratuit.
- **metrics fuit VITE** (~40 Mo/h) : cap resserré 24 h → **6 h** (metrics 1.12.5).
  Note : metrics tourne EN DOUBLE (standalone collecteur + monté dans l'aggregator)
  → double collecte probable + la fuite contamine aussi l'aggregator (94→116 Mo).
  Fix de fond à trancher : metrics UNIQUEMENT standalone (démonter de l'aggregator)
  OU uniquement dans l'aggregator (mais alors la fuite n'est plus isolable/cappable).
- **FAIT — metrics démonté de l'aggregator** : nginx route DÉJÀ `/api/v1/metrics/`
  → `metrics.sock` (le montage était donc inutile et ne servait qu'à DUPLIQUER ses
  boucles de fond dans l'aggregator). Retiré de `/etc/secubox/aggregator.toml`
  (114 modules restants) + restart. API metrics toujours 200 (via son socket),
  les 10 masqués toujours 200. Gain steady-state **~34 Mo** (aggregator 184→150 Mo)
  + arrêt de la double-collecte. ⚠️ Le « 23 Mo » post-restart était un TRANSITOIRE
  (modules pas encore initialisés) — l'aggregator se stabilise ~150 Mo avec 114
  modules montés (coût inhérent au mount-everything ; à surveiller si ça croît =
  leak d'un autre module monté → alors RuntimeMaxSec sur l'aggregator, mais un
  restart coupe brièvement TOUTES les APIs mountées).
- **PATTERN identifié** : ne PAS monter dans l'aggregator un module qui (a) a une
  boucle de fond/collecteur ET (b) est déjà routé en direct par nginx → montage
  redondant qui fuit dans l'aggregator.
- **FAIT — waf/dpi vérifiés (même pattern que metrics)** : contrairement à metrics,
  ni waf ni dpi n'étaient montés dans l'aggregator (confirmé via
  `/api/v1/aggregator/health` : absents de `mounted[]`) — tous deux routés en direct
  (`waf.sock`/`dpi.sock`). **Pas de double-collecte.** Retirés quand même de
  `aggregator.toml` par ceinture-et-bretelles (114→112) ; APIs 200 après restart.
- **CAUSE RACINE DE LA FUITE metrics — trouvée par tracemalloc (le vrai fix)** :
  endpoint diag temporaire `/_leak` (start → baseline → diff 15 min) déployé puis
  retiré. Verdict : sur 15 min la RSS monte de **~98 Mo** MAIS les objets **Python
  ne grossissent quasi pas** (~140 Ko : `json/encoder` = churn de sérialisation,
  `vhost_stats:292/325` = parsing de logs — tout transitoire/réassigné). ⇒ La
  croissance est dans le **TAS NATIF glibc**, pas le tas Python. Les 4 boucles
  parsent de gros logs via `asyncio.to_thread` (THREADS) ; glibc alloue **une arène
  par thread** (défaut 8×cœurs) qu'il ne rend jamais spontanément à l'OS →
  fragmentation, RSS qui creep. « ~40 Mo/h » était donc de la frag native, pas une
  fuite d'objet. **Fix racine (metrics 1.12.6)** : `Environment=MALLOC_ARENA_MAX=2`
  (unité) + `malloc_trim(0)` toutes les 2 min (tâche de lifespan). Bonus correctness :
  `_geo_cache` (IP→pays) était non plafonné (1 entrée/IP publique à vie) → borné en
  LRU (OrderedDict, 16384) ; il n'apparaissait PAS dans le top tracemalloc (peu d'IP
  neuves sur 15 min) donc pas le foyer dominant, mais fuite lente réelle sur des jours.
  `RuntimeMaxSec` 6 h **dégradé en simple filet** (plus la mesure principale).
  Mesure avant/après RSS en cours pour valider l'aplatissement de la pente.
  **Leçon** : « objets Python plats + RSS qui monte » = fuite NATIVE (glibc/arènes),
  pas un objet retenu → chercher `MALLOC_ARENA_MAX`/`malloc_trim`, pas un dict.
  Idem devwatch (~140 Mo/j) resté sur `RuntimeMaxSec` : même profil probable (threads
  + churn HTTP GitHub) — appliquer MALLOC_ARENA_MAX si la fuite persiste après mesure.
- **P3** : journald capé (`SystemMaxUse=120M`). **KSM activé mais SANS gain** :
  `run=0`, 0 page partagée — KSM ne fusionne que les pages `MADV_MERGEABLE`
  (opt-in process) que les daemons Python ne posent pas ; abandonné (paquet laissé
  actif, inoffensif). LXC : déjà cappés (photoprism/gitea/peertube), gains marginaux.
- **Bilan RAM : 130 → ~2260 Mo dispo ; swap 3501 → ~3086 Mo** (en drainage).

### ⏳ P4 / P5 — NON exécutés (chantiers délibérés, pas de bâclage prod)
- **P4 (on-demand)** : mécanisme = `modules.d/<mod>.toml` `lifecycle="on-demand"`
  **shipé par le paquet du module** (la CLI `secubox-profilectl set-lifecycle` refuse
  un module « unknown » sans manifeste). ⚠️ **Prérequis** : le chemin de RÉVEIL doit
  être câblé par module (wake-proxy) — sinon requêtes en échec pendant le sommeil
  (le bug « réveils »). Ex. : freeboxtv a son propre relais (pas le wake standard) →
  NE PAS le passer on-demand sans câbler son réveil (casserait la TV). À faire
  module par module, avec validation du réveil (facilité maintenant que la RAM respire).
- **P5** : réécritures Go (`toolbox`→toolbox-ng, `auth`, `hub`) = multi-jours ;
  purge `mitmproxy`/`ndpid` = nettoyer d'abord les 7 `control` qui les déclarent en
  Depends (cookies, grafana, interceptor, lyrion, profils, yacy ; dpi).
