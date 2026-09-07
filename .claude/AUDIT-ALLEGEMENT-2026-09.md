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
| surf | **désactivé** ✅ | **supprimé** ✅ | POC absorbé par le BiB/webos. |
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
- **P2** : désactivé 4 standalones redondants (montés dans l'aggregator) : **vhost,
  hub, admin, auth** (~64 Mo), tout vérifié 200 (rollback auto sinon). Les 6 autres
  (metacatalog, repo, vm, soc, portal, users) NON servis par l'aggregator (`pre=000`)
  → **gardés** (à investiguer : pas montés, ou consommateurs directs du socket).
  **Fuite cappée durablement** : `RuntimeMaxSec` (metrics 24 h, devwatch 6 h) +
  `Restart=always` → redémarrage propre périodique (paquets metrics 1.12.4, devwatch 1.0.13).
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
