# TODO — SecuBox-DEB Backlog
*Mis à jour : 2026-08-13*
---

## Après v2.20.0 — ce que la fusion a laissé voir

### Cause en amont, à traiter avant le reste

- [ ] **Un module servi par l'agrégateur ne doit pas livrer un daemon résident.**
      103 daemons uvicorn tournaient, 41 des 42 sans appelant étaient servis en
      processus. Ramenés à 68 à la main — mais **l'empaquetage les réactivera à
      la prochaine réinstallation**. Tant que ce point n'est pas corrigé, tout
      le gain se perdra.
- [ ] **`secubox-waf` ne se monte pas dans l'agrégateur** — `PermissionError`
      sur `waf-threats.log`. #1017 se rejoue.

### Défauts ouverts

- [ ] `torrent-search` : les résultats n'exposent pas leurs liens magnet.
- [ ] `publish`, `repo`, `reporter` : l'agrégateur ne répond pas pour eux.
- [ ] ManageSieve (4190) injoignable — pas de filtres depuis Nextcloud.
- [ ] `www.gk2.net` : DNS à repointer, puis certificat.
- [ ] Streamlit : plafond CPU à 0,3 cœur et verrou de réveil manquant.

### Arriéré

- [ ] **13 branches anciennes** non fusionnées. Aucune ne tourne en production —
      vérifié paquet par paquet. Ce n'est plus un piège, seulement un arriéré à
      arbitrer.

### Leçon à graver

Neuf des douze corrections de v2.20.0 ont le même squelette : **un mécanisme
existe, est livré, et ne s'exécute jamais**. Le veilleur n'avait jamais tourné.
Les épingles n'étaient jamais appliquées. Le cache ne revalidait pas. Le journal
de modération était écrit mais jamais lu. Deux minuteries livrées ce jour même
sont arrivées désactivées, parce que `dh_installsystemd` ignore les instances de
gabarit.

**Livrer un mécanisme ne suffit pas : il faut prouver qu'il s'exécute.**

## Arbitrage des branches — TERMINE (2026-08-13)

**421 -> 20 branches. 401 supprimees, aucune fonctionnalite perdue.**

Il reste **13 branches non fusionnees** :

- **7 a contenu unique**, sans arbre de travail : elles apportent des fichiers
  ABSENTS de master. Les deux plus grosses sont `license-headers-phase-a` et
  `license-phase-b-full` (35 fichiers chacune) — les en-tetes SPDX, sujet
  transverse jamais acheve.
- **6 retenues par un arbre de travail**, dont **4 portent du travail NON
  COMMITE** : `429-nextcloud` (3 fichiers), `820-presence-guardian` (5),
  `823-sbxmitm-sentinel` (8), `826-sentinel-c2` (2). Ces quatre-la ne doivent
  etre ni supprimees ni liberees avant que ce travail soit commite ou
  abandonne EXPLICITEMENT.

Les arbres de travail sont passes de 18 a 9.

| Groupe | Nombre | Signal |
|---|---|---|
| Tous les fichiers existent deja dans master | **28** | fonctionnalites verifiees PRESENTES dans master |
| Apportent des fichiers absents de master | **11** | contenu unique, a examiner |

### Les 28 : doublons historiques, tres probablement

Leur diff est enorme (jusqu'a 228 971 insertions) : ce ne sont pas des residus
mais les fonctionnalites entieres. Or celles-ci sont **deja dans master**,
arrivees par rebase ou reimplementation — `sbx-sentinel`, l'auto-apprentissage
C2, la federation P2P DHT, Frigate et le cache media sbxwaf sont tous presents,
et en production sur gk2.

Les supprimer perd l'historique de developpement, pas la fonctionnalite.
**Decision utilisateur.**

### Les 11 qui apportent des fichiers absents de master

| Branche | Fichiers absents |
|---|---|
| `feature/license-headers-phase-a` | 35 |
| `feature/license-phase-b-full` | 35 |
| `feature/127-phase2-square-variant` | 33 |
| `feature/429-nextcloud-real-manageable` | 6 |
| `feature/127-phase3-python-kiosk` | 5 |
| `feature/136-mail-stack-phase-1` | 3 |
| `feature/247-health-banner-clickable` | 3 |
| `feature/615-security-posture` | 1 |
| `feature/738-aggregator-resilience` | 1 |
| `fix/133-remote-ui-square-4-bugs` | 1 |
| `fix/139-round-image-usb0-otg` | 1 |

Les deux `license-*` (35 fichiers chacune) sont les plus interessantes : elles
posent les en-tetes SPDX, sujet transverse jamais acheve.

### Une reserve gardee pour arbitrage

`fix/round-real-root-icons` SUPPRIMERAIT `build-eye-remote-image.sh`, fichier
toujours present et reference dans master. Une suppression dont l'intention ne
se verifie pas ne se fusionne pas.

### Lecon de methode

`git cherry` a classe « contenu nouveau » quatre branches dont le correctif
etait **deja dans master**, reimplemente sous un autre patch : `fix/92`,
`fix/218`, `feature/790` et `feature/239`. L'outil oriente, il ne tranche pas —
chaque suppression a ete verifiee sur le contenu, jamais sur le classement.

---


---

## Branches non fusionnees restantes (2026-08-11)

33 branches sont en conflit avec master et demandent un arbitrage, une par
une. Certaines datent de mai et peuvent etre abandonnees ; d'autres portent
peut-etre du code vivant sur gk2 — c'est a verifier AVANT de trancher, pas
apres.

- [ ] `archive/429-b715-occ-direct`
- [ ] `chore/982-streamlit-bascule-du-parc-vivant-vers-le`
- [ ] `feat/963-lien-reveil-tuiles`
- [ ] `feat/tor-onion-pac`
- [ ] `feature/241-secubox-zigbee-v2-4-0-rewrite-in-place-z`
- [ ] `feature/264-secubox-zigbee-secubox-lyrion-swap-lan-o`
- [ ] `feature/429-nextcloud-real-manageable`
- [ ] `feature/615-security-posture-add-security-posture-to`
- [ ] `feature/738-aggregator-resilience-sweep-async-handle`
- [ ] `feature/740-anti-pub-renforce-sinkhole-dns-unbound-e`
- [ ] `feature/748-enhanced-tow-boot-http-netboot-serial-fl`
- [ ] `feature/761-fix-podcaster-audio-player-stops-every-f`
- [ ] `feature/789-sbxwaf-styled-html-421-page-for-unrouted`
- [ ] `feature/817-device-guardian-consolidation`
- [ ] `feature/820-presence-guardian`
- [ ] `feature/823-sentinel-toolbox-surfaces`
- [ ] `feature/826-feed-report-surface`
- [ ] `feature/826-feeds-honest-ja4capture`
- [ ] `feature/826-ja4-plumb`
- [ ] `feature/826-sentinel-c2-botnet-auto-learning-high-pr`
- [ ] `feature/92-health-banner-visitor-origin-feed-anonym`
- [ ] `feature/967-router-les-mp3-flac-conserves-vers-lyrio`
- [ ] `feature/license-phase-b-full`
- [ ] `feature/license-phase-b-hub`
- [ ] `fix/361-secubox-threat-analyst-v1-1-0-wire-metri`
- [ ] `fix/494-secubox-core-service-execstart-overrides`
- [ ] `fix/826-c2-rare-alone-fp`
- [ ] `fix/961-toutes-applis-endormissables`
- [ ] `fix/962-barre-globale-recouvre-hub`
- [ ] `fix/989-derive-nginx-systemique-les-paquets-inst`
- [ ] `fix/issue-77-hyperpixel-init`
- [ ] `fix/round-real-root-icons`
- [ ] `fix/rpi4b-radar-arcs-top-centered`

## HAProxy — suites de #986/#988 (2026-08-10)

- [ ] Décider, vhost par vhost, si les 10 qui déclarent `ssl_redirect = true`
      sans `ssl = true` doivent rediriger (`bbs`, `social`, `nc`, `sso`,
      `zigbee`, `picobrew`, `zem`, `shiptest`, `wiztest2`, `wiztest3`).
      Correctif = ajouter `ssl = true` dans leur bloc de `haproxy.toml`.
- [x] ~~Reconstruire `secubox-toolbox`~~ — **rien à faire, verifie le
      2026-08-10** : `/etc/haproxy/cfg.d/30-toolbox-landing.cfg` est deja
      livre par dpkg sur la board (2.8.9, meme empreinte que les sources).
      L'item avait ete ecrit en deduisant l'etat de la board depuis le diff de
      fusion, sans regarder la board — la meme erreur que celle qui a fait
      rediagnostiquer #986/#988.
- [ ] Fusionner les branches de worktree qui portent du code **déjà vivant**
      sur la board : c'est ce qui a fait rediagnostiquer #986/#988 à l'aveugle.

## 🎬 Média/perf — suite marathon v2.16.0 (2026-07-31)

- [ ] **502 brandé global** : câbler le snippet `secubox-errorpages.conf` dans chaque `server{}` (script python balanced-brace + `nginx -t` avant reload) ; les 2 tentatives naïves (sed) ont cassé `nginx -t`.
- [ ] **Ré-import library torrent** : les 5 films (Marsupilami/Nautilus/Supergirl/Fantastic Four/Jack Ryan) — fichiers intacts sur `/data/torrent`, effacés de `library.db` par erreur. Seed local → régénère infohash/magnet, réinsère complete=1.
- [ ] **Paquets → vhost dans haproxy.toml** (directive user, LE fix du drift) : chaque postinst enregistre son vhost dans le toml ; déclarer aussi `gitea_ssh` (tcp) + `toolbox_landing` (http custom) pour que `haproxyctl generate` redevienne utilisable → fin des hand-add (jellyfin.gk2, ytsas.gk2).
- [ ] **Jellyfin** : (a) auto-wizard 10.11 (séquence `/Startup/*` — POST sert la page HTML, pas du JSON) ; (b) intégration `users` (gk2/admin provisionnés comme les autres) ; (c) photoprism en biblio **photos** (pas homevideos).
- [ ] **QoS dynamique + veille-sur-accès** : boost cpu.weight à l'accès, freeze/scale-to-zero des idle, wake à la 1ʳᵉ requête. Kernel gk2 **sans `CONFIG_CFS_BANDWIDTH`** → pas de `cpu.max` ; utiliser `cpu.idle` (SCHED_IDLE) + `cpu.weight`. Cf. `project_resource_governance_vision`.
- [ ] **Watchdog circuit-breaker** : noter l'oops/OOM → alerter → **pause (ne plus relancer)** après N répétitions, au lieu du restart-loop.
- [ ] **Companion QR pairing** (QR brandé emoji central) + **WG tunnel** phasé (déléguer→embarquer VpnService). Cf. `project_companion_qr_wg_distribution`.
- [ ] **Split-box mesh** (cible) : répartir les ~20 LXC sur 2 boards quand mesh-stable.

---

## 🚨 Incident 2026-07-28 — malware C2 + WAN mvpp2 (URGENT)

- [ ] **Sweep IOC malware fleet** (#914) : sur **amd64 secubox-live (192.168.1.9 / 10.10.0.3, x86-64 → la charge TOURNERAIT)** puis **c3box (10.10.0.2)** — chercher `/usr/local/bin/notwork-monitoring`, l'unit `notwork-monitoring.service`, connexions actives vers `5.182.207.11`. SHA-256 `f2ca2b2051c2a98e23b80aab601369474006f6a6dd1dfb8f212f51a726b23dcc`.
- [ ] **Vecteur d'accès initial** ~2026-06-09 : qu'exposait gk2 vers Internet ? Revue surface + rotation secrets/clés par prudence. Confirmer la clé `deploy@server` dans `authorized_keys` root.
- [ ] **RE de l'échantillon** sur VM x86-64 isolée (`upx -d` + VirusTotal + sandbox) — bundle `/root/notwork-incident-2026-07-27.tar.gz` (+ copie locale scratchpad). Ne JAMAIS exécuter en prod.
- [ ] **Détection fleet-wide** : ajouter ces IOC (filename/hash/unit/C2 IP+domaine+ASN) aux règles SecuBox. Signalement abus AS213250 possible.
- [ ] **WAN mvpp2** : confirmer le recovery **unbind/rebind `f2000000.ethernet`** (playbook `docs/FAQ-NETWORK-WAN-RECOVERY.md`), puis finaliser **#913** (netplan `.200` statique coexist DHCP, board + `secubox-net-detect`). Rappel : U-Boot pinge OK → HW sain, bug driver Linux.

## 🧅 Transparent .onion / proxypac — follow-ups fallback WPAD/PAC (2026-07-25, non-bloquant)

> Le mécanisme **transparent** (primaire, wg-toolbox+LAN) est déployé et couvre le
> cas réel. Ces items ne concernent que le **fallback PAC/WPAD** (clients non
> force-routés) — pas urgents.

- [ ] **Route HAProxy pour `wpad.gk2.secubox.in`** : le vhost `wpad-vhost.conf` a
  `listen 80`, mais sur gk2 nginx sert sur `:9080` derrière HAProxy (qui possède
  `:80`) → `/wpad.dat` renvoie 421. Câbler une route HAProxy `wpad.gk2` → nginx:9080
  (patron public-vhost [[project_sbxwaf_live_routing]]) + `listen 9080` dans le vhost.
  La résolution DNS `wpad.gk2` → box marche déjà (record tier2 Unbound).
- [ ] **MIME strict `/proxy.pac` sur le vhost admin** : renvoie `text/html` car
  `webui.conf` (vhost admin réel) n'inclut pas `secubox.d/`. Ajouter la `location
  = /proxy.pac` (MIME `application/x-ns-proxy-autoconfig`) à `webui.conf`, OU router
  via le vhost wpad ci-dessus.
- [ ] **Backport source** : la board a l'`api.py` proxypac patchée + le bind Unbound
  LAN + la règle onion repointée en live ; vérifier que le rebuild depuis la branche
  mergée (#900) réconcilie tout (aggregator.toml registration incluse).

## 🎚️ R-level par peer — follow-ups (2026-07-25, non-bloquant)

- [ ] **Réconcilier le drift .deb** : la live api.py toolbox est patchée A' (ctl
  sans sudo, NNP=true préservé) mais le `.deb 2.8.7` installé prédate. Rebuilder
  `secubox-toolbox` **2.8.8** depuis master (#901 mergée) + redéployer pour durabilité
  (un reinstall du 2.8.7 régresserait vers le chemin sudo qui ne marche pas).
- [ ] **Enforcement `reel` — ban/rewrite temps réel** : v1 honore le block existant ;
  les hooks ban/rewrite par-peer restent à étoffer (hors périmètre v1).

---

## 📺 Intégration webui LXC — frigate + hexo (2026-07-24)

> Motif validé (réf. secubox-picobrew) : service à webui complète → sous-domaine
> `<mod>.gk2` LAN-confiné (patron lyrion : snippet exposure allow-privé/deny-all,
> nginx:9080 → LXC:port, TLS par HAProxy, route dans haproxy-routes.json, upgrade
> WebSocket) + page admin = COCKPIT (contrôle + statut + accès + logs), PAS une
> iframe pleine page. Le fix WebSocket sbxmitm (déployé) profite à tous.

- [ ] **frigate — BLOQUÉ au provisionnement.** LXC provisionné (10.100.0.140,
  systemd PID 1 OK) mais `frigate.service` échoue : `Failed to locate executable
  /usr/bin/podman` — frigate tourne en conteneur **podman DANS le LXC**, podman
  absent. `frigatectl` a déjà `PUBLIC_HOSTNAME=frigate.gk2` + `HTTP_PORT=5000`
  (prêt pour le sous-domaine). À TRANCHER d'abord (systematic-debugging) :
  installer podman+pull l'image frigate DANS le LXC, OU réécrire frigate en natif
  (cf. [[feedback_lxc_native_over_docker_package]] : le dépôt préfère natif). Une
  fois frigate qui SERT sur :5000 → appliquer sous-domaine + cockpit comme picobrew.
  Nécessitera aussi une config caméras pour être utile. NB race frigatectl : `svc
  start` juste après lxc-start échoue (systemd du conteneur pas encore booté) —
  attendre. LXC laissé STOPPED (état antérieur restauré).
- [ ] **hexo — cas DIFFÉRENT (pas un LXC).** secubox-hexo = api/ + www/ +
  nginx dropin secubox.d (aggregator-served, générateur de blog host). Le patron
  « sous-domaine iframe LXC » ne s'applique pas tel quel : évaluer d'abord ce
  qu'est la « webui complète » de hexo (admin blog ? blog généré ?) et l'intégrer
  en conséquence.

---

## 📧 Vie privée mail & traceurs (en pause, 2026-07-23)

- [ ] **Pixels de suivi email — plan d'implémentation**. Spec **validé et commité** :
  `docs/superpowers/specs/2026-07-23-email-tracking-pixel-detection-design.md` (`fc8e0f9d`).
  Reste à faire : ouvrir l'issue GitHub, puis dérouler writing-plans. Aucun code écrit.
  Rappel des décisions : `data:` URI 1×1 inline (zéro requête émise), archive du brut DKIM-intact,
  heuristique conservatrice, intégrité du courrier non négociable (exception ⇒ original intact).
  Cœur = `pixelscan.py`, fonction pure testable sur de vrais `.eml` sans Postfix ni LXC.
- [ ] **⚠ rspamd ne filtre rien** (anomalie constatée 2026-07-23, hors périmètre du spec) :
  `rspamd` est `active` dans le LXC `mail` mais `smtpd_milters` est **vide** → aucun milter Postfix
  ne l'appelle. L'antispam est vraisemblablement inopérant depuis un moment. Issue à ouvrir.
- [ ] **Suivi #ads** : vérifier après quelques heures d'usage réel via wg-toolbox que
  `total_candidates` progresse et que `candidates_cumulative` repasse à `false`. Si rien ne bouge,
  un filtre subsiste en amont → reprendre l'enquête depuis cette preuve.

---

## 🖥️ Afficheurs & appliances (en pause, 2026-07-23)

> Trois sujets suspendus explicitement par l'utilisateur. Contexte complet : HISTORY/WIP 07-22→23.

- [ ] **rpi400 — pas de réseau** (bloquant). L'image kiosk boote sur une console mais n'a pas de
  réseau utilisable : IP affichée, aucun ping. **Piste n°1** : l'IP visible est probablement celle
  du bridge isolé `eye-br0` (10.55.0.1/24, `secubox-eye-remote`) alors qu'`eth0` n'a jamais obtenu
  de bail DHCP — trancher en console (root/secubox) avec `ip -br a; ip r`. `10-eth.network` est
  pourtant correct (`Match eth* en*`, `DHCP=yes`, non bridgé). **Piste n°2** (kiosk qui ne
  s'affiche pas) : `config.txt` porte `gpu_mem=64` et **aucun** `dtoverlay=vc4-kms-v3d` → X n'a
  peut-être pas de driver d'affichage exploitable.
- [ ] **rpi400 — restaurer `cmdline.txt.bak`** sur la partition boot de la carte (j'y ai retiré
  `quiet splash` et ajouté `loglevel=7` pour diagnostiquer). À faire avant toute mise en service.
- [ ] **Propager le fix postinst mediaflow** (`#DEBHELPER#` dans un commentaire, `~bookworm3`) vers
  apt.secubox.in et gk2 : le bug cassait le `configure` de **toutes** les installs, pas seulement
  l'image rpi.
- [ ] **Round eye gadget — à reflasher** (« bugge dernièrement »). ⚠ Ne pas reflasher à l'aveugle :
  identifier d'abord le symptôme (écran figé ? plus de données ? gadget USB non détecté ? boucle de
  reboot ?), sinon on re-livre proprement le même défaut — leçon du rpi400. Outillage :
  `remote-ui/round/build-eye-remote-image.sh`, `deploy.sh`, CI `.github/workflows/build-eye-remote.yml`.
- [ ] **Console double écran carré (Pepper's ghost)** — brainstorming suspendu au choix des dalles.
  **Acté** : 2 écrans = 2 couches de *profondeur* (pas maître/détail) ; composition optique par
  demi-miroir 45° ; rôle = console de contrôle SecuBox (fond = santé globale, avant = module en
  focus + actions) ; commande **au geste sans contact** (ToF/IR) car aucun écran n'est touchable en
  Pepper's ghost. **Contrainte de design à honorer** : les actions destructives (restart/ban)
  exigent une confirmation explicite, le capteur étant imprécis. **Point de reprise** : échelle des
  dalles + SBC (l'utilisateur penche « small » ; ⚠ le demi-miroir divise la luminosité par ~2, ce
  qui est le critère décisif contre du petit SPI).

---

## 🕸️ MIND — metalogue OSINT suite (#845, suivis 2026-07-12)

> Maigret + SpiderFoot **live/installés** sur gk2 ; OpenCTI différé. Voir [[Metalogue]] wiki + HISTORY 07-12.

- [ ] **P3 — OpenCTI** (hub graphe Maltego) sur nœud amd64 (192.168.1.9) ou hardware dédié :
  LXC OpenCTI (ES+Redis+RabbitMQ+MinIO), connecteurs depuis Maigret/SpiderFoot/openclaw, route
  WAF cross-mesh vers la navbar gk2. Migrer le rôle hub de SpiderFoot → OpenCTI. Trop lourd pour
  gk2 (~1.5 Go libre).
- [ ] **ip_forward reset au runtime** : la valeur dérive à `0` après boot malgré
  `99-secubox-zz-lxc-forward.conf` (=1) → coupe la sortie internet de TOUS les LXC. Trouver le
  service/script qui remet `ip_forward=0` et le neutraliser (récurrent).
- [ ] **Self-registration `aggregator.toml`** : maigret/spiderfoot ajoutés à la main dans
  `modules=[]` (comme openclaw). Un postinst devrait s'auto-enregistrer (idempotent, sans race
  sur le fichier partagé) — sinon une image neuve perd les modules.
- [ ] **Re-enable SpiderFoot public sur image neuve** : l'expo `spiderfoot.gk2` (vhost + route
  sbxwaf + ACL HAProxy + nft :9043 + snippet exposure) a été câblée **live**. Idéalement via
  `secubox-exposure emancipate spiderfoot 5001 spiderfoot.gk2.secubox.in` (le tool documenté).
- [ ] **Bridge collecteurs → hub** : pousser les findings Maigret/openclaw dans SpiderFoot (import
  API) en attendant OpenCTI ; stub `metalogue-bridge` pour le connecteur OpenCTI P3.

---

## 🟣 MIND — ToolBox rapport vie privée (suivis #785/#790, ajouts 2026-07-04)

> Contexte : rapport kbin fidèle PDF↔web (donut-grids, media types, fiche de personnage,
> Quêtes réelles) mergé (#785 #787 · #790 #794 · #792). Voir [[ToolBox]] wiki + HISTORY 07-04.

- [ ] **#786 — double-caching de l'agrégation media-catch** (non bloquant, dormant hors R3/R4).
  `/media_types` (secubox-dpi) + `_media_stats` (toolbox) agrègent `/run/secubox/media-catch.jsonl`
  **par requête** (borné mémoire par tail-read, mais pas de cache 60 s comme la règle
  double-caching CLAUDE.md). Option préférée : sbxmitm émet un `media-stats.json` pré-roulé
  (pattern producteur→static→lecture, comme `/exfil`) ; sinon cache asyncio 60 s dans chaque
  process consommateur. Fichiers : `common/secubox_core/media_catch.py`, `secubox-dpi/api/main.py`,
  `secubox-toolbox/.../api.py`.
- [ ] **Cosmétique HTML Quêtes** : double-espace quand une menace a un `detail` mais pas de
  `service`/`dst` (`report-live.html.j2`, garde `{% if _dest or q.detail %}`).
- [ ] **Nettoyage post-`.deb`** : le board gk2 a un drop-in MPLCONFIGDIR manuel
  `/etc/systemd/system/secubox-toolbox.service.d/50-mplconfigdir.conf` ; le paquet livre
  l'équivalent `30-mplcache.conf` → retirer le `/etc` manuel au prochain install du `.deb`.

---

## 🟢 P2P — Roadmap post-DHT/Federation/Master-link (#774 · PR #775)

> Socle livré & live sur le mesh 3 nœuds (voir HISTORY 2026-07-02 +
> `docs/P2P-EVOLUTIONS-POSTER-PROMPT.md`). Suites, par priorité :

### 🔜 Pont bans mesh → moteur sbxwaf

- [ ] Alimenter sbxwaf (bouncer CrowdSec) avec les bans fédérés threatmesh (#768) :
  `cscli decisions add --ip <IP> -R "secubox-mesh" -d 4h` en plus du nft
  `inet secubox_meshban` actuel.
- [ ] Anti-boucle : dans `secubox-threatmesh-bridge`, filtrer les décisions de *reason*
  `secubox-mesh` pour ne pas re-fédérer une décision déjà reçue par le mesh.
- [ ] Vérifier que sbxwaf applique bien (403 + `X-SecuBox-WAF: banned`) sur une IP reçue
  uniquement via le mesh (0 décision crowdsec locale).

### 🔜 macroctl sur satellites (chemin privilégié)

- [ ] `secubox-p2p` standalone tourne `NoNewPrivileges=yes` → `sudo macroctl activate`
  refusé (« NNP flag is set »). OK sur gk2 (p2p dans l'aggregator NNP=no).
- [ ] Fixer sans affaiblir le durcissement satellite : drop-in ciblé ou helper vetté
  (pas de `NoNewPrivileges=no` global sur l'unité durcie).

### 🔜 Fenêtre transitoire du socket p2p

- [ ] Restart de `secubox-p2p` → webui satellite 502/504 le temps de recréer `p2p.sock`.
  Lisser via socket-wait / `RuntimeDirectoryPreserve=yes` pour supprimer les erreurs
  `apiGet` visibles.

### 🌀 Horizon (conçu, non construit)

- [ ] Mesh phases 2–4 (`project_mesh_gk2_c3box`).
- [ ] Liaison NIZK/PSI GK·HAM : remplacer les stubs `ZKP-HAM-v1` par `zkp-hamiltonian` cffi.
- [ ] Nouveaux kinds macro (`wg-relay`, `dns-resolver`, `http-mirror`).
- [ ] Macros en mode `pending` (fédération cross-nœud des Subscription/APPROVE).
- [ ] Mesh master→satellite (nft c3box) + Freebox forward UDP 51822 pour le remote.

---

## ⚪ T5 — Images / OS variants / Hardware (ajouts 2026-06-27)

### ⬜ MOCHAbin — bootloader propre (adresses réservées + extlinux)

> Workaround actif : `/boot/boot.scr` compilé forçant le kernel à `0x0a000000`. Fix durable requis.

- [ ] **Option A — Corriger l'image** : patcher `extlinux.conf` généré par le CI pour utiliser
  `0x0a000000` (kernel) et `0x10000000` (initrd) au lieu de `0x02080000` (adresse réservée
  factory U-Boot 2020.10 → reset immédiat). Boot.scr deviendrait redondant.
- [ ] **Option B — Enhanced Tow-Boot (#748)** : bloqué par le ciseau U-Boot (voir ci-dessous) ;
  déverrouille wget/HTTP natif dans U-Boot, supprime le besoin de TFTP pour les futures installs.
- [ ] **Valider** que le fix d'adresse tient sur les deux MOCHAbin (gk2 + c3box).

### ⬜ #748 — wget dans U-Boot pour MOCHAbin (bloquant documenté)

> Bloquant dur (ciseau) confirmé 2026-06-27. Branche
> `feature/748-enhanced-tow-boot-http-netboot-serial-fl` : spec + plan + Kconfig +
> `build-uboot-overlay.sh --tow-boot` + CI `.github/workflows/build-tow-boot.yml` en place.
> Problème : board mochabin UNIQUEMENT dans fork Tow-Boot U-Boot 2022.07 (pas de `wget`) ;
> `wget`/TCP UNIQUEMENT dans stock U-Boot ≥2023.07 (pas de board mochabin/DTS).

- [ ] **Voie 1** : backporter le stack TCP + `wget` de U-Boot ≥2023.07 dans le fork Tow-Boot
  2022.07 (mochabin board natif). Diff TCP = `net/wget.c` + dépendances `CONFIG_NET_WGET`.
- [ ] **Voie 2** : porter le board mochabin (DTS Armada 7040 + PHY + eMMC) vers U-Boot mainline
  ≥2023.07 (sans Tow-Boot). Plus long mais durable.
- [ ] Choisir une voie, débloquer #748.

### ⬜ Packager le flow netboot + install signé (rig temporaire → procédure reproductible)

> Actuellement rig manuel sur gk2 : `lan1=192.168.77.1/24`, dnsmasq DHCP, nft, nginx `:8099`.

- [ ] Scripter la publication de l'image signée dans le root HTTP netboot (wget + sha256 + sig).
- [ ] Documenter / packager la config dnsmasq + nft + nginx pour un segment `lan1` dédié.
- [ ] Intégrer dans `scripts/deploy-netboot.sh` ou équivalent.

### ⬜ Teardown rig netboot temporaire gk2

> Le rig (lan1 bridge, dnsmasq, nft iif lan1 accept, nginx extra listen) reste actif jusqu'à
> ce que c3box soit autonome en prod.

- [ ] Retirer la règle nft `iif lan1 accept` (risque : tout le segment lan1 est accepté sans filtrage).
- [ ] Désactiver / retirer dnsmasq test sur lan1.
- [ ] Retirer le extra listen `192.168.77.1:8099` du vhost nginx netboot (ou couper le vhost si
  plus nécessaire).
- [ ] Vérifier que c3box auto-boot sans rig (boot.scr en place → OK).

---

## ✅ Clos 2026-06-22 — DPI exfil + report Netrunner + sbxmitm

- ✅ **#687 DPI exfil pipeline** — flowcap + Go collector + dashboard + cumulatif 7j,
  packagé `secubox-dpi 1.1.2` (inclut #692/#693/#695/#705).
- ✅ **#707 report kbin = fiche Netrunner** HTML+PDF (#699/#701/#703/#709/#711/#714/#716).
- ✅ **#689** sbxmitm cert 365d · **#697** stream >8MiB (Gmail) · **#688** splice rejeté.

### DPI Phase 3
- [x] Enrichissement **ASN** (GeoLite2-ASN) pour l'egress sans SNI — **#719 mergé, live**
  (`secubox-dpi 1.1.3`, maxminddb-golang vendored).
- [x] **Historique + timeline par device** — **#721 mergé, live** (`secubox-dpi 1.1.4`,
  buckets quotidiens `history.json` 14j + `/api/v1/dpi/history` + panneau Timeline
  dashboard). NB : JSON daily buckets (pas SQLite — pas de driver CGO dans le binaire
  statique ; SQL riche reportable si besoin).
- [x] Démon **nDPId** — **évalué puis ÉCARTÉ** (#722/#723 revertés). Raison perf :
  ndpiReader tourne en fenêtres bornées (Nice 15, ~1% CPU, libère le cœur entre
  les passes) ; nDPId = démon permanent + nDPIsrvd → CPU/RAM **continue** sur une
  board déjà saturée (load ~4.6/4 cœurs). Gain (JSON riche, pas de respawn) <
  risque. **Décision : on garde ndpiReader** comme producteur du pipeline exfil.
  (Le build CI QEMU a aussi échoué au 1er essai → chemin fragile en plus.)

### ⬜ Cosmétique report PDF (non bloquant)
- [ ] Glyphes drapeaux régionaux → lettres (police embarquée). Option : drapeaux PNG.
- [ ] Chiffres espacés dans certaines cellules (fallback police).

### ⬜ APK on-device #685/#686 — NON-ROOT ONLY (plan verrouillé, à faire)
> Décision 2026-06-22 : cible **non-root uniquement** ; chemin root abandonné.
> Plan détaillé : commentaire #685.
- [ ] **VpnService in-app** (`com.wireguard.android:tunnel` / GoBackend wireguard-go)
  — l'APK EST le client WG, plus de Play Store, détection tunnel in-app fiable.
- [ ] **CA en DER** (fix « nom de cert vide » du KeyChain intent) + `network-security-config`
  pour que la WebView in-app fasse confiance au CA ca-wg.
- [ ] Retirer RootShell/RootOnboard/BootReceiver ; manifest VpnService + consent VPN.
- [ ] Limite Android : pas de CA **système** sans root → MITM système impossible ;
  surface « safe browsing » = WebView in-app. À documenter.
- [ ] Build via CI `build-android-apk` + **test sur appareil** (gros build, itératif).

---

## 🎯 Backlog priorisé — revue 2026-06-24 (64 issues ouvertes)

> Index d'autorité du triage. Les sections « Phase X » plus bas sont historiques :
> plusieurs portent « ✅ COMPLETE » alors que l'issue est restée **ouverte** (livré
> mais jamais fermé) → marquées **[vérifier→fermer]** ci-dessous.

### 🔴 T0 — Régressions & bugs sécurité (petits, débloquants, CSPN priv-sep)
- #494 secubox-core ExecStart écrase tmpfiles.d `/run/secubox` *(worktree actif)*
- #468 `/etc/secubox` parent 0750 casse la traversée non-secubox *(régression récurrente)*
- #471 secubox-mesh postinst écrase perms `/run/secubox` *(régression)*
- #421 sockets `/run/secubox` cachés en mount-ns privé (RuntimeDirectory)
- #447 kiosk : mot de passe admin semé par le CI (users.json shippe un hash) **← fuite**
- #91 haproxyctl régénère haproxy.cfg avec `waf_inspector` inexistant *(intégrité WAF)*
- #65 nginx : routes API manquantes dans webui.conf
- #53 Wazuh uvicorn 100% CPU spin
- #121 metablog ingest : dirs en `secubox:secubox`

### 🟠 T1 — Plan d'enforcement sécurité (mission CSPN ; détection→action)
- #498 Phase 7 — WAF active enforcement (mitm→CrowdSec→nft drop) *(worktree actif)*
- ✅ #519 Phase 13 — enforcement plane **FERMÉ 2026-06-22** (livré + réparé :
  blacklist-sync avortait sur NXDOMAIN + timeout unit → fix `|| true` +
  TimeoutStartSec 600 ; vérifié live, default-off). Inclut 13.B #522.
- #455 secubox-egress — détection egress + corrélation RDS multi-signaux
- #500 Phase 8 — Utiq operator-grade tracking (detect/alert/bypass)
- #514 Phase 12 — plateforme anti-human-detection (parent ; sous-tracks fermés)
- ✅ #515 Phase 12.A CDN cache detection — **FERMÉ** (live, `social_host_meta.cdn_vendor`)
- ✅ #516 Phase 12.B anti-bot detection — **FERMÉ** (live via #564/#565, `social_antibot`)
- #525 Phase 14 — plan de déception (idée future, parké)
- ⬜ Suivi #519 perf (non bloquant) : DNS-guard ne résout que les 2000 premiers
  domaines/cycle (5523 en base) → couverture partielle ; résolution séquentielle
  lourde sur board saturé. Option : résolution parallèle bornée + rotation du cap.

### 🟡 T2 — UX / Hub / conscommateurs report (worktrees actifs + polish)
- #615 security-posture dans la sidebar Hub *(worktree actif)*
- #655 webext content-script banner CSP-immune *(worktree actif)*
- #485 toolbox SOC scoring *(worktree actif)*
- #513 ToolBox WebUI : sous-onglets + retrait UI /admin redondante
- #69 diagramme flux trafic responsive
- #67 cache history-aware glances/netdata
- #68 health checks + dépendances services au démarrage

### 🟢 T3 — Backlog feature (valeur, non bloquant)
- #685 APK 'corrupt' — CI signe avec clé éphémère *(plan APK verrouillé)*
- #686 android-toolbox flux non-root cassé *(plan APK verrouillé)*
- #429 nextcloud dashboard : API stubs au lieu de la vraie instance *(bug)*
- #430 nextcloud — fédération OCM (doc/outillage)
- #472 nextcloud — Gondwana Desktop (canvas + widgets)
- #592 secubox-webmail-hub (Gmail OAuth2 + Gandi + OVH)
- #66 auth Google OAuth
- #70 Health Banner System *(preplanned)*
- #71 CDN proxy injection *(preplanned)*
- #393 source-home des scripts health prober

### 🔵 T4 — Hardware-gated (dépend de pièces ; piste parallèle ; pas de spare EP06)
- Modem/PCIe : #254 modules kernel LTE · #255 pins mPCIe modem · #460 DTS cp0_pcie2 ·
  #467 U-Boot comphy5 SerDes · #462 pivot HW AR9271/MT
- Mesh/BLE : #449 WiFi 802.11s · #452 BT mesh · #453 QR multi-canaux · #454 sourcing BLE 5.x
- GSM : #347 sentinelle-gsm
- Smart-Strip : #33 module HMI · #42 sous-repo · #379 packaging
- Eye-remote : #41 sous-repo · #79 buildroot · #127 variante square · #138 radar_concentric ·
  #155 collision link-rename *(bug)* · #158 multi-gadget L3 · #478 métriques live Round Eye
- VILLAGE3B : #480 dossier presse · #497 poster grand public

### ⚪ T5 — Images / OS variants (basse urgence)
- #446 Full Traveller OS multi-mode/arch · #125 build-live-usb +virtualbox · #422 vm-x64 cascade

### ⚫ T6 — Docs / housekeeping
- #81 headers SPDX CMSD-1.0 partout · #243 clarifier scope secubox-zkp-auth *(question)*
- #474 ToolBoX (epic parent — garder comme tracker)

---

## 🔥 P0 — Immediate (in flight)

### kbin Tor endpoint — anonymized quick-switch surfing (#683)

> Capstone du couteau suisse cyber : l'anonymat de la sortie. Spec :
> `docs/superpowers/specs/2026-06-19-kbin-tor-anonymized-surfing-design.md`.
> Invariants : inspection préservée, fail-closed, opt-in (défaut OFF), no DNS leak, CSPN audit.

- [ ] **Transport** — Option A dialer SOCKS5 upstream (cœur Go #662, *préféré*) vs
  Option B nft mark → Tor TransPort (fallback pré-#662).
- [ ] **Profil Tor egress** — réutiliser `secubox-exposure` (bootstrap/NEWNYM), egress-only.
- [ ] **API toolbox** — `POST /admin/tor/{on,off}` (WG-hash scoped) + `GET /tor/state` +
  `POST /tor/newnym` + état SQLite per-client (TTL 24h).
- [ ] **UI kbin** — toggle 🧅 + badge état + flag pays de sortie + bouton « nouvelle identité ».
- [ ] **Leak-guard nft** + DNS-over-Tor (test exit IP + resolver ≠ Unbound).
- [ ] **`tls_splice` OFF en mode Tor** (#649) — sinon les flux asset fuient l'IP réelle.
- [ ] **CSPN** — audit-log chaque bascule ; soak DARK (flag présent, UI cachée) avant flip.

### ToolBox clients (`clients/`)

- [x] **#531 Android scaffold + CI** — Gradle/Compose one-tap onboarding,
  debug APK via `build-android-apk.yml`. CI green.
- [x] **#536 serve APK from toolbox** — `GET /wg/toolbox.apk` + onboard button +
  `secubox-toolbox-fetch-apk` helper.
- [x] **#538 Android root-mode silent** (PR #539) — system CA install + native
  kernel WireGuard + auto R3 verify, gated behind explicit root tap.
- [x] **#532 browser extension** (`clients/webext-toolbox/`) — MV3 Firefox
  `.xpi`/Chromium; live tracker badge + popup mini Round-Eye graph over
  `/social/*`; `GET /wg/toolbox.xpi` + fetch helper + `build-webext.yml`.
- [x] **#532 release** — tag `webext-v0.1.1` published the `.xpi`
  (downloadable, verified 200). `make_latest:false` + tag-pinned URL so it
  doesn't steal "Latest" from the Android APK release.
- [ ] **release signing** — Android keystore + AMO `.xpi` signing secrets in CI
  for stable published fingerprints (currently unsigned sideload).
- [ ] **#532 follow-ups** — optional `GET /social/live/{token}` SSE (replace the
  client-side poll) ; Poke/Emancipate per-site control once #525 (deception)
  ships ; Chromium PNG icon rasterisation for the Web Store.

### Phase 13 — Protection enforcement plane (#519) — ✅ COMPLETE

- [x] **13.A spine** (#521, `2.6.8`, v2.13.17) — nft blacklist set + forward-drop
  chain + sync (CrowdSec + threat-intel). + override_dh_strip drift fix.
- [x] **13.B DNS-guard** (#522, `2.6.9`, v2.13.17) — résout domaines blocklistés
  → IPs ; détection DoH/DoT (block opt-in).
- [x] **13.C attribution** (#524, `2.6.10`, v2.13.18) — per-device blocked-attempts
  + quarantine + endpoints + tile.
- [x] **13.D feedback** (#527, `2.6.11`, v2.13.19) — escalation evaluator
  (detections→nft/cscli/quarantine), audit-log, **default OFF**.
- [ ] **13.x opt-in tuning** — activer `SECUBOX_ESCALATE_*` / `SECUBOX_DOH_BLOCK`
  selon politique opérateur quand voulu.
- [ ] **threatfox feed = 0** — investiguer l'ingestion domain vide (impacte
  13.B resolved_domains).

### Phase 14 — Plan de déception (#525, idée future)

- [ ] Pseudo-réponses proxy au lieu de blocage IP (indistinguable, pollue
  le profil) + neutralisation des scripts CDN préchargés. R3 consenti,
  réutilise la détection Phase 11/12. **Pour plus tard.**

### Phase 11 — Social mapping per device (#502) — ✅ COMPLETE (v2.13.15)

- [x] **11.A backend** (#505, `2.6.0`) — correlation engine + SQLite + API.
- [x] **11.B frontend** (#507, `2.6.1`) — d3 graph + i18n + favicon proxy + wipe.
- [x] **11.C evidence + PDF** (#508, `2.6.3`) — consent-probe + bilingue FR/EN PDF.
- [x] **Toolbox WebUI tabs** (#513, `2.6.2`) — 5-tab nav, kbin /admin/ supprimé.
- [x] **Mergé** via PR #517 → master, tag `v2.13.15`.
- [ ] **11.D opérateur** (futur, optionnel) — vue HTML `/admin/social/`
  dédiée (le tab Cartographie sociale dans /toolbox/ couvre déjà l'agrégat).

### Phase 12 — Anti-human-detection platform (#514)

- [x] **12.A CDN** (#515, `2.6.4`) — detect_cdn + Round-Eye central-hotspot
  graph + by_cdn. Mergé.
- [x] **12.B anti-bot** (#516, `2.6.5/2.6.6`) — detect_antibot (détection
  seule) + ring levels visibles + Carto/Reset opérateur. Mergé.
- [x] **12.C opérateur-grade / state-adjacent** (#518, `2.6.7`, v2.13.16) —
  detect_operator_grade (telco MSISDN/x-acr + consortium Utiq/TrustPid +
  data-broker LiveRamp/BlueKai/Palantir-class). Top-severity lens + PDF.
- [ ] **12.B bypass** — résolution de challenge (gated derrière doctrine
  lawful-use + design review ; R3 opt-in uniquement).
- [ ] **12.D noise counter-measures** — cookie-noising / header-strip /
  decoy-traffic (gated derrière doctrine ; R3 opt-in, interférence active).

### Système — bugs gk2 (2026-06-10) — ✅ résolus

- [x] **CrowdSec firewall** — restart bouncer → tables nft recréées.
- [x] **WAF /var/log/secubox traversal** — fix source #511/#512 (mergé).
- [x] **WAF /stats perf** (#509/#510, `secubox-waf 1.2.2`) — double-buffer cache.
- [x] **PeerTube + PhotoPrism** — LXC redémarrés.
- [ ] **Round Eye gadget** — USB CDC-Ethernet TX queue wedged (NETDEV
  WATCHDOG, probe -110). Recovery gk2 épuisée. **Fix physique : power-cycle
  Pi Zero / re-seat câble OTG.** Reprendre côté gk2 au prochain boot propre.

### Phase 10 — Banner injection perf (#501) — ✅ shipped 2026-06-09

- [x] **Banner perf quick wins** (`secubox-toolbox` 2.5.1, commit `ce059d0f`)
  — LRU `_host_signals` (2048), drop body tracker scan, 2 MB body cap,
  trim dead tile. Deployed live sur gk2, iPhone confirme "better...
  perfect work".
- [x] **Postinst regression fix** (`secubox-toolbox` 2.5.2, commit `15f48d9d`)
  — auto-deploy fanout drop-in en `zz-`, try-restart sur upgrade. Push
  origin, code-only (pas encore déployé).
- [ ] **Build + deploy 2.5.2 sur gk2** — postinst-only, attendre fenêtre
  de maintenance (ne pas perturber session iPhone stable).
- [ ] **Ouvrir PR #501** sur instruction utilisateur (branche poussée :
  `perf/501-banner-injection-quickwins`).
- [ ] **Phase 10 future** — refactor banner JS-driven async (élimine
  buffer-read pour tous corps, pas seulement < 2 MB).

### Phase 9 — mitm-wg multi-worker fanout (#501) — ✅ shipped 2026-06-08

- [x] **4-worker template + numgen DNAT fanout** (`secubox-toolbox`
  2.5.0, merged `89380a12`). Live numbers gk2 : CPU 68/44/50/54 % au
  lieu d'un single ~90 %.
- [ ] **Phase 9.1 future** : real filelock pour
  `/var/lib/secubox/toolbox/mitm-bypass-dynamic.conf` (race 4-worker
  tolérable via launcher's `sort -u`, mais propre serait mieux).

### Phase 8 — Anti-tracking opérateur (Utiq) — issue #500

Plan complet documenté en issue. À implémenter :

- [ ] **Quick Win (1 j)** — addon `utiq_defense.py` R0 (log) + R1 (block),
  tile banner "🎯 Utiq detecté", tableau brut `/admin/utiq-events`,
  schéma SQLite.
- [ ] **Phase 2 (1 sem)** — R2 (mask `utiqLoader.js` → mtid=null) +
  R3 (pseudo-avatar via `avatar.py`).
- [ ] **Phase 3 (doctrine)** — section CSPN sur la forge d'identifiant
  R3, consentement explicite par client, banner UX étoffé.
- [ ] **Tests E2E** — 5 sites éditeurs européens (lemonde.fr,
  lefigaro.fr, marmiton.org, tf1.fr, 20minutes.fr) avec attendus
  par niveau.

### Phase 7.E follow-ups (de 2026-06-08, ref #498)

- [ ] `secubox-aggregator` 0.2.1 build + dpkg upgrade live sur gk2
  (ProtectSystem=full + /etc/secubox dans ReadWritePaths). Le live
  drop-in `40-etc-secubox-rw.conf` est en place tant que le paquet
  n'est pas upgrade.
- [ ] Rebuild + déploiement `secubox-users` 1.4.2 (postinst chowne
  aussi auth.toml).
- [ ] Investigation : pourquoi `systemd-timesyncd` reste
  `NTPSynchronized: no` sur gk2 même avec NTP servers configurés et
  UDP 123 outbound fonctionnel. Peut-être un IPv6-only resolve qui
  échoue silencieusement.

### Phase 9 ✅ shipped 2026-06-08 — voir bloc P0 ci-dessus

Approche initialement envisagée (dispatcher custom, LXC privilégiée
shared-netfilter) — résolue plus simplement via nft `numgen inc mod 4`
+ conntrack flow-pinning + systemd template `@.service`.
**#502 D redesign** capture la suite (captive → LXC TPROXY-inside).

---



### Phase 6 R3 WireGuard ✅ MAJOR RELEASE shipped 2026-06-05 (ref #496)

- [x] **#496 Phase 6** R3 portable WG tunnel + mitm + multi-OS install — branch
  `feature/496-phase-6-wireguard-mitm-autocert-mode-r3` (30 commits, 2918 lines, 26 files).
  Live on gk2 + wiki + landing public kbin.gk2.secubox.in.
- [x] **mitm WAF leak fix** (Connection: close upstream) — FDs 1513→3, scur 812→87.
  Live + backported `packages/secubox-mitmproxy/addons/secubox_waf.py`.
- [x] **Kbin filter-control READ-ONLY** + admin.gk2 toolbox webui editable card.
- [ ] **iPhone + Android E2E confirm** : reinstall NEW CA
  (SHA1 `D5:E4:3A...`), test banner sur HTTPS, validate "Mon rapport" link
  → kbin/?mh= ouverture rapport perso.
- [ ] **Merge** branche feature/496-... → master + push.
- [ ] **PR #495** (Phase 5 LXC) + **PR #496** (Phase 6 WG) à ouvrir après E2E confirmé.

### Phase 6 follow-ups

- [ ] threat_counts dict cleanup périodique dans secubox_waf.py (mineur leak)
- [ ] WAF leak fix : backporter aussi `packages/secubox-waf/mitmproxy/secubox_waf.py`
  (le 2e fichier mitmproxy addon en sync, currently 756 lines vs 930 dans secubox-mitmproxy)
- [ ] Investigate mitm-wg CPU > 30% au repos (idle keep-alives ?)

### 🛡 Phase 7 — WAF active enforcement (issue #498 filée 2026-06-05)

- [x] **#498 Phase 7.A** SHIPPED 2026-06-05 same-day : bridge mitm WAF →
  CrowdSec `/v1/alerts` (machine JWT auth) → nft drop via existing bouncer.
  Live verified : login 200, alert 201, cscli decision, nft entry,
  ~12s round-trip. Merged `3eb5378e`.
- [x] **#498 Phase 7.A.2 SHIPPED 2026-06-05** : backport secubox-waf, postinst
  auto-setup, `/api/v1/mitmproxy/waf/enforcement` endpoint, `threats.html`
  dashboard with 6 KPI + bans/threats tables auto-refresh. Merge `a35ab5c5`.
  - [ ] Tune `BAN_THRESHOLD` per category (XSS=2, SQLi=1, scanner=5) — open
- [x] **#498 Phase 7.B SHIPPED 2026-06-05** : nft rate-limit pre-mitm
  (`secubox_waf_ratelimit` table, drop > 30/s SYN with 5-min self-healing
  TTL), `secubox-waf-ratelimit.service` boot persist, honeypot nginx routes
  for /wp-admin /.env /.git/config /phpmyadmin /actuator + custom log_format
  `secubox_honeypot` → `/var/log/nginx/honeypot.log`. Merge `a35ab5c5`.
- [ ] **#498 Phase 7.C** long-term : eBPF/XDP kernel filter + ModSecurity
  remplacement mitm WAF + federation CrowdSec Hub/OTX/Spamhaus.
- [x] Roadmap doc : `.claude/PHASE-7-WAF-ROADMAP.md` ✅

### Release pipeline ✅ v2.13.4 APT GREEN + v2.13.12 rpi400 kiosk SALON-READY

- [x] **v2.13.4** APT publish vert (chaîne #425 + #427/PR #428 + #431/PR #432).
- [x] **v2.13.10** rpi400 image build SUCCESS (chaîne #436 — PRs #437/#438/#439/#440/#441).
- [x] **v2.13.11** mass-mask non-essential services (#442 / PR #443) — Pi 400 boote
  enfin sur multi-user → graphical → kiosk.
- [x] **v2.13.12** cursor visible sur kiosk (#444 / PR #445) — salon-ready.
- [x] **Boot test Pi 400** : SD v2.13.10 + live patches (mass-mask + admin password seed)
  boote, kiosk Chromium affiche, login admin/secubox OK.

### 🎪 Salon demo readiness — issues filées 2026-06-02

- [ ] **#447** admin password seed côté CI : `users.json` ship avec password seedé
  (Option A : seed admin/secubox at build + drop `runnervm3jyl0` stray ; Option B :
  implémenter `/setup` flow first-login). Recommandation : A maintenant, B follow-up.
- [ ] **#448** LAN IP visible sur la kiosk login UI : backend
  `GET /api/v1/system/identity` + frontend display IP/hostname/version au bas du form.
- [ ] **#446** Full Traveller OS (multi-mode / multi-boot / multi-arch / shared data) —
  vision opérateur 2026-06-02, big architectural feature, post-salon.

### Issues ouvertes filées 2026-05-31 (post-v2.13.4)

### Espressobin / live-amd64 / mochabin builds (à traiter séparément)

- [ ] `build-live-usb x64 amd64` failure préexistante depuis v2.13.x — bloque
  la publication GH Release sur tous les tags.
- [ ] `build-mochabin-live-usb` failure préexistante.
- [ ] `build-image espressobin-v7` / `-ultra` failure préexistante.

Ces 4 jobs sont distincts du chain kiosk #436. À investiguer un par un.

### Issues ouvertes filées 2026-05-31 (post-v2.13.4)

- [ ] **PR #429** à OUVRIR : branche `feature/429-secubox-nextcloud-dashboard-api-renvoie`
  pushée (commit `b715c0e4`), fix déployé live sur gk2 mais pas encore mergé
  en master. Dashboard NC retourne enfin les vraies données (overwrite.cli.url,
  occ users, du/df dans container).

- [ ] **#430** Fédération Nextcloud OCM entre deux SecuBox : documenter le
  workflow `occ federation:trusted-servers:add`, ajouter une page UI dans le
  dashboard NC (`Settings → Federation`) + endpoints API GET/POST/DELETE
  `/api/v1/nextcloud/federation/trusted-servers`, test d'intégration avec
  une seconde LXC NC factice.

- [x] **#433** `build-rpi-usb.sh --kiosk` silently fails — closed by PR #435
  (fail-loud + assertion). Subsequent #436 chain made the assertion pass.

- [ ] **#434** kiosk login lockdown après N attempts (CSPN hardening) :
  frontend kiosk login switch vers template `<lockdown />` après N fails
  (default N=1), backend rate-limit 429 + endpoint admin unlock, TOML
  config `/etc/secubox/kiosk.toml [lockdown]`, audit log immuable sur
  lockdown. Unlock paths : reboot / USB key / timed.

- [ ] **cloud.gk2.secubox.in pas dans aucun vhost nginx** — tombe sur
  default_server `_` qui sert `wrong-domain.html`. Fix 1-ligne : ajouter
  `cloud.gk2.secubox.in` à la ligne `server_name nc.gk2.secubox.in
  nextcloud.gk2.secubox.in;` de `/etc/nginx/sites-available/nextcloud.conf`
  (sur gk2 ET dans `packages/secubox-nextcloud/nginx/` source-side).

### Issues encore ouvertes de 2026-05-30

- [ ] **#421** sockets `/run/secubox/*.sock` cachés (cause des 502 sur
  `/api/v1/cookies` + `/api/v1/certs` + des 500 sur tous les vhosts gated
  Authelia, dont lyrion). Cause racine identifiée : collision entre tmpfs
  mount dédié à `/run/secubox` (créé par secubox-runtime/tmpfiles) et
  `RuntimeDirectory=secubox` dans plusieurs units (qui crée un namespace
  privé). Fix : choisir UNE seule mécanique de création et l'appliquer
  partout, reboot-tested. Puis revert le contournement live sur lyrion
  (`/etc/nginx/sites-available/lyrion.conf.bak.sso-removed.*`) pour
  réactiver `auth_request /__sbx_auth_verify`.

- [ ] **#422** image `vm-x64` cascade `[FAILED]` en VirtualBox (otg-gadget,
  networkd-wait-online, mitmproxy, crowdsec, net-fallback, openclaw en
  restart loop ; sshd accepte TCP mais pas de bannière). Fix : ajouter au
  profil de build `vm-x64` un `systemctl mask` des services exclusivement
  hardware-appliance (`secubox-otg-gadget`, etc.). Masker
  `systemd-networkd-wait-online` sur le profil VM ou passer en `--any`.
  Re-tester la VM `SecuBox-amd64` (gardée *powered off* sur le dev box)
  une fois fixé. Tag v2.13.3.

### Espressobin image builds (pré-existant)

- [ ] **espressobin-v7 + espressobin-ultra** : `build-image` failure dans
  toutes les Releases v2.13.x. Pas dans la chaîne packaging — distinct.
  À investiguer séparément (board/espressobin-* config, kernel, etc.).

### Session 2026-05-27 evening follow-ups (peertube + photoprism + WAF)

- [x] **Peertube install** — DONE 2026-05-28. LIVE at
  https://peertube.gk2.secubox.in/, upload confirmed. Native-in-LXC
  (Node 22 + pnpm). See HISTORY 2026-05-28. Did NOT need Docker
  fallback — native install worked once Node bumped 20→22 + ownership
  fixed + production.yaml patched.

- [~] **Peertube SOURCE backport** — DONE 2026-05-28, pushed on
  `feature/388-rework-secubox-peertube-align-with-secub` (commit `5e52598c`).
  Native-LXC rework + dashboard correction + yt-dlp URL import. **#390 is
  superseded** (its vhost folded in with the port corrected to LXC :9000;
  user to close #390). PeerTube native HTTP import (yt-dlp) ALSO enabled on
  the live gk2 instance — "Import with URL" now available in the PeerTube UI.
  Pending: rebuild+deploy the `secubox-peertube` .deb to gk2 so the dashboard
  Import tab + corrected status go live (currently only the upstream PeerTube
  UI import is live). No PR opened yet (awaiting user go-ahead).

- [ ] **(historical) Peertube SOURCE backport notes** — two issues/worktrees:
  - **#388** (`feature/388-rework-secubox-peertube-align-with-secub`):
    package describes a *Docker/Podman API-managed* model; live deploy
    went *native-in-LXC* (Node 22 + pnpm + systemd `peertube.service`
    inside the container). Reconcile: either (a) ship the native
    install recipe as a packaged `install-peertube.sh` + document the
    LXC pattern, or (b) rewrite to actually drive Docker/Podman.
    Decide with operator — affects what the package ships + how it
    reproduces. Live install script lives at
    `/data/lxc/peertube/rootfs/root/{install-peertube.sh,peertube-finish.sh,install-node22.sh,peertube-config.py}`.
  - **#390** ✅ DONE 2026-05-29 — already backported (folded into the #388
    merge). The full public vhost lives in source at
    `packages/secubox-peertube/conf/peertube.nginx.conf` (listen :9080,
    `proxy_pass http://10.100.0.120:9000`, 8G upload, 7d timeouts, WS, ACME)
    and is **byte-identical** to the live `/etc/nginx/sites-available/
    peertube.conf` (diff clean, ignoring comments). `debian/rules` ships it to
    `sites-available/` and `postinst` symlinks it into `sites-enabled/`. The
    `feature/390-…` branch is superseded — **operator can close #390**.

- [x] **NC bruteforce protection** — WON'T re-enable (operator decision
  2026-05-29). The WAF (CIDR-aware LAN whitelist, commit 0bf67891) is the
  brute-force layer; NC's built-in counter stays OFF. See memory
  `project_nc_bruteforce_disabled`.

- [x] **PhotoPrism admin password** — DONE 2026-05-29 via `secubox-user-sync
  seed` (#410): the seed ran `photoprism users mod -p` on admin, so the
  password is the operator's chosen one. `PHOTOPRISM_ADMIN_PASSWORD` is
  first-init-only in PhotoPrism, so the stale `secubox-CHANGE-ME` env in the
  unit does NOT revert it — purely cosmetic. Optional tidy: drop that plaintext
  default from the unit + source install-lxc.sh.

- [x] **PhotoPrism auto-index + NC photo wiring** — DONE LIVE 2026-05-28.
  Root cause: NC↔PhotoPrism were never connected — `/data/shared/photos`
  (PhotoPrism originals) was bind-mounted to NC `data/Photos` (a path NC
  doesn't serve), so it stayed empty while phone sync landed in
  `data/<user>/files/`. Fix applied live:
  - NC LXC bind re-pointed `/data/shared/photos → media/photos` (outside
    data dir); `files_external` app enabled; Local external mount
    **"PhotoLibrary"** (mount id 2, all users) → `/media/photos`, with
    `filesystem_check_changes=1`.
  - PhotoPrism: `photoprism-index.timer` (every 15 min, OnBootSec=5min) runs
    `podman exec photoprism photoprism index` — PhotoPrism's built-in
    auto-index only fires for its own UI uploads, NOT external/NC-synced
    files, hence the timer.
  - Verified round-trip: host file → NC PhotoLibrary → PhotoPrism originals.
  - **Operator action**: point the phone NC client's auto-upload to the
    **PhotoLibrary** folder.
- [ ] **SOURCE backport of the PhotoPrism↔NC integration (DRIFT)** — both
  `secubox-photoprism` and `secubox-nextcloud` are still dashboard-only
  packages (no install-lxc.sh; the live LXC+podman installs were ad-hoc,
  same pre-#388 state PeerTube was in). Capturing this integration in source
  needs the SAME native-LXC rework as #388 for both packages (install-lxc.sh
  with: NC media/photos bind + files_external PhotoLibrary mount;
  photoprism-index.timer + podman run with originals=/data/shared/photos +
  PHOTOPRISM_AUTO_INDEX). Sizeable — file as its own issue(s) before doing.

- [ ] **LXC template bootstrap fixes** (capture lessons-learned):
  1. **DNS**: fresh download-template LXCs ship a
     systemd-resolved stub with no nameservers. Workaround: overwrite
     `/etc/resolv.conf` with `nameserver 1.1.1.1 / 8.8.8.8`. Should
     bake into the LXC template or a one-shot first-boot script.
  2. **Template choice**: `lxc-create -t download -- -d debian` uses
     `common.conf + userns.conf + apparmor=generated` by default,
     which breaks postgres-15 postinst + podman CNI. Use
     `debian.common.conf` (matrix template). Document in
     wiki.
  3. **Bind-mount UID ownership**: bind-mounted dirs default to host
     root, LXC root (UID 100000 outside) can't chown across. Recipe:
     `chown -R 100000:100000 /data/<svc>/` on host BEFORE first
     container start. Document.

- [ ] **mitmproxy + WAF live-config drift**: host's
  `/srv/mitmproxy/haproxy-routes.json` and `secubox_waf.py` are NOT
  bind-mounted into the mitmproxy LXC. Each has its own copy →
  source-side edits don't propagate. Fix: add
  `lxc.mount.entry = /srv/mitmproxy srv/mitmproxy none bind,create=dir`
  to `/data/lxc/mitmproxy/config` so edits flow either way. Beware:
  the LXC currently has `mitmproxy:mitmproxy` ownership; host owns
  by root. Need to align UIDs first.

- [ ] **IP-forward + lan0-masquerade backport to
  `secubox-system-tuning`**: live fix on gk2 used
  `99-secubox-zz-lxc-forward.conf` (alphabetical win) + manual
  `nft add rule inet nat postrouting oif lan0 masquerade`. Backport
  both as part of the tuning package so other boards inherit it on
  apt install. Bump secubox-system-tuning to 1.1.0.

- [ ] **CrowdSec public-IP allowlist**: operator's home/cellular IP
  not in `secubox-trusted` allowlist (would need them to run
  `curl ifconfig.me`). Without it they may hit external bf
  scenarios. Add when known.

### Session 2026-05-27 follow-ups (consolidation pass)

- [ ] **`secubox-daemon` arm64 cross-build + deploy** so the
  c3box binary-package rename (#378, in master at `4cd5f343`)
  lands on gk2 and other arm64 boards. Either:
  (a) on a Marvell-arm64 host: `cd daemon && make build-arm64`,
      rename `secuboxd-arm64` → `secuboxd` (etc.) in `daemon/build/`,
      then `cd packages/secubox-daemon && dpkg-buildpackage -us -uc -b`;
  (b) patch `packages/secubox-daemon/debian/rules` to detect target
      arch and use the `-arm64`-suffixed binaries when cross-building
      from amd64 (cleaner, lets the dev box build everything).
  Non-acute: secubox-daemon not currently installed on gk2.

- [ ] **`secubox-ndpid 1.0.1` blocked from gk2** by missing
  `ndpid | ndpi-reader` apt source. Options:
  (a) add an apt source that provides `ndpid` for bookworm/arm64;
  (b) package `ndpid` ourselves under `packages/ndpid/`;
  (c) relax `secubox-ndpid` `Depends:` → `Recommends:` and add a
      runtime check that surfaces "ndpid daemon unavailable" in the
      dashboard instead of refusing to install.
  Recommend (c) for shortest path — operators who want the
  fingerprinting dashboard install ndpid themselves.

- [ ] **Mail transitional postinsts** (#380) should rm orphan nginx
  snippets on upgrade. On gk2 today, dpkg's `.list` for
  `secubox-mail-lxc 2.2.1`, `secubox-webmail 2.2.0`, `secubox-
  webmail-lxc 2.2.0` claimed to own `/etc/nginx/secubox.d/
  {mail-lxc,webmail,webmail-lxc}.conf` but the new (empty) .debs
  don't ship them — leftovers from a pre-2.2 install that dpkg
  didn't auto-clean. Patch each transitional postinst to add:

  ```sh
  rm -f /etc/nginx/secubox.d/<name>.conf
  systemctl reload nginx 2>/dev/null || true
  ```

  (Mirror the mmpm pattern from #381's transitional postinst.)
  Bump versions, rebuild, mass-redeploy. Without this fix, other
  boards upgrading from <2.2 will inherit the same orphan files.

### Session 2026-05-26 follow-ups

- [ ] **Finir Preserve fix sur 2 services restants** : `secubox-torrent` et
  `secubox-voip` (les seuls avec `RuntimeDirectory=` mais sans
  `RuntimeDirectoryPreserve=yes` après le mass-redeploy). Rebuild +
  `dpkg -i` ces deux .debs seulement. ~2 min.

- [ ] **Auditer tous les `postinst` qui font `systemctl enable` sans
  tolérer les units masked.** Pattern à reproduire (depuis le fix
  wazuh `63284497`) :

  ```sh
  if [ "$(systemctl is-enabled secubox-X.service 2>/dev/null)" != "masked" ]; then
    systemctl enable secubox-X.service
    systemctl start secubox-X.service || true
  fi
  ```

  Sinon le prochain mass-redeploy se ramasse les mêmes
  `half-configured` sur toute box qui a masked un service par choix
  opérateur. Audit via `grep -L 'is-enabled.*masked' packages/*/debian/postinst | xargs grep -l 'systemctl enable'`.

- [ ] **`secubox-system-restart` orchestrateur** (issue à créer) :
  remplacer le `dpkg -i pkg1.deb pkg2.deb ... pkgN.deb` brutal par un
  workflow ordonné qui :
  1. Bloque les writers dashboard (mode read-only sur /data)
  2. `sync` + `umount /data` (ou snapshot lvm)
  3. Stop ordonné des services (dependency-graph aware)
  4. Replay `dpkg -i` sur le lot
  5. Remount /data + bring up dans l'ordre `secubox.target` →
     `secubox-core` → modules
  6. Unblock writers
  Évite le cascade de 100 systemd restarts en parallèle + le fsck forcé
  sur /data au reboot. Pas urgent mais nécessaire avant la prochaine
  mass-deploy.

- [ ] **`scripts/build-packages.sh` discovery dynamique** : la liste
  `PACKAGES=()` est hardcodée (30 entrées) alors qu'on a 100+ paquets
  dans `packages/*/debian/`. Remplacer par
  `mapfile -t PACKAGES < <(find packages -maxdepth 2 -type d -name debian | sed 's|/debian||;s|^packages/||' | sort)`.
  Le `--filter` continuera de fonctionner.

- [ ] **v2.11.1 patch** — commit + PR + tag the 4 install-lxc.sh fixes once
  validated on board gk2:
  1. `lxc-create -t download` (bookworm unprivileged)
  2. `ensure_masquerade` for 10.100.0.0/24
  3. `gpg --dearmor` on grafana apt key
  4. unlink `/etc/resolv.conf` symlink + write via `lxc-attach`
- [ ] Validate end-to-end `grafanactl install`, `yacyctl install`, `rustdeskctl install` on the board (LXC green, daemon running, web UI reachable through nginx)

## 🟡 P1 — Next release (v2.12.0 target)

- [ ] **v1.1.0 verb implementations** for the three new ctl tools (currently stub `exit 2` for the noun-specific verbs):
  - `grafanactl dashboard list/add/remove/export` + `datasource list/add/remove/test` + `alert list/mute/unmute` + `user list/add/remove/passwd` + `api-key list/create/revoke`. Backend = Grafana HTTP API on `10.100.0.70:3000`, auth = admin password from `/etc/secubox/secrets/grafana-admin`.
  - `yacyctl peer list/add/remove/status` + `index status/build/clear/optimize` + `query test/count` + `blacklist list/add/remove` + `crawler list/start/stop/schedule`.
  - `rustdeskctl peer list/add/remove` + `relay status/restart/log` + `key show/rotate` + `session list/kill`.
- [ ] Add the 3 new modules to `docs/MODULES.md` catalog
- [ ] Add the 3 new grammar rows to `docs/grammar.md` canonical table (OPS MONITORING / SEARCH / REMOTE-ACCESS)
- [ ] Update `.claude/MIGRATION-MAP.md` with grafana / yacy / rustdesk

## 🟣 P2 — Sensor stack (WALL/MIND alignment)

- [ ] **#236 `secubox-rbs-sensor`** — Quectel EP06-E modem-based rogue-base-station sensor (WALL).
  Spec: `docs/superpowers/specs/2026-05-20-secubox-wall-ep06.md`.
  Prerequisites flagged: needs `wall_rbs_sensor.py` / `Observer(Protocol)` /
  `CellObservation` / `NeighbourObservation` / OODA verdict engine scaffolded as part of the same package (none exist yet in repo).
- [ ] **#237 `secubox-sentinelle-gsm`** — RTL-SDR + gr-gsm passive RX-only sensor for false-BTS detection (MIND, feeds WALL/OPAD).
  Spec: `docs/superpowers/specs/2026-05-20-secubox-sentinelle-gsm.md`.
  Privacy-by-design: HMAC-truncated identifiers in PROD, LAB mode with consent banner + audit. Hard limits: RX only, no decryption, no tracking primitive.
- [ ] Decide build order: `rbs-sensor` framework first (Observer Protocol + CellObservation as part of `secubox-core` or its own package?), then `sentinelle-gsm` plugs as second backend.

---

## ✅ PHASE 1 — Bootstrap HW + OS (S01–S03) — TERMINÉ

- [x] **P1-01** Images Debian bookworm arm64 + amd64
- [x] **P1-02** build-image.sh (debootstrap multi-arch)
- [x] **P1-03** firstboot.sh (JWT, SSH, hostname, nftables)
- [x] **P1-04** netplan templates par board
- [x] **P1-05** create-vbox-vm.sh (VirtualBox VM)
- [ ] **P1-06** Kernel 6.6 LTS cross-compile (optionnel)

---

## ✅ PHASE 2 — API Gateway + secubox-core + secubox-hub (S04–S07) — TERMINÉ

- [x] **P2-01** Implémenter `common/secubox_core/` (lib Python partagée)
  - `auth.py` : JWT HS256, require_jwt dependency, login endpoint
  - `config.py` : charger /etc/secubox/secubox.conf (TOML), get_board_info()
  - `logger.py` : logging structuré JSON vers journald
  - `system.py` : board_info(), uptime(), service_status(), disk_usage()
- [x] **P2-02** Écrire `common/nginx/secubox.conf`
  - Serve `/usr/share/secubox/www/` pour les statics
  - Proxy `/api/v1/<module>/` → `unix:/run/secubox/<module>.sock`
  - TLS autosigné firstboot + Let's Encrypt optionnel
- [x] **P2-03** Paquet `secubox-core` complet
  - `debian/control`, `debian/rules`, `debian/postinst`
  - Installe secubox_core dans `/usr/lib/python3/dist-packages/`
  - Crée `/etc/secubox/`, `/run/secubox/`, `/var/lib/secubox/`
- [x] **P2-04** Paquet `secubox-hub` (référence de pattern)
  - Porter `luci-app-secubox` : dashboard central, module launcher
  - `api/main.py` : endpoints status, modules, alerts, monitoring, settings
  - `debian/` complet + unit systemd `secubox-hub.service`
- [x] **P2-05** Script `scripts/rewrite-xhr.py`
  - Remplace `rpc.declare({object:'luci.X',method:'Y'})` → `fetch('/api/v1/X/Y')`
  - Mode dry-run + mode patch in-place

---

## ✅ PHASE 3 — Modules (S07–S12) — TERMINÉ (33 modules)

All 33 modules ported and running:
- [x] **P3-01** `secubox-crowdsec` — 54 endpoints
- [x] **P3-02** `secubox-netdata` — 16 endpoints
- [x] **P3-03** `secubox-wireguard` — 28+ endpoints
- [x] **P3-04** `secubox-vhost` — vhosts, SSL, certs
- [x] **P3-05** `secubox-mediaflow` — streams, alerts
- [x] **P3-06** `secubox-dpi` — 40+ endpoints netifyd
- [x] **P3-07** `secubox-qos` — 60+ endpoints HTB
- [x] **P3-08** `secubox-auth` — 20+ endpoints
- [x] **P3-09** `secubox-cdn` — 25+ endpoints
- [x] **P3-10** `secubox-system` — 35+ endpoints
- [x] **P3-11** `secubox-netmodes` — 25+ endpoints + templates
- [x] **P3-12** `secubox-nac` — 25+ endpoints
- [x] **P3-13** `secubox-haproxy` — stats, backends, WAF
- [x] **P3-14** `secubox-droplet` — upload, publish
- [x] **P3-15** `secubox-streamlit` — apps, deploy
- [x] **P3-16** `secubox-streamforge` — apps, templates
- [x] **P3-17** `secubox-metablogizer` — sites, tor
- [x] **P3-18** `secubox-dns` — zones, BIND
- [x] **P3-19** `secubox-mail` — Postfix/Dovecot + DKIM + SpamAssassin + Postgrey + ClamAV
- [x] **P3-20** `secubox-users` — unified identity
- [x] **P3-21** `secubox-webmail` — Roundcube
- [x] **P3-22** `secubox-waf` — 300+ rules, CrowdSec
- [x] **P3-23** `secubox-gitea` — Git server LXC
- [x] **P3-24** `secubox-nextcloud` — File sync LXC
- [x] **P3-25** `secubox-c3box` — Services portal
- [x] **P3-26** `secubox-publish` — Unified publishing

---

## ✅ PHASE 4 — APT Repo + Packaging (S13–S14) — TERMINÉ

- [x] **P4-01** APT repo signé GPG (apt.secubox.in)
- [x] **P4-02** reprepro config + publish workflow
- [x] **P4-03** Métapaquets (secubox-full, secubox-lite)
- [x] **P4-04** Local cache build system (apt-cacher-ng)
- [x] **P4-05** Deployment scripts (export-secrets.sh, local-publish.sh, install.sh)

---

## ✅ PHASE 5 — CSPN Hardening (S15–S18) — TERMINÉ

- [x] **P5-01** AppArmor profiles pour chaque service
  - Base profile: /etc/apparmor.d/local/secubox-base
  - Hub, Mail, WireGuard, CrowdSec specific profiles
  - Generic profile for simple services
  - Install script: scripts/install-apparmor.sh
- [x] **P5-02** Kernel config hardening — secubox-hardening module
  - Sysctl hardening (ASLR, kptr_restrict, dmesg_restrict)
  - Network hardening (SYN cookies, rp_filter, no redirects)
  - Module blacklist (uncommon protocols, filesystems)
  - hardeningctl CLI + FastAPI + web dashboard
- [ ] **P5-03** Rootfs read-only : overlayfs + A/B partition eMMC
- [x] **P5-04** Secrets : firstboot génère dans /run/secubox/keys (tmpfs)
  - JWT secret generated at firstboot
  - Stored in /run/secubox/ (tmpfs)
- [x] **P5-05** auditd rules for SecuBox services
  - Config changes, JWT access, firewall rules
  - Authentication, privilege escalation
  - Install script: scripts/install-audit.sh
- [x] **P5-06** nftables DEFAULT DROP policy + règles minimales
  - inet secubox_filter with DROP policy
  - Only SSH, HTTP/HTTPS, WireGuard open
- [ ] **P5-07** Cible de sécurité ANSSI (rédiger draft CC EAL2)

---

## ✅ PHASE 6 — CI/CD Image Factory (S19–S21)

- [x] **P6-01** `build-packages.yml` : dpkg-buildpackage cross arm64 + reprepro
  - Dynamic matrix from packages directory
  - Dual architecture (arm64 + amd64)
  - Auto-publish on tag v*
  - build-all.sh for local development
- [x] **P6-02** `build-image.yml` : matrix 5 boards + SHA256SUMS signés
  - MOCHAbin, ESPRESSObin v7, ESPRESSObin Ultra, vm-x64, vm-arm64
  - Compressed with gzip and xz
  - GPG signed checksums
- [x] **P6-03** Release pipeline : tag v* → GitHub Release + APT repo update
  - Auto-publish packages to apt.secubox.in
  - Auto-create GitHub Release with images
  - Installation instructions in release notes

---

## ✅ PHASE 7 — Documentation (S22–S24) — TERMINÉ

- [x] **P7-01** Comprehensive API Reference (EN, FR, ZH)
  - 48 modules documented with ~1000+ endpoints
  - Organized by category (Core, Security, Network, Services, Apps, Intel)
  - Code examples for common operations
  - WebSocket documentation
  - Error handling and rate limiting
- [x] **P7-02** Multilingual module documentation
  - wiki/MODULES-EN.md, MODULES-FR.md, MODULES-DE.md, MODULES-ZH.md
  - 48 modules with screenshots and descriptions
- [x] **P7-03** Installation guides (EN, FR, ZH)
- [x] **P7-04** Live USB guide with persistence

---

## ✅ COMPLÉTÉ

- Phase 1: Hardware bootstrap — Images arm64 + amd64, VirtualBox VM
- Phase 2: Infrastructure — secubox_core, nginx proxy, rewrite-xhr.py
- Phase 3: Modules — All 48 modules ported (~1000+ API endpoints)
- Phase 4: APT Repo — reprepro, GPG, metapackages, local cache
- Phase 5: CSPN Hardening — AppArmor, sysctl, auditd, nftables (mostly complete)
- Phase 6: CI/CD — build-packages.yml, build-image.yml, release.yml
- Phase 7: Documentation — API Reference (EN/FR/ZH), Module docs, Installation guides

**Current status:**
- 52 packages total (48 modules + metapackages)
- Mail server: DKIM + SpamAssassin + Postgrey + ClamAV
- WAF: 300+ rules with CrowdSec integration
- Hardening: Kernel sysctl + module blacklist
- Documentation: Comprehensive API docs in 3 languages

---

## ✅ PHASE 8 — Applications (21 modules) — COMPLETE

High-value user-facing services:

- [x] **P8-01** `secubox-ollama` — LLM inference, Ollama API proxy ✅
- [x] **P8-02** `secubox-jellyfin` — Media server LXC ✅
- [x] **P8-03** `secubox-homeassistant` — IoT hub LXC ✅
- [x] **P8-04** `secubox-zigbee` — Zigbee2MQTT gateway ✅
- [x] **P8-05** `secubox-photoprism` — Photo management ✅
- [x] **P8-06** `secubox-matrix` — Synapse chat server LXC ✅
- [x] **P8-07** `secubox-jitsi` — Video conferencing LXC ✅
- [x] **P8-08** `secubox-gotosocial` — Fediverse server ✅
- [x] **P8-09** `secubox-peertube` — Video platform LXC ✅
- [x] **P8-10** `secubox-hexo` — Static blog generator ✅
- [x] **P8-11** `secubox-magicmirror` — Smart display ✅
- [x] **P8-12** `secubox-lyrion` — Music server ✅
- [x] **P8-13** `secubox-webradio` — Internet radio ✅
- [x] **P8-14** `secubox-voip` — VoIP/PBX LXC ✅
- [x] **P8-15** `secubox-jabber` — XMPP server ✅
- [x] **P8-16** `secubox-simplex` — Secure messaging ✅
- [x] **P8-17** `secubox-torrent` — BitTorrent client ✅
- [x] **P8-18** `secubox-newsbin` — Usenet client ✅
- [x] **P8-19** `secubox-domoticz` — Home automation ✅
- [x] **P8-20** `secubox-localai` — Alternative LLM backend ✅
- [x] **P8-21** `secubox-mmpm` — MagicMirror package manager ✅

---

## ✅ PHASE 9 — System Tools (22 modules) — COMPLETE

Infrastructure utilities:

- [x] **P9-01** `secubox-vault` — Config backup/restore ✅
- [x] **P9-02** `secubox-cloner` — System imaging ✅
- [x] **P9-03** `secubox-vm` — QEMU/KVM virtualization ✅
- [x] **P9-04** `secubox-glances` — System monitor ✅
- [x] **P9-05** `secubox-rtty` — Remote terminal ✅
- [x] **P9-06** `secubox-nettweak` — Network tuning ✅
- [x] **P9-07** `secubox-routes` — Routing table view ✅
- [x] **P9-08** `secubox-ksm` — Kernel same-page merging ✅
- [x] **P9-09** `secubox-reporter` — System reports ✅
- [x] **P9-10** `secubox-metabolizer` — Log processor ✅
- [x] **P9-11** `secubox-metacatalog` — Service catalog ✅
- [x] **P9-12** `secubox-saas-relay` — SaaS proxy ✅
- [x] **P9-13** `secubox-rezapp` — App deployment ✅
- [x] **P9-14** `secubox-turn` — TURN/STUN server ✅
- [x] **P9-15** `secubox-smtp-relay` — Mail relay ✅
- [x] **P9-16** `secubox-mqtt` — MQTT broker ✅
- [x] **P9-17** `secubox-cyberfeed` — Threat feed aggregator ✅
- [x] **P9-18** `secubox-avatar` — Identity management ✅
- [x] **P9-19** `secubox-admin` — Admin dashboard ✅
- [x] **P9-20** `secubox-mirror` — Mirror/CDN ✅
- [x] **P9-21** `secubox-netdiag` — Network diagnostics ✅
- [x] **P9-22** `secubox-picobrew` — Homebrew controller ✅

---

## ✅ PHASE 10 — Security Extensions (10 modules) — COMPLETE

Advanced security features:

- [x] **P10-01** `secubox-wazuh` — SIEM integration ✅
- [x] **P10-02** `secubox-ai-insights` — ML threat detection ✅
- [x] **P10-03** `secubox-ipblock` — IP blocklist manager ✅
- [x] **P10-04** `secubox-interceptor` — Traffic interception ✅
- [x] **P10-05** `secubox-cookies` — Cookie analysis ✅
- [x] **P10-06** `secubox-mac-guard` — MAC address control ✅
- [x] **P10-07** `secubox-dns-provider` — DNS API (OVH, Gandi) ✅
- [x] **P10-08** `secubox-threats` — Threat dashboard ✅
- [x] **P10-09** `secubox-openclaw` — OSINT tool ✅
- [x] **P10-10** `secubox-netifyd` — DPI daemon ✅

---

## 🔄 PHASE 11 — Live USB Enhancements (v1.7.0)

### Remote UI / HyperPixel 2.1 Round
- [x] **P11-R01** USB OTG composite gadget (ECM + ACM)
- [x] **P11-R02** TransportManager with OTG/WiFi failover
- [x] **P11-R03** install_zerow.sh with safe device check
- [x] **P11-R04** Fix vc4-kms-v3d conflict with HyperPixel
- [x] **P11-R05** Bookworm userconf file for pi:raspberry
- [x] **P11-R06** usb0-up.sh bypass NetworkManager
- [x] **P11-R07** Test HyperPixel display on real hardware ✅ v1.10.0
- [x] **P11-R17** USB OTG network fix — Use usb1 (ECM) for Linux hosts ✅ v2.1.1
  - Fixed: dtoverlay=hyperpixel2r (not hyperpixel4)
  - Fixed: hyperpixel2r-init uses pigpio instead of RPi.GPIO (lgpio issues on Bookworm)
  - Fixed: Service dependencies (requires pigpiod)
- [x] **P11-R08** Display verified working after reboot ✅
- [x] **P11-R09** Framebuffer dashboard for Pi Zero W ✅ v1.11.0
  - Pi Zero W (ARMv6) lacks NEON SIMD required by Chromium
  - Created Python PIL-based framebuffer dashboard (fb_dashboard.py)
  - Renders directly to /dev/fb0 without X11
  - 6 circular module rings with animated metrics
  - Auto-starts via secubox-fb-dashboard.service

### Eye Remote Full Integration (v2.0.0) — Issue #31
- [ ] **P11-R10** secubox-eye-agent — Multi-SecuBox connection manager
  - Device token auto-authentication
  - Metrics bridge (Unix socket to dashboard)
  - WebSocket command handler
  - Touch gestures for control
- [ ] **P11-R11** secubox-eye-remote module — SecuBox side
  - FastAPI endpoints for device management
  - Device registry + token manager
  - Pairing flow with QR generation
  - WebSocket bidirectional commands
  - Serial console bridge (xterm.js)
- [ ] **P11-R12** WebUI management dashboard
  - Device status, screenshot, reboot, OTA
  - Configuration panel
  - Pairing QR display
  - Serial terminal (xterm.js)
- [ ] **P11-R13** Touchless pairing
  - QR code URL to SecuBox
  - SSH auto-provisioning
  - Device token generation
- [ ] **P11-R14** Eye Remote as controller
  - Service restart via touch
  - OTG mode switching
  - Emergency lockdown (3-finger tap)
- [ ] **P11-R15** secubox-eye-gateway tool
  - Emulator mode (fake metrics)
  - Gateway mode (proxy to real SecuBox)
  - Fleet mode (multi-SecuBox aggregation)
  - Metrics profiles (idle/normal/busy/stressed)
- [ ] **P11-R16** OTA updates + screenshot capture

### Kiosk Mode
- [ ] **P11-01** Display SecuBox version in kiosk mode header/footer
- [ ] **P11-02** Show current authentication mode (ZKP/standard) in kiosk UI
- [ ] **P11-03** Add boot mode indicator (kiosk/console/bridge) on splash

### Authentication Feedback
- [ ] **P11-04** Visual feedback for auth mode in portal login page
- [ ] **P11-05** Auth mode toggle in system settings
- [ ] **P11-06** ZKP status indicator in dashboard

### Boot Experience
- [ ] **P11-07** Plymouth theme with version number
- [ ] **P11-08** GRUB menu version display
- [ ] **P11-09** Boot mode selection with descriptions

---

## 🔄 PHASE 12 — Meta-Script Generator (v2.0.0)

*SecuBox Appliance Factory — Profile-based, modular image generation with version tracking*

### Architecture Core
- [ ] **P12-01** Profile hierarchy system ("gigogne" nested inheritance)
  - base/ → tier-lite/ → tier-standard/ → tier-pro/
  - Profile YAML with `inherits:` directive
  - Component capability matrix (memory, CPU, storage requirements)
  - Automatic profile selection based on detected hardware
- [ ] **P12-02** Board-specific tweaks registry
  - boards/<board>/tweaks.yaml — hardware-specific optimizations
  - DTS/DTB overrides per board
  - Kernel module blacklist/whitelist per board
  - Performance profiles (idle, normal, busy, stressed)
- [ ] **P12-03** Component versioning system
  - component-version.yaml per package
  - Semantic versioning with SecuBox patch suffix (e.g., 1.7.7-sb3)
  - Compatibility matrix (min memory, requires, conflicts)
  - Tag system for feature categorization

### Generator CLI
- [ ] **P12-04** `secubox-gen` — Manifest generator
  ```bash
  secubox-gen --profile tier-lite --board espressobin-v7 \
    --enable crowdsec,wireguard --tweak low-memory \
    --output manifest.yaml
  ```
  - Interactive mode with hardware detection
  - Profile auto-selection based on target specs
  - Dependency resolution and conflict detection
- [ ] **P12-05** `secubox-build` — Image builder from manifest
  - Reproducible builds from manifest.yaml
  - Incremental builds (delta from base image)
  - Multi-stage build with checkpoints
  - Build cache for faster iteration
- [ ] **P12-06** `secubox-fetch` — GitHub release downloader
  - Download pre-built images for tested boards
  - GPG signature verification
  - SHA256 checksum validation
  - Automatic version matching

### Appliance README Generator
- [ ] **P12-07** Auto-generated appliance documentation
  - Hardware profile summary
  - Component version table with status
  - Applied tweaks and optimizations
  - Support contact and issue reporting
- [ ] **P12-08** Machine-readable manifest for bug reports
  - JSON export for automated support
  - Hardware capability snapshot
  - Service status at generation time
  - Version fingerprint hash

### Portable Application
- [ ] **P12-09** Electron/Tauri desktop app for image generation
  - Cross-platform (Linux, macOS, Windows)
  - GitHub OAuth for release access
  - Visual board/profile selector
  - Progress tracking with logs
- [ ] **P12-10** Web-based generator (optional)
  - Static site hosted on GitHub Pages
  - Manifest builder with live preview
  - Download link generator
  - QR code for mobile access

### Version Tracking & Participation
- [ ] **P12-11** Component version registry API
  - FastAPI service for version queries
  - Compatibility checks via API
  - Update notifications
  - Usage statistics (opt-in)
- [ ] **P12-12** Participative development workflow
  - Issue templates with device fingerprint
  - Feature request with profile context
  - Automated testing matrix based on device reports
  - Community board support voting

### Profile Definitions
```yaml
# profiles/tier-lite/profile.yaml
name: tier-lite
inherits: base
description: Constrained devices (≤1GB RAM, ≤2 cores)
constraints:
  max_memory: 1G
  max_cores: 2
  max_storage: 8G
components:
  exclude:
    - secubox-ollama      # Too heavy
    - secubox-jellyfin    # Needs GPU
  optimize:
    - secubox-crowdsec: --no-hub-download
    - secubox-nginx: --worker-processes 1
tweaks:
  kernel:
    vm.swappiness: 10
    vm.dirty_ratio: 20
  systemd:
    DefaultMemoryAccounting: yes
    DefaultTasksMax: 100
```

### Board-Specific Tweaks
```yaml
# boards/espressobin-v7/tweaks.yaml
board: espressobin-v7
soc: Marvell Armada 3720
profile: tier-lite
capabilities:
  ram: 1GB
  cores: 2
  storage: eMMC 8GB
  network:
    - wan: eth0
    - lan: lan0, lan1
  usb: 1x USB 3.0, 1x USB 2.0
tweaks:
  kernel_modules:
    blacklist: [bluetooth, btusb]  # No BT hardware
  device_tree:
    overlay: espressobin-v7-secubox.dtbo
  network:
    default_mode: router
    wan_interface: eth0
```

---

> **Reference**: See [REMAINING-PACKAGES.md](REMAINING-PACKAGES.md) for detailed inventory with complexity classification
