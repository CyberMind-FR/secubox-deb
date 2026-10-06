<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.

  Dossier d'analyse et de plan (2026-10-06) — NON implémenté.
  Demande du propriétaire : regrouper les composants aux fonctionnalités proches ou identiques pour réduire
  le nombre de .deb, ou, pour les fonctions liées aux profils, les afficher de façon agrégée / extensible,
  en vue des versions beta. « Plan et analyse profonde avant proposition de mise en place. »
-->

# Simplification des modules — analyse et plan (avant les versions beta)

Statut : **proposition à valider**, aucun changement de code. Sept analyses en lecture seule ont été menées en
parallèle (six grappes fonctionnelles et le modèle commun d'emballage) ; ce dossier les croise avec un inventaire
chiffré du dépôt. Tout constat sans preuve vérifiable est marqué « à vérifier » (§15).

---

## 1. Résumé

1. **Le dépôt compte 166 paquets sources et 222 .deb**, dont 48 méta-paquets. La taille médiane d'un module est
   de 1 800 lignes (code + web) ; 42 modules font moins de 1 000 lignes ; 25 font moins de 500 lignes de code.
2. **Fusionner réduit surtout l'emballage, pas le code.** Pour un module simple, 100 à 150 lignes de `debian/` sont
   du gabarit copié-collé, et environ 2 500 fichiers d'emballage (hors code) sont répétés d'un module à l'autre.
   Le gain est un gain de **maintenance, de CI et de déploiement**, pas de volume de code.
3. **La bonne unité de fusion est le .deb à plusieurs composants** (option A), pas la fusion de processus (option B) :
   chaque composant garde son unité, son socket, son utilisateur et ses privilèges. L'option B n'est retenue que
   pour de rares cas (§8) et jamais avant la beta pour l'identité.
4. **Estimation** (cumul des sept analyses, avec un possible recouvrement de quelques unités entre grappes) :
   **environ 55 à 70 .deb fonctionnels en moins sur ~160**, auxquels s'ajoutent jusqu'à **33 méta-paquets de
   « service » remplaçables** par des vues générées. Le parc actif passerait de 222 à **~130–140 (prudent)** ou
   **~100–110 (ambitieux)**.
5. **Le levier central n'est pas le regroupement lui-même, c'est un manifeste de composant unique** : le catalogue
   des modules a aujourd'hui **neuf sources de vérité** qui se recoupent (§4.2). Un manifeste dérivé alimenterait le
   Hall, les profils, l'App Store, l'agrégateur et les méta-paquets : c'est ce qui rend les fonctions « agrégées »
   et « extensibles » sans toucher aux frontends portés.
6. **Un préalable de sécurité apparaît dans toutes les grappes** : la règle « un utilisateur dédié + un profil
   AppArmor par service » n'est tenue que par une minorité de modules (§4.3). Une fusion n'aggrave rien, mais ne
   corrige rien : ce chantier doit être mené à part, en parallèle.
7. **Une vague 0 de nettoyage s'impose avant toute fusion** (§11) : violations de règles (iptables, root),
   dépendances manquantes, résidus et contradictions entre `arbre.yaml` et l'existant.

---

## 2. Périmètre et contraintes à respecter

- Un composant = API FastAPI sur socket Unix `/run/secubox/<m>.sock`, préfixe `/api/v1/<m>/`, unité systemd,
  conf nginx, entrée `menu.d`, interface `www/` **portée et non modifiable**, config TOML dans `/etc/secubox/`.
- Sécurité (CSPN) : utilisateur dédié et AppArmor `enforce` par service ; nftables en DEFAULT DROP, jamais iptables ;
  conteneurs LXC uniquement ; aucun contournement du WAF `sbxwaf`.
- Compatibilité : toute fusion exige un paquet de transition (`Replaces/Breaks/Provides`), des URL
  `/api/v1/<ancien>/` préservées ou redirigées, et une migration d'état idempotente.
- **Aurora (`secubox-sbxos` `0.6.0~aurora*`) est en pré-alpha et n'entre dans aucun build** ; il est hors périmètre.
- Règle actuelle « un déploiement se fait par paquet » (`AGENTS.md`) : à réinterpréter pour les gros paquets (§10).

---

## 3. État des lieux chiffré

| Mesure | Valeur |
|---|---|
| Paquets sources / .deb produits | 166 / 222 (dont **48 méta-paquets** : 2 racines, 13 fonctions, 33 services) |
| Architecture | 204 `all`, 15 `any`, 1 `amd64`, 2 `arm64` |
| Code (hors tests) | ≈ 291 k lignes Python, 112 k Go, 257 k shell, 170 k web |
| Taille médiane d'un module | 1 782 lignes (code + web) ; 42 < 1 000 ; 108 < 3 000 ; 16 > 10 000 |
| Modules < 500 lignes de code | 25 sur 160 |
| Fichiers d'emballage hors code | ≈ 2 500 (`debian/` : 1 972 ; unités : 171 ; nginx : 148 ; menu : 126 ; www : 156) |
| Variantes distinctes | `postinst` : 130 pour 150 fichiers ; unités : 112 pour 113 ; menus : 126 pour 126 |
| Profils : jeux de modules définis à | **trois endroits** (niveaux mémoire, profils d'exécution, méta-paquets) |

Échantillon de 14 modules (code propre / `debian/` hors changelog) : l'emballage pur est de l'ordre de
100–150 lignes par module simple, contre quelques centaines à quelques milliers de lignes de code propre. Le
changelog seul pèse 4 186 lignes sur l'échantillon.

---

## 4. Ce que l'analyse établit

### 4.1 L'identifiant du module est le pivot de tout
Un seul identifiant `<m>` sert de nom de paquet, d'unité, de socket, de répertoire `/usr/lib/secubox/<m>/`, de
préfixe d'API, d'id de menu et d'id de manifeste de profil. **Toute fusion casse cette égalité** : le plan doit donc
conserver un identifiant de **composant** distinct de l'identifiant de **paquet** (§6).

### 4.2 Neuf sources de vérité pour « quels modules existent »
`menu.d/*.json` (lu par le hub), le registre du Hall (cache dérivé de `menu.json` + santé + sockets),
`debian/secubox.yaml` (App Store ; **dérivé**, `tier: lite` pour 139 fiches sur 158 = valeur par défaut générée,
`category: misc` pour 63), `groupes.yaml`, `arbre.yaml` (48 méta-paquets, source de `debian/control` via
`gen-meta.py`), les profils d'exécution (`secubox-profiles`, listes `on = [...]`), `aggregator.toml`, `groupable.d`,
et `secubox-metacatalog`. **Contradictions relevées :**
- `secubox-hub` est classé « remplacé » dans `arbre.yaml` (`hors-arbre`), mais il est vivant (1.9.37), `lite` en
  dépend et il génère le menu du Hall ;
- `lite`, `isp`, `full` sont aussi en `hors-arbre` alors que `docs/PROFILS-COMPARATIF.md` en fait les méta-paquets
  de référence ; les profils d'exécution livrés (`lite`, `full`, `secure-gateway`, `media-lab`) ne leur correspondent
  pas, et **aucun profil d'exécution `isp` n'existe** ;
- le mot « tier » a trois sens (palier mémoire, liste de modules actifs, méta-paquet).

### 4.3 La sécurité réelle est en deçà de la règle
Sur les unités versionnées : 118 en `User=secubox` (compte partagé), 26 en `root`, seulement une poignée avec un
utilisateur dédié (`toolbox`, `waf`, `bbs`, `webfilter`, `assist`, `coffre`…). Profils AppArmor dédiés : **3 paquets**
(`macro`, `waf-ng`, `webfilter`), plus `eye-square` ; `common/apparmor/` ne contient que 5 profils génériques ; les
LXC utilisent `lxc.apparmor.profile = generated`. **Conséquence** : une fusion « un .deb, plusieurs unités » n'affaiblit
pas ce qui n'existe pas ; mais le plan ne doit jamais rapprocher deux composants d'identités différentes dans une
même unité. Le chantier « un utilisateur + un profil par service » est un **projet distinct**, à mener en parallèle.

### 4.4 Le paquet et le processus sont deux décisions indépendantes
L'agrégateur importe en processus ~110 modules (un seul uvicorn). Incidents documentés (`.claude/AUDIT-ALLEGEMENT-2026-09.md`) :
blocage sous rafale, un module bloquant fige les autres, un redémarrage coupe brièvement toutes les API, fuites
(metrics, ~40 Mo/h), 23 modules trouvés actifs en double. Le montage est séquentiel sans délai maximal
(`aggregator/main.py:350`). **Règle du plan** : fusionner des paquets ne doit jamais ajouter un module à boucle de fond,
collecteur ou bloquant dans le processus partagé ; `health`, `system`, `admin`, `ksm`, `actor`, `radio`, `vault`
restent hors agrégateur. `groupd` isole par groupe (dont un groupe `root`) : ne pas le fondre dans l'agrégateur sans
préserver cette frontière.

### 4.5 Architecture : un .deb `all` ne contient jamais un binaire
153 paquets sur 166 sont `all`. Les 13 autres (Go, C, binaires préconstruits) ne se mêlent pas à des composants `all`
(le générateur de méta-paquets le refuse déjà). `secubox-voice-moteur` (arm64) et `secubox-voicestudio` (amd64) restent
des `Suggests`. **Regroupement par type d'architecture** : un paquet `all` Python par grappe, un paquet binaire par
grappe Go (plusieurs binaires, un seul `go.mod`).

### 4.6 Écrivains concurrents de la même ressource (défauts à corriger, indépendants de la fusion)
- `unbound.conf.d` : webfilter (93), ad-guard (94, 95), dns-lan (96, 98), vortex-dns, tor (48), mail (97), toolbox (99) —
  sans propriétaire commun ni validation commune ; **deux moteurs de « vues » Unbound** (webfilter, ad-guard TV) visent
  les mêmes clients alors qu'Unbound n'accepte qu'une vue par réseau de clients.
- `tc qdisc … root` : `qos` et `traffic` s'écrasent mutuellement ; sysctl : `netmodes` et `nettweak` ;
  `/etc/tor/torrc` et `/etc/nftables.conf` : `exposure` les édite par regex.
- Cinq mécanismes de blocage, cinq tables nft (`waf_drop`, `vortex_firewall`, `ipblock`, `secubox_threatmesh`,
  `secubox_nac`) ; quatre sources de flux de menaces ; quatre tableaux de bord de menaces.
- Trois gestionnaires de tunnels WireGuard (`wireguard`, `p2p` pour `wg-mesh`, `netmodes` pour `vpnrelay`) ;
  trois façons de déclarer une publication (`vhost`, `haproxy`, `exposure`).

### 4.7 L'enveloppe LXC est répétée presque à l'identique
Huit scripts `install-lxc.sh` (≈ 2 300 lignes : jellyfin, yacy, lyrion, photoprism, peertube, torrent, ytsas, clamav)
partagent les mêmes fonctions (`ensure_bridge`, `create_lxc`, `write_lxc_config`, `wait_for_network`…) et une IP fixe
par application sur `10.100.0.0/24`. Un composant commun piloté par manifeste (déjà amorcé dans `secubox-core` :
`secubox-lxcctl`, `secubox-lxc-racine`, `secubox-lxc-reseau`) couvrirait ≈ 60 % du code et supprimerait ≈ 1 500 lignes
de doublon. Il ne retire pas de .deb à lui seul, mais fiabilise tous les regroupements.

---

## 5. Principes de regroupement

1. **Un .deb par grappe fonctionnelle stable et de même cadence**, avec un composant par ancienne unité.
2. **Jamais de mélange** : d'architectures (`all` / `any` / `arm64` / `amd64`), de privilèges (root / compte dédié /
   `secubox`), ni de matériels différents dans une même unité.
3. **Le profil décide de l'activation, pas le `postinst`** : les unités sont livrées désactivées et `profilectl apply`
   (déjà doté de snapshot, rollback et protection du cœur) est l'unique décideur. Les 132 `postinst` qui font
   `systemctl enable` sont à adapter.
4. **Conserver les chemins** : un répertoire `/usr/lib/secubox/<ancien>/` par ancien module, mêmes noms de socket, mêmes
   routes `/api/v1/<ancien>/`, mêmes `menu.d` ; la clé de découverte (`dpkg -S` sur l'unité, `scan` par nom d'unité) reste valide.
5. **Dérivé, pas nouveau** : le manifeste est une source qui génère les autres, il ne s'y ajoute pas.
6. **Les applications lourdes restent à la carte** (jellyfin, lyrion, peertube, nextcloud, photoprism, gitea) : elles se
   rendent pilotables par manifeste, pas fusionnées.

---

## 6. Le manifeste de composant (extensibilité)

Un fichier par composant (`debian/component.toml`), lu par **un seul générateur** (extension de `gen-meta.py` et de
`generate-secubox-yaml.py`). Format candidat, compatible avec l'existant :

```toml
package   = "secubox-mail"                 # .deb porteur
[[component]]
id        = "webmail"                      # = id actuel : unité, socket, /api/v1/<id>/, id de menu
unit      = "secubox-webmail.service"      # optionnel (module monté par l'agrégateur)
api       = "api/webmail/main.py"
mount     = "aggregator"                   # aggregator | standalone | lxc
menu      = { category = "mesh", order = 470, path = "/webmail/", theme = "messagerie" }
nginx     = "nginx/webmail.conf"
tier      = "standard"                     # palier mémoire (ancien tier de secubox.yaml)
lifecycle = "on-demand"                    # always-on | eager | on-demand | manual
profiles  = ["isp", "full"]                # activation par défaut (remplace les listes on = [...])
requires  = ["core:auth"]                  # composants, pas des paquets
arch      = "all"                          # all | amd64 | arm64
privilege = "dedie"                        # dedie | partage | root (pour l'audit CSPN)
replaces  = ["secubox-webmail"]            # génère Replaces/Breaks et redirections
```

**Le générateur émet** : `menu.d/*.json`, `secubox.yaml` et `catalog.json`, les entrées d'`aggregator.toml`, les
manifestes `modules.d`, les listes de profils, les presets systemd, et l'arbre des méta-paquets. Un **profil devient une
requête sur les étiquettes** (`profiles`, `tier`, `theme`) ; un tiers peut déposer son manifeste pour être extensible.
Un test de dérive (comme celui qui existe déjà pour `debian/control` ↔ `arbre.yaml`) refuse tout fichier généré divergent.
**Premier pas à faible risque** : enrichir `menu.d` (déjà lu par le hub et par `secubox-profiles`) avec `theme`, `tier`,
`profiles`, puis faire lire ces champs par l'App Store.

---

## 7. Affichage agrégé et extensible

Constat : le menu est plat, un JSON par module, avec des catégories incohérentes (`mesh`, `mind`, `wall`, `root`, `boot`,
`auth`…) qui ne reflètent pas les thèmes de l'arbre. **Proposition** : un champ déclaratif `theme` / `panel` + `tab`
dans le manifeste ; le Hall construit des **panneaux à onglets** à partir des composants **installés**, chaque onglet
pointant vers la page `www/` existante (cadre ou lien : le frontend porté n'est pas modifié). Un module absent
disparaît, un module nouveau apparaît sans modifier le Hall.

| Panneau | Onglets (composants actuels) |
|---|---|
| Filtrage DNS | dns, dns-provider, dns-guard, webfilter, ad-guard, vortex-dns (+ réseau local : dns-lan en CLI) |
| Sécurité | WAF/acteurs, listes de blocage, menaces + IA, posture/CVE/antirootkit, SOC, DPI/JA4/média, appareils (NAC) |
| Réseau | Routage et qualité de service, Exposition (haproxy/vhost/exposure), Tunnels, Maillage |
| Système | système, supervision et santé, métriques, mises à jour, sauvegarde |
| Identité | comptes, appareils, sessions et vouchers, clients OIDC, coffre, ZKP |
| Assistant | ZIA, Lexie (voix), VoiceStudio, moteurs |
| Médiathèque | jellyfin, lyrion, peertube, radio, podcaster, freeboxtv, ytsas, torrent, USB |
| Messagerie | courrier, relais SMTP, matrix, jabber, forum, mur |
| Publication | sites, dépôt, billets, relais social |
| Nuage | fichiers, photos, forge git, partage |

**Profils** : l'affichage se lit sur les étiquettes (« installé / recommandé / non installé » selon lite/isp/full) ; la
notion de « fonction activable » est déjà celle de l'**unité systemd** et du cycle de vie
(`always-on`/`eager`/`on-demand`/`manual`, gérés par `secubox-sleeper` et `secubox-waker`).

---

## 8. Regroupements proposés par grappe

Gains = .deb retirés en option A (un .deb, plusieurs composants). Effort : S (jours), M (semaine), L (plusieurs semaines).

### 8.1 DNS et filtrage (10 paquets)
| # | Regroupement | Effort | Gain | Notes |
|---|---|---|---|---|
| D1 | `dns` + `dns-provider` (+ `dns-lan` en CLI) | S | −2 | `/zone`, `/record` déclarés deux fois dans `dns/api/main.py:322-346` et `521-604` à corriger |
| D2 | `dns-guard` + `network-anomaly` | S | −1 | même thème de détection, `Recommends: dnsmasq` à clarifier |
| D3 | moteur de blocage : `vortex-dns` + `dns-guard`(listes) + `ad-guard` | M | −1 à −2 | quatre à cinq listes de domaines sur deux moteurs (Unbound, dnsmasq) ; **à trancher d'abord** |
| D4 | **bibliothèque commune de rendu des vues Unbound** (webfilter + ad-guard TV) | M à L | — | la vraie fusion utile : un seul propriétaire de `unbound.conf.d`, un seul `checkconf`/`reload` |
Reste séparé : `webfilter` (seul modèle CSPN complet), `cookies` (root, mitmproxy, à durcir), `ipblock` (famille pare-feu).

### 8.2 Sécurité réseau et détection (≈ 26 paquets)
| # | Regroupement | Effort | Gain | Notes |
|---|---|---|---|---|
| S1 | supprimer les 3 shims NAC (`mac-guard`, `device-intel`, `iot-guard`) | S | −3 | déjà des 308 vers `/api/v1/nac/` ; plan existant : `docs/superpowers/plans/2026-07-05-device-guardian-consolidation.md` |
| S2 | `soc` + `soc-web` (agent séparé) | S | −1 | `Replaces` croisés incohérents à nettoyer |
| S3 | listes de blocage : `vortex-firewall` + `ipblock` + `cyberfeed` (+ `threatmesh` après découplage de `toolbox.db`) | M | −3 | cinq tables nft aujourd'hui ; B (une seule table) = L, déconseillé avant beta |
| S4 | `threats` + `ai-insights` | S/M | −1 à −2 | redirection `/api/v1/ai-insights/` |
| S5 | pile DPI : `dpi` + `ndpid` + `mediaflow` (moteur C séparé) | M | −2 | `dpi` et `ndpid` écrivent le même `/var/lib/secubox/dpi` |
| S6 | posture : `security-posture` + `cve-triage` + `antirootkit` | M | −2 | `antirootkit` garde son utilisateur et ses privilèges |
| S7 | `waf` + `waf-ng` | M/L | −1 | un seul source Go déjà partagé avec `toolbox-ng` ; l'API Python et le moteur Go restent deux processus |
Reste séparé : `toolbox-ng` (chemin de tout le trafic), `toolbox` (cabine captive, TCP), `ndpid-engine`, `antirootkit`.
`interceptor` : rôle flou, à auditer (candidat à l'archivage).

### 8.3 Noyau, administration, supervision, interface (≈ 44 paquets)
| # | Regroupement | Effort | Gain |
|---|---|---|---|
| N1 | `defaults` → `core`, `groupd` → `aggregator` | S | −2 |
| N2 | système : `system` + `system-hub` + `admin` + `ksm` + `system-tuning` (une unité par composant, `root` conservé) | M | −4 |
| N3 | santé : `health` + `health-doctor` + `watchdog` (le superviseur reste **hors agrégateur**) | S | −2 |
| N4 | métriques : `metrics` + `glances` + `grafana` + `reporter` | S/M | −3 |
| N5 | Hall : `webos` + `sbxui` + `sbxos` (`portal` reste séparé) | S | −2 |
| N6 | `release` → `repo` ; `cloner` → `backup` (deux unités, privilèges conservés) | S/M | −2 |
| N7 | `eye-square` → `eye-remote` | S | −1 |
Écarter de la première vague : `cloner`, `system-tuning`, `ksm`, `eye-square` (gain total 16 → 12). Huit implémentations
de la « santé » à rationaliser dans un second temps. **Option B déconseillée** (processus privilégiés partagés).

### 8.4 Réseau, tunnels, maillage (≈ 31 paquets)
| # | Regroupement | Effort | Gain |
|---|---|---|---|
| R1 | exposition : `haproxy` + `vhost` + `exposure` (+ `cdn` + `mirror`) | M | −2 à −4 |
| R2 | `qos` + `traffic` (+ `nettweak`) — **un seul propriétaire du `qdisc root`** | S/M | −2 |
| R3 | `netdiag` + `routes` (lecture non root / écriture séparées) | S | −1 |
| R4 | tunnels : `wireguard` + `reality` + `tor` + `macro` + `proxypac`, composants activables | M | −3 à −4 |
| R5 | maillage de confiance : `annuaire` + `openpgp` + `p2p` + `meshname` (`federation` Go séparé) | M/L | −3 |
| R6 | `turn` + `jitsi` | S | −1 |
Reste séparé : `wan-link-guard`, `meshtastic`, `mesh` (802.11s), `sentinelle-gsm`, `rbs-sensor`, `saas-relay`, `federation`.

### 8.5 Médias, communication, cloud (≈ 31 paquets)
| # | Regroupement | Effort | Gain |
|---|---|---|---|
| M1 | `mail` + `smtp-relay` (`clamav` composant optionnel) | M | −1 à −2 |
| M2 | `matrix` + `jabber` | S | −1 |
| M3 | `bbs` + `messagerie` | S | −1 |
| M4 | publication : `metablogizer` + `droplet` + `publish` | M | −2 |
| M5 | sas web : `ytsas` + `torrent` (mêmes squelette et minuteurs) | S/M | −1 |
| M6 | `media` + `smb` + `freeboxtv` | S | −2 |
| M7 | veille : `metanews` + `surf` + `devwatch` + `yacy` (`surf` passe sur socket Unix) | M | −2 |
| M8 | `metacatalog` absorbé (portal ou appstore) | S | −1 |
| M9 | démons Go (`bbs`, `radio`, `metanews`, `socialrelay`) : **un seul source Go, quatre binaires, quatre comptes** | M | −3 (poussé) |
Gain prudent −12 (31 → 19) ; poussé −18. **Ne pas** fondre les quatre démons Go en un seul binaire.

### 8.6 IA, voix, domotique, identité (≈ 23 paquets)
| # | Regroupement | Effort | Gain |
|---|---|---|---|
| I1 | identité (option A uniquement) : `auth` + `users` + `sbxid` + `oidc` (+ `avatar` après clarification) | M | −3 à −4 |
| I2 | `zkp` + `zkp-hamiltonian-tools` (bibliothèques `libzkp-*` séparées) | S | −1 |
| I3 | IA : `ai-gateway` + `localrecall` + `mcp-server` (`mcp-server` désactivé par défaut) | M | −2 |
| I4 | `streamlit` + `streamforge` (même `APPS_DIR`) | M | −1 |
| I5 | domotique : `mqtt` + `zigbee` + `iot-guard` (deux LXC distincts) | M | −2 |
**Identité : ne pas fondre les processus ni les modèles de personne avant la beta** (sessions, TOTP, JWT, frontend porté).
Voix : pas de .deb unique possible (`all` + `arm64` + `amd64`) ; `vault` reste séparé (compte dédié, clé en mémoire).

### 8.7 Total
| Hypothèse | .deb fonctionnels retirés | .deb actifs après (hors transitoires) |
|---|---|---|
| Sûr (S1, S2, N1, N3, N5, M2, M3, D1, D2, I2…) | ≈ 30 à 35 | ≈ 150–160 |
| Prudent (toutes les options A ci-dessus, sans les cas écartés) | ≈ 55 à 60 | ≈ 130–140 |
| Ambitieux (+ M9, S3 en B partiel, R5, N2 complet, méta-paquets de service générés) | ≈ 70 + 33 méta | ≈ 100–110 |

Les paquets de transition **restent publiés un cycle de release** et augmentent temporairement le dépôt, pas les installations.

---

## 9. Ce qui reste séparé, et pourquoi

Séparation de privilèges : `admin`, `ksm`, `qos`, `traffic`, `netdiag`, `nettweak`, `exposure`, `certs`, `vm`, `netboot`
(root), `antirootkit`, `vault`, `webfilter`. Matériel ou architecture : `wan-link-guard`, `meshtastic`, `mesh`,
`sentinelle-gsm`, `rbs-sensor`, `voice-moteur` (arm64), `voicestudio` (amd64), `zia-llm`, `federation`, `ndpid-engine`.
Applications lourdes installables à la carte : `jellyfin`, `lyrion`, `peertube`, `nextcloud`, `photoprism`, `gitea`.
Périmètre distinct : `toolbox`, `toolbox-ng`, `cookies` (à durcir), `portal`.

---

## 10. Procédure de compatibilité d'une fusion (patron éprouvé dans le dépôt)

Précédents : `mail` (absorbe `mail-lxc`, `webmail`), `sbxid` (absorbe `acces`, avec nettoyage d'unité dans le `postinst`),
`soc` (`Conflicts` + `Replaces` pour retirer `soc-web`), `p2p` (absorbe `master-link`), `mesh` (absorbe `yggdrasil`),
`portal`/`nac` (absorbent `hub`) ; 17 `control` portent déjà un `Replaces`.

1. Le paquet absorbant porte `Replaces: ancien (<< V)` et `Breaks: ancien (<< V)` (et `Provides` si d'autres en dépendent) ;
   `Conflicts` en plus seulement pour retirer un paquet dont les fichiers se chevauchent.
2. L'ancien paquet devient un transitoire `Section: oldlibs` vide qui dépend du nouveau, **publié un cycle complet**.
3. Le `postinst` migre l'état de façon **idempotente** (modèle `mailctl migrate-config`), désactive et supprime l'ancienne
   unité, `daemon-reload`.
4. URL : même répertoire, même nom d'agrégateur, ou alias nginx ; **mêmes chemins d'API et de pages**.
5. Mettre à jour dans le même lot : `arbre.yaml`/manifeste, `menu.d`, listes de profils, `pins.toml`, manifestes `modules.d`.
6. **Pièges** : `systemctl disable` ne survit pas à un `apt upgrade` si l'ancien `postinst` réactive (seul `mask` survit) ;
   `aggregator.toml` est un conffile modifié par le `postinst` du hub (`try-restart` coupe toutes les API) ; les `Replaces`
   doivent suivre la numérotation `~bookworm1`/`~trixie1` retamponnée par la CI ; renommer une unité perd son manifeste
   et sa politique de sommeil ; aucun outillage de renommage de conffiles (`dpkg-maintscript-helper` jamais utilisé).
7. **Granularité de déploiement** : pour qu'un gros paquet ne redémarre pas tous ses composants, le `postinst` ne
   `try-restart` que les unités dont les fichiers ont changé (empreinte), et `dh_installsystemd` est utilisé avec
   `--no-restart-after-upgrade`. La règle « un déploiement par paquet » devient « par composant modifié ».

---

## 11. Séquencement en vagues

**Vague 0 — nettoyage (avant toute fusion, sans risque de compatibilité)**
- `secubox-netmodes` : retirer `iptables -A FORWARD` (`api/main.py:401`) au profit de nftables.
- Unités en `root` à justifier ou corriger : `qos`, `traffic`, `netdiag`, `nettweak`, `exposure`, `cookies`, `mail`,
  `zigbee-backup`, `admin`, `ksm`, `certs`…
- `secubox-zkp` appelle les binaires de `zkp-hamiltonian-tools` sans en dépendre ; `streamforge` recommande un nom qui
  n'existe pas ; doublon possible de l'unité `led-heartbeat` entre `core` et son paquet ; routes `/zone` dupliquées
  dans `dns` ; `socialrelay` en Go 1.25 (les autres en 1.22) avec une toolchain versionnée (14 849 fichiers à vérifier) ;
  `gotosocial` (résidu `debian/` non suivi) et `.deb` suivis à la racine (`gabriel-mood_*.deb`) à supprimer ;
  `surf` et `mesh` écoutent en TCP au lieu d'un socket Unix.
- Réconcilier `arbre.yaml` avec l'existant (`secubox-hub`, `lite/isp/full` en `hors-arbre`) ; mettre à jour le README de
  `secubox-profiles` (« `apply` n'existe pas encore » alors qu'il existe).
- Écrivains concurrents : un propriétaire unique de `qdisc root`, de `unbound.conf.d`, de `torrc` et de `nftables.conf`.
- Documenter la dette AppArmor/utilisateurs et ouvrir le chantier de sécurité parallèle.

**Vague 1 — outillage**
- Générateur de manifeste et test de dérive ; clé `theme`/`panel` dans `menu.d` et panneaux à onglets du Hall.
- Gabarit unique de `postinst`/`rules` (adduser, `/run/secubox`, enable via `profilectl`, `try-restart` sélectif).
- Composant commun « app-lxc » dans `secubox-core` + manifestes LXC.
- Banc de test de montée de version (installer N-1, mettre à niveau vers le .deb fusionné, vérifier unités, état, URL).
- Adopter `dpkg-maintscript-helper` pour les conffiles déplacés.

**Vague 2 — fusions sûres** (Python `all`, mêmes privilèges, aucune migration d'état) : S1, S2, N1, N3, N5, M2, M3, D1, D2, I2, M8.

**Vague 3 — fusions à migration légère** : N4, N6, M1, M4, M5, M6, M7, I3, I4, I5, S4, S5, R2, R3, R6.

**Vague 4 — fusions à enjeux** (privilèges, nftables, identité, Go) : S3, S6, S7, R1, R4, R5, I1 (option A), M9, D3/D4, N2.

**Vague 5 — méta-paquets et gel beta** : remplacer les 33 méta-paquets de service par des vues générées (conserver
`lite`, `isp`, `full` et éventuellement les fonctions), supprimer les transitoires de la release précédente.

Chaque vague : une issue, un lot de tests, un déploiement sur gk3 (amd64) puis gk2 (arm64), retour arrière documenté.

---

## 12. Indicateurs et critères de succès

- Nombre de .deb actifs (222 → cible), nombre de jobs de la matrice CI (marge par rapport au plafond de 256), lignes de
  `debian/` par module, nombre de sources de vérité du catalogue (9 → 1 + dérivés), nombre d'unités en root et de
  composants sans AppArmor (à ne jamais augmenter).
- Critères par fusion : montée de version N-1 → N réussie sur une machine réelle, aucune URL `/api/v1/` cassée
  (test de non-régression des routes), état migré, profils/pins intacts, temps de redémarrage de l'agrégateur inchangé.

---

## 13. Risques

| Risque | Parade |
|---|---|
| Un gros paquet redémarre trop de composants | `try-restart` sélectif par empreinte (§10.7) |
| Un composant cassé bloque l'installation de ses frères | `postinst` par composant, tolérant, avec journal |
| Fusion de processus → perte d'isolation / agrégateur saturé | option A par défaut ; garde-fous de §4.4 |
| Migration d'état (identité, sessions, TOTP) | A seulement, jamais de migration avant la beta |
| Perte d'un pin ou d'un manifeste d'un ancien id | migration des `pins.toml` et `modules.d` dans le même lot |
| Régression des URL du frontend porté | mêmes chemins, test de routes, alias nginx |
| Dépôt apt transitoirement plus gros | un cycle de release puis suppression |
| Charge de travail | vagues courtes, chaque fusion indépendante et réversible |

---

## 14. Décisions demandées au propriétaire

1. **Unité de fusion** : valider « un .deb à plusieurs composants » comme règle, et « aucune fusion de processus avant
   la beta » sauf exceptions listées.
2. **Méta-paquets** : accepter de remplacer les 33 méta-paquets de service par des vues générées (garder `lite`, `isp`,
   `full`), ou en conserver certains.
3. **Un seul « profil »** : définir une fois pour toutes la notion (étiquettes du manifeste) et retirer les deux autres
   définitions.
4. **Sécurité** : lancer en parallèle le chantier « utilisateur dédié + AppArmor » (par où commencer : unités en root ?).
5. **Priorité de la première vague** (§11) et grappes à écarter du périmètre beta.
6. **Durée de vie des transitoires** : un cycle de release ?
7. **Identité** : confirmer l'option A seule.
8. **`interceptor`, `cookies`, `avatar`** : audit puis décision (archiver, durcir ou intégrer).

---

## 15. Ce qui n'a pas pu être vérifié

- Composition réelle de `lite`/`isp`/`full` pour plusieurs grappes (les méta-paquets sont en `hors-arbre`) ; l'état de
  `aggregator.toml` et de `groupable.d` sur une box (modules effectivement montés, adoption de `groupd`).
- Profils AppArmor effectifs sur les machines (générés hors des paquets ?) ; `sudoers` exacts ; ce que `p2p` délègue à root.
- Quel résolveur tourne par défaut (Unbound ou dnsmasq) sur lite/isp/full ; si `adblock-sync` tourne en root.
- Conflit réel `qos`/`traffic` à l'exécution ; usage du port AT par `modem` et `rbs-sensor`.
- Qui écrit `users.json` et `sessions.json` (probablement `secubox-core`).
- Schéma exact de `menu.d` et capacité du Hall à lire des clés supplémentaires sans modification.
- Contenu des `www/` portés (portabilité réelle des frontends), `debian/*.install`, `postinst` de migration.
- Les tests n'ont pas été exécutés ; l'analyse est statique.
