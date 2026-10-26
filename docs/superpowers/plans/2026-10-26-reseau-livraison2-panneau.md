<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Réseau, livraison 2 : panneau « Réseau » (switch, clients, maillage, mode routeur) — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** remplacer la page `/netmodes/` par le panneau Réseau de la maquette approuvée (cartographie, switch, clients LAN,
liens du maillage, mode routeur), avec couper/rétablir un port et une application du mode routeur asynchrone.

**Architecture :** trois routes de lecture netmodes (`/reseau/ports|clients|carte`, sans privilège : `ip -j`, `bridge -j`,
`/sys/class/net`, baux) ; deux verbes du contrôleur root (`port-couper`, `port-retablir`) par sudo à argv exact ;
`/routeur/appliquer` et `/routeur/retour` lancés en tâche de fond, la page interroge `/routeur/etat` (échéance réelle du
minuteur) ; pages Aurora autonomes encadrées par un hôte à onglets ; la page compose aussi les API existantes de p2p (noms des
pairs), WireGuard (état des tunnels) et NAC (zones).

**Tech Stack :** Python 3.13 (FastAPI, stdlib), HTML/CSS/JS en ligne sans dépendance (profil Aurora), pytest, Playwright si présent.

**Spec :** `docs/superpowers/specs/2026-10-26-reseau-routeur-switch-design.md` (section 3 et « Décisions du propriétaire ») ;
maquette approuvée : `/tmp/claude-1000/-home-reepost-CyberMindStudio-secubox-deb-secubox-deb/dd6762e6-f034-4417-bd75-e92d1336483e/scratchpad/maquette-reseau-gk2/project/Main.dc.html`
(cartographie) et `…/Switch.dc.html` (switch, clients, liens) ; charte : `.claude/AURORA-REFERENCE.md` (fait foi).

## Global Constraints

- Aucune commande, aucun fichier ne cible `eth0|eth1|eth2` en action ; lecture seule autorisée (`ip -j addr show dev eth2`,
  `ip -j neigh show dev eth2`, `/sys/class/net/eth2/*`). Jamais `netplan apply`.
- Ports actionnables : `lan0 lan1 lan2 lan3` uniquement (`PORTS_LAN` de `api/routeur_config.py`).
- Routes de lecture `require_lecture` ; toute route `POST` `require_jwt` ; aucun `subprocess` ni `sudo` dans un `async def` ;
  `subprocess.run([...], timeout=…, capture_output=True, text=True)`, jamais `shell=True`.
- Lecteur anonyme (`require_lecture` sans `sub`, mode tableau de bord) : jamais l'`acteur` ni l'adresse du client dans une réponse.
- Pages Aurora (§ 1–12 de `.claude/AURORA-REFERENCE.md`) : HTML autonome, aucun `<script src=` externe (seul `/shared/sidebar.js`,
  chargé hors `?embed=1` et hors démo), aucune `confirm(`/`alert(`/`prompt(`, aucun `innerHTML` alimenté par des données (texte par
  `textContent`), `?demo=1` avec données de documentation (RFC 5737 / 3849) et **aucune écriture**, « — » pour une mesure absente,
  panne d'une source affichée comme panne, hauteur postée `{sbxVue, onglet}` mesurée sur `.cadre`, jetons de couleur §2, container
  queries, 420 px sans défilement de page.
- Versions : `secubox-netmodes 1.5.0-1~trixie1`, `secubox-wireguard` +0.0.1 sur sa version courante ; changelog `Mon, 26 Oct 2026`,
  `Gérald Kerma <devel@cybermind.fr>`, `(ref #3190)`.
- Commits `type: message (ref #3190)` terminés par `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Python de test : `/home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python`, tests par paquet.

## Review Focus

1. **L'administrateur coupe le port derrière lequel il est** : refus 409 avec l'explication (adresse du client → MAC par `ip neigh` →
   port par `bridge fdb`), avant tout appel au contrôleur (tâche 3).
2. **Une source tombe** (WireGuard, NAC ou p2p en 401/503, `wgctl dump` en échec) : la carte et les onglets affichent la panne de
   cette source, jamais « aucun pair » ni « 0 » (tâches 4, 5, 6).
3. **Application par le panneau plus longue que 30 s** (HAProxy) : réponse 202 immédiate, page en « bascule en cours » puis compte à
   rebours réel jusqu'à l'échéance du minuteur, bouton Confirmer ; jamais `depuis + 180` (tâches 3, 7).
4. **Port coupé puis mode routeur réappliqué** : la vérification d'attachement ignore les ports coupés (sinon chaque application
   échoue et revient en arrière) (tâche 2).
5. **Lecteur anonyme du LAN** sur `/routeur/etat` : ni `acteur` ni adresse, réponse mise en cache 5 s (pas un sudo root par requête)
   (tâche 3).

---

### Task 1 : routes de lecture du réseau

**Files :** Create `packages/secubox-netmodes/api/reseau_lecture.py`, `packages/secubox-netmodes/api/reseau_api.py`
(`APIRouter(prefix="/reseau")`, inclus par `api/main.py`) ; Modify `packages/secubox-netmodes/apparmor/secubox-netmodes`
(exécution de `/usr/sbin/bridge`, lecture `/sys/class/net/**`, `/sys/devices/**/net/**`, `/var/lib/misc/dnsmasq.leases r`,
`/etc/systemd/network/ r`, `/etc/systemd/network/04-secubox-port-*.network r`) ; Test `packages/secubox-netmodes/tests/test_reseau_lecture_3190.py`.

**Interfaces :**
- Produces (fonctions pures sur des sorties déjà lues, testables sans système) :
  - `ROLES = {"eth2": "wan", "eth1": "conduit", "eth0": "sfp", "lan0": "lan", "lan1": "lan", "lan2": "lan", "lan3": "lan"}`
  - `ports(ip_link: list, fdb: list, sysfs: dict[str, dict], coupes: set[str], macs_box: set[str]) -> list[dict]` — par port :
    `{"nom", "role", "porteuse": bool|None, "vitesse_mbps": int|None, "etat_admin": "up"|"down", "maitre": str|None,
    "macs": [str], "plusieurs_appareils": bool, "coupe": bool}` ; `macs` = adresses apprises (`bridge -j fdb show br br-lan`,
    entrées sans `permanent`/`self`, hors `macs_box`) ; `plusieurs_appareils` = plus d'une MAC ; vitesse « — » (None) si
    `/sys/class/net/<p>/speed` vaut -1 ou est illisible.
  - `clients(baux: str, fdb: list, voisins: list) -> list[dict]` — `{"mac", "ip", "nom", "port", "source": "bail"|"voisin",
    "expire": int|None}` (bail dnsmasq `<expiry> <mac> <ip> <nom> <id>` ; un voisin `ip neigh` de `br-lan` sans bail apparaît
    avec `source: "voisin"`).
  - `carte(wan_addr: list, route_defaut: list, voisins_wan: list, membres_lxc: list, liens_wg: list) -> dict` —
    `{"wan": {"interface": "eth2", "adresse", "passerelle", "voisins": [{"ip", "mac"}]}, "lxc": {"pont": "br-lxc", "actifs": int},
    "tunnels": [{"nom", "etat"}]}` (`ip -j link show type wireguard`).
  - `lire_systeme() -> dict` (dans `reseau_api.py`, seul endroit avec `subprocess`) : exécute `ip -j link`, `bridge -j fdb show br br-lan`,
    `ip -j neigh show dev br-lan`, `ip -j -4 addr show dev eth2`, `ip -j -4 route show default`, `ip -j neigh show dev eth2`,
    `ip -j link show master br-lxc`, `ip -j link show type wireguard`, lit `/sys/class/net/<p>/{carrier,speed,operstate}`,
    `/var/lib/misc/dnsmasq.leases`, la liste des fichiers `04-secubox-port-*.network` ; chaque commande en échec → la clé vaut
    `None` et la réponse porte `"pannes": [<nom de la source>]` (jamais une liste vide inventée). Cache mémoire 5 s.
  - Routes `GET /reseau/ports`, `/reseau/clients`, `/reseau/carte` (`require_lecture`, `def`).
- [ ] Step 1 : tests en échec — fixtures JSON réalistes (sorties `ip -j`/`bridge -j` relevées sur gk2 le 26/10 : `lan0` et `lan3`
  maîtres `br-lan`, MAC `d4:93:90:27:a7:dd` sur lan0, `dc:a6:32:e6:74:e1` sur lan3) : rôles exacts ; `plusieurs_appareils` vrai à
  deux MAC ; vitesse -1 → None ; client depuis bail + port depuis fdb ; voisin sans bail → `source: "voisin"` ; `eth2` toujours
  rôle `wan` sans action ; une source en échec → `pannes` contient son nom et la clé vaut None ; routes gardées `require_lecture` ;
  aucun `subprocess` dans un `async def` (AST).
- [ ] Step 2 : `cd packages/secubox-netmodes && $PY -m pytest tests/test_reseau_lecture_3190.py -q` → FAIL. Step 3 : implémenter.
  Step 4 : PASS + suite du paquet. Step 5 : commit `feat(netmodes): lecture des ports, clients et carte du réseau (ref #3190)`.

### Task 2 : couper et rétablir un port (contrôleur)

**Files :** Modify `packages/secubox-netmodes/api/routeur_ctl.py`, `packages/secubox-netmodes/sbin/netmodesctl`,
`packages/secubox-netmodes/debian/secubox-netmodes.sudoers` ; Test `packages/secubox-netmodes/tests/test_ports_coupes_3190.py`.

**Interfaces :**
- Produces : `FICHIER_COUPE = "/etc/systemd/network/04-secubox-port-{port}-coupe.network"` (`[Match] Name=<port>`,
  `[Link] ActivationPolicy=down`, marque `GÉNÉRÉ par secubox-netmodes`) ; `ports_coupes(ctx) -> set[str]` ;
  `port_couper(ctx, port: str, acteur: str) -> dict`, `port_retablir(ctx, port: str, acteur: str) -> dict` : verrou du contrôleur,
  port ∈ `PORTS_LAN` sinon `Refus`, mode routeur `actif` requis sinon `Refus`, écriture atomique (ou suppression), `networkctl
  reload` puis `networkctl reconfigure <port>`, vérification (≤ 15 s) : coupé ⇒ port sans maître `br-lan` et `operstate` down ;
  rétabli ⇒ port maître `br-lan` ; échec ⇒ restauration de l'état précédent du fichier + `Echec` ; audit `port-couper` /
  `port-retablir` ; rend `etat()` complété de `"ports_coupes"`.
- CLI : verbes `port-couper <port> <acteur>` et `port-retablir <port> <acteur>` (deux arguments, port validé par liste blanche avant
  tout) ; sudoers ajoute `/usr/sbin/netmodesctl port-couper *, /usr/sbin/netmodesctl port-retablir *`.
- `_attendre_pont` (application et retour) **exclut les ports coupés** de l'exigence d'attachement ; `etat()` ajoute
  `"ports_coupes": [..]`.
- [ ] Step 1 : tests en échec : couper `lan1` → fichier exact, commandes `networkctl reload` puis `networkctl reconfigure lan1`,
  aucune commande vers `eth*` ni `br-lan` ; `eth2`, `lan4`, `br-lan` refusés (code 2/3) ; mode routeur inactif → `Refus` ;
  vérification non atteinte → fichier restauré, `Echec` ; rétablir supprime le fichier ; réappliquer le mode routeur avec `lan1`
  coupé → succès (Review Focus 4) ; `ports_coupes` dans `etat()` ; sudoers croisé avec les argv.
- [ ] Steps 2–4 (FAIL, implémenter, PASS + suite) ; Step 5 : commit `feat(netmodes): couper et rétablir un port du switch (ref #3190)`.

### Task 3 : API — actions de port, application asynchrone, état enrichi

**Files :** Modify `packages/secubox-netmodes/api/routeur_api.py`, `packages/secubox-netmodes/api/routeur_ctl.py` (`etat()`),
`packages/secubox-netmodes/api/main.py` (`est_mochabin`) ; Create `packages/secubox-netmodes/api/ports_api.py`
(`APIRouter(prefix="/ports")`) ; Test `packages/secubox-netmodes/tests/test_panneau_api_3190.py`.

**Interfaces :**
- `etat()` ajoute `"echeance"` (horodatage RFC 3339 tiré de `systemctl show -p NextElapseUSecRealtime --value
  secubox-netmodes-retour.timer`, None sans minuteur) et `"bascule_en_cours"` (verrou du contrôleur tenu par un autre : essai
  `LOCK_NB` relâché aussitôt).
- `POST /routeur/appliquer` : validation locale (400), puis lancement de `sudo -n netmodesctl routeur-appliquer <acteur>` dans un
  fil d'arrière-plan (sortie conservée en mémoire : dernier résultat) ; réponse **202** `{"lancee": true}` ;
  `POST /routeur/retour` idem ; `GET /routeur/derniere` (`require_jwt`) rend le dernier résultat `{verbe, code, sortie, fini}`.
  `POST /routeur/confirmer` reste synchrone.
- `GET /routeur/etat` : lecteur anonyme ⇒ réponse sans `acteur`, servie depuis un cache de 5 s ; administrateur ⇒ complète.
- `POST /routeur/apercu` ajoute `"avertissement"` (même texte qu'en livraison 1) si l'adresse du client est dans le réseau actuel de
  `br-lan` et que le réseau demandé diffère. La clé `wan` n'est plus acceptée (`CLES_CONFIG` sans `wan` ; le contrôleur garde `eth2`).
- `est_mochabin()` **fermé par défaut** : modèle illisible ⇒ vrai (les anciens chemins netplan restent refusés).
- `POST /ports/{port}/couper` et `/retablir` (`require_jwt`, corps `{"confirmer": "<port>"}`) : port ∈ `PORTS_LAN` (400) ; pour
  couper, **refus 409** si l'adresse du client (X-Real-IP sinon `request.client.host`) a sa MAC (`ip -j neigh show dev br-lan`)
  apprise derrière ce port (`bridge -j fdb`) ; puis `sudo -n netmodesctl port-couper <port> <acteur>` (synchrone, ≤ 60 s) ; codes du
  contrôleur → HTTP comme `routeur_api`.
- [ ] Step 1 : tests en échec : 202 + fil lancé avec l'argv exact ; `derniere` après fin ; `etat` anonyme sans `acteur`, deux appels
  en < 5 s ⇒ un seul `subprocess` ; `echeance` relayée ; `apercu` avec avertissement ; `wan` dans le corps ⇒ 400 ; `est_mochabin`
  sur fichier absent ⇒ vrai ; couper le port de la session ⇒ 409 sans appel au contrôleur (Review Focus 1) ; couper un autre port ⇒
  argv exact ; `eth2` ⇒ 400 ; routes POST gardées ; pas de `subprocess` en `async def`.
- [ ] Steps 2–4 ; Step 5 : commit `feat(netmodes): actions de port et application asynchrone du mode routeur (ref #3190)`.

### Task 4 : secubox-wireguard — une panne n'est pas « aucun pair »

**Files :** Modify `packages/secubox-wireguard/api/main.py` (`_parse_wg_show` ~l.158-209, `/peers/status` ~l.672, `/summary`
~l.908), `debian/changelog` ; Test `packages/secubox-wireguard/tests/test_panne_dump_3190.py`.

- `_parse_wg_show` signale l'échec (`wgctl dump` code ≠ 0, délai, exception) au lieu de rendre `{"interfaces": {}}` ;
  `/peers/status` et `/summary` répondent **503** `{"detail": "wgctl dump en échec : …"}` dans ce cas ; succès inchangé.
- [ ] Tests en échec (code 1, délai, exception → 503 ; succès → forme actuelle inchangée), implémenter, suite du paquet, commit
  `fix(wireguard): wgctl dump en échec rend 503, plus une liste vide (ref #3190)`.

### Task 5 : hôte à onglets, Cartographie et Liens du maillage

**Files :** Modify `packages/secubox-netmodes/www/netmodes/index.html` (devient l'hôte) ; Create
`packages/secubox-netmodes/www/netmodes/carte.html`, `…/maillage.html` ; Modify `packages/secubox-netmodes/menu.d/30-netmodes.json`
(`"name": "Réseau"`, description française) ; Test `packages/secubox-netmodes/tests/test_pages_reseau_3190.py`.

- **Hôte** (`index.html`, modèle `packages/secubox-soc/www/soc/index.html`) : en-tête « Réseau » (marque + pastille du mode
  routeur depuis `/api/v1/netmodes/routeur/etat`), onglets `role="tab"` : Cartographie (`carte.html?embed=1`, par défaut), Switch
  (`switch.html?embed=1`), Clients LAN (`clients.html?embed=1`), Liens du maillage (`maillage.html?embed=1`), Mode routeur
  (`routeur.html?embed=1`), Modes (hérité) = **l'ancien contenu conservé dans le DOM avec tous ses identifiants**, pour que
  `tests/test_page_aurora_2457.py` reste vert sans modification ; une seule iframe, hauteur par `sbxVue`+`onglet` (vérif.
  d'origine et de source), `?demo=1` propagé, bandeau « LAN temporaire / mode routeur non actif » si `etat` ≠ `actif`.
- **Cartographie** (`carte.html`) : reprend `Main.dc.html` (positions et couleurs) en SVG écrit à la main : Internet → Freebox
  (passerelle de `/reseau/carte`) → voisins WAN ; gk2 (WAN eth2, adresse) ; maillage `wg-mesh` (pairs : noms de
  `/api/v1/p2p/peers`, état et volumes de `/api/v1/wireguard/peers/status`, jointure par clé publique) ; autres tunnels
  (`/api/v1/wireguard/summary`) ; pont LXC (actifs) ; switch et clients (de `/reseau/ports` et `/reseau/clients`) ; carte « Hubs
  et switchs détectés ». Chaque source a sa pastille ; une source en 401/503 ⇒ « session requise » ou « source en panne » sur son
  bloc, jamais un vide présenté comme « aucun ».
- **Liens du maillage** (`maillage.html`) : tableau `Switch.dc.html` « Liens du maillage » (pair, IP de maillage, dernier
  échange, reçu, état actif/muet, « à retirer ? » pour un pair sans nom ou sans échange depuis 30 jours) + autres tunnels ; aucune
  action.
- Tests statiques (§ 11.1 Aurora) des trois pages + Playwright si disponible (`?demo=1`, 1400 et 420 px, aucun débordement, aucune
  erreur JS, onglets basculés). Commit `feat(netmodes): panneau Réseau, hôte à onglets, cartographie et maillage (ref #3190)`.

### Task 6 : onglets Switch et Clients LAN

**Files :** Create `packages/secubox-netmodes/www/netmodes/switch.html`, `…/clients.html` ; Test (même fichier que la tâche 5,
tests ajoutés).

- **Switch** (`switch.html`, d'après `Switch.dc.html`) : façade (eth2 WAN, SFP+ eth0, lan0–lan3 ; voyants lien/activité depuis
  `porteuse`/`etat_admin`) ; tableau des ports (rôle, lien et vitesse, membre de, derrière le port, actions) ; **Couper… /
  Rétablir…** seulement sur `lan0`–`lan3`, confirmation intégrée (saisie du nom du port), appel `POST /api/v1/netmodes/ports/<p>/couper`
  ou `/retablir` avec `{"confirmer": "<p>"}`, résultat ou erreur (409 « vous couperiez votre propre accès ») dans la page ; « Isoler »
  affiché désactivé avec l'infobulle « livraison 3 » ; `eth1` « jamais ponté », `eth2` « jamais relancé à distance », sans action ;
  « plusieurs appareils derrière ce port (switch, hub ou point d'accès) » quand `plusieurs_appareils`.
- **Clients LAN** (`clients.html`) : tableau appareil (nom, MAC), adresse, port, zone NAC (jointure par MAC avec
  `/api/v1/nac/clients` ; absent du NAC ou `allow_state` « unknown » ⇒ pastille orange « à classer ») ; panne du NAC ⇒ colonne zone
  « NAC indisponible » ; carte « Hubs et switchs détectés ».
- Tests statiques + Playwright ; actions inertes en démo. Commit `feat(netmodes): onglets Switch et Clients LAN (ref #3190)`.

### Task 7 : onglet Mode routeur, paquetage 1.5.0

**Files :** Create `packages/secubox-netmodes/www/netmodes/routeur.html` ; Modify `debian/changelog` (1.5.0), `README.md`,
`apparmor/secubox-netmodes` si la tâche 1 ne l'a pas couvert ; Test (même fichier).

- **Mode routeur** : formulaire (adresse du pont, plage DHCP, bail, ports) prérempli depuis `etat.config` ; « Aperçu » (`POST
  /routeur/apercu`, fichiers rendus repliables, avertissement) ; « Appliquer… » (confirmation intégrée) → `POST /routeur/appliquer`
  (202) → état « bascule en cours » (interrogation de `/routeur/etat` toutes les 3 s, `bascule_en_cours`) → « à confirmer » avec
  **compte à rebours jusqu'à `echeance`** et bouton **Confirmer** (`POST /routeur/confirmer`) → « actif » ; « Revenir en arrière… »
  (`POST /routeur/retour` `{"confirmer": "retour"}`) ; dernier résultat (`/routeur/derniere`) affiché ; rappel « jamais eth2 », note
  webfilter (`[reseau].lan`). Démo : enchaînement simulé, aucune écriture.
- Changelog 1.5.0 (dit ce qui change et ce qui n'est pas repris : Isoler = livraison 3), README (panneau, routes, verbes).
- Tests statiques + Playwright ; `dpkg-buildpackage` du paquet. Commit `feat(netmodes): 1.5.0, onglet Mode routeur asynchrone (ref #3190)`.

### Task 8 : déploiement gk2 et gk1 (contrôleur)

- [ ] Construire netmodes 1.5.0 et wireguard ; publier (rebond par gk1 si SSH direct refusé) ; installer sur gk2 puis gk1 ; vérifier :
  routes `/reseau/*` 200 par le chemin public, pages 200, aucun refus AppArmor, `bridge`/`ip` lisibles par l'API ; capture réelle des
  onglets par le propriétaire ; couper puis rétablir `lan1` (sans câble) sur gk2 ; refus 409 en tentant de couper `lan0` depuis le
  PC ; une application par le panneau (bail modifié) suivie du compte à rebours et d'une confirmation.
- [ ] Suivi : HISTORY, WIP, issue ; `closes #3190` après validation par le propriétaire.
