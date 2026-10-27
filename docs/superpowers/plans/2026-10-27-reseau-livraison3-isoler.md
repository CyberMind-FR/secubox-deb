<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Réseau, livraison 3 : isoler un port du switch (Internet seul) — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** « Isoler » un port `lan0..lan3` du MOCHAbin : il sort du pont `br-lan`, reçoit son propre /24 avec DHCP et DNS
de la box, et n'atteint qu'Internet ; « Rendre au LAN » le rattache au pont. Persistant, audité, remis en l'état sur échec.

**Architecture :** même schéma que couper/rétablir (#3190). Deux verbes root de `netmodesctl` posent ou retirent trois
fichiers par port : un `.network` de préfixe `04-` qui gagne sur le `05-` du pont, un fragment dnsmasq lu par
`secubox-lan-dhcp` (`--conf-dir`) et une table nft par port. Unbound écoute d'avance les quatre passerelles, par le drop-in
du mode routeur. Deux routes `POST` et l'onglet Switch s'appuient sur ces verbes.

**Tech Stack :** Python 3.13 (FastAPI, stdlib), systemd-networkd, dnsmasq, nftables, HTML/CSS/JS en ligne (profil Aurora), pytest.

**Spec :** `docs/superpowers/specs/2026-10-26-reseau-routeur-switch-design.md`, § 4 et ses « Précisions du constructeur
(livraison 3, #3201) ». Ces précisions font foi pour les valeurs ci-dessous.

## Global Constraints

- Aucune commande ne nomme `eth*` ni `br-lan` en action : `networkctl reconfigure <port>` avec le port seul. Seule exception :
  le contenu des fichiers `.nft` (nom du WAN dans les règles), comme le fragment du LAN. Jamais `netplan apply`.
- Ports actionnables : `lan0 lan1 lan2 lan3` (`PORTS_LAN`), vérifiés avant tout, dans le contrôleur comme dans l'API.
- Valeurs fixes : réserve `192.168.248.0/22` ; `lanN` → passerelle `192.168.(248+N).1/24` ; DHCP `.100` à `.199` ; bail `2h`.
- Chemins par port :
  - `/etc/systemd/network/04-secubox-port-<port>-isole.network` ;
  - `/var/lib/secubox-netmodes/dhcp.d/isole-<port>.conf` (arbre root seul : `0700` pour le dossier, `0644` pour le fichier) ;
  - `/etc/nftables.d/zz-secubox-netmodes-isole-<port>.nft`.
- Nommage nft : table `inet secubox_netmodes_isole_<port>` ; commentaires de règles commençant par `secubox netmodes isole <port>`.
  Ce préfixe ne commence jamais par celui du LAN, `secubox netmodes lan` : le retour du mode routeur supprime par préfixe.
- Toute route `POST` est en `require_jwt`. Aucun `subprocess` dans un `async def`, jamais `shell=True`.
- Pages Aurora : `textContent` seulement ; `?demo=1` sans aucune écriture ; « — » pour une donnée absente ; panne affichée
  comme panne ; aucun `confirm(`/`alert(`/`prompt(`.
- En-tête SPDX CMSD-1.0 sur tout fichier créé.
- Version `secubox-netmodes 1.6.0-1~trixie1`, changelog `Tue, 27 Oct 2026`, `Gérald Kerma <devel@cybermind.fr>`, `(ref #3201)`.
- Commits `type: message (ref #3201)`, terminés par `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Tests : depuis `packages/secubox-netmodes`, `/home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python -m pytest tests -q`.

## Review Focus

1. **Mode routeur réappliqué (ou retour) alors qu'un port est isolé** : la vérification du pont ignore les ports isolés.
   Sinon chaque application échoue, revient en arrière et recrée le pont, ce qui coupe le LAN (tâche 2).
2. **L'administrateur isole le port derrière lequel il est** : refus 409 avant tout appel au contrôleur (tâche 4).
3. **Isolement demandé avant la mise à jour d'Unbound** (gk2, juste après l'installation de 1.6.0) : refus clair
   (« réappliquer le mode routeur »), aucun fichier posé, aucune commande (tâche 2).
4. **dnsmasq refuse de repartir après l'isolement** (AppArmor, fragment rejeté) : les fichiers d'avant sont remis, le DHCP du LAN est relancé,
   et l'échec est rendu. Le LAN ne reste jamais sans DHCP (tâche 2).
5. **Un client du port isolé vise le LAN, la Freebox, un tunnel ou l'administration**, en IPv4 comme en IPv6 : la table nft rendue le
   refuse. Le test porte sur le texte rendu (tâche 1), puis `nft -c` sur gk1 au déploiement.

---

### Task 1 : rendu pur de l'isolement, réserve et écoute d'Unbound

**Files :**
- Create `packages/secubox-netmodes/api/isolement.py`.
- Modify `api/routeur_config.py` (réserve interdite au LAN) et `api/routeur_rendu.py` (drop-in Unbound).
- Test : create `tests/test_isolement_3201.py` ; update `tests/test_routeur_rendu_3189.py` et `tests/test_routeur_config_3189.py`
  si une attente change.

**Interfaces :**
- Produces (`routeur_config.py`) : `RESERVE_ISOLES = IPv4Network("192.168.248.0/22")`. `depuis_dict` et `verifier_reseaux`
  lèvent `ErreurConfig("192.168.248.0/22 est réservé aux ports isolés : choisir un autre sous-réseau")` si le LAN chevauche la
  réserve. Le message de `192.168.255.0/24` et de `10.100.0.0/24` ne change pas.
- Produces (`isolement.py`, sans effet de bord) :
  - `RESERVE = RESERVE_ISOLES`, `BAIL = "2h"`, `COMMENTAIRE = "secubox netmodes isole"`,
    `DOSSIER_DHCP = "/var/lib/secubox-netmodes/dhcp.d"` ;
  - `CHEMINS = {"network": "/etc/systemd/network/04-secubox-port-{port}-isole.network", "dhcp": DOSSIER_DHCP + "/isole-{port}.conf", "nft": "/etc/nftables.d/zz-secubox-netmodes-isole-{port}.nft"}` ;
  - `passerelle(port: str) -> IPv4Interface` (`lan2` → `192.168.250.1/24` ; `ValueError` hors `PORTS_LAN`) ;
  - `PASSERELLES: tuple[IPv4Address, ...]` (les quatre, dans l'ordre de `PORTS_LAN`) ;
  - `table(port) -> str` (`secubox_netmodes_isole_lan2`) ; `chemins(port) -> dict[str, str]` ;
  - `rendre(port: str, wan: str) -> dict[str, str]` : clés `network`, `dhcp`, `nft`. `ValueError` si `wan` ne vérifie pas
    `^eth[0-9]$` ou si `port` est hors liste.
- Chaque fichier rendu commence par `# SPDX-License-Identifier: LicenseRef-CMSD-1.0\n# GÉNÉRÉ par secubox-netmodes\n`
  (`MARQUE` de `routeur_rendu`).

- [ ] **Step 1 : tests (`tests/test_isolement_3201.py`), écrits avant le code**
  - `test_passerelles` : `passerelle("lan0") == IPv4Interface("192.168.248.1/24")`, `passerelle("lan3") == IPv4Interface("192.168.251.1/24")` ;
    `ValueError` pour `"eth2"`, `"br-lan"`, `"lan4"`.
  - `test_network` : `rendre("lan2", "eth2")["network"]` contient `[Match]\nName=lan2\n` et `Address=192.168.250.1/24`,
    `ConfigureWithoutCarrier=yes`, `IPv6AcceptRA=no`, `LinkLocalAddressing=no`, et ni `Bridge=` ni `eth`.
  - `test_dhcp` : exactement ces lignes, après l'en-tête :
    `interface=lan2`,
    `dhcp-range=set:isole-lan2,192.168.250.100,192.168.250.199,255.255.255.0,2h`,
    `dhcp-option=tag:isole-lan2,option:router,192.168.250.1`,
    `dhcp-option=tag:isole-lan2,option:dns-server,192.168.250.1`.
    Aucune ligne `port=`, `user=`, `dhcp-leasefile=` : elles restent dans `lan-dhcp.conf`.
  - `test_nft_entree` : trois lignes `add rule inet filter input iifname "lan2" …` (udp 67, udp 53, tcp 53) dont le commentaire
    commence par `secubox netmodes isole lan2` ; l'idiome `table inet secubox_netmodes_isole_lan2` /
    `delete table inet secubox_netmodes_isole_lan2` puis la table ; chaîne `input` (`hook input priority filter - 3`) qui accepte
    established/related, udp 53/67 et tcp 53 depuis `lan2`, puis `iifname "lan2" drop`.
  - `test_nft_transit` : chaîne `forward` (`priority filter - 3`) avec, dans cet ordre :
    1. `iifname "lan2" oifname != "eth2" drop` ;
    2. `iifname "lan2" meta nfproto ipv6 drop` ;
    3. `iifname "lan2" ip daddr { 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 } drop` ;
    4. `oifname "lan2" ct state established,related accept` ;
    5. `oifname "lan2" drop`.
    Chaîne `postrouting` (`type nat hook postrouting priority srcnat`) avec
    `ip saddr 192.168.250.0/24 oifname "eth2" masquerade`.
  - `test_aucun_commentaire_du_lan` : aucun commentaire rendu ne commence par `secubox netmodes lan`.
  - `test_wan_refuse` : `rendre("lan2", "eth2; drop")` et `rendre("lan2", "br-lan")` lèvent `ValueError`.
  - `test_unbound_ecoute_les_passerelles` : `routeur_rendu.rendre(cfg)["unbound"]` (cfg de 192.168.42.1/24) contient, après
    `ip-freebind: yes`, `interface: 192.168.248.1` … `interface: 192.168.251.1` et `access-control: 192.168.248.0/22 allow`,
    et garde `interface: 192.168.42.1` et `access-control: 192.168.42.0/24 allow`.
  - `test_lan_dans_la_reserve_refuse` : `depuis_dict({"adresse": "192.168.249.1/24", "dhcp_debut": "192.168.249.100", "dhcp_fin": "192.168.249.199"})`
    et une adresse `192.168.0.1/16` lèvent `ErreurConfig` avec « réservé aux ports isolés ».
- [ ] **Step 2 : lancer `pytest tests/test_isolement_3201.py -q`** — attendu : échec (module absent).
- [ ] **Step 3 : écrire `isolement.py` et modifier `routeur_config.py` et `routeur_rendu.py`.** `isolement` importe
  `PORTS_LAN` et `RESERVE_ISOLES` de `routeur_config` (jamais l'inverse : import circulaire).
- [ ] **Step 4 : lancer toute la suite** — attendu : tout passe, attentes 3189 mises à jour si besoin.
- [ ] **Step 5 : commit** `feat(netmodes): rendu de l'isolement d'un port, Unbound écoute les passerelles isolées (ref #3201)`.

### Task 2 : contrôleur — `port-isoler`, `port-rattacher`

**Files :**
- Modify `packages/secubox-netmodes/api/routeur_ctl.py` et `sbin/netmodesctl`.
- Test : create `tests/test_ports_isoles_3201.py`, sur le harnais de `tests/test_ports_coupes_3190.py` (importer `Faux`, `preparer_racine`,
  `audits`, `etat_fichier`, `CFG42`, etc.). Mettre à jour l'attente `cli.AVEC_PORT` de `test_ports_coupes_3190.py`.

**Interfaces :**
- Consumes : `isolement.*` (tâche 1).
- Produces : `port_isoler(ctx, port, acteur) -> dict` et `port_rattacher(ctx, port, acteur) -> dict` (rendent `etat(ctx)`) ;
  `ports_isoles(ctx) -> set[str]` (ports dont le `.network` d'isolement existe ; `os.path.lexists`, aucune commande) ;
  `etat(ctx)["ports_isoles"]` (liste triée). Côté `netmodesctl`, `AVEC_PORT` devient
  `("port-couper", "port-retablir", "port-isoler", "port-rattacher")`, avec la même ligne d'usage, les mêmes codes et le même JSON.
- Audit : actions `port-isoler`, `port-isoler-refus`, `port-isoler-echec`, `port-rattacher`, `port-rattacher-refus`,
  `port-rattacher-echec`.

**Comportement (le corps est laissé à l'implémenteur ; voici l'ordre et les gardes) :**

- **Isoler.** Sous `_verrou`, `_auditer_chemins`, puis `_sans_interruption` de la première écriture jusqu'à la fin.
  - Gardes, sans aucune commande d'action ; chacune lève `Refus`, audité `port-isoler-refus` :
    1. acteur et port valides ;
    2. `_verifier_arbre` ;
    3. mode routeur `actif` ;
    4. `routeur.toml` lisible, avec le port dans `cfg.ports` ;
    5. port ni coupé ni déjà isolé ;
    6. `secubox-lan-dhcp.service` actif ;
    7. inclusion `nftables.d` vérifiée (`_verifier_inclusion_nft`) ;
    8. le drop-in Unbound posé est identique à `rendre(cfg)["unbound"]`. Sinon, motif exact :
       « Unbound n'écoute pas encore les passerelles des ports isolés : réappliquer le mode routeur (Unbound redémarre, 2 à 4 min sans DNS) puis isoler » ;
    9. le /24 du port ne chevauche aucun réseau d'une autre interface (`_adresses(ctx)`, sauf ce port).
  - Étapes :
    1. `fichiers.creer_dossiers(DOSSIER_DHCP, 0o700, racine)` ; poser `network` et `nft` en `0644`, puis `dhcp` en `0644` en mode strict (avec `racine`) ;
    2. `nft -c -f <nft>` ;
    3. `networkctl reload`, puis `networkctl reconfigure <port>` ;
    4. supprimer les règles d'entrée de préfixe `secubox netmodes isole <port>` (`_supprimer_regles`), puis `nft -f <nft>` ;
    5. `systemctl restart secubox-lan-dhcp.service`, puis `_attendre_dhcp_actif` ;
    6. relire le port jusqu'à l'état « isolé », dans `DELAI_PORT` : pas `br-lan` pour maître, drapeau `UP`, et `passerelle(port)`
       présente dans `ip -j -4 addr show dev <port>`.
  - Sur toute exception, y compris imprévue, remise de l'état d'avant :
    1. les trois fichiers remis tels qu'ils étaient (absent compris) ;
    2. `networkctl reload` et `networkctl reconfigure <port>` ;
    3. règles de préfixe supprimées et table supprimée si `nft list table inet <table>` réussit ; `nft -f` si un `.nft` d'avant est remis ;
    4. `systemctl restart secubox-lan-dhcp.service`.
    On continue après chaque erreur, et toutes sont rendues dans le message d'échec et l'audit `port-isoler-echec`.
- **Rendre au LAN (rattacher).** Permis en tout mode, comme rétablir.
  - Refus si aucun des trois fichiers n'existe (« <port> n'est pas isolé »), ou si le port est à la fois coupé et isolé.
  - Étapes : retirer les trois fichiers ; `networkctl reload` puis `networkctl reconfigure <port>` ; retirer les règles et la table ;
    si le DHCP est actif, le relancer et attendre qu'il soit actif.
  - État attendu : au pont si le mode routeur est actif et le port dans `cfg.ports`, sinon levé (`_lever_port`). Vérification par `_attendre_port`.
  - Même remise sur échec.
- **Gardes croisées.** `port-couper` refuse un port isolé (« <port> est isolé : le rendre au LAN d'abord »). `port-retablir`
  refuse un port isolé (« <port> est isolé, pas coupé : « Rendre au LAN » le rattache au pont »), qu'il soit coupé ou non.
- **Review Focus 1.** `_ports_non_asservis` ignore les ports isolés, comme les ports coupés.

- [ ] **Step 1 : tests, écrits avant le code.**
  - `test_isoler_ordre_des_commandes` : ordre exact des commandes ci-dessus ; trois fichiers posés au contenu de `isolement.rendre` ;
    audit `port-isoler` ; état rendu avec `"ports_isoles": ["lan2"]`.
  - `test_isoler_refus_sans_commande` (paramétré) : chaque garde (mode non actif, port hors `cfg.ports`, coupé, déjà isolé, DHCP
    arrêté, drop-in Unbound ancien, /24 déjà porté par `eth2`) lève `Refus`, n'appelle aucune commande d'action
    (ni `networkctl`, ni `nft -f`, ni `systemctl restart`), ne pose aucun fichier et audite `port-isoler-refus`.
  - `test_isoler_unbound_ancien_message` : le motif cite « réappliquer le mode routeur ».
  - `test_isoler_dhcp_ko_remet_tout` (Review Focus 4) : `is-active` toujours en échec après la relance. Attendus : fichiers absents,
    règles et table supprimées, `reconfigure lan2` rejoué, `systemctl restart secubox-lan-dhcp.service` rejoué après la remise,
    `Echec`, audit `port-isoler-echec`.
  - `test_isoler_exception_imprevue_remet_tout` : une `RuntimeError` du faux `networkctl reconfigure` produit la même remise et
    se propage.
  - `test_rattacher_ordre_et_au_pont` puis `test_rattacher_hors_mode_routeur_leve` : la seconde vérifie `ip link set dev lan2 up`
    quand le port reste baissé.
  - `test_rattacher_refus` : port non isolé ; port coupé et isolé.
  - `test_couper_et_retablir_refusent_un_port_isole`.
  - `test_reappliquer_ignore_un_port_isole` (Review Focus 1) : `_ports_non_asservis(ctx, ("lan0", "lan1", "lan2", "lan3"))` est
    vide quand `lan2` est isolé et hors du pont ; `_pont_a_recreer(ctx, False, ports)` est faux.
  - `test_aucune_commande_ne_nomme_eth_ni_br_lan` : sur tous les scénarios, aucun argv ne contient `eth0|eth1|eth2|br-lan`.
    Exceptions : `nft -c -f`/`nft -f` d'un fichier, et les lectures `ip -j … show dev br-lan` déjà admises par le harnais.
  - `test_cli_verbes` : `netmodesctl port-isoler lan2 admin` est bien distribué ; `port-isoler eth2 admin` sort en code 2 sans
    import du contrôleur.
- [ ] **Step 2 : lancer les nouveaux tests** — attendu : échec (fonctions absentes).
- [ ] **Step 3 : écrire le code** dans `routeur_ctl.py`, section « ports du switch », et dans `netmodesctl` : docstring, `AVEC_PORT`, `USAGE`, aiguillage.
- [ ] **Step 4 : lancer toute la suite** — attendu : tout passe.
- [ ] **Step 5 : commit** `feat(netmodes): isoler un port et le rendre au LAN (netmodesctl port-isoler, port-rattacher) (ref #3201)`.

### Task 3 : paquetage — dnsmasq lit les fragments, sudoers, AppArmor, postinst

**Files :**
- Modify `packages/secubox-netmodes/debian/secubox-lan-dhcp.service`, `apparmor/secubox-lan-dhcp`,
  `debian/secubox-netmodes.sudoers` et `debian/postinst`.
- Test : create `tests/test_paquet_3201.py` ; update l'attente `ExecStart` de `tests/test_paquet_3189.py`.

**Interfaces :**
- `ExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/var/lib/secubox-netmodes/lan-dhcp.conf --conf-dir=/var/lib/secubox-netmodes/dhcp.d,*.conf --pid-file=`.
  Le commentaire de l'unité dit pourquoi : un fragment par port isolé (#3201).
- AppArmor `secubox-lan-dhcp` : ajouter `/var/lib/secubox-netmodes/dhcp.d/ r,` et `/var/lib/secubox-netmodes/dhcp.d/*.conf r,`, rien d'autre.
- Sudoers : ajouter `, /usr/sbin/netmodesctl port-isoler *, /usr/sbin/netmodesctl port-rattacher *` à la ligne existante.
- postinst : `install -d -m 0700 -o root -g root /var/lib/secubox-netmodes/dhcp.d`, juste après la création de l'arbre root seul.
  Il faut le dossier **avant** la relance de `secubox-lan-dhcp` : dnsmasq s'arrête si `--conf-dir` manque.

- [ ] **Step 1 : tests, écrits avant le code.**
  - `test_dhcp_lit_les_fragments` : `ExecStart` exact ci-dessus.
  - `test_apparmor_fragments` : deux règles exactes, aucune règle en `w` ajoutée.
  - `test_sudoers_verbes_exacts` : la ligne contient les six verbes, sans aucun autre joker que l'`*` final de chaque verbe.
  - `test_postinst_dossier_fragments` : la ligne `install -d -m 0700 -o root -g root /var/lib/secubox-netmodes/dhcp.d` précède
    `systemctl restart secubox-lan-dhcp.service`.
- [ ] **Step 2 : lancer les tests** — attendu : échec.
- [ ] **Step 3 : modifier les quatre fichiers.** `sh -n debian/postinst` et
  `apparmor_parser -Q -K apparmor/secubox-lan-dhcp`, si disponible.
- [ ] **Step 4 : lancer toute la suite** — attendu : tout passe.
- [ ] **Step 5 : commit** `feat(netmodes): dnsmasq lit les fragments des ports isolés, sudoers et AppArmor (ref #3201)`.

### Task 4 : API — `POST /ports/{port}/isoler` et `/rattacher`, lecture « isolé »

**Files :**
- Modify `packages/secubox-netmodes/api/ports_api.py`, `api/reseau_api.py` et `api/reseau_lecture.py`.
- Test : create `tests/test_ports_isoles_api_3201.py` ; update `tests/test_routeur_api_3189.py::test_argv_conformes_au_sudoers`
  (nouveaux verbes) et les appels de `lect.ports(...)` dans `tests/test_reseau_lecture_3190.py` et `tests/test_panneau_api_3190.py`.

**Interfaces :**
- `POST /ports/{port}/isoler` : corps `{"confirmer": "<port>"}`, `require_jwt`, refus pendant une bascule. Avant tout appel au contrôleur, 409
  « vous perdriez votre propre accès (votre poste est derrière <port>) » si `port in _ports_du_poste(request)`. Ensuite
  `_ctl("port-isoler", port, acteur, delai=DELAI_PORT)` puis `_apres_action()`.
- `POST /ports/{port}/rattacher` : même schéma, sans garde anti-coupure, verbe `port-rattacher`.
- Message 400 d'un port hors liste : « port refusé : seuls lan0, lan1, lan2, lan3 sont actionnables ».
- Lecture :
  - `reseau_api` lit `ISOLE_RE = ^04-secubox-port-(lan[0-3])-isole\.network$` dans le même listage que les coupures. Si ce
    listage échoue, `coupes` et `isoles` valent `None` et `pannes` nomme les deux ;
  - `reseau_lecture.ports(ip_link, fdb, sysfs, coupes, macs_box, isoles)` (nouveau paramètre obligatoire, en dernier) ajoute à chaque port
    `"isole"` (`None` si `isoles` vaut `None`) et `"reseau_isole"` (`str(passerelle(nom).network)` si isolé, sinon `None`).

- [ ] **Step 1 : tests, écrits avant le code.**
  - `test_isoler_anti_coupure_409` (Review Focus 2) : poste derrière `lan2` (faux `ip neigh` et `bridge fdb`) → 409, contrôleur
    jamais appelé.
  - `test_isoler_argv_exact` : `["sudo", "-n", "/usr/sbin/netmodesctl", "port-isoler", "lan2", "<acteur>"]`.
    `test_rattacher_argv_exact` : même attente avec `port-rattacher`.
  - `test_confirmation_requise` (400 sans `confirmer` ou avec un autre port) ; `test_port_hors_liste_400` (`eth2`, `br-lan`) ;
    `test_sans_jeton_401`.
  - `test_lecture_isole` : `lan2` isolé → `"isole": true`, `"reseau_isole": "192.168.250.0/24"` ; les autres ports → `false` et `null`.
    Listage en échec → `null`, `"isoles"` dans `pannes`.
- [ ] **Step 2 : lancer les tests** — attendu : échec.
- [ ] **Step 3 : écrire le code.**
- [ ] **Step 4 : lancer toute la suite** — attendu : tout passe.
- [ ] **Step 5 : commit** `feat(netmodes): routes isoler et rattacher, état isolé des ports (ref #3201)`.

### Task 5 : onglet Switch, changelog 1.6.0, README

**Files :**
- Modify `packages/secubox-netmodes/www/netmodes/switch.html`, `debian/changelog` (entrée `1.6.0-1~trixie1`) et `README.md` du
  paquet (routes, verbes, fichiers par port, réserve).
- Test : create `tests/test_page_switch_isoler_3201.py`, sur l'outillage de `tests/test_pages_switch_clients_3190.py` (statique,
  puis Playwright s'il est présent).

**Interfaces / copie exacte :**
- Port de la liste avec `isole === true` :
  - pastille `isolé`, titre « Internet seul — <reseau_isole> » ;
  - sous-titre de la façade `isolé` ;
  - bouton « Rendre au LAN… » (verbe `rattacher`).
- Port de la liste avec `coupe === false && isole === false` : boutons « Couper… » et « Isoler… » (verbe `isoler`).
  `isole` à `null` : aucun bouton Isoler.
- Texte de confirmation de « Isoler », où `<reseau>` vaut `192.168.(248+N).0/24`, calculé dans la page :
  « Isoler <port> : il sort du pont et reçoit son propre réseau <reseau> (DHCP et DNS de la box). Les appareils branchés
  n'auront accès qu'à Internet : ni au LAN, ni à la Freebox, ni à l'administration. Ceux déjà branchés changent d'adresse au
  renouvellement de leur bail (débrancher puis rebrancher pour l'immédiat). »
- Texte de confirmation de « Rendre au LAN » : « Rendre <port> au LAN : il rejoint le pont br-lan si le mode routeur est actif. Les
  appareils branchés reprennent une adresse du LAN au renouvellement de leur bail. »
- Dans la note de bas de page, la phrase « « Isoler » placera un port dans son propre VLAN (livraison 3). » devient : « « Isoler »
  sort un port du pont : son propre réseau (192.168.248.0/24 pour lan0 … 192.168.251.0/24 pour lan3), DHCP et DNS de la box,
  Internet seul ; en mode routeur actif seulement, jamais sur le port de votre poste. « Rendre au LAN » le rattache en tout mode. »
- La confirmation ouverte se ferme si l'état du port ne permet plus le verbe : `rattacher` exige `isole === true` ; `isoler`
  et `couper` exigent `coupe === false && isole === false` ; `retablir` exige `coupe === true`.
- Démo : `lan2` isolé (`"isole": true`, `"reseau_isole": "192.168.250.0/24"`). Exception documentée au RFC 5737 : c'est une
  adresse de la réserve, pas une mesure.

- [ ] **Step 1 : tests, écrits avant le code.**
  - Statiques : aucun `innerHTML` ; présence des chemins `/isoler` et `/rattacher` ; libellés exacts « Isoler… » et
    « Rendre au LAN… » ; plus de « VLAN (livraison 3) ».
  - Navigateur, si présent : en démo, `lan2` montre « isolé » et « Rendre au LAN… » ; aucune requête `POST` ; pas de défilement à 420 px ;
    une réponse 409 de `/isoler` (route simulée) s'affiche telle quelle.
- [ ] **Step 2 : lancer les tests** — attendu : échec.
- [ ] **Step 3 : modifier la page, le changelog (1.6.0 : isolement, Unbound, fragments dnsmasq, gardes croisées) et le README.**
- [ ] **Step 4 : lancer toute la suite** — attendu : tout passe.
- [ ] **Step 5 : commit** `feat(netmodes): onglet Switch — Isoler et Rendre au LAN ; 1.6.0 (ref #3201)`.

---

## Déploiement (contrôleur, après fusion — pas une tâche d'implémenteur)

1. `scripts/apt-publier.sh` (enveloppes à rebond), puis `systemd-run apt-get install secubox-netmodes` sur gk1, puis sur gk2.
   Ensuite : `secubox-lan-dhcp` actif, `/var/lib/secubox-netmodes/dhcp.d` en `0700`, aucun refus AppArmor.
2. gk1 (pilote) :
   - réappliquer la même configuration, puis confirmer (Unbound redémarre et écoute les passerelles) ;
   - `port-isoler lan1` : vérifier le port hors du pont, `192.168.249.1/24`, les tables nft, dnsmasq actif, et
     `dig +short @192.168.249.1 -b 192.168.249.1 secubox.in` ;
   - `port-rattacher lan1` : vérifier le retour au pont.
3. gk2 : paquet installé seulement. La réapplication, qui redémarre Unbound (2,5 à 4 min sans DNS pour le foyer), revient au
   propriétaire, lors de son essai « Appliquer par le panneau » ; l'isolement devient possible ensuite.
