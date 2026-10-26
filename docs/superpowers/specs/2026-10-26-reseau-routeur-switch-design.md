<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Réseau de gk2 : mode routeur durable, switch et cartographie — conception (ref #3189, #3190)

Statut : **maquette approuvée par le propriétaire le 2026-10-26** (« Réseau gk2 — switch et cartographie », deux écrans :
https://claude.ai/artifact/YR3N8rfGMX7xQaYDAoD1cE, fichiers `project/Main.dc.html` et `project/Switch.dc.html`). Ce
document en tire la conception ; les points marqués **(mon choix)** sont des décisions de l'auteur. Relu par un constructeur
neuf le 2026-10-26 ; ses constats sont intégrés.

## Intention

Le 2026-10-26, gk4 (rpi400) et le PC du propriétaire ont été branchés sur les ports LAN de gk2 : sans adresse ni DHCP, rien
ne passait. Un LAN a été monté à la main, en mémoire (pont `br-lan`, `dnsmasq` transitoire, deux règles d'entrée), et il
disparaît au prochain redémarrage. Le propriétaire veut deux choses :

1. **Un vrai mode routeur pour le MOCHAbin** dans `secubox-netmodes` (« modifier, étendre ou adapter et corriger netmodes ») :
   les ports `lan0` à `lan3` deviennent un LAN durable, servi en DHCP et DNS par la box, routé et filtré par elle.
2. **Une administration du réseau dans l'admin de gk2** : le switch (ports, liens, appareils derrière chaque port), la
   cartographie (WAN, Freebox, liens du maillage et tunnels WireGuard, conteneurs, clients du LAN, hubs détectés).

Pourquoi c'est mieux qu'un réseau plat : derrière un vrai routeur, aller **et** retour passent par la box. Les zones du NAC
(`inet secubox_nac`, chaîne `forward` à `filter - 5`) s'appliquent alors pour de bon, ce que le pseudo-routeur du réseau plat
(#2940) ne pouvait offrir qu'à l'aller.

## Ce que l'état réel impose (relevé sur gk2 le 2026-10-26)

- **Le WAN `eth2` (mvpp2) ne se relance jamais à distance.** Le 2026-10-26, un changement de MTU sur `eth2` de gk1 a bloqué
  le comphy : 35 minutes hors ligne, redémarrage à froid. Or le mode routeur actuel de netmodes réécrit tout
  `/etc/netplan/00-secubox.yaml` (WAN compris) et lance `netplan apply` complet : il est **interdit** sur un MOCHAbin.
- Rôles des ports (#3101, déjà dans `secubox-net-detect`) : `eth2` WAN 1G, `eth1` conduit du switch DSA (**jamais ponté**),
  `lan0` à `lan3` ports du switch (même MAC), `eth0` SFP+ 10G.
- **Le switch Marvell (mv88e6xxx, noyau 6.12.113) refuse l'isolement de port dans le pont** :
  `bridge link set dev lan1 isolated on` → « bridge flag offload is not supported ». Deux ports d'un même pont se parlent
  dans le switch, sans passer par le processeur : aucun pare-feu ne les voit. Isoler un port impose de le **sortir du pont**.
- **192.168.255.1 sur `lo` est voulu** : HAProxy écoute `192.168.255.1:9443`, le serveur TURN `192.168.255.1:3478`.
  `secubox-core` (`secubox-wait-network.sh`, `LOOPBACK_ALIAS`) le repose à chaque démarrage, **en /24**, et gk2 a en plus un
  `/etc/systemd/network/00-lo.network` fait main (mai) avec le même /24. Un /24 sur `lo` rend tout le sous-réseau « local » :
  la box répond à l'ARP pour chaque 192.168.255.x, et la détection de conflit d'adresse des clients DHCP échoue
  (NetworkManager : `acd failed`, DHCPDECLINE en boucle). Même défaut dans l'image du rpi400 (gk4). Conséquence en plus :
  **le LAN ne peut pas être 192.168.255.0/24**, puisque chaque box porte 192.168.255.1 en local.
- `dnsmasq` ne sert pas un port DSA directement (« no address available » sur `lan3`) : il sert le pont.
- Pare-feu d'entrée : `inet filter input` (secubox-hardening) en `policy drop`. Une règle `accept` dans une autre table ne
  suffit pas : les paquets doivent être acceptés par **toutes** les chaînes de base. Les paquets ajoutent donc leurs règles
  à cette chaîne par un fichier `/etc/nftables.d/zz-<paquet>.nft` (`add rule inet filter input …`), comme Auto-Load.
- NAT : sur gk2, une règle `oif "eth2" masquerade` posée à la main couvre le LAN ; **la base livrée ne masque que
  10.100.0.0/24** (`secubox-hardening`, table `secubox_lxc_nat`). Sur un autre MOCHAbin, le LAN ne sortirait pas. Transit
  (`inet filter forward`) en `policy accept`.
- `ip_forward` est déjà à 1 par `secubox-core` (`99-secubox-zz-lxc-forward.conf`, trié après `99-secubox-hardening.conf`
  qui le met à 0).
- `secubox-wait-network.sh` ne tourne qu'au démarrage (unité à exécution unique) et contient un repli `netplan apply`
  complet : on ne peut pas l'appeler depuis un script d'installation sur un MOCHAbin.
- `secubox-net-detect` est appelé **depuis l'interface web** par l'assistant premier-pas (`premier_pas/moteur.py`) : il
  réécrit `00-secubox.yaml` et lance `netplan apply` complet. Son mode routeur déclare `br-lan` (192.168.10.1/24) dans
  netplan : un second propriétaire du pont si rien ne change.
- Le pseudo-routeur (#2940) n'est **pas installé** sur gk2 ; sa chaîne `forward` (`policy drop`, n'accepte que les appareils
  déjà rangés dans une zone du NAC) est faite pour le réseau plat et ne doit pas coexister avec le mode routeur.
- Confiance « LAN » de nginx (`secubox-hub`, `secubox-lan-geo.conf`, `$lan_client`) : 192.168.1.0/24 et 192.168.255.0/24
  (« segment lan3 ») passent la porte d'authentification des applis réservées au LAN ; 192.168.42.0/24 n'y est pas.
- Webfilter : son profil « défaut » ne s'applique qu'aux réseaux de `[reseau].lan` dans `/etc/secubox/webfilter.toml`, vide
  à la livraison ; les affectations par appareil s'appliquent, elles.
- Le NAC lit déjà les baux de `dnsmasq` dans `/var/lib/misc/dnsmasq.leases` (`api/discovery.py`) ; `dnsmasq.service` est
  masqué sur gk2 et ce fichier n'est plus alimenté.
- DNS du LAN : `secubox-dns-lan` génère `96-secubox-lan.conf` pour **une** interface (`192.168.1.200`). Une nouvelle écoute
  (`interface:`) impose un redémarrage d'Unbound (un `reload` ne rouvre pas les sockets).
- netmodes est **monté dans l'agrégateur** (absent de `DEDICATED_MODULES`), sous l'utilisateur `secubox` : ses actions
  privilégiées échoueraient (mémoire « modules root montés dans l'agrégateur »).
- Pare-feu par zones (#2891) : conception écrite le 2026-10-18 (worktree dédié), **non approuvée**, rien de construit. Elle
  recoupe l'action « Isoler » (un port = une zone).

## Objectifs

1. Mode routeur MOCHAbin **persistant** (survit au redémarrage), appliqué **sans jamais régénérer ni relancer `eth2`, `eth1`
   ni `eth0`**, avec retour arrière automatique s'il n'est pas confirmé.
2. Le LAN reçoit du DHCP et le DNS **de la box** (Unbound, donc filtrage DNS, webfilter et ad-guard effectifs), et les zones
   du NAC s'appliquent à son trafic.
3. Corriger `lo` en /32 partout (gk2, gk1, image du rpi400), sans que l'adresse disparaisse un instant.
4. Un panneau **Réseau** dans l'admin, fidèle à la maquette : Cartographie, Switch, Clients LAN, Liens du maillage, Mode
   routeur.
5. Reprendre sans coupure le LAN temporaire de gk2 (mêmes adresses pour le PC et gk4 si possible).

## Non-objectifs

- Pare-feu par zones complet (profils, zones personnalisées) : c'est #2891. Ce module en sera la vue « ports » ; quand #2891
  sera livré, l'affectation d'un port à une zone passera par son moteur.
- LLDP et découverte active des équipements (pas d'`lldpd` installé) : la détection des hubs se fait par les adresses MAC
  apprises par port.
- VLAN 802.1Q sur le switch : la colonne existe dans la maquette comme « à venir », rien n'est configuré.
- IPv6 sur le LAN (#2938) : lien local seulement dans cette version.
- Retirer des pairs du maillage : la page les marque « à retirer ? », sans action.

## Anti-objectifs

- Toute commande qui touche `eth2` (MTU, `down`/`up`, `netplan apply` complet, réécriture de `00-secubox.yaml`) depuis ce
  module, y compris en retour arrière.
- Se couper l'accès : couper le port derrière lequel se trouve l'administrateur, ou un LAN sans retour automatique.
- Une page qui affiche un zéro ou « aucun » quand une source est en panne : une panne s'affiche comme une panne.
- Un second démon DHCP ou DNS qui entre en conflit avec ceux qui tournent (Eye Remote, `lxcbr0`, Unbound).

## Conception

### 1. `lo` en /32 (secubox-core) — livré en premier

- Un petit outil dédié de `secubox-core` (sans aucun appel à netplan) **(mon choix)** : si `lo` porte `192.168.255.1/24`, il
  **ajoute d'abord le /32 puis retire le /24** — l'adresse ne disparaît jamais, HAProxy et TURN gardent leurs sockets ; il
  corrige `/etc/systemd/network/00-lo.network` s'il contient `Address=192.168.255.1/24` (copie de secours à côté, ligne
  remplacée par le /32), pour que networkd ne repose pas le /24 **(mon choix : `secubox-core` possède l'alias, il possède sa
  correction ; ce fichier n'appartient à aucun paquet)**. Idempotent, chaque correction auditée.
- Appelé par le `postinst` de `secubox-core` (correction à la mise à jour, sans redémarrage) et par
  `secubox-wait-network.sh`, dont `LOOPBACK_ALIAS` passe à `192.168.255.1/32` (son test actuel, « l'adresse est-elle
  présente », laissait le /24 en place).
- Vaut pour gk2, gk1 et toute image qui embarque `secubox-core` (rpi400 compris) à la prochaine mise à jour.

### 2. Mode routeur MOCHAbin (secubox-netmodes)

**Portée** **(mon choix)** : tout MOCHAbin (gk2 d'abord, gk1 et les nouvelles images ensuite), donc le module porte tout ce
dont le LAN a besoin, NAT compris, sans compter sur une règle faite main. Le contrôleur **refuse** d'appliquer si un fichier
netplan déclare déjà `br-lan` (deux propriétaires) ou si le pseudo-routeur (#2940) est actif, avec l'explication.

**Configuration** : `/etc/secubox/netmodes/routeur.toml` — adresse du pont (CIDR), plage DHCP, durée des baux, ports
membres (par défaut `lan0` à `lan3`). Valeur posée sur gk2 : **192.168.42.1/24**, plage .100 à .199, 12 h, la même que le LAN
temporaire **(mon choix : le PC et gk4 gardent ou retrouvent leurs adresses)**. Refusés : 192.168.255.0/24 (gestion),
tout chevauchement avec le sous-réseau du WAN, `br-lxc` (10.100.0.0/24), les tunnels (10.10.0.0/24, 10.99.0.0/16…) ; un port
hors de `lan0`…`lan3` ; `eth*` dans tous les cas.

**Fichiers systemd-networkd, jamais netplan** **(mon choix)** :

- `/etc/systemd/network/05-secubox-br-lan.netdev` (pont, STP coupé) ;
- `05-secubox-br-lan.network` (adresse, `ConfigureWithoutCarrier=yes`, lien local IPv6 seulement) ;
- `05-secubox-lan-ports.network` (`[Match] Name=` les ports membres, `Bridge=br-lan`).

Le préfixe `05-` passe avant `10-netplan-lanX.network` et avant l'ancien `10-br-lan.network` fait main (mis de côté en
copie de secours). `00-secubox.yaml` n'est **pas** modifié. Application : `networkctl reload` puis
`networkctl reconfigure br-lan <ports membres>` — jamais `eth*`. Un test vérifie qu'aucune section `[Match]` générée ne peut
correspondre à `eth*`.

**DHCP** : une unité `secubox-lan-dhcp.service` (dnsmasq, DHCP seul `port=0`, `bind-interfaces` sur `br-lan`, fichier
`/etc/secubox/netmodes/lan-dhcp.conf` généré, sans `conf-dir`), passerelle et DNS distribués = l'adresse du pont, baux dans
`/var/lib/misc/dnsmasq.leases` **(mon choix : le NAC les lit déjà, sans changement)**. Au passage du LAN temporaire, les baux
de `/run/sbx-lan-dhcp-42.leases` sont repris. Le profil AppArmor de dnsmasq de Debian doit autoriser ces chemins (à
vérifier au construire).

**DNS** : drop-in Unbound `95-secubox-lan-routeur.conf` (`interface:` l'adresse du pont, `access-control:` son sous-réseau),
validé par `unbound-checkconf`, écrit sous le verrou `/run/lock/secubox-dns-lan.lock` (partagé avec `secubox-dns-lan`,
mémoire « verrou obligatoire unbound »), suivi d'un **redémarrage** d'Unbound (nouvelle écoute). Marque « GÉNÉRÉ par
secubox-netmodes ».

**Pare-feu** : `/etc/nftables.d/zz-secubox-netmodes-lan.nft`, généré :

- entrée (`add rule inet filter input`, la seule façon d'ouvrir une chaîne en `policy drop`) : sur `br-lan`, DHCP (udp 67),
  DNS (udp et tcp 53), ICMP. L'administration HTTPS reste régie par `secubox-hardening` (déjà ouverte) ; **pas de SSH depuis
  le LAN (mon choix)** ;
- table propre `inet secubox_netmodes_lan` : NAT `ip saddr <sous-réseau du LAN> oifname <WAN> masquerade` ; au transit,
  **les connexions nouvelles du WAN vers `br-lan` sont refusées** (seuls les retours `established,related` entrent), comme
  tout routeur domestique **(mon choix)**.

Appliqué aussi à chaud par le contrôleur, de façon idempotente (règles d'entrée retrouvées par leur commentaire, table
remplacée d'un bloc). `ip_forward` : vérifié à l'application (refus s'il vaut 0), pas réécrit.

**Filtrage** : le DNS de la box rend effectifs ad-guard et dns-guard pour le LAN ; le profil « défaut » de webfilter ne s'y
applique qu'une fois le sous-réseau ajouté à `[reseau].lan` de `webfilter.toml`. La page le signale ; le module n'écrit
pas dans la configuration de webfilter **(mon choix)**.

**Application gardée** (comme #2940 et #2891) : sauvegarde de l'état courant (fichiers networkd, drop-in Unbound,
`lan-dhcp.conf`, `.nft`) → génération en **shadow** → validation (`networkd` : syntaxe des fichiers ; `unbound-checkconf` ;
`nft -c`) → bascule → **minuteur de retour de 3 minutes** (unité transitoire `systemd-run --on-active=180`) qui restaure la
sauvegarde sauf confirmation (`POST /routeur/confirmer`, possible depuis une autre session) → audit de chaque étape. Le retour
ne touche que `br-lan`, ses ports, Unbound, dnsmasq et la règle d'entrée : **jamais `eth2`**. Rollback 4R : 4 sauvegardes.

**Reprise du LAN temporaire de gk2** : le contrôleur reconnaît le pont existant, arrête `sbx-lan-dhcp`, retire les deux règles
`sbx-lan-temporaire-*` par leur handle, retire 192.168.255.1 du pont **après** l'étape 1 (le /32 sur `lo` doit être là).

**Anciens chemins de netmodes** : sur une carte détectée MOCHAbin, `apply_mode`, `auto_apply` et `rollback` (netplan complet)
répondent 409 avec l'explication (« réécrirait le WAN mvpp2 »). `secubox-net-detect` (appelé depuis l'interface web par
premier-pas) change sur MOCHAbin **(mon choix)** : il ne déclare plus `br-lan` dans netplan (le LAN passe par le même
contrôleur que le mode routeur) et, si le WAN a déjà une adresse IPv4, il ne réécrit pas `00-secubox.yaml` et ne lance pas
`netplan apply`. Une carte neuve sans WAN configuré garde le comportement actuel.

**Privilèges** : un contrôleur root `netmodesctl` à verbes étroits (sudoers) : `routeur-appliquer`, `routeur-confirmer`,
`routeur-retour`, `routeur-etat`, `port-couper <lanN>`, `port-retablir <lanN>`. netmodes rejoint `DEDICATED_MODULES` de
l'agrégateur (son service tourne déjà sur `/run/secubox/netmodes.sock`) ; le redémarrage de l'agrégateur est groupé avec
d'autres (mémoire « grouper les redémarrages »).

### 3. Panneau Réseau (secubox-netmodes, page Aurora)

La page `www/netmodes/` devient le panneau **Réseau** (entrée de menu renommée) avec les onglets de la maquette ; l'ancien
contenu (modes, interfaces, détection) passe sous « Mode routeur ». Mobile d'abord, aucun `innerHTML`, conteneur
`max-width`, tableaux dans des boîtes à défilement horizontal, mode démo `?demo=1` sans écriture.

**Lecture (API netmodes, `require_lecture`)** :

- `GET /reseau/ports` : pour `eth2`, `eth1`, `eth0`, `lan0`…`lan3` : rôle, porteuse, vitesse, état administratif, pont
  maître, adresses MAC apprises (`bridge -j fdb`, hors adresses de la box), coupé ou non.
- `GET /reseau/clients` : baux DHCP ⨝ table du pont (port) ⨝ voisins ARP ; zone NAC lue auprès du NAC, jamais recalculée ;
  « à classer » si le NAC ne connaît pas l'appareil.
- `GET /reseau/carte` : WAN (adresse, passerelle, voisins de `eth2` avec les noms connus), pont des conteneurs (conteneurs
  actifs = interfaces membres de `br-lxc`), résumé des tunnels. Les pairs du maillage viennent de l'API WireGuard
  (`/peers/status`, réservée à l'administrateur, comme ce panneau) et des noms de `secubox-p2p` ; la page les compose
  **(mon choix : pas de seconde lecture de `wg`)**. Correction dans `secubox-wireguard` : quand `wgctl dump` échoue,
  `/peers/status` répond une erreur (503), pas une liste vide prise pour « aucun pair ».
- **Hubs** : plus d'une adresse MAC apprise derrière un port → « plusieurs appareils derrière ce port (switch, hub ou point
  d'accès) ».
- Lectures légères (`ip -j`, `bridge -j`, fichiers) : cache mémoire de quelques secondes, pas de tâche de fond.

**Actions (`require_jwt`)** :

- `POST /routeur/appliquer`, `/routeur/confirmer`, `/routeur/retour` (section 2), avec aperçu des fichiers avant application.
- `POST /ports/{lanN}/couper` et `/retablir` : persistant (drop-in networkd `ActivationPolicy=down` sur ce port), confirmé
  dans la page, audité. **Refusé si l'adresse de la session qui le demande est vue derrière ce port** (anti-coupure).
  Jamais proposé sur `eth*`.

### 4. « Isoler » un port — troisième livrable

Le switch ne sait pas isoler un port dans le pont. « Isoler » **sort le port du pont** : il devient une interface routée avec
son propre petit sous-réseau et son DHCP, et la box n'y laisse passer qu'Internet, DHCP et DNS (aucun accès aux autres
réseaux privés, ni à l'administration). C'est le profil « Visiteurs » de #2891 réduit à un port. Livré après les deux
premiers, et repris par le moteur de #2891 le jour où il existe.

## Livrables (déployables séparément, dans cet ordre)

1. **`lo` /32** (secubox-core) + **mode routeur durable** (netmodes, contrôleur, agrégateur) ; reprise du LAN temporaire de gk2.
2. **Panneau Réseau** : lecture complète + couper/rétablir un port.
3. **Isoler un port.**

## Tests

- Rendu des fichiers networkd, `lan-dhcp.conf`, drop-in Unbound, `.nft` d'après des TOML types ; refus des sous-réseaux
  interdits et des ports hors liste ; aucun `[Match]` qui atteint `eth*`.
- Contrôleur (faux `networkctl`, `nft`, `unbound-checkconf`, `systemctl`, `systemd-run`) : ordre des étapes, aucun appel qui
  nomme `eth*`, retour sur échec de validation, minuteur armé puis désarmé par la confirmation, retour automatique,
  idempotence (deux applications = un seul jeu de règles).
- `lo` : passage /24 → /32 sans fenêtre sans adresse (ordre ajout puis retrait), correction de `00-lo.network`, aucun appel
  à netplan.
- Pare-feu : NAT du seul sous-réseau du LAN vers le WAN, refus des connexions nouvelles WAN → LAN, `nft -c` sur le fichier.
- `secubox-net-detect` sur MOCHAbin au WAN configuré : ni `br-lan` dans netplan, ni réécriture, ni `netplan apply`.
- Refus d'appliquer si netplan déclare `br-lan` ou si le pseudo-routeur est actif.
- API : gardes, 409 des anciens chemins sur MOCHAbin, refus anti-coupure, pannes de source affichées comme pannes.
- Page : onglets, pas d'`innerHTML`, mode démo.
- **Essai réel sur gk2** : reprise du LAN temporaire, PC et gk4 servis, DNS par la box, une confirmation puis un retour
  automatique volontaire ; puis un redémarrage de gk2 au moment choisi par le propriétaire pour prouver la persistance.

## À trancher par le propriétaire

1. **Nouveaux appareils branchés sur le LAN** : Internet ouvert dès le branchement (affichés « à classer » dans le NAC), ou
   quarantaine jusqu'à classement, comme décidé le 2026-10-19 pour le pseudo-routeur ?
2. **Confiance du LAN** : 192.168.42.0/24 entre-t-il dans le « LAN » de nginx (`$lan_client`), comme le réseau de la Freebox
   et l'ancien segment 192.168.255.0/24 — accès sans connexion aux applis réservées au LAN — ou reste-t-il soumis à la
   connexion ?

## Laissé au constructeur

Noms exacts des routes et des verbes, format du TOML, découpage des modules Python, harnais des faux binaires, détail visuel
dans le cadre Aurora et la maquette, durée exacte du cache de lecture.
