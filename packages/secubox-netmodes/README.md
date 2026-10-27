<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🌐 Network Modes

Network topology configuration

**Category:** Network

## Screenshot

![Network Modes](../../docs/screenshots/vm/netmodes.png)

## Features

- Router mode
- Bridge mode
- AP mode
- VLAN

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-netmodes
```

## Configuration

Configuration file: `/etc/secubox/netmodes.toml`

## API Endpoints

- `GET /api/v1/netmodes/status` - Module status
- `GET /api/v1/netmodes/health` - Health check

## Mode routeur durable (MOCHAbin)

Depuis 1.4.0 (#3189), corrigé en 1.4.1. Le LAN du MOCHAbin (pont `br-lan` sur `lan0`..`lan3`, DHCP, DNS, NAT)
est posé par systemd-networkd, dnsmasq, Unbound et nftables, sans netplan : aucune commande ne relance ni ne reconfigure une
interface `eth*` (le WAN mvpp2 bloque son PHY si son lien est relancé à distance). Sur MOCHAbin, les anciennes routes
netplan (`/apply_mode`, `/auto_apply`, `/rollback`…) répondent 409.

### Configuration

`/etc/secubox/netmodes/routeur.toml` (0640, root), écrit par le contrôleur à chaque application :

```toml
[lan]
adresse = "192.168.42.1/24"      # adresse du pont, préfixe du LAN
dhcp_debut = "192.168.42.100"
dhcp_fin = "192.168.42.199"
bail = "12h"                     # 1 à 9999, en m ou h
ports = ["lan0", "lan1", "lan2", "lan3"]
wan = "eth2"                     # lu seulement : NAT et transit, jamais reconfiguré
```

Refusés : `192.168.255.0/24` (gestion), `10.100.0.0/24` (LXC), tout réseau déjà porté par une autre interface, une
plage DHCP hors du réseau ou qui contient l'adresse du pont.

### Contrôleur `netmodesctl` (root)

Seule surface privilégiée du module ; l'API (utilisateur `secubox-netmodes`) l'appelle par `sudo -n`, à verbes exacts
(`/etc/sudoers.d/secubox-netmodes`). Sortie : toujours un JSON. Codes : 0 succès, 2 usage ou acteur invalide, 3 refus
(configuration ou garde), 4 occupé, 1 autre échec.

| Verbe | Rôle |
|---|---|
| `routeur-etat` | état (`inactif`, `en_attente`, `actif`, `config_invalide`), configuration, minuteur et son échéance (`echeance`, UTC), bascule en cours, DHCP, adresses du pont, ports coupés |
| `routeur-appliquer <acteur>` | configuration JSON sur l'entrée standard : sauvegarde, rendu, validation (`nft -c`, `unbound-checkconf`, `nginx -t` par `systemd-run`), bascule, minuteur de retour |
| `routeur-confirmer <acteur>` | garde la nouvelle configuration, annule le retour automatique |
| `routeur-retour <acteur>` | restaure la dernière sauvegarde (`minuteur` : seulement si l'application attend sa confirmation) |
| `routeur-retour-demarrage` | au démarrage (`secubox-netmodes-retour-boot.service`), défait une application restée en attente ; jamais accordé à l'API |
| `port-couper <lanN> <acteur>` | coupe un port du pont (1.5.0) : `04-secubox-port-<lanN>-coupe.network` (`ActivationPolicy=down`), `networkctl reload` puis `networkctl reconfigure <lanN>`, vérifié (plus de maître `br-lan`, lien DOWN) ; échec : fichier précédent remis ; mode routeur `actif` requis |
| `port-retablir <lanN> <acteur>` | retire la coupure et relance ce seul port, vérifié (maître `br-lan` en mode actif, lien UP sinon) ; permis quel que soit le mode |

Les verbes de port n'acceptent que `lan0` à `lan3` (liste blanche vérifiée avant tout, jamais `eth*` ni `br-lan`). Une
coupure est une décision de l'administrateur : elle survit à une réapplication et à un retour en arrière, et l'attente du
pont ignore les ports coupés (une réapplication avec un port coupé ne revient pas en arrière).

Avant toute écriture, `routeur-appliquer` refuse si netplan déclare `br-lan`, si le pseudo-routeur (#2940) est actif,
si `net.ipv4.ip_forward` ne vaut pas 1, si `dnsmasq.service` est actif, si `/etc/nftables.conf` n'inclut pas
`/etc/nftables.d/*.nft` (le pare-feu du LAN ne serait pas rechargé au démarrage), ou si l'ancien
`/etc/systemd/network/10-br-lan.network` ne vise pas `br-lan` seul (section `[Match]` réduite à la ligne
`Name=br-lan` : sinon le mettre de côté reconfigurerait d'autres interfaces, le WAN compris). Pendant la bascule,
Unbound n'est redémarré (coupure du DNS de toute la box) que si son drop-in change ; après la relance du DHCP,
dnsmasq doit être vu actif deux fois de suite (5 s au plus), sinon la bascule est défaite. Un `routeur.toml` illisible
(édité à la main, non UTF-8) rend l'état `config_invalide` et n'empêche jamais le retour.

**Pont `br-lan` (1.4.1).** networkd ne crée, puis n'asservit ses ports, qu'à un netdev qu'il a créé lui-même : un
`br-lan` déjà là (pont fait main, ancien netdev) donne « Failed to create netdev: File exists » et des ports
« configuring » à jamais. Quand les fichiers du pont changent (ou qu'un pont fait main est remplacé), le contrôleur
supprime `br-lan`, et lui seul, avant `networkctl reload`, puis reconfigure les ports seuls (`networkctl reconfigure
lan0 …`, jamais `br-lan`). Il relit ensuite le résultat, toutes les 2 s et 30 s au plus : chaque port a `br-lan` pour
maître (avec ou sans porteuse), `br-lan` est UP et porte l'adresse configurée ; sinon la bascule est défaite. Un `br-lan`
dont les ports n'ont pas `br-lan` pour maître (netdev de networkd en échec) est lui aussi supprimé avant reload, même
si ses fichiers ne changent pas. Au retour, même règle, et le pont du `routeur.toml` restauré est relu de la même façon
(pas prêt : retour incomplet) ; un pont fait main que networkd ne saurait recréer (seul un `.network` le vise) est
gardé, et son absence rend le retour incomplet.

**Unbound lent (1.4.1).** Sur gk2, Unbound met jusqu'à 115 s à s'arrêter et 38 à 112 s à démarrer. Il est relancé par
`systemctl restart --no-block` puis attendu jusqu'à sa vraie issue (relevé toutes les 5 s) : actif et nouvellement
démarré (`ActiveEnterTimestampMonotonic`), `failed` après le début du nouveau démarrage, ou délai dépassé. Le délai
vient de l'unité : `TimeoutStopUSec` + `TimeoutStartUSec` + 30 s, borné à [180 s, 900 s] (illisible ou `infinity` :
900 s). Même attente au retour et au démarrage ; `secubox-netmodes-retour-boot.service` a `TimeoutStartSec=1200`.
Le verrou partagé avec `secubox-dns-lan` est tenu de la pose des fichiers jusqu'à la relance d'Unbound. Le retour d'une
bascule en échec ne relance Unbound que si la bascule l'avait relancé (un échec au pont ne coupe plus le DNS de la
box) ; le minuteur, le démarrage et l'administrateur le relancent si le drop-in restauré diffère de celui en place.

**API et Unbound lent.** Depuis 1.5.0 (#3190), `POST /routeur/appliquer` et `/routeur/retour` répondent **202** tout
de suite et la bascule part dans un fil d'arrière-plan (délai 2400 s, au-delà du pire cas de deux relances d'Unbound) :
une bascule lente ne se termine plus en 502/504 d'HAProxy ou de l'agrégateur. Le contrôleur ignore TERM, HUP et INT
pendant la bascule et survit à un redémarrage de l'API (`KillMode=process`) ; il la défait lui-même si une étape échoue,
et la garde de 3 minutes, armée à sa fin, la protège ensuite. On suit la bascule par `GET /routeur/etat`
(`bascule_en_cours`) et `GET /routeur/derniere` ; après un redémarrage de l'API, `derniere` est vide alors que la bascule
peut se poursuivre : l'état fait foi. La console (`netmodesctl routeur-appliquer <acteur>`) reste possible.

Chaque décision est écrite dans `/var/log/secubox/audit.log` (une ligne JSON, `"module": "netmodes"`).

### Routes

| Méthode | Route | Garde | Contrôleur |
|---|---|---|---|
| GET | `/api/v1/netmodes/routeur/etat` | `require_lecture` | `routeur-etat` (lecteur qui n'est pas administrateur réel : copie expurgée, cache 5 s) |
| GET | `/api/v1/netmodes/routeur/derniere` | `require_jwt` | aucun : dernier résultat d'une bascule lancée par l'API |
| POST | `/api/v1/netmodes/routeur/apercu` | `require_jwt` | `routeur-etat` pour l'avertissement ; fichiers rendus, rien d'écrit |
| POST | `/api/v1/netmodes/routeur/appliquer` | `require_jwt`, corps `"confirmer": "routeur"` | `routeur-appliquer`, **202** puis tâche de fond |
| POST | `/api/v1/netmodes/routeur/confirmer` | `require_jwt` | `routeur-confirmer` (synchrone) |
| POST | `/api/v1/netmodes/routeur/retour` | `require_jwt`, corps `"confirmer": "retour"` | `routeur-retour`, **202** puis tâche de fond |
| POST | `/api/v1/netmodes/ports/{lanN}/couper` | `require_jwt`, corps `"confirmer": "<lanN>"` | `port-couper` (après l'anti-coupure) |
| POST | `/api/v1/netmodes/ports/{lanN}/retablir` | `require_jwt`, corps `"confirmer": "<lanN>"` | `port-retablir` |
| GET | `/api/v1/netmodes/reseau/ports` | `require_lecture` | aucun : `ip -j link`, `bridge -j fdb`, sysfs |
| GET | `/api/v1/netmodes/reseau/clients` | `require_jwt` | aucun : baux dnsmasq, table du pont, voisins |
| GET | `/api/v1/netmodes/reseau/carte` | `require_lecture` | aucun : WAN, `br-lxc`, tunnels WireGuard |

Corps de `/apercu` et `/appliquer` : `adresse`, `dhcp_debut`, `dhcp_fin`, `bail` (facultatif, 12h), `ports`
(facultatif, les quatre). La clé `wan` est **refusée** (400) : le WAN reste `eth2`, jamais relancé à distance. Les
erreurs sont `{"detail": "<message>"}` : 400 (configuration, confirmation, acteur), 409 (refus du contrôleur, bascule ou
opération déjà en cours, poste derrière le port à couper), 502 (contrôleur en échec ou muet), 503 (fil impossible à
lancer, anti-coupure illisible).

`GET /routeur/derniere` : `{"verbe", "code", "sortie", "fini", "debut", "fin"}`. Rien lancé depuis le démarrage de
l'API : `verbe` null et `fini` vrai ; en cours : `fini` faux ; fini : `code` 200 et `sortie` = état du contrôleur, ou
`code` d'erreur HTTP et `sortie` = `{"erreur": "…"}`.

`GET /routeur/etat`, champs ajoutés en 1.5.0 : `echeance` (échéance réelle du minuteur de retour, RFC 3339 UTC, null
sans minuteur ; le compte à rebours se fait sur elle, jamais sur `depuis` + 180), `bascule_en_cours` (verrou du
contrôleur tenu ; null s'il est illisible) et `ports_coupes`. Tout lecteur qui n'est pas un **administrateur réel**
(`est_admin_reel` de `secubox_core.auth` : compte actif de rôle admin, jamais un appareil ni une session plafonnée) —
lecteur anonyme du tableau de bord, usager, appareil enrôlé, invité — reçoit une liste blanche de champs, **sans
`acteur` ni `sauvegarde`**, servie d'un cache de 5 s (au plus un sudo par 5 s, panne comprise) ; un administrateur réel
n'est jamais servi depuis ce cache. De même, `/reseau/ports` et `/reseau/carte` retirent pour ce lecteur les MAC
apprises et les voisins du WAN (il garde leur nombre).

**Anti-coupure.** `POST /ports/{lanN}/couper` est refusé (409, « vous couperiez votre propre accès ») avant tout appel
au contrôleur si le poste qui le demande est vu derrière ce port : adresses du client (X-Real-IP et
X-Forwarded-For), puis sa MAC dans `ip -j neigh show dev br-lan`, puis le port où elle est apprise dans
`bridge -j fdb show br br-lan`, tout relu à l'instant. Table illisible : 503, rien n'est coupé. **Limite** : un
administrateur qui atteint la box par un tunnel ou un routeur sans NAT porté par un port du LAN n'est pas reconnu (son
adresse n'est pas un voisin de `br-lan`), pas plus qu'une MAC sortie de la table du pont.

### Fichiers écrits

| Fichier | Lu par |
|---|---|
| `/etc/systemd/network/05-secubox-br-lan.netdev`, `/etc/systemd/network/05-secubox-br-lan.network`, `/etc/systemd/network/05-secubox-lan-ports.network` | systemd-networkd |
| `/var/lib/secubox-netmodes/lan-dhcp.conf` | dnsmasq de `secubox-lan-dhcp.service` |
| `/etc/unbound/unbound.conf.d/95-secubox-lan-routeur.conf` | Unbound |
| `/etc/nftables.d/zz-secubox-netmodes-lan.nft` | nftables (règles d'entrée commentées, table `inet secubox_netmodes_lan`) |
| `/etc/nginx/secubox-lan-geo.d/netmodes-lan.conf` | nginx (bloc géo du LAN, secubox-hub) |
| `/etc/secubox/netmodes/routeur.toml` | le contrôleur |

Sauvegardes (`sauvegardes/<horodatage>/`) et état (`routeur-etat.json`) vivent dans `/var/lib/secubox-netmodes`, arbre
root seul (0700) dont le contrôleur vérifie propriétaire et mode à chaque usage. Les baux restent dans
`/var/lib/misc/dnsmasq.leases` (lus par le NAC).

### Retour automatique sous 3 minutes

Une application arme d'abord la garde (état `en_attente`), puis bascule et lance une unité transitoire
`secubox-netmodes-retour` (180 s). Sans `POST /routeur/confirmer` dans les 3 minutes, la sauvegarde est restaurée.
Confirmer depuis la nouvelle adresse : appliquer depuis l'ancien LAN coupe la connexion (la réponse l'annonce). Une
coupure ou un redémarrage avant la confirmation est défait au démarrage par `secubox-netmodes-retour-boot.service`.

### Unités

- `secubox-netmodes.service` : API, utilisateur `secubox-netmodes`, profil AppArmor `secubox-netmodes-api`,
  `KillMode=process` (un contrôleur en pleine bascule survit à un redémarrage de l'API). État des anciens modes :
  `/var/lib/secubox-netmodes-api/state.json` (`StateDirectory`).
- `secubox-lan-dhcp.service` : dnsmasq en DHCP seul (`Type=exec`), profil AppArmor `secubox-lan-dhcp` ; ni activé ni
  démarré par le paquet, le contrôleur l'active à la bascule et le désactive au retour.
- `secubox-netmodes-retour-boot.service` : oneshot root durci, activé par le paquet, ordonné avant
  `secubox-lan-dhcp.service` : après un redémarrage, aucun bail n'est servi sur un sous-réseau non confirmé.

Retirer ou mettre à jour le paquet n'arrête que l'API : le LAN posé reste en place.

## Panneau Réseau (1.5.0)

Depuis 1.5.0 (#3190), `/netmodes/` est le panneau **Réseau** (entrée de menu « Réseau ») au profil Aurora
(`.claude/AURORA-REFERENCE.md`) : un hôte à onglets (`www/netmodes/index.html`) et une page autonome par onglet, chargée
en `?embed=1` dans une seule iframe de même origine ; chaque page annonce sa hauteur (`{sbxVue, onglet}`, mesurée sur
son cadre), l'hôte vérifie l'origine, la fenêtre source et l'onglet. L'en-tête montre l'état du mode routeur et, tant
qu'il n'est pas actif, un bandeau « LAN temporaire » qui mène à l'onglet Mode routeur. Lien direct : `#carte`,
`#switch`, `#clients`, `#maillage`, `#routeur`, `#modes`. `?demo=1` (propagé aux onglets) : données de documentation,
aucune écriture.

| Onglet | Page | Lit | Agit |
|---|---|---|---|
| Cartographie (par défaut) | `carte.html` | `/reseau/carte`, `/reseau/ports`, `/reseau/clients`, `/routeur/etat`, `/api/v1/p2p/peers`, `/api/v1/wireguard/peers/status`, `/api/v1/wireguard/summary` | rien |
| Switch | `switch.html` | `/reseau/ports`, `/reseau/clients`, `/routeur/etat` | Couper… / Rétablir… `lan0` à `lan3` (saisie du nom du port) ; « Isoler » désactivé (livraison 3) |
| Clients LAN | `clients.html` | `/reseau/clients`, `/reseau/ports`, `/api/v1/nac/clients` | rien |
| Liens du maillage | `maillage.html` | `/api/v1/p2p/peers`, `/api/v1/wireguard/peers/status`, `/api/v1/wireguard/summary` | rien |
| Mode routeur | `routeur.html` | `/routeur/etat`, `/routeur/derniere` | aperçu, appliquer, confirmer, revenir en arrière |
| Modes (hérité) | dans `index.html` | anciennes routes netplan | anciennes actions, refusées (409) sur MOCHAbin |

Chaque source a sa pastille : une source en 401 dit « session requise », en échec (503 de WireGuard quand `wgctl dump`
échoue, 502 du contrôleur) « source en panne » ; jamais un vide présenté comme « aucun pair » ou « 0 ». Une mesure
absente s'affiche « — ». Toute action passe par une confirmation intégrée à la page (jamais `confirm()`), son résultat
ou son refus s'affiche dans la page, et aucune actualisation n'a lieu pendant une confirmation ouverte ni page cachée.

**Mode routeur, application asynchrone.** Formulaire prérempli depuis `etat.config` (pont, plage DHCP, bail, ports ;
`wan` n'est jamais renvoyé). « Aperçu » montre les fichiers rendus (texte brut, repliables) et l'avertissement de perte
de connexion ; « Appliquer… » refait l'aperçu des valeurs exactes, demande confirmation, puis `POST /routeur/appliquer`
(202). La page passe en « bascule en cours » (état et dernier résultat relus toutes les 3 s tant que
`bascule_en_cours` est vrai ou que `derniere.fini` est faux), puis en « à confirmer » (relu toutes les 3 s jusqu'à
l'échéance + 15 s, le temps d'observer le retour automatique, puis toutes les 30 s) :
compte à rebours jusqu'à `echeance`, corrigé de l'écart d'horloge entre le poste et la box (en-tête `Date` de la
réponse), « échéance inconnue » si elle manque, et bouton **Confirmer** (`POST /routeur/confirmer`) → « actif ». Une
lecture d'état ratée ne fait rien oublier : la page garde le dernier relevé, l'annonce « relevé ancien » et laisse
Confirmer jusqu'à l'échéance. Échéance inconnue ou état illisible : relecture toutes les 3 s pendant 5 minutes au plus
depuis le début de la situation, puis toutes les 30 s (chaque relevé d'administrateur coûte un sudo root). Une lecture partie avant une écriture (appliquer, confirmer,
retour) est jetée à son arrivée, et la relecture qui suit l'écriture s'enchaîne à elle. Un Confirmer refusé dit le
temps qui reste avant le retour automatique, ou « échéance dépassée ».
« Revenir en arrière… » (`POST /routeur/retour`, 202) suit le même chemin. Si le poste perd la box (changement de
sous-réseau), la page continue d'essayer toutes les 3 s et rappelle la nouvelle adresse du pont : par l'API, une bascule
lente (Unbound) continue même si le navigateur perd la connexion, et la garde de 3 minutes protège.

Le profil « défaut » de webfilter ne s'applique au LAN qu'une fois son sous-réseau ajouté à `[reseau].lan` de
`/etc/secubox/webfilter.toml` : la page le rappelle, le module ne l'écrit pas.

## Isoler un port (1.6.0)

Depuis 1.6.0 (#3201), l'onglet Switch propose **Isoler…** : un port `lan0` à `lan3` sort du pont `br-lan` et reçoit son
propre réseau, avec le DHCP et le DNS de la box, et un accès à Internet seul. **Rendre au LAN…** le rattache. Les deux
gestes passent par la confirmation intégrée (saisie du nom du port) et sont inscrits au journal d'audit.

- Routes (`require_jwt`, corps `{"confirmer": "<port>"}`) : `POST /api/v1/netmodes/ports/{port}/isoler` et `/rattacher`,
  mêmes formes d'erreur que `/couper`. `GET /reseau/ports` rend par port `isole` (vrai, faux, `null` si illisible) et
  `reseau_isole` ; `GET /routeur/etat` ajoute `ports_isoles`.
- Verbes de `netmodesctl` (root, via sudoers à verbes exacts) : `port-isoler <port> <acteur>` et
  `port-rattacher <port> <acteur>`.
- Trois fichiers par port : `/etc/systemd/network/04-secubox-port-<port>-isole.network`,
  `/var/lib/secubox-netmodes/dhcp.d/isole-<port>.conf` (arbre root seul, dossier `0700`, lu par dnsmasq en
  `--conf-dir`) et `/etc/nftables.d/zz-secubox-netmodes-isole-<port>.nft`.
- Réserve `192.168.248.0/22` : `lanN` reçoit `192.168.(248+N).0/24` (lan0 `192.168.248.0/24` … lan3
  `192.168.251.0/24`), passerelle `.1`, DHCP `.100` à `.199`, bail 2 h.
- Table nft `inet secubox_netmodes_isole_<port>` : les clients du port peuvent joindre Internet, le DHCP et le DNS de la
  box ; ils ne joignent ni le LAN, ni la Freebox, ni un tunnel, ni l'administration, en IPv4 comme en IPv6.
- Le DHCP du LAN tourne en `bind-dynamic` : un port isolé sans adresse n'arrête pas dnsmasq ; l'isolement attend l'adresse
  du port avant de relancer le DHCP, et le rattachement retire le fragment DHCP en premier.
- Unbound écoute les passerelles des ports isolés d'avance : **réappliquer une fois le mode routeur** (puis confirmer)
  avant le premier isolement ; sans cela l'isolement est refusé, sans rien poser. La réapplication redémarre Unbound
  (jusqu'à quelques minutes sans DNS pour le foyer).
- Gardes : isoler est refusé (409, avant tout appel au contrôleur) derrière le port où se trouve le poste de
  l'administrateur ; le contrôleur le refuse aussi hors mode routeur actif et sur un port coupé, et refuse de couper un
  port isolé (la page ne propose alors que « Rendre au LAN… »). Rendre au LAN et Rétablir restent permis en tout mode.
- L'isolement survit à un retour en arrière du mode routeur (la vérification du pont ignore les ports isolés) ; sans
  mode routeur il n'y a toutefois plus de DHCP pour le port.

## LAN de confiance (1.7.0)

Le LAN du mode routeur est de confiance comme le réseau de la Freebox (décision du propriétaire du 2026-10-26, #3206) :
le fragment nft du mode routeur ajoute `iifname "br-lan" accept` en fin de `inet filter input` (pendant de
`iif "eth2" accept`) et insère en tête `iifname "br-lan" tcp dport 22 accept` (le durcissement refuse le 22 hors
10/8 et 192.168.1.0/24 plus haut). Un nœud du LAN routé rejoint ainsi le maillage (API de jonction, 7331). Les deux
règles portent le préfixe `secubox netmodes lan` : la réapplication et le retour les retirent. Prend effet à la
prochaine application du mode routeur (Unbound inchangé, pas de redémarrage).

Gardes qui l'accompagnent, imposées par `Breaks: secubox-hardening (<< 1.6.2~), secubox-nac (<< 3.9.5~)` :
backends fermés depuis br-lan comme depuis eth2 (secubox-hardening 1.6.2), zones IoT et Invités limitées à DNS et
DHCP vers la box (secubox-nac 3.9.5). Les ports isolés (`lanN`, 1.6.0) ne sont pas br-lan : ils restent Internet seul.

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
