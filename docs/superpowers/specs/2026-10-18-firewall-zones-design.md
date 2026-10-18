<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Pare-feu par zones — conception (ref #2891)

Statut : **à valider par le propriétaire**. Rien n'est construit tant que ce document n'est pas approuvé.
Les points marqués **(mon choix)** sont des décisions prises par l'auteur, pas par le propriétaire.

## Intention

Un pare-feu lisible par un non-spécialiste, qui travaille sur le **réseau physique** de la carte : les ports `lan0`
à `lan3`, le WAN, les ponts de conteneurs et les tunnels. Une personne règle « ce qui a le droit de parler à quoi »
en choisissant des **zones** (Enfants, Objets connectés, Visiteurs, Libre, ou les siennes), pas en écrivant du nftables.
Les maquettes fournies (cartes de zones, appareils par zone, règles, trafic, vue mobile) fixent l'interface.

## Le modèle : deux couches

- **Zone physique** : un port (ou un groupe de ports) appartient à une zone. Tout ce qui est branché sur `lan1`
  (prise, switch, point d'accès Wi-Fi) hérite de la zone de `lan1`.
- **Zone logique** : un appareil précis, reconnu par son adresse MAC, peut être rangé dans une autre zone que celle de
  son port (une caméra Wi-Fi sur le port « Libre » traitée comme « Objet connecté »).
- **Précédence** : l'affectation de l'appareil prime sur la zone du port ; sans affectation, l'appareil suit son port.
- **Zones par défaut** (profils) : Enfants (Internet filtré, pas d'accès aux autres zones), Objets connectés (accès
  limité aux services essentiels, aucun accès au réseau privé), Visiteurs (Internet seulement), Libre (accès standard).
  Leur contenu vit dans un fichier de configuration (`/etc/secubox/firewall/zones.toml`), pas dans le code.
- **Zones personnalisées** : nom, couleur, profil de départ copié puis modifiable.
- Le WAN, les ponts de conteneurs (`br-lxc`) et les tunnels (`wg-*`) sont des zones **système** : visibles, jamais
  supprimables, leurs règles actuelles sont conservées.

## Objectifs

1. Moteur : traduire zones, ports et affectations en règles nftables, avec validation et retour arrière automatique.
2. Ports : faire des ports physiques de véritables frontières de zone sur les cartes réelles.
3. API et interface (mobile first, style Aurora, `.claude/WEBUI-PANEL-GUIDELINES.md`) reprenant les maquettes.
4. Le tout livré en **trois livrables déployables séparément**, dans cet ordre : moteur, ports, API + interface.

## Non-objectifs (première version)

- Règles « par application » (mode applicatif) : elles dépendent de la classification DPI (nDPId), traitée plus tard.
- Planification horaire des règles, contrôle parental par contenu au-delà du filtrage DNS déjà fourni par DNS Guardian.
- Pare-feu multi-sites ou centralisé entre boxes.
- Remplacer `secubox-nac` ou `secubox-hardening` : le module s'appuie sur eux.

## Anti-objectifs (ce qui serait un échec même si ça « marche »)

- **Se couper l'accès à la box** (administration, SSH du support) par une règle de zone.
- Casser DNS Guardian, les règles du NAC, le frontal HAProxy → sbxwaf, ou la politique par défaut en DROP.
- Alourdir une carte de 1 Go : le module ne doit tourner qu'avec nftables et **un seul** petit service d'API
  (pas de démon résident lourd, pas de base externe).
- Un appareil inconnu qui arrive sur un port « Enfants » doit être traité comme Enfants, pas laissé libre.

## Contraintes du dépôt

Paquet `packages/secubox-firewall/` (`api/`, `www/`, `debian/`, `nft/`, `sbin/`, `tests/`), version `X.Y.Z-N~bookworm1`,
`debian/compat` 13, FastAPI sur socket Unix `/run/secubox/firewall.sock`, groupable (`groupable.d/firewall`),
utilisateur dédié, jamais root dans l'API : les écritures passent par un ctl root à portée étroite via sudoers
(`firewallctl`, comme `certsctl`, `wgctl`). nftables uniquement (jamais iptables). Aucun secret dans le dépôt.
Chaque décision est écrite dans `/var/log/secubox/audit.log`. Ne pas utiliser `uci`.
Nom : `secubox-firewall` (convention du dépôt), pas `sbx-firewall` **(mon choix)**.

## Ce que l'état réel des cartes nous apprend (mesuré sur gk2)

- `lan0` à `lan3` sont des ports DSA du switch Marvell, chacun **déjà un périphérique réseau distinct** (conduit `eth1`),
  non pontés entre eux. Un flux d'un port à l'autre passe donc par le routage de la box et par la chaîne `forward` :
  le filtrage inter-zones est possible par `iifname` / `oifname` **sans** reconfigurer le switch. L'isolation entre
  ports, que je craignais, est ici naturelle ; elle sera vérifiée sur l'ESPRESSObin avant de s'y fier.
- Aujourd'hui ces ports sont sans adresse : le plan d'adressage par zone reste à définir (voir « À trancher »).
- La table `inet secubox_nac` filtre déjà par MAC à la priorité `filter - 5` (ensembles `guest_zone`, `iot_zone`,
  `quarantine_zone`, `lan_allowed`, `lxc_zone`). Les zones logiques **réutilisent** ces ensembles et la commande
  `secubox-nac-apply` au lieu d'en créer de nouveaux.
- Le panneau Réseau affiche déjà un mode (« Router »). Le mode réseau reste le point de départ : il décide du gabarit
  de base entre WAN et LAN, les zones affinent à l'intérieur.

## Le moteur (livrable 1)

- Une table dédiée `inet secubox_firewall`, chaîne `forward` à une priorité **entre** le NAC (`filter - 5`) et les
  bases (0) **(mon choix)** : un `drop` du NAC reste final, les zones ne rendent jamais accessible ce que le NAC bloque.
- Génération : le modèle (zones, ports, affectations) produit un fichier nftables unique ; l'appartenance d'un port à une
  zone est un ensemble d'interfaces (`iifname @zone_<id>`), pas une règle par port.
- Application sûre, dans l'ordre : écrire en **shadow** → `nft -c -f` (validation à sec) → application atomique
  (une transaction `nft -f`) → **minuterie de confirmation** : sans confirmation sous 60 s, retour automatique à la
  configuration précédente **(mon choix)** → entrée dans `audit.log`. Jusqu'à 4 sauvegardes (rollback 4R).
- Garde d'administration : la table ne s'accroche pas à `input` pour l'administration ; les accès à la box (SSH, interface
  d'administration, DNS, DHCP) restent régis par `secubox-hardening`. Un test refuse tout modèle qui rendrait ces accès
  inaccessibles depuis la zone de l'administrateur.
- **Appareil inconnu** : la zone d'un port se décide par l'ensemble d'interfaces seul (`iifname`), sans fiche d'appareil.
  Un inconnu sur un port « Enfants » est donc Enfants dès qu'il se branche **(mon choix)**.
- **Correspondance avec les ensembles du NAC** **(mon choix)** : `guest_zone` ↔ Visiteurs, `iot_zone` ↔ Objets connectés,
  `lan_allowed` ↔ Libre. Enfants et les zones personnalisées ont leurs propres ensembles de MAC dans
  `secubox_firewall`. Les appareils déjà rangés par le NAC gardent leur zone ; le NAC reste le gardien de la quarantaine
  et du blocage.
- **Zone et chemins de l'administrateur** **(mon choix)** : la zone d'administration est celle de l'interface par laquelle
  arrive la session qui applique (plus, toujours, la zone de l'interface qui porte la route d'administration). Les
  chemins protégés sont SSH (22), l'interface d'administration (HTTPS) et DNS/DHCP de la box. Le test refuse tout modèle
  qui bloquerait un de ces chemins depuis cette zone.
- **Retour arrière** **(mon choix)** : la minuterie est une unité transitoire systemd (`systemd-run --on-active=60`) qui
  appelle `firewallctl rollback` ; aucun démon résident. La confirmation est une action de l'API (`POST /confirmer`), faisable
  depuis n'importe quelle session, y compris une autre que celle qui a appliqué ; sans confirmation, le retour se fait seul,
  même si la session de l'administrateur est coupée.
- Modes d'ensemble de la maquette **(mon choix pour la première version)** : « Analyse » (les seules règles de ZONE passent en
  comptage/journal sans bloquer ; elle ne neutralise jamais le NAC ni la politique par défaut en DROP) et « Intelligent » (profils recommandés appliqués). « Applicatif » est reporté (DPI).

## Les ports (livrable 2)

- Inventaire des ports par carte : ESPRESSObin (`lan0`/`lan1`, `wan`), Mochabin / gk2 (`lan0`–`lan3`, `eth2` WAN), cartes
  sans switch. Le module ne propose que les ports qui existent.
- Pour chaque port affecté à une zone : adresse, DHCP et DNS de cette zone (voir « À trancher »).
- Vérification réelle sur au moins une carte avant déploiement.

## API et interface (livrable 3)

- Routes `GET|POST /api/v1/firewall/<m>` : `zones`, `ports`, `appareils`, `regles`, `trafic`, `modes`. Lecture
  `require_lecture`, écriture `require_jwt`. Stats lourdes en tâche de fond avec cache fichier, jamais pour les actions.
- Pages : Zones (quatre cartes + « Créer une zone personnalisée »), Appareils (par zone, déplacement), Règles de la zone,
  Connexions bloquées récentes, Trafic sortant par zone. Vue mobile d'abord. Les appareils viennent du NAC (pas de
  seconde base). Mode démo `?demo=1` sans écriture, comme les autres pages Aurora.
- Aucune fausse valeur : une panne de source s'affiche comme une panne, jamais comme zéro.

## Tests

Pytest à chaque livrable : génération nftables d'après des modèles types (chaque profil), validation `nft -c` quand `nft`
est présent, précédence appareil > port, refus d'un modèle qui coupe l'administration, retour arrière sur échec et sur
absence de confirmation, API (gardes, modèles invalides). Essai réel sur gk2 puis l'ESPRESSObin avant de dire « livré ».

## À trancher par le propriétaire

1. **Adressage par zone.** Chaque port-zone doit-il avoir son propre sous-réseau et son DHCP (comme un vrai routeur
   multi-zones), ou les ports restent-ils sur un seul sous-réseau avec filtrage par appareil ? Le premier est plus
   propre mais change l'adressage des boxes ; le second est plus simple mais ne protège pas entre ports du même LAN.
2. **Boxes cibles de la première livraison** : gk2 seul, ou aussi l'ESPRESSObin ? (L'ESPRESSObin 1 Go est la plus
   contrainte.)
3. **gk3** reste inaccessible (accès refusé) : il est exclu des essais tant qu'il le reste.

## Laissé au constructeur

Format exact du TOML, noms des chaînes et ensembles, découpage interne des modules Python, détail visuel des pages dans
le cadre Aurora, choix des couleurs de zones personnalisées.
