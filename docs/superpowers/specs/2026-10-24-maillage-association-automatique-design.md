<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Maillage : association automatique des box (#3100)

Projet 1 sur 4. Les suivants, chacun avec son document : 2. maillage entre pairs ; 3. plan de gestion (TR-369/USP,
connexion et supervision depuis le webui admin du maître, accès renforcé : prise en main à distance et état rafraîchi) ;
4. App Store partagé (catalogue du maître, et blogs metablog d'un nœud distant rendus disponibles en local : clonage de la
configuration du module et synchronisation de ses données).

## Intention

Aujourd'hui, une box n'entre dans le maillage que si quelqu'un génère un code d'invitation sur le maître (JWT
administrateur), le recopie et le dépose sur la box. gk1, fraîchement flashée par le netboot de gk2, n'est donc nulle
part : pas de tunnel, pas d'identité, absente de la Flotte, et `admin.gk1.secubox.in` tombe sur une route morte.

Le propriétaire veut que les box se relient seules, sans copier de code, sans ouvrir le maillage à n'importe quel
appareil branché sur le réseau.

## Décisions du propriétaire (2026-10-24)

1. **Une box rejoint le maître qui l'a flashée, et seulement lui.** Le netboot du maître dépose dans l'image un code
   d'invitation à usage unique ET l'identité du maître. Flashée par gk2, donc à gk2.
2. **Toute autre box vue sur le réseau** apparaît sur le maître comme « nouvel appareil » et entre après un clic.
3. **Le maître reste maître pour la gestion et la télé-administration**, pas pour les liens et le partage de services
   (projet 2 ; le présent document ne doit rien rendre impossible pour lui).

## Objectifs

- O1. Une box flashée par `sbx-netflash` depuis le live d'un maître démarre, rejoint ce maître et apparaît dans sa
  Flotte et derrière ses noms `*.<nom>.secubox.in`, sans aucune action après le flash.
- O2. La box flashée porte son nom et son domaine dès le premier démarrage (`gk1`, `gk1.secubox.in`).
- O3. La box n'accepte que le maître qui l'a flashée : un faux maître sur le réseau local ne peut pas la capturer.
- O4. Une box non flashée par le maître (clé USB, image CI, autre maître) apparaît sur le maître comme « nouvel
  appareil » et entre après un clic sur le maître ET une acceptation sur la box (voir D5).
- O5. Toute décision est journalisée dans `/var/log/secubox/audit.log` (append-only), sans jamais écrire un code ni un
  jeton.

## Non-objectifs

- Liens directs entre pairs et partage de services hors du maître : projet 2.
- TR-369, supervision, accès renforcé : projet 3.
- Changer de maître une box déjà associée, ou la retirer du maillage (le retrait existant reste tel quel).
- Box hors du réseau local du maître au moment de l'association (le maître public / DDNS viendra avec le projet 2).

## Anti-objectifs (échec même si ça « marche »)

- Un appareil inconnu entre dans le maillage sans clic du propriétaire.
- Une box accepte un maître dont elle n'a pas l'identité ancrée ou acceptée.
- Un code d'invitation se retrouve dans un journal, dans `images.txt`, dans le squashfs du live ou dans une URL
  journalisée par nginx.
- Le flash dépend d'une action manuelle sur le maître au moment même du flash (la décision 1 dit « rejoint seule »).

## Ce qui existe (relevé dans le code le 2026-10-24)

- **Jonction** : `secubox-automesh.timer` (démarrage puis toutes les 2 min) lit `/var/lib/secubox/p2p/automesh.code`
  (`sbxmesh1.<b64url{"a":adresse,"t":jeton}>.<somme>`, jeton de 64 hexadécimaux) et lance `sbx-mesh-join`, qui envoie
  `POST /api/v1/p2p/master-link/join` (HTTP 7331 sur le LAN, HTTPS 443 sinon) avec sa clé publique WireGuard. Le
  maître répond `mesh_ip`, `master_public_key`, `master_mesh_ip`. Approbation immédiate si le jeton est auto-approuvé.
- **Trou de sécurité** : la box ne vérifie jamais l'identité du maître ; elle accepte la clé WireGuard qu'on lui donne.
- **Jetons** : `/master-link/invite` exige un JWT ; la CLI root `sbx-mesh-invite` produit des jetons de 32 caractères
  sans code `sbxmesh1.`, inutilisables par automesh. La fonction à envelopper est `ml_token_generate` +
  `_code_invitation` (`secubox-p2p/api/main.py`).
- **Flash** : `sbx-netflash` (dans le live) vérifie la signature puis `exec secubox-flash-emmc`, qui écrit l'image et
  redémarre. Aucune étape ne monte la racine écrite (MOCHAbin : p1 boot vfat, **p2 racine ext4**, p3 data).
- **Identité de premier démarrage** : `secubox-premier-pas` lit `profil.toml` dans `/boot/secubox/` ; il fixe le nom
  (`hostnamectl`, `/etc/hosts`), le domaine (`[global] domain`, `[api] sso_cookie_domain` dans
  `/etc/secubox/secubox.conf`) et l'étape maillage (mode `automesh` : active `secubox-automesh.timer`).
- **Identité d'annuaire** : `annuairectl init` ne tourne qu'après la jonction (`secubox-annuaire-maillage`).
- **Découverte** : `secubox-annuaire-noms` publie `_secubox._tcp` (Avahi, TXT `boxname`, `node_id`, `mesh_ip`) ; le
  maître sait le parcourir (`discover_mdns` dans `secubox-p2p`), sans rien en faire pour l'association.
- **Après la jonction, déjà automatique** : routes `*.<domaine-du-pair>` par `secubox-relais-maillage synchroniser`
  (horaire, sur le maître) ; Flotte par l'annuaire (port 8799 sur l'adresse maillée).

## Conception

### D1. L'ancre de confiance

L'identité du maître, telle que la box la garde : **la clé publique WireGuard du maillage du maître**
(`wg_mesh.json` → `public_key`), son adresse de jonction (LAN), son nom et son empreinte p2p. Fichier sur la box :
`/etc/secubox/p2p/ancre-maitre.json`, root, 0644 (rien de secret).

`sbx-mesh-join` refuse la réponse d'un maître dont `master_public_key` diffère de l'ancre, et l'écrit au journal
d'audit. Le maître légitime le prouve ensuite par la poignée de main WireGuard : un faux maître qui recopierait la clé
publique ne peut pas terminer la poignée de main sans la clé privée. Un faux maître peut au pire consommer le jeton
(à usage unique) : la box échoue, le vrai maître voit un jeton déjà utilisé ; c'est un déni de service, pas une capture.

Une box sans ancre suit le chemin D5 ; elle n'accepte jamais un maître d'elle-même.

**Authenticité au flash (choix de Claude)** : le live est servi en HTTP clair ; un attaquant actif sur le LAN pourrait
substituer une fausse ancre. L'ancre et le code remis au live sont donc **signés avec la clé netboot du maître**, dont
le live embarque déjà la clé publique pour vérifier les images ; `sbx-netflash` refuse un lot dont la signature ne
vérifie pas, comme il refuse une image.

### D2. Le code d'invitation, émis par le maître pour un flash

Une CLI root sur le maître émet un code au format automesh (jeton de 64 hexadécimaux, `sbxmesh1.`, auto-approuvé),
lié au nom prévu de la box et à une durée de validité. Elle aligne `sbx-mesh-invite` sur ce format plutôt que d'en créer
une troisième variante.

**Comment le live obtient ce code — décision du propriétaire (2026-10-24) : génération automatique.** Pendant le flash,
`sbx-netflash` demande lui-même un code au maître ; le réseau local est considéré comme sûr pendant cette fenêtre de
netboot. Le maître n'émet que pour une demande venant du LAN, à destination d'un live qu'il sert, et chaque code est à
usage unique, lié au nom demandé (`--nom`), avec une durée courte. L'authenticité reste assurée par la signature netboot
de l'ancre et du code (D1) : un attaquant du LAN peut obtenir un code, pas faire accepter un faux maître.

### D3. Le flash dépose l'identité et la jonction dans le système écrit

`sbx-netflash` gagne `--nom <nom>`. Après l'écriture, il appelle `secubox-flash-emmc --no-reboot`, monte la racine
écrite (p2) et la partition de démarrage (p1), y dépose :
- `/var/lib/secubox/p2p/automesh.code` (le code, 0600 root) ;
- `/etc/secubox/p2p/ancre-maitre.json` (D1) ;
- `/boot/secubox/profil.toml` pour `secubox-premier-pas` : nom, domaine, mode maillage `automesh`.

puis démonte, journalise (sans le code) et redémarre. Un échec de dépôt laisse la box flashée mais non associée, et le
dit à la console ; il n'efface rien.

**Le domaine** : `<nom>.` suivi du domaine parent du maître (gk2 a `gk2.secubox.in`, donc gk1 reçoit
`gk1.secubox.in`). Le DNS public `*.<nom>.secubox.in` est déjà couvert par le joker `*.secubox.in` vers l'IP du maître ;
`secubox-relais-maillage` vérifie déjà la résolution avant de relayer.

### D4. Premier démarrage de la box flashée

`secubox-premier-pas` applique `profil.toml` (nom, domaine, active `secubox-automesh.timer`). Au passage suivant du
minuteur, `secubox-automesh` lit le code, `sbx-mesh-join` vérifie l'ancre (D1), le maître approuve (jeton
auto-approuvé), `sbx-mesh-up` monte `wg-mesh`, `secubox-annuaire-maillage` lance `annuairectl init`. Le code est
supprimé après approbation (déjà le cas). À la synchronisation horaire suivante, le maître relaie les noms de la box ;
la Flotte la récupère.

### D5. Box non flashée par le maître : « nouvel appareil », un clic

**Choix de Claude : bâtir sur le panneau maître de `secubox-premier-pas`**, qui existe déjà (`premier_pas/maitre.py`,
`www/premier-pas-maitre/`) : il découvre les box neuves du réseau et leur pousse un profil grâce au code court que la box
affiche sur son écran ou sa console. Ce code affiché sert de preuve : l'opérateur a la box sous les yeux, et la box
accepte l'ancre du maître qui le lui présente. Pas de troisième chemin d'association ; le panneau gagne l'étape
maillage (code d'invitation + ancre signée) et la page Maillage du maître y renvoie.

- **Le maître voit** les box neuves dans ce panneau : nom, adresse, modèle.
- **Le clic** : « Associer », avec le code affiché par la box. Le maître pousse profil, ancre et code d'invitation ; la
  jonction suit comme en D4.
- Une box neuve n'accepte jamais une ancre sans ce code affiché : un faux maître ne la capture pas.

### D6. Journal d'audit

Sur le maître : émission d'un code (nom prévu, durée, sans le code), préparation de flash, consommation, approbation,
refus. Sur la box : dépôt au flash, ancre écrite, offre reçue, acceptée ou refusée, jonction réussie, maître refusé
(clé différente de l'ancre).

### D7. Box déjà connue du maître (choix de Claude)

Un code émis par le maître pour un flash nommé `gk1` **remplace** l'entrée existante du même nom : nouvelle clé
WireGuard, même adresse maillée, ancienne clé retirée de `wg-mesh`, routes du relais conservées (même nom, même
adresse). C'est le maître lui-même qui a préparé ce flash ; refuser le doublon bloquerait tout reflash. Hors d'un code
de flash, un nom déjà pris est refusé, comme aujourd'hui.

### D8. Rattrapage des box déjà associées (décision du propriétaire)

Les box entrées dans le maillage avant ce mécanisme (gk1, jointe à la main le 2026-10-24 ; gk3) n'ont pas d'ancre. Le
maître la leur remet par le tunnel déjà établi (la box vérifie que la clé proposée est celle de son pair maître actuel
dans `wg-mesh`), sans rejoindre ni rebond du tunnel. Ensuite elles se comportent comme une box flashée : n'acceptent que
ce maître.

## Contraintes

- Règles du dépôt (`AGENTS.md`, `.claude/RULES-CODE.md`) : nftables DEFAULT DROP, aucun secret dans le code ni les TOML
  versionnés, CLI root confinées, utilisateur dédié pour les services, version montée et paquet déployé.
- Le port 7331 du maître reste limité au LAN et au maillage (`nginx/p2p-masterlink.conf`).
- La jonction actuelle (code déposé à la main, Auto-Load) continue de fonctionner ; une box déjà associée n'est pas
  touchée. Une box associée sans ancre (gk3, c3box…) en reçoit une, sans rebond du tunnel, lors d'une mise à jour.
- Banc de validation : gk1 (MOCHAbin 8 Go), reflashée par le live de gk2.

## Laissé au constructeur

- Noms des CLI, formats exacts des fichiers, durée de validité du code (au moins 24 h après le flash, puisque
  `automesh` jette un code déposé depuis plus de 24 h).
- Comment la box signale « sans maître » dans son annonce mDNS.
- Mise en forme de la page Maillage et de l'écran d'acceptation (charte `.claude/WEBUI-PANEL-GUIDELINES.md`).
- Découpage en paquets (`secubox-p2p`, `secubox-netboot`, `secubox-premier-pas`) et ordre des livraisons.

## Décisions sur les questions ouvertes

Toutes tranchées le 2026-10-24 :
- **Q1** (D2) : génération automatique pendant le netboot, réseau local de confiance pendant cette fenêtre.
- **Q2** (D3) : le mot de passe administrateur de la box flashée est choisi dans un formulaire « Préparer un flash »
  sur le maître (nom de la box + mot de passe) ; sans préparation, `sbx-netflash` le demande à la console.
- **Rattrapage** (D8) : les box déjà associées reçoivent l'ancre par le tunnel.
