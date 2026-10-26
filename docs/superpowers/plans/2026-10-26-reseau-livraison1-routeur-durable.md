<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Réseau, livraison 1 : `lo` /32 et mode routeur durable MOCHAbin — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** rendre le LAN des ports `lan0`…`lan3` d'un MOCHAbin durable (pont, DHCP, DNS, NAT, pare-feu), appliqué sans jamais
toucher le WAN, avec retour automatique sans confirmation, et corriger 192.168.255.1 en /32 sur `lo`.

**Architecture :** un contrôleur root `netmodesctl` (Python, stdlib) rend des fichiers systemd-networkd, dnsmasq, Unbound,
nftables et nginx depuis `/etc/secubox/netmodes/routeur.toml`, les applique de façon gardée (sauvegarde, validation,
bascule, minuteur de retour de 180 s) et n'adresse que `br-lan` et ses ports. L'API netmodes (utilisateur dédié, socket
dédiée) l'appelle par sudo à argv exact. `secubox-core` corrige `lo` ; `secubox-hub` ouvre sa géo nginx à un fragment ;
l'agrégateur relaie netmodes au lieu de le monter.

**Tech Stack :** Python 3.13 stdlib (`tomllib`, `ipaddress`, `fcntl`, `json`), FastAPI, bash (scripts existants),
systemd-networkd, dnsmasq-base, Unbound, nftables, nginx, pytest.

**Spec :** `docs/superpowers/specs/2026-10-26-reseau-routeur-switch-design.md` (sections 1 et 2, « Décisions du
propriétaire »). Livraisons 2 et 3 (panneau, isoler) : plans séparés, après déploiement de celle-ci.

## Global Constraints

- Aucune commande, aucun fichier généré ne nomme `eth0`, `eth1` ou `eth2` comme cible d'action ; seule exception :
  `oifname "<wan>"`/`iifname "<wan>"` en **lecture** dans les règles nft (NAT, transit). Jamais `netplan apply`, jamais
  réécriture de `/etc/netplan/*`, jamais `ip link set … down|up|mtu` sur `eth*`.
- Versions : `secubox-core 1.7.16-1~trixie1`, `secubox-netmodes 1.4.0-1~trixie1`, `secubox-hub 1.12.29-1~trixie1`,
  `secubox-aggregator 0.4.10-1~trixie1` ; `debian/compat` 13 ; `Standards-Version: 4.6.2` ; entrée de changelog datée
  `Mon, 26 Oct 2026`, auteur `Gérald Kerma <devel@cybermind.fr>`, `(ref #3189)`.
- En-tête SPDX CMSD-1.0 sur tout fichier créé (`scripts/license-headers.py`).
- Python : `subprocess.run([...], check=…, timeout=N, capture_output=True, text=True)`, jamais `shell=True` ; aucun
  `subprocess` ni `sudo` dans un `async def` (routes `def` ou `asyncio.to_thread`) ; pas d'`except Exception: pass`.
- Shell : `#!/usr/bin/env bash` + `set -euo pipefail` ; `debian/*` en `#!/bin/sh` POSIX (`sh -n`).
- Fichiers écrits : atomiques (temporaire dans le même dossier + `fsync` + `os.replace`), lien symbolique refusé
  (`O_NOFOLLOW`), modes : config 0644 pour networkd/nft/unbound/nginx (lus par leurs démons), TOML et état 0640.
- Audit : une ligne JSON par décision dans `/var/log/secubox/audit.log`, format
  `{"ts": "<RFC 3339 UTC>", "module": "netmodes", "action": "<action>", "acteur": "<acteur>", "detail": "<texte>"}`.
- Acteur : `^[A-Za-z0-9._@-]{1,64}$`, sinon refus ; « root » en console, « minuteur » pour le retour automatique,
  « demarrage » pour le retour au boot.
- Sous-réseau du LAN posé sur gk2 : `192.168.42.1/24`, DHCP `.100`–`.199`, bail `12h`, ports `lan0 lan1 lan2 lan3`,
  WAN `eth2`. Interdits : `192.168.255.0/24`, `10.100.0.0/24`, et tout réseau déjà porté par une autre interface.
- Minuteur de retour : 180 s, unité transitoire `secubox-netmodes-retour`. Verrou du contrôleur :
  `/run/lock/secubox-netmodes.lock` ; verrou Unbound partagé : `/run/lock/secubox-dns-lan.lock`.
- Python de test : `PY=/home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python` ; tests lancés par paquet
  (`cd packages/<paquet> && $PY -m pytest tests -q`).
- Commits `type: message (ref #3189)` terminés par `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Redémarrage pendant l'attente de confirmation** : le minuteur transitoire disparaît ; au démarrage, un état
   `en_attente` doit déclencher le retour (unité `secubox-netmodes-retour-boot`, tâche 4 et 7).
2. **Deux applications simultanées** (double clic, deux onglets) : la seconde échoue tout de suite, « occupé », sans rien
   écrire (verrou, tâche 4).
3. **TOML édité à la main et invalide** : `routeur-etat` répond `{"etat": "config_invalide", "erreur": …}` sans trace
   Python ; `routeur-appliquer` refuse (tâche 2 et 4).
4. **L'administrateur applique depuis le LAN un autre sous-réseau** : la réponse le prévient qu'il perdra la connexion et
   qu'il doit confirmer depuis la nouvelle adresse sous 3 minutes (tâche 5).
5. **192.168.255.1 retiré du pont alors que `lo` ne le porte pas en /32** : HAProxy :9443 et TURN perdraient leur adresse ;
   le contrôleur refuse avant toute écriture (tâche 4).

---

### Task 1 : `lo` en /32 (secubox-core)

**Files :**
- Create : `packages/secubox-core/usr/sbin/secubox-lo-alias`
- Modify : `packages/secubox-core/usr/bin/secubox-wait-network.sh` (bloc « Alias de bouclage », l. 96-109)
- Modify : `packages/secubox-core/debian/rules` (installer l'outil, comme `secubox-lxc-reseau`), `debian/postinst`
  (appel `/usr/sbin/secubox-lo-alias || true` dans `configure`), `debian/changelog` (1.7.16)
- Test : `packages/secubox-core/tests/test_lo_alias_3189.py`

**Interfaces :**
- Produces : `/usr/sbin/secubox-lo-alias` (bash, sans argument, code 0 toujours sauf erreur d'usage), surchargeable en
  test par `SECUBOX_LO_NETWORK` (défaut `/etc/systemd/network/00-lo.network`), `SECUBOX_AUDIT_LOG`, et `PATH` (faux `ip`).

- [ ] **Step 1 : tests en échec.** Un faux `ip` (script dans `tmp_path/bin`) tient l'état de `lo` dans un fichier et
  journalise chaque appel. Tests :
  - `test_24_devient_32_sans_fenetre` : état initial `192.168.255.1/24` → journal des appels = `addr add 192.168.255.1/32 dev lo`
    **avant** `addr del 192.168.255.1/24 dev lo` ; état final `/32` seul.
  - `test_absent_pose_32` : état vide → un seul `addr add 192.168.255.1/32 dev lo`.
  - `test_deja_32_ne_fait_rien` : état `/32` → aucun `add`/`del`, aucune ligne d'audit.
  - `test_fichier_networkd_corrige` : `00-lo.network` contenant `Address=192.168.255.1/24` → ligne remplacée par
    `Address=192.168.255.1/32`, copie `00-lo.network.avant-3189` à côté, `Address=127.0.0.1/8` intacte ; une ligne d'audit
    `{"module": "core", "action": "lo-alias-32", …}`.
  - `test_fichier_lien_symbolique_refuse` : `00-lo.network` lien symbolique → non modifié.
  - `test_wait_network_appelle_l_outil` : `secubox-wait-network.sh` contient `LOOPBACK_ALIAS="${SECUBOX_LOOPBACK_ALIAS:-192.168.255.1/32}"`
    et appelle `secubox-lo-alias` ; ne contient plus `ip addr add "$LOOPBACK_ALIAS"`.
- [ ] **Step 2 :** `cd packages/secubox-core && $PY -m pytest tests/test_lo_alias_3189.py -q` → FAIL (outil absent).
- [ ] **Step 3 :** écrire `secubox-lo-alias` (ordre : ajouter le /32 s'il manque, puis retirer le /24 ; correction du
  fichier par réécriture atomique ; audit) ; dans `secubox-wait-network.sh`, remplacer le bloc d'ajout par l'appel de
  l'outil (s'il est exécutable) et passer le défaut à /32 ; `rules`, `postinst`, changelog.
- [ ] **Step 4 :** relancer le test → PASS ; puis `$PY -m pytest tests -q` (suite du paquet) et `sh -n debian/postinst`.
- [ ] **Step 5 :** commit `fix(core): 192.168.255.1 en /32 sur lo, plus de réponse ARP pour tout le /24 (ref #3189)`.

### Task 2 : configuration du mode routeur (`api/routeur_config.py`)

**Files :**
- Create : `packages/secubox-netmodes/api/routeur_config.py`
- Test : `packages/secubox-netmodes/tests/test_routeur_config_3189.py`

**Interfaces :**
- Produces :
  - `PORTS_LAN: tuple[str, ...] = ("lan0", "lan1", "lan2", "lan3")`
  - `RESEAUX_INTERDITS: tuple[IPv4Network, ...]` = `192.168.255.0/24`, `10.100.0.0/24`
  - `class ErreurConfig(ValueError)`
  - `@dataclass(frozen=True) class ConfigRouteur: adresse: IPv4Interface; dhcp_debut: IPv4Address; dhcp_fin: IPv4Address;
    bail: str; ports: tuple[str, ...]; wan: str`
  - `depuis_dict(d: dict) -> ConfigRouteur` (clés : `adresse`, `dhcp_debut`, `dhcp_fin`, `bail`, `ports`, `wan` ; défauts
    `bail="12h"`, `ports=PORTS_LAN`, `wan="eth2"`) — lève `ErreurConfig` avec un message en français.
  - `charger(chemin: Path) -> ConfigRouteur` (TOML, table `[lan]` avec ces clés) ; `en_toml(cfg) -> str`.
  - `verifier_reseaux(cfg, occupes: Iterable[IPv4Network]) -> None` — lève `ErreurConfig` si le réseau du LAN chevauche un
    réseau occupé ou interdit.

- [ ] **Step 1 : tests en échec** (valeurs exactes) :
  - `depuis_dict({"adresse": "192.168.42.1/24", "dhcp_debut": "192.168.42.100", "dhcp_fin": "192.168.42.199"})` → `bail ==
    "12h"`, `ports == ("lan0","lan1","lan2","lan3")`, `wan == "eth2"`, `str(adresse.network) == "192.168.42.0/24"`.
  - refus (`pytest.raises(ErreurConfig)`) : adresse `192.168.255.1/24` ; `10.100.0.1/24` ; préfixe /31 et /32 ; adresse de
    réseau `192.168.42.0/24` ; plage hors du réseau ; `dhcp_debut > dhcp_fin` ; plage contenant l'adresse du pont ; port
    `eth1` ; port `lan4` ; port en double ; `ports` vide ; bail `"12x"`, `"0h"`, `"99999h"` ; `wan` hors motif `^eth[0-9]$` ;
    adresse IPv6.
  - `verifier_reseaux(cfg42, [IPv4Network("192.168.1.0/24")])` passe ; `verifier_reseaux(cfg42, [IPv4Network("192.168.0.0/16")])`
    lève.
  - aller-retour : `charger(fichier écrit par en_toml(cfg)) == cfg` ; `charger` sur un TOML cassé ou sans `[lan]` lève
    `ErreurConfig` (pas `TOMLDecodeError`).
- [ ] **Step 2 :** `cd packages/secubox-netmodes && $PY -m pytest tests/test_routeur_config_3189.py -q` → FAIL (module absent).
- [ ] **Step 3 :** implémenter (bail : motif `^[1-9][0-9]{0,3}[mh]$`).
- [ ] **Step 4 :** test → PASS.
- [ ] **Step 5 :** commit `feat(netmodes): configuration validée du mode routeur (ref #3189)`.

### Task 3 : rendu des fichiers (`api/routeur_rendu.py`)

**Files :**
- Create : `packages/secubox-netmodes/api/routeur_rendu.py`
- Test : `packages/secubox-netmodes/tests/test_routeur_rendu_3189.py`

**Interfaces :**
- Consumes : `ConfigRouteur` (tâche 2).
- Produces :
  - `MARQUE = "GÉNÉRÉ par secubox-netmodes"` (en tête de chaque fichier, en commentaire)
  - `CHEMINS: dict[str, str]` : `netdev` → `/etc/systemd/network/05-secubox-br-lan.netdev`, `pont` →
    `/etc/systemd/network/05-secubox-br-lan.network`, `ports` → `/etc/systemd/network/05-secubox-lan-ports.network`,
    `dhcp` → `/etc/secubox/netmodes/lan-dhcp.conf`, `unbound` → `/etc/unbound/unbound.conf.d/95-secubox-lan-routeur.conf`,
    `nft` → `/etc/nftables.d/zz-secubox-netmodes-lan.nft`, `geo` → `/etc/nginx/secubox-lan-geo.d/netmodes-lan.conf`
  - `COMMENTAIRE_NFT = "secubox netmodes lan"` (préfixe des commentaires des règles d'entrée)
  - `TABLE_NFT = "secubox_netmodes_lan"`
  - `rendre(cfg: ConfigRouteur) -> dict[str, str]` (clé = clé de `CHEMINS`, valeur = contenu)

- [ ] **Step 1 : tests en échec** sur `rendre(cfg42)` :
  - `netdev` : `Name=br-lan`, `Kind=bridge`, `STP=no`.
  - `pont` : `[Match]` `Name=br-lan` ; `Address=192.168.42.1/24` ; `ConfigureWithoutCarrier=yes` ; `IPv6AcceptRA=no`.
  - `ports` : `Name=lan0 lan1 lan2 lan3`, `Bridge=br-lan`.
  - **aucune** ligne `Name=` de `netdev`, `pont`, `ports` ne contient `eth` (test paramétré sur trois configurations).
  - `dhcp` : contient exactement les lignes `port=0`, `interface=br-lan`, `bind-interfaces`, `except-interface=lo`,
    `dhcp-authoritative`, `dhcp-range=192.168.42.100,192.168.42.199,255.255.255.0,12h`,
    `dhcp-option=option:router,192.168.42.1`, `dhcp-option=option:dns-server,192.168.42.1`,
    `dhcp-leasefile=/var/lib/misc/dnsmasq.leases`, `user=dnsmasq` ; ne contient ni `conf-dir` ni `no-ping`.
  - `unbound` : `server:`, `interface: 192.168.42.1`, `access-control: 192.168.42.0/24 allow`.
  - `nft` : trois lignes `add rule inet filter input iifname "br-lan" …` (udp 67, udp 53, tcp 53), chacune avec
    `comment "secubox netmodes lan <suffixe>"` ; puis `table inet secubox_netmodes_lan` créée, supprimée et redéfinie
    (idiome `table …` / `delete table …` / `table … { … }`) avec une chaîne `forward` (hook forward, `policy accept`) :
    `iifname "eth2" oifname "br-lan" ct state established,related accept` puis
    `iifname "eth2" oifname "br-lan" drop`, et une chaîne `postrouting` (type nat, hook postrouting, priority srcnat) :
    `ip saddr 192.168.42.0/24 oifname "eth2" masquerade`.
  - `geo` : une ligne `192.168.42.0/24 1;`.
  - chaque contenu commence par un commentaire contenant `MARQUE`.
  - `test_nft_valide` : si `shutil.which("nft")` et droits suffisants, `nft -c -f` sur un fichier qui définit d'abord
    `table inet filter { chain input { type filter hook input priority filter; policy drop; } }` puis le contenu → code 0 ;
    sinon `pytest.skip`.
- [ ] **Step 2 :** `$PY -m pytest tests/test_routeur_rendu_3189.py -q` → FAIL.
- [ ] **Step 3 :** implémenter (gabarits en chaînes, aucune dépendance).
- [ ] **Step 4 :** test → PASS.
- [ ] **Step 5 :** commit `feat(netmodes): rendu networkd, dnsmasq, Unbound, nft et géo du mode routeur (ref #3189)`.

### Task 4 : contrôleur `netmodesctl` (`api/routeur_ctl.py` + `sbin/netmodesctl`)

**Files :**
- Create : `packages/secubox-netmodes/api/routeur_ctl.py`, `packages/secubox-netmodes/sbin/netmodesctl`
- Test : `packages/secubox-netmodes/tests/test_routeur_ctl_3189.py`

**Interfaces :**
- Consumes : tâches 2 et 3.
- Produces :
  - `class Occupe(RuntimeError)`, `class Refus(RuntimeError)` (message français destiné à l'administrateur)
  - `@dataclass class Contexte: racine: Path; executer: Callable[[list[str]], subprocess.CompletedProcess]; maintenant:
    Callable[[], datetime]` — `racine` préfixe **tout** chemin absolu (`/` en production) ; `executer` lance toute commande
    externe (faux en test).
  - `appliquer(ctx, cfg_dict: dict, acteur: str) -> dict`, `confirmer(ctx, acteur) -> dict`, `retour(ctx, acteur) -> dict`,
    `etat(ctx) -> dict`, `retour_si_en_attente(ctx) -> dict`
  - État : `<racine>/var/lib/secubox/netmodes/routeur-etat.json` = `{"etat": "inactif"|"en_attente"|"actif"|"config_invalide",
    "depuis": RFC 3339, "acteur": str, "sauvegarde": str|null}` ; `etat()` y ajoute `"config"` (dict ou null),
    `"minuteur_actif"` (bool), `"dhcp_actif"` (bool), `"adresses_pont"` (list[str]), `"erreur"` si `config_invalide`.
  - Sauvegardes : `<racine>/var/lib/secubox/netmodes-backup/routeur/<AAAAMMJJTHHMMSSZ>/` = copie des fichiers de `CHEMINS`,
    de `routeur.toml` et de `/etc/systemd/network/10-br-lan.network` présents, plus `absents.json` (chemins absents) ;
    4 plus récentes gardées.
  - `sbin/netmodesctl <verbe> [acteur]` : verbes `routeur-etat`, `routeur-appliquer <acteur>` (config JSON sur stdin),
    `routeur-confirmer <acteur>`, `routeur-retour <acteur>`, `routeur-retour-demarrage` ; sortie JSON sur stdout ; codes :
    0 succès, 2 usage/acteur invalide, 3 `Refus`/`ErreurConfig`, 4 `Occupe`, 1 autre échec. Doit tourner en root ; ajoute
    `/usr/lib/secubox/netmodes` à `sys.path` et importe `api.routeur_ctl`.

`appliquer`, dans cet ordre (chaque étape testée sur l'ordre des commandes du faux `executer`) :
1. verrou `flock` non bloquant sur `/run/lock/secubox-netmodes.lock`, sinon `Occupe` ;
2. `depuis_dict` + `verifier_reseaux` (réseaux occupés = `ip -j -4 addr` de toutes les interfaces sauf `br-lan` et `lo`) ;
3. refus (`Refus`, rien d'écrit) : un `/etc/netplan/*.yaml` déclare `bridges: br-lan` (lecture YAML, `yaml.safe_load`) ;
   `systemctl is-active --quiet pseudo-routeur-sonde.timer` réussit ; `/proc/sys/net/ipv4/ip_forward` ≠ `1` ;
   `systemctl is-active --quiet dnsmasq.service` réussit (il écrirait le même fichier de baux) ; `br-lan` porte
   192.168.255.1 alors que `lo` ne porte pas `192.168.255.1/32` ;
4. sauvegarde ;
5. écriture de tous les fichiers de `rendre(cfg)` (sauf `geo` si `/etc/nginx/secubox-lan-geo.d` n'existe pas), de
   `routeur.toml` ; retrait de `/etc/systemd/network/10-br-lan.network` s'il porte `Name=br-lan` (il est dans la sauvegarde) ;
6. validation : `nft -c -f <fichier nft>` ; sous le verrou Unbound, `unbound-checkconf` ; `nginx -t` si `geo` écrit — un
   échec ⇒ restauration de la sauvegarde, audit `appliquer-echec`, `Refus` ;
7. `networkctl reload` puis `networkctl reconfigure br-lan <ports>` ;
8. reprise du LAN temporaire : `systemctl stop sbx-lan-dhcp.service` s'il est actif ; si `/var/lib/misc/dnsmasq.leases`
   est absent ou vide, copie de `/run/sbx-lan-dhcp-*.leases` ; suppression par handle (`nft -j -a list chain inet filter
   input`) des règles dont le commentaire commence par `sbx-lan-temporaire` ; `ip addr del` de chaque IPv4 de `br-lan`
   différente de `cfg.adresse` ;
9. suppression par handle des règles d'entrée au commentaire `secubox netmodes lan*`, puis `nft -f <fichier nft>` ;
10. sous le verrou Unbound : `systemctl restart unbound.service` ;
11. `systemctl enable secubox-lan-dhcp.service` puis `systemctl restart secubox-lan-dhcp.service` ;
12. `systemctl reload nginx.service` si `geo` écrit ;
13. `systemd-run --unit=secubox-netmodes-retour --on-active=180 --description=… /usr/sbin/netmodesctl routeur-retour minuteur`
    (après `systemctl stop secubox-netmodes-retour.timer` s'il existait) ; état `en_attente` ; audit `appliquer`.
Un échec aux étapes 7 à 12 ⇒ `retour` immédiat (acteur « echec »), audit, exception.

`retour` : restaure la dernière sauvegarde (écrit les fichiers sauvegardés, supprime ceux de `absents.json`), puis
`networkctl reload` + `networkctl reconfigure br-lan <ports>` si un `.network` de `br-lan` subsiste, sinon
`ip link delete br-lan` ; règles d'entrée retirées par handle puis `nft -f` du fichier restauré s'il existe, sinon
`nft delete table inet secubox_netmodes_lan` ; Unbound redémarré sous verrou ; `secubox-lan-dhcp` redémarré si
`lan-dhcp.conf` subsiste, sinon `systemctl disable --now` ; nginx rechargé ; arrêt du minuteur ; état `actif` si la
sauvegarde contenait un `routeur.toml`, sinon `inactif` ; audit `retour`.
`confirmer` : refuse (`Refus`) hors `en_attente` ; `systemctl stop secubox-netmodes-retour.timer` ; état `actif` ; audit.
`retour_si_en_attente` : `retour(ctx, "demarrage")` si l'état est `en_attente`, sinon `{"etat": …}` inchangé.

- [ ] **Step 1 : tests en échec** (racine `tmp_path`, faux `executer` qui journalise et renvoie des sorties préparées) :
  - `test_ordre_des_etapes` : liste des commandes d'un `appliquer` réussi == ordre ci-dessus (préfixes de commande).
  - `test_aucune_commande_ne_nomme_eth` : aucune commande journalisée ne contient un argument `eth0|eth1|eth2`, sauf
    `nft -c -f`/`nft -f` (fichier) — vérifié sur appliquer, retour, confirmer.
  - `test_refus_netplan_declare_br_lan`, `test_refus_pseudo_routeur_actif`, `test_refus_ip_forward_0`,
    `test_refus_dnsmasq_service_actif`, `test_refus_255_sans_lo_32` : `Refus`, aucun fichier écrit, aucune sauvegarde.
  - `test_occupe` : verrou tenu par un autre descripteur → `Occupe`, rien d'écrit.
  - `test_validation_nft_echoue_restaure` : `nft -c` renvoie 1 → fichiers d'avant restaurés, audit `appliquer-echec`.
  - `test_reprise_lan_temporaire` : règles `sbx-lan-temporaire-dhcp`/`-ping` supprimées par leur handle, `ip addr del
    192.168.255.1/24 dev br-lan`, baux copiés.
  - `test_idempotent` : deux `appliquer` + `confirmer` successifs → au second, suppression par handle des règles
    `secubox netmodes lan*` avant `nft -f`.
  - `test_minuteur_puis_confirmer` : `systemd-run … --on-active=180 … routeur-retour minuteur` ; `confirmer` arrête
    `secubox-netmodes-retour.timer`, état `actif`.
  - `test_retour_premiere_application` : sauvegarde sans `routeur.toml` → fichiers supprimés, `ip link delete br-lan`,
    `nft delete table inet secubox_netmodes_lan`, `systemctl disable --now secubox-lan-dhcp.service`, état `inactif`.
  - `test_retour_si_en_attente` : état `en_attente` → retour avec acteur `demarrage` ; état `actif` → rien.
  - `test_etat_config_invalide` : `routeur.toml` illisible → `etat()["etat"] == "config_invalide"` et `"erreur"` présent.
  - `test_quatre_sauvegardes` : cinq applications → quatre dossiers.
  - `test_audit_format` : chaque ligne écrite est un JSON avec `ts`, `module == "netmodes"`, `action`, `acteur`, `detail`.
  - `test_cli_acteur_invalide` : `netmodesctl routeur-confirmer "a b"` → code 2 (exécuté avec `racine` de test via import,
    pas par variable d'environnement).
- [ ] **Step 2 :** `$PY -m pytest tests/test_routeur_ctl_3189.py -q` → FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** test → PASS, puis la suite du paquet.
- [ ] **Step 5 :** commit `feat(netmodes): netmodesctl, mode routeur appliqué sous garde avec retour automatique (ref #3189)`.

### Task 5 : routes de l'API et garde des anciens chemins

**Files :**
- Create : `packages/secubox-netmodes/api/routeur_api.py` (`APIRouter(prefix="/routeur")`), inclus par `api/main.py`
- Modify : `packages/secubox-netmodes/api/main.py` (`apply_mode`, `auto_apply`, `rollback` : 409 sur MOCHAbin ;
  `STATE_FILE` → `/var/lib/secubox/netmodes/state.json`)
- Test : `packages/secubox-netmodes/tests/test_routeur_api_3189.py`

**Interfaces :**
- Consumes : `netmodesctl` (tâche 4) par `sudo -n /usr/sbin/netmodesctl <verbe> [acteur]` (JSON sur stdin pour
  `routeur-appliquer`), appelé dans une route `def` ; `rendre` et `depuis_dict` (aperçu sans sudo).
- Produces :
  - `GET /routeur/etat` (`require_lecture`) → JSON de `routeur-etat`.
  - `POST /routeur/apercu` (`require_jwt`), corps = config → `{"fichiers": rendre(cfg)}` ou 400.
  - `POST /routeur/appliquer` (`require_jwt`), corps = config + `"confirmer": "routeur"` → état ; ajoute
    `"avertissement"` si l'adresse du client est dans le réseau actuel de `br-lan` et que le nouveau réseau diffère.
  - `POST /routeur/confirmer` (`require_jwt`) ; `POST /routeur/retour` (`require_jwt`, corps `"confirmer": "retour"`).
  - Codes : sortie 3 du contrôleur → 409 avec son message ; 4 → 409 « une application est déjà en cours » ; 2 → 400 ;
    autre → 502 avec le message. Acteur = `sub` du jeton.
  - `est_mochabin() -> bool` (modèle du device tree contenant `MOCHAbin`, `mochabin` ou `7040`, comme `detect_board`).

- [ ] **Step 1 : tests en échec** (TestClient, `require_jwt`/`require_lecture` surchargés, `subprocess.run` simulé) :
  - `test_appliquer_sans_mot_de_confirmation_400`, `test_appliquer_transmet_json_et_acteur` (argv exact
    `["sudo", "-n", "/usr/sbin/netmodesctl", "routeur-appliquer", "<sub>"]`, stdin = JSON de la config),
    `test_refus_controleur_409`, `test_occupe_409`, `test_avertissement_depuis_le_lan`.
  - `test_anciens_chemins_409_sur_mochabin` : `apply_mode`, `auto_apply`, `rollback` → 409 quand `est_mochabin()`, message
    contenant « WAN » ; inchangés sinon.
  - `test_routes_mutantes_gardees` : toute route `POST` de `routeur_api` porte `require_jwt`.
  - `test_pas_de_subprocess_dans_async` : aucune fonction `async def` de `routeur_api.py` n'appelle `subprocess` (AST).
- [ ] **Step 2 :** `$PY -m pytest tests/test_routeur_api_3189.py -q` → FAIL.
- [ ] **Step 3 :** implémenter ; brancher le routeur dans `main.py`.
- [ ] **Step 4 :** test → PASS, puis la suite du paquet.
- [ ] **Step 5 :** commit `feat(netmodes): API du mode routeur, anciens chemins netplan refusés sur MOCHAbin (ref #3189)`.

### Task 6 : `secubox-net-detect` sur MOCHAbin

**Files :**
- Modify : `packages/secubox-netmodes/sbin/secubox-net-detect` (`generate_netplan`, branche `apply` de `main`)
- Test : `packages/secubox-netmodes/tests/test_net_detect_routeur_3189.py` (même technique que
  `test_ports_mochabin_3101.py` : script chargé sans `main "$@"`)

- [ ] **Step 1 : tests en échec** :
  - `test_mochabin_routeur_sans_br_lan` : `generate_netplan mochabin eth2 "lan0 lan1 lan2 lan3" eth0 router` (avec
    `NETPLAN_DIR` pointé sur `tmp_path`) → fichier sans `br-lan`, avec `br-lxc`.
  - `test_autres_cartes_inchangees` : `espressobin` garde `br-lan`.
  - `test_wan_configure_ni_reecriture_ni_apply` : faux `ip` qui rend une IPv4 sur `eth2`, faux `netplan` qui journalise ;
    `main apply router` sur MOCHAbin → aucun fichier écrit, `netplan` jamais appelé, message qui l'explique.
  - `test_wan_sans_adresse_comportement_actuel` : sans IPv4 sur `eth2` → fichier écrit et `netplan apply` appelé.
- [ ] **Step 2 :** `$PY -m pytest tests/test_net_detect_routeur_3189.py -q` → FAIL.
- [ ] **Step 3 :** implémenter (détection de carte par une fonction surchargeable en test, comme `detect_board`).
- [ ] **Step 4 :** test → PASS, suite du paquet.
- [ ] **Step 5 :** commit `fix(netmodes): net-detect ne relance plus le WAN d'un MOCHAbin configuré (ref #3189)`.

### Task 7 : paquetage de netmodes

**Files :**
- Modify : `packages/secubox-netmodes/debian/secubox-netmodes.service`, `debian/rules`, `debian/control`,
  `debian/postinst`, `debian/prerm`, `debian/changelog` (1.4.0), `README.md`
- Create : `debian/secubox-lan-dhcp.service`, `debian/secubox-netmodes-retour-boot.service`,
  `debian/secubox-netmodes.sudoers`, `apparmor/secubox-netmodes` (profil `secubox-netmodes-api`),
  `apparmor/secubox-lan-dhcp` (profil `secubox-lan-dhcp`)
- Modify : `.claude/RULES-CODE.md` (ligne d'exception § 10 : `secubox-netmodes.service` `NoNewPrivileges=no`, seule
  surface privilégiée `netmodesctl` à verbes exacts, `ReadWritePaths` élargi parce que le contrôleur hérite de l'espace de
  montage de l'unité ; test qui la fige)
- Test : `packages/secubox-netmodes/tests/test_paquet_3189.py`

**Valeurs :**
- API : `User=secubox-netmodes`, `Group=secubox`, `UMask=0027`, `NoNewPrivileges=no`, `ProtectSystem=strict`,
  `ReadWritePaths=/run/secubox /run/lock /var/lib/secubox/netmodes /var/lib/secubox/netmodes-backup /var/log/secubox
  /etc/systemd/network /etc/secubox/netmodes /etc/unbound/unbound.conf.d /etc/nftables.d /etc/nginx/secubox-lan-geo.d
  /var/lib/misc`, `ProtectHome=yes`, `PrivateTmp=yes`, `ProtectKernelTunables=yes`, `ProtectControlGroups=yes`,
  `LockPersonality=yes`, `AppArmorProfile=secubox-netmodes-api`, plus d'`AmbientCapabilities` ; socket chmod 660 en
  `ExecStartPost` (modèle `secubox-pseudo-routeur.service`). `RestrictSUIDSGID` absent (neutraliserait sudo).
- `secubox-lan-dhcp.service` : `ExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/etc/secubox/netmodes/lan-dhcp.conf
  --pid-file=`, `After=systemd-networkd.service`, `Restart=on-failure`, `ProtectSystem=strict`,
  `ReadWritePaths=/var/lib/misc`, `ProtectHome=yes`, `PrivateTmp=yes`, `ProtectKernelTunables=yes`,
  `ProtectControlGroups=yes`, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETUID CAP_SETGID
  CAP_CHOWN`, `AppArmorProfile=secubox-lan-dhcp` ; ni activé ni démarré par le paquet.
- `secubox-netmodes-retour-boot.service` : oneshot, `After=network-online.target`, `ExecStart=/usr/sbin/netmodesctl
  routeur-retour-demarrage`, activé par le paquet.
- sudoers (`/etc/sudoers.d/secubox-netmodes`, 0440) : `secubox-netmodes ALL=(root) NOPASSWD: /usr/sbin/netmodesctl
  routeur-etat, /usr/sbin/netmodesctl routeur-appliquer *, /usr/sbin/netmodesctl routeur-confirmer *, /usr/sbin/netmodesctl
  routeur-retour *`.
- `control` : `Depends` ajoute `python3 (>= 3.11)`, `python3-yaml`, `dnsmasq-base`, `nftables`, `sudo`, `apparmor`.
- `postinst` : utilisateur système `secubox-netmodes` (groupe `secubox`) ; `/var/lib/secubox/netmodes` 0750
  `secubox-netmodes:secubox` ; déplace `/var/lib/secubox/netmodes-state.json` vers `…/netmodes/state.json` s'il existe ;
  `visudo -cf` du sudoers ; `apparmor_parser -r` des deux profils (message clair si échec, modèle `secubox-meet`) ;
  `systemctl enable secubox-netmodes-retour-boot.service` ; redémarre l'API.
- `prerm` : `systemctl stop secubox-netmodes.service` (le LAN, lui, reste en place).

- [ ] **Step 1 : tests en échec** (`test_paquet_3189.py`) : valeurs ci-dessus lues dans les fichiers (unités, sudoers
  ligne exacte, `Depends`), `sh -n` des scripts `debian/*`, profils AppArmor contenant `/usr/bin/sudo Ux` (API) et
  `/etc/secubox/netmodes/lan-dhcp.conf r` + `/var/lib/misc/dnsmasq.leases* rw` (dnsmasq), `rules` installe `netmodesctl` en
  0755, les deux unités, le sudoers en 0440, les profils ; exception écrite dans `RULES-CODE.md` avec le nom de ce test.
- [ ] **Step 2 :** `$PY -m pytest tests/test_paquet_3189.py -q` → FAIL.
- [ ] **Step 3 :** écrire les fichiers ; `dpkg-buildpackage -d -us -uc -b` dans le paquet → `.deb` construit ; `lintian`
  sans erreur nouvelle.
- [ ] **Step 4 :** suite du paquet → PASS.
- [ ] **Step 5 :** commit `feat(netmodes): 1.4.0, utilisateur dédié, contrôleur sudo, DHCP du LAN, retour au démarrage (ref #3189)`.

### Task 8 : géo nginx de confiance (secubox-hub)

**Files :**
- Modify : `packages/secubox-hub/nginx/secubox-lan-geo.conf` (dans le bloc `geo $lan_client`, ligne
  `include /etc/nginx/secubox-lan-geo.d/*.conf;` après les plages fixes, commentée), `debian/postinst` (crée
  `/etc/nginx/secubox-lan-geo.d` 0755), `debian/changelog` (1.12.29)
- Test : `packages/secubox-hub/tests/test_geo_fragments_3189.py`

- [ ] **Step 1 : tests en échec** : l'`include` est à l'intérieur du bloc `geo $lan_client { … }` ; le postinst crée le
  dossier ; si `nginx` est présent localement, `nginx -t -c` sur un fichier minimal incluant la géo et un fragment
  `192.168.42.0/24 1;` → 0, sinon `skip`.
- [ ] **Step 2 :** test → FAIL. **Step 3 :** implémenter. **Step 4 :** test → PASS, suite du paquet.
- [ ] **Step 5 :** commit `feat(hub): la géo du LAN accepte des fragments, LAN du mode routeur de confiance (ref #3189)`.

### Task 9 : netmodes à socket dédiée (secubox-aggregator)

**Files :**
- Modify : `packages/secubox-aggregator/aggregator/main.py` (`DEDICATED_MODULES` + commentaire « #3189 : netmodes appelle
  netmodesctl par sudo, impossible sous l'utilisateur de l'agrégateur »), `sbin/secubox-aggregator-migrate`
  (`AGG_EXCLUDE`), `debian/changelog` (0.4.10)
- Test : `packages/secubox-aggregator/tests/test_socket_dediee_netmodes_3189.py`

- [ ] **Step 1 : test en échec** : `"netmodes" in ag.DEDICATED_MODULES`, absent de `RETIRED_MODULES`, présent dans
  `AGG_EXCLUDE` du script de migration (lecture du fichier).
- [ ] **Step 2 :** FAIL. **Step 3 :** implémenter. **Step 4 :** PASS + suite du paquet.
- [ ] **Step 5 :** commit `fix(aggregator): netmodes relayé vers sa socket (ref #3189)`.

### Task 10 : déploiement sur gk2 et reprise du LAN temporaire

Pas de code ; chaque vérification lue, pas supposée. Aucune commande vers `eth2`.

- [ ] **Step 1 :** `df -h /` sur gk2 (> 1 Go libre) ; construire les quatre paquets ; `scripts/apt-publier.sh <deb>` pour
  chacun.
- [ ] **Step 2 :** sur gk2, `systemd-run --wait --pipe --collect --unit=sbx-maj-3189 env DEBIAN_FRONTEND=noninteractive
  apt-get install -y --only-upgrade -o Dpkg::Options::=--force-confold secubox-core secubox-netmodes secubox-hub
  secubox-aggregator` (sans délai). Attendre `/health` = 200 de l'agrégateur.
- [ ] **Step 3 :** vérifier : `ip -4 addr show lo` → `192.168.255.1/32` seul ; `00-lo.network` en /32 ;
  `ss -ltn` montre encore `192.168.255.1:9443` ; `systemctl is-active secubox-netmodes` ; `curl` de
  `/api/v1/netmodes/routeur/etat` par le chemin public → 200 ; aucun refus AppArmor (`journalctl -k | grep -i apparmor`).
- [ ] **Step 4 :** appliquer en console : `printf '%s' '{"adresse":"192.168.42.1/24","dhcp_debut":"192.168.42.100",
  "dhcp_fin":"192.168.42.199"}' | netmodesctl routeur-appliquer root` ; vérifier `br-lan` = `192.168.42.1/24` seul,
  `secubox-lan-dhcp` actif, baux du PC présents, règles `sbx-lan-temporaire-*` absentes, `dig @192.168.42.1 secubox.in`
  répond, `nft list table inet secubox_netmodes_lan` présent ; puis `netmodesctl routeur-confirmer root`.
- [ ] **Step 5 :** essai du retour automatique : réappliquer avec `"bail": "6h"`, ne pas confirmer, attendre 200 s →
  `lan-dhcp.conf` revenu à `12h`, état `actif`, ligne d'audit `retour` d'acteur `minuteur`.
- [ ] **Step 6 :** demander au propriétaire le moment d'un redémarrage de gk2 pour prouver la persistance ; après
  redémarrage, mêmes vérifications qu'aux étapes 3 et 4.
- [ ] **Step 7 :** suivi : `.claude/HISTORY.md` (entrée datée), `.claude/WIP.md`, README de netmodes ; PR par
  `scripts/agent-worktree.sh finish`, fusion ; `closes #3189` une fois l'étape 6 faite.
