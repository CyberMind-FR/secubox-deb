<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# RULES-CODE — règles permanentes de code

S'appliquent à **tout code nouveau ou modifié**, dès la ligne touchée. **Aucune correction de masse** :
on ne réécrit pas l'existant pour s'y conformer ; on ne l'aggrave pas, et on corrige ce qu'on modifie.
Complète `MODULE-COMPLIANCE.md` (conformité d'un module) et `PATTERNS.md` (patterns). Le
sous-agent `relecteur-securite` relit un diff contre ce fichier. Un écart voulu s'écrit en
**exception**, dans ce fichier, avec sa raison et son test (voir § Exceptions).

## 1. Archives : extraction par helper validé

- Jamais `tarfile.extractall` / `zipfile.extractall` nu. Extraire par un helper qui **résout chaque
  entrée** et refuse tout ce qui sort du répertoire cible (`..`, chemin absolu, lien symbolique
  sortant, périphérique), puis plafonne le nombre d'entrées et la taille décompressée.
- Modèle : `_extract_archive` de `packages/secubox-publish/api/main.py` et son test
  `packages/secubox-publish/tests/test_publication_1823.py` (#1823, « archive tar confinée »).
- Un nouvel appelant **réutilise** ce helper ; il n'en écrit pas un second.

## 2. Permissions

- Pas de `0o666`, pas de `0o777`, pas de `chmod 666|777|a+w|o+w`, pas de `os.umask(0)`.
  Fichiers de config `0640`, secrets `0600`, répertoires `0750` ; un répertoire partagé reste `0755`
  (ne jamais resserrer un parent traversé par d'autres modules).
- Unités systemd : `UMask=0027` (au pire `0002`), jamais `0000` (#1416).
- Sockets Unix : sous `/run/secubox/<module>.sock`, propriétaire le service, groupe `secubox`,
  mode `0660`. L'unité porte `ExecStartPre=+/bin/rm -f /run/secubox/<module>.sock` ; **jamais**
  `RuntimeDirectory=secubox` ni `chown` du parent `/run/secubox` (voir `MODULE-COMPLIANCE.md`, § Socket).

## 3. API : toute route mutante porte une garde

- `POST|PUT|PATCH|DELETE` : `Depends(require_jwt)` (administrateur réel). `require_session` ou
  `require_personne` seulement sur une route d'**usager**, posés explicitement. Lecture :
  `require_lecture`. Jamais une route mutante sans garde « parce qu'elle est en LAN ».
- Le rôle vient du jeton vérifié côté serveur, jamais d'un en-tête, d'un paramètre ou du corps.
- Routes sous `sudo`/`ctl` : arguments validés par liste blanche ou motif entier avant l'appel.

## 4. TLS

- Pas de `verify=False`, pas de `ssl._create_unverified_context`, pas de `CERT_NONE`, pas de
  `curl -k` dans du code livré. Un service interne se vérifie avec la **CA interne** de la box
  (`verify="<chemin de la CA>"`, ex. `/usr/share/secubox/egress-ca.pem`) ; TLS 1.3 minimum côté frontal.

## 5. XML externe

- Tout XML qui ne vient pas de nous (flux, uploads, réponses distantes) se lit avec `defusedxml`
  (`defusedxml.ElementTree`), jamais `xml.etree` / `xml.dom` / `lxml` sans désactiver entités et DTD.

## 6. Async

- Dans un `async def` : ni `subprocess.*`, ni `time.sleep`, ni `requests`, ni lecture/écriture
  de fichier volumineuse, ni appel `sudo`. Utiliser `asyncio.create_subprocess_exec`, `httpx.AsyncClient`,
  `await asyncio.to_thread(...)` ou une route `def` simple (exécutée dans le pool).
- Un module servi par l'agrégateur partage **une seule boucle** : un appel bloquant la gèle pour tout le parc.

## 7. Erreurs et sous-processus

- Pas d'`except:` nu ; pas d'`except Exception: pass` — attraper l'exception précise, journaliser
  (`logger.exception` / `logger.warning` avec le motif), ou propager. Un échec silencieux est un bug.
- `subprocess.run([...], check=True, timeout=N, capture_output=True, text=True)` : liste d'arguments,
  `check` et `timeout` toujours présents. **Jamais `shell=True`**, jamais d'argument assemblé par f-string
  dans une commande shell.

## 8. Dates

- UTC avec fuseau : `datetime.now(timezone.utc)` ; sérialisation RFC 3339. Plus de `datetime.utcnow()`
  ni de `datetime.now()` sans fuseau pour un horodatage persistant.

## 9. Shell

- `#!/usr/bin/env bash` + `set -euo pipefail` ; variables entre guillemets ; `[[ ]]` ; `mktemp`.
- `trap` correctement quoté : `trap 'rm -f -- "$tmp"' EXIT` (apostrophes : l'expansion a lieu au
  déclenchement). Scripts `debian/*` en `#!/bin/sh` POSIX : `sh -n` doit passer.
- JSON par `jq`, jamais `grep`/`sed` ; `ss -tlnp`, `journalctl`, `systemctl` (pas de commandes OpenWrt).

## 10. systemd : socle de durcissement commun

Toute unité de service porte au minimum : `User=secubox-<module>` (jamais root, sauf exception),
`NoNewPrivileges=yes`, `ProtectSystem=strict` (ou `full` avec raison) + `ReadWritePaths=` explicite,
`ProtectHome=yes`, `PrivateTmp=yes`, `ProtectKernelTunables=yes`, `ProtectControlGroups=yes`,
`RestrictSUIDSGID=yes`, `LockPersonality=yes`, `UMask=0027`. Modèle : `packages/secubox-vault/debian/secubox-vault.service`.
Un `ReadWritePaths` n'est pas un lien symbolique vers un autre disque (le bac à sable le bloque en silence).

## Exceptions (explicites, listées)

Une exception n'existe que si elle est écrite ici avec sa raison et un test qui la fige.

| Règle | Exception | Raison | Test |
|---|---|---|---|
| § 3 garde | `POST /login`, `/login/mfa`, `/totp/confirm`, `/set-password` (secubox-auth) | portent leur propre preuve (mot de passe, défi, jeton à portée) | `packages/secubox-auth/tests/` |
| § 3 garde | `POST /compte/*`, `/personne/*` (secubox-vault, socket interne) | servent secubox-auth par la socket, refusent la marque du relais web | `packages/secubox-vault/tests/test_compte_1855.py`, `test_personne_connexion_1855.py` |
| § 10 durcissement | unités qui pilotent LXC ou nftables (`User=root` ou capacités) | accès conteneurs / pare-feu ; confinées par `ReadWritePaths`, sudoers exacts, AppArmor | revue au cas par cas |
| § 10 durcissement | `secubox-ad-guard-auto.service` (minuterie du mode auto : `NoNewPrivileges=no`, `User=secubox` partagé, `ReadWritePaths` élargi à `/etc/unbound/unbound.conf.d` et `/var/log/secubox`) | sudo est neutralisé par `NoNewPrivileges=yes`, et le contrôleur root lancé par sudo hérite de l'espace de montage de l'unité (sous `ProtectSystem=strict` sans ces chemins il échoue en lecture seule). La seule surface privilégiée est `secubox-adguard-tv regles-appliquer` (argv exact dans sudoers, état relu sans lien symbolique et revalidé, audit). `RestrictSUIDSGID` absent : il neutraliserait sudo. Dette nommée : utilisateur dédié + unité root sans sudo | `packages/secubox-ad-guard/tests/test_dnstv_revue_1954.py::test_c2_unite_autorise_les_chemins_du_controleur_et_porte_son_exception` |
| § 10 durcissement | `secubox-ad-guard-dnsdump.service` (instantané des réponses d'Unbound pour le capteur DNS, #2240 : `NoNewPrivileges=no`, `User=secubox` partagé) | sudo est neutralisé par `NoNewPrivileges=yes`. La seule surface privilégiée est `secubox-adguard-tv cache-dump` (argv exact dans le sudoers existant) : LECTURE SEULE du cache d'Unbound, sortie filtrée par expression stricte et adresses revalidées, root n'écrit rien (l'unité range elle-même le texte sous son compte). Le jugement est fait par `secubox-ad-guard-dnssensor.service`, entièrement durci (`NoNewPrivileges=yes`, `RestrictAddressFamilies=AF_UNIX`, aucun sudo). Même dette nommée que le mode auto : utilisateur dédié | `packages/secubox-ad-guard/tests/test_dnssensor_2240.py::test_sudoers_et_unite_de_collecte` |
| § 10 durcissement | unités d'API qui appellent un sudoers à argv EXACT (`secubox-voicestudio-api` : `NoNewPrivileges=no`, `User=secubox` partagé) | sudo est neutralisé par `NoNewPrivileges=yes` ; la seule surface privilégiée est `voicestudioctl api` (JSON sur stdin, actions en liste blanche, audit). Dette nommée : utilisateur dédié `secubox-voicestudio` + sudoers à son nom | `packages/secubox-voicestudio/tests/test_paquet_1917.py`, `test_api_1917.py::test_sudoers_et_argv_sont_identiques` |
| § 10 durcissement | `secubox-autoload.service` (`NoNewPrivileges=no`, `User=secubox-autoload`) | sudo est neutralisé par `NoNewPrivileges=yes` ; la seule surface privilégiée du module est UN argv exact (`autoloadctl tunnel-sync`, pairs WireGuard) accordé par `sudoers.d/secubox-autoload` ; les options qui imposent NoNewPrivileges par seccomp en sont absentes (précédent voicestudio) ; profil AppArmor enforce | `packages/secubox-autoload/tests/test_sync_2190.py` |
| § 10 durcissement | `secubox-webfilter-apply.service` (`User=root`, oneshot) | root est requis pour déposer la source de `secubox-dns-listes` (`/var/lib/secubox-dns-listes/sources`, arbre root hors de `/var/lib/secubox`) et lire puis rendre l'état 0700 du compte du service ; depuis #3205 il ne touche plus Unbound (ni `/etc/unbound`, ni `unbound-control`). Déclenché par FICHIER (`appliquer.demande` + `.path`, minuterie 04:00), jamais par sudo : l'API garde `NoNewPrivileges`. Confiné : `CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE`, `ReadWritePaths` exacts, aucun réseau IP (`RestrictAddressFamilies=AF_UNIX AF_NETLINK`, `IPAddressDeny=any`), `MemoryMax`. Entrée non fiable : dossier d'état ouvert sans suivre de lien et propriétaire vérifié, `config.json` plafonné et validé, listes relues par descripteur avec budget d'octets. AppArmor chargé sur gk2 depuis le noyau 6.12 (#3093) | `packages/secubox-webfilter/tests/test_paquet.py::test_service_du_controleur_est_root_deplenche_par_fichier_et_bac_a_sable` |
| § 10 durcissement | `secubox-netmodes.service` (API du mode routeur, #3189 : `NoNewPrivileges=no`, `KillMode=process`, `ReadWritePaths` élargi ; `User=secubox-netmodes` dédié) | sudo est neutralisé par `NoNewPrivileges=yes` et par toute option seccomp (`ProtectKernelTunables`, `LockPersonality`, `RestrictSUIDSGID` absents pour cette raison). La seule surface privilégiée est `netmodesctl` à verbes exacts (`routeur-etat` sans argument ; `routeur-appliquer`, `routeur-confirmer`, `routeur-retour` avec un seul acteur, revalidé ; `port-couper`, `port-retablir` avec un port de `lan0`..`lan3` en liste blanche puis un acteur, #3190 ; jamais `routeur-retour-demarrage`), audit JSON. Le contrôleur root lancé par sudo hérite de l'espace de montage de l'unité : `ReadWritePaths` couvre chaque dossier qu'il écrit (networkd, Unbound, nft, géo, baux, arbre root seul `/var/lib/secubox-netmodes`, audit) ; `nginx -t` passe par `systemd-run`, hors de cet espace. État des anciens modes en `StateDirectory=secubox-netmodes-api`, jamais sous `/var/lib/secubox` (compte partagé). `KillMode=process` : le contrôleur survit à un redémarrage de l'API en pleine bascule. Profil AppArmor `secubox-netmodes-api` enforce (sudo en `Ux`, aucun shell) | `packages/secubox-netmodes/tests/test_paquet_3189.py::test_unite_api_durcie_et_exception` |
| § 10 durcissement | `secubox-lan-dhcp.service` (DHCP du LAN du mode routeur, #3189 : démarre en root, sans `User=`) | dnsmasq démarre en root pour lier 67/udp et ses sockets brutes (sonde ICMP, ARP) et lire sa configuration dans l'arbre root seul `/var/lib/secubox-netmodes`, puis descend lui-même vers `user=dnsmasq`. Confiné par le profil AppArmor `secubox-lan-dhcp` (enforce, capacités égales à la borne de l'unité) et `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETUID CAP_SETGID CAP_CHOWN`, `NoNewPrivileges=yes`, `ProtectSystem=strict` avec `ReadWritePaths=/var/lib/misc` (baux) et le reste du socle. `UMask=0022` : les baux restent lisibles par le NAC. Ni activé ni démarré par le paquet | `packages/secubox-netmodes/tests/test_paquet_3189.py::test_unite_lan_dhcp_root_confinee` |
| § 10 durcissement | `secubox-netmodes-retour-boot.service` (oneshot root sans AppArmor, #3189) | exécute `netmodesctl routeur-retour-demarrage` : défaire au démarrage une application non confirmée demande root (networkd, nft, Unbound, DHCP), et le contrôleur vérifie lui-même son arbre root seul. Pas de sudo : `NoNewPrivileges=yes` et tout le socle § 10 sauf `User=`. Confiné par `ProtectSystem=strict` et les `ReadWritePaths` du contrôleur (même liste que `secubox-netmodes.service`). Ordonné avant `secubox-lan-dhcp.service`, sans attendre `network-online` : après un redémarrage, jamais de bail servi sur un sous-réseau non confirmé | `packages/secubox-netmodes/tests/test_paquet_3189.py::test_unite_retour_boot_root_durcie` |
| § 10 durcissement | `secubox-dns-listes.service` (#3205 : oneshot **root**, pas de compte dédié) | Il écrit `/etc/unbound/unbound.conf.d/92-secubox-listes.conf` (root), retire les trois anciens fichiers de listes et lance `unbound-checkconf` puis `unbound-control reload` (socket `/run/unbound.ctl` root:unbound). Socle appliqué : `NoNewPrivileges`, `ProtectSystem=strict` + `ReadWritePaths` exacts, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `ProtectKernel{Tunables,Modules,Logs}`, `ProtectControlGroups`, `RestrictSUIDSGID`, `RestrictNamespaces`, `RestrictRealtime`, `LockPersonality`, `SystemCallArchitectures=native`, `UMask=0027`, `CapabilityBoundingSet=CAP_DAC_OVERRIDE` (seule capacité : `audit.log` appartient à `secubox`, 0640), réseau boucle locale seulement (+ `AF_NETLINK` pour `unbound-checkconf`) ; profil AppArmor enforce `/usr/sbin/secubox-dns-listes` qui n'écrit que ses fichiers, sans shell ni sudo. Son arbre (`/var/lib/secubox-dns-listes`, sources, état, verrou 0600) est root et HORS de `/var/lib/secubox` (compte partagé) ; chaque écriture vérifie le dossier et son parent. Profil vérifié en enforce sur gk1 ; AppArmor chargé sur gk2 depuis le noyau 6.12 (#3093). Les générateurs (webfilter, adblock, adult) n'écrivent plus dans `/etc/unbound` : ils déposent leur source | `packages/secubox-core/tests/test_dns_listes_depot_3205.py::test_service_root_durci_et_exception_ecrite` |
| § 6 async | Montage progressif de l'agrégateur (#3216) : `_monter_progressivement` importe chaque module (`exec_module`, fichiers et code de niveau module) dans un `async def`, sur la boucle partagée | `_load_app_from_path` permute `sys.modules['api*']` et `sys.path` : un fil le ferait pendant que les requêtes importent, d'où le fil de la boucle. Avant, ces imports bloquaient tout avant l'écoute (4 à 8 min de 502). Bornes : un module à la fois, les essentiels d'abord, puis une pause au moins égale à la durée de l'import (50 ms à 2 s) pour servir les requêtes en attente ; un import de plus de 10 s peut encore faire expirer une sous-requête d'authentification nginx (`proxy_read_timeout`) | `packages/secubox-aggregator/tests/test_montage_progressif_3216.py::test_la_passerelle_repond_pendant_le_montage`, `::test_la_pause_suit_la_duree_de_l_import` |
| § 1 archives | `packages/secubox-streamlit/api/publication.py` (`_entrees_zip`, `_extraire`, verbe `deposer`, #3247) : second helper d'extraction, pas `_extract_archive` | Exécuté EN ROOT par `streamlitctl` en `python3 -I` (bibliothèque standard seule, vérifié par test) : il ne peut pas importer le helper de référence, qui vit dans un module FastAPI d'un autre paquet. Il valide TOUTES les entrées avant la première écriture (chemin absolu, `..`, lettre de lecteur, lien, FIFO, périphérique ; 10 000 entrées, 1 Gio déclaré puis réel), n'ouvre l'archive qu'en `O_NOFOLLOW` (fichier ordinaire de l'appelant), vérifie la place disque, écrit par descripteurs `O_EXCL\|O_NOFOLLOW` dans un brouillon `mkdir` aléatoire sous le dossier des applis (lui-même ouvert sans suivre de lien), puis met en place par renommage | `packages/secubox-streamlit/api/tests/test_securite_depot_3247.py::test_depot_refuse_une_entree_hostile` |
| § 10 durcissement | `sbx-autoflash.service` (#3233 : oneshot **root**, posé par `build-cle-finale.sh` sur la SEULE clé USB finale, jamais sur une box) | Il écrit le périphérique bloc de l'eMMC et monte la partition `SBXFLASH` de sa clé : ni compte dédié ni sudo possibles sur ce chemin. Ne part qu'avec `sbx_autoflash=1` (autoflash.scr tapé à la console U-Boot, aucun bootcmd ne le charge) ; annonce cible, contenu, image et empreinte sur la console série puis compte à rebours annulable (confirmation de l'opérateur) ; image prise sur son propre disque, empreinte gravée à la construction, signature vérifiée, écriture par le flux vérifié de `secubox-flash-emmc`. Socle : `ProtectSystem=strict` + `ReadWritePaths` exacts, `UMask=0027`, `NoNewPrivileges`, `Protect*`, `RestrictSUIDSGID`, `RestrictNamespaces`, `CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_OVERRIDE` (montage, écriture du bloc) | `packages/secubox-netboot/tests/test_relecture2_3233.py::test_unite_autoflash_durcie_et_exception_ecrite` |
