<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
Source-Disclosed License — All rights reserved except as expressly granted.
See LICENCE-CMSD-1.0.md for terms.
-->
# secubox-pilotage-agent

Agent de pilotage distant d'une box SecuBox (#3126 : livraison L1 « Voir », lecture seule ; L2 « Agir » en cours).
Binaire Go unique `/usr/sbin/sbx-pilotage-agent`, bibliothèque standard seule, `CGO_ENABLED=0`, et ctl root
`/usr/sbin/secubox-pilotagectl` (Python 3), seule voie d'action de l'agent.

## Fonctionnement

- **Connexion sortante uniquement** vers le maître (nginx `10.10.0.1:8472` sur `wg-mesh`, ou `10.64.0.1:8472`
  sur `wg-autoload`), interrogation longue. L'agent n'ouvre **aucun port d'écoute**.
- Répond à Get et GetSupportedDM (modèle TR-181 : système, services systemd, paquets, exposition, maillage,
  pilotage), notifie les événements (boucle de relances, mémoire basse, swap, démarrage) et réalise
  l'Operate `Device.X_SECUBOX_Releve.Mesurer()` (10 à 300 s, un seul à la fois ; lu sous la racine absolue `/`, M2).
- Rien ne part vers le maître tant que son ancre n'est pas vérifiée (voir « Ancre du maître »).
- Les Operate d'action de L2 (redémarrer, mettre à niveau, piloter un service, renommer, renouveler les secrets,
  support) passent par le ctl root : voir « Operate d'action (L2) ». Jamais la ligne de commande d'un processus
  (`comm`).
- Le maître est choisi ainsi : `PILOTAGE_MAITRE` s'il est posé ; sinon `wg-mesh` en `10.10.0.0/24`, puis
  `wg-autoload` en `10.64.0.0/16` ; sinon l'agent attend et revérifie toutes les 300 s. L'adresse de sortie
  est celle de l'interface du maillage dont la plage contient le maître.
  `PILOTAGE_MAITRE` n'accepte qu'une IP littérale parmi `10.10.0.1`, `10.64.0.1`, `127.0.0.1` (pas de nom
  d'hôte : pas de DNS sous le profil ; pas d'IPv6 : ni `AF_INET6` dans l'unité ni `inet6` dans le profil). Une valeur
  refusée est journalisée une fois, puis l'agent attend l'arrêt sans réessayer : la corriger, puis redémarrer l'unité.
- **Sur le maître lui-même** (gk2 : `wg-mesh` en `10.10.0.1`, `wg-autoload` en `10.64.0.1`), l'agent ne se pilote pas
  par son propre canal en L1 (R35) : il journalise une fois « cette box porte l'adresse du maître », puis attend l'arrêt
  sans jamais contacter le canal (qui refuserait `.1` et écrirait une ligne d'audit à chaque essai).
- **Limite connue** : le maître est choisi au démarrage seulement. Si l'adresse du tunnel change ou disparaît
  durablement, le canal recule jusqu'à 300 s et réessaie sans fin, sans refaire ce choix ni sortir en échec :
  `Restart=on-failure` n'y peut rien, seul un redémarrage de l'unité (`systemctl restart secubox-pilotage-agent`)
  refait le choix du maître.

## Configuration (`/etc/secubox/pilotage-agent.env`, facultatif)

Voir `conf/pilotage-agent.env` (installé en exemple sous `/usr/share/doc/secubox-pilotage-agent/`) :
`PILOTAGE_MAITRE`, `PILOTAGE_RELEVE_INTERVALLE_S` (30, de 5 à 300), `PILOTAGE_MEMOIRE_SEUIL_MO` (200),
`PILOTAGE_SWAP_SEUIL_PCT` (80), `PILOTAGE_BOUCLE_RELANCES` (3), `PILOTAGE_BOUCLE_FENETRE_S` (600).

`/etc/secubox` appartient au compte partagé `secubox` (R12, R36) : le fichier est lu par l'agent lui-même au démarrage,
pas par systemd (pas d'`EnvironmentFile=`), par descripteur et sans suivre aucun lien. Il doit être un fichier régulier
`root:root`, sans droit d'écriture pour le groupe ni les autres (`0644`), à un seul lien physique ; sinon il est ignoré en
entier, avec une ligne de journal. Même règle pour le drapeau « mains liées » `/etc/secubox/pilotage/mains-liees` : non
fiable, il vaut « non » (ligne de journal à chaque refus nouveau). Le paquet ne crée rien sous `/etc/secubox`.
Le compte `secubox` peut encore renommer, dans `/etc/secubox`, un autre fichier `root:root` à la place de ceux-ci : en L2,
l'état « mains liées » qui fait foi vit donc hors de `/etc/secubox` (`/var/lib/secubox-pilotagectl`, voir ci-dessous) ;
`/etc/secubox/pilotage/mains-liees` n'en est que la projection lue par l'agent.

## Actions (L2) : `secubox-pilotagectl`

L'agent ne devient jamais root : sa seule voie d'action est
`sudo -n /usr/sbin/secubox-pilotagectl [--acteur <login>] <verbe> …`
(`/etc/sudoers.d/secubox-pilotage-agent` : `secubox-pilotage-agent ALL=(root) NOPASSWD: /usr/sbin/secubox-pilotagectl *`,
rien d'autre). Toute la validation vit dans le ctl (patron `secubox-appstorectl`) ; la politique est décidée sur la box.
Sortie : une ligne JSON ; code 0 pour une réussite (`{"ok": true, "job": "<id>"}`) ou un refus
(`{"ok": false, "refus": "…"}`), 2 pour un argv invalide, 1 pour une erreur (état non fiable, audit impossible).

`--acteur <login>` (facultatif, seulement en tête, `^[a-z_][a-z0-9_.-]{0,63}$`) : l'administrateur du maître à
l'origine de la demande, audité dans le champ `acteur` ; absent, l'acteur d'un appel de l'agent est
`secubox-pilotage-agent`.

| Verbe | Effet |
|---|---|
| `reboot` | redémarrage, différé de 5 s (la réponse part d'abord) |
| `maj-paquets` | `apt-get update` puis `upgrade` (jamais `dist-upgrade` ni `autoremove`), opération longue |
| `service <demarrer\|arreter\|redemarrer> <unité>` | unité `^secubox-[a-z0-9][a-z0-9@.-]{0,62}\.(service\|timer)$`, jamais celle de l'agent (`secubox-pilotage-agent.*`, `@…` compris), ni une unité du ctl (`secubox-pilotage-op-*`), ni une unité inconnue de systemd, ni une unité protégée (`protected = true` dans `/etc/secubox/modules.d/*.toml`, ou socle : auth, aggregator, core, nginx, firewall, profiles, vault, autoload-agent). **Service durable seulement** (R-L2-46) : voir « Services durables » |
| `renouveler-secrets` | `secubox-renouvelle-secrets --tout --oui`, opération longue |
| `renommer <nom>` | (tâche 5, D3) libellé DNS ; `/usr/sbin/secubox-renommer --acteur <acteur> <nom>` (secubox-core >= 1.8.10 : hosts, secubox.conf, hostnamectl, Avahi, audit `box_renommee`, retour arrière ; nom réservé ou pris au maillage refusé) dans une unité transitoire de PID 1 bornée (`RuntimeMaxSec=120`) et en bac à sable (`NoNewPrivileges`, `ProtectSystem=strict` sauf `/etc`, `/run`, `/var/log/secubox`, `ProtectHome`, `PrivateTmp`) : l'espace de montage de l'agent garde `/etc` en lecture seule. Box cliente : accord du détenteur |
| `maillage-rejoindre` | (tâche 5, R-L2-2) **le code `sbxmesh1.…` est lu sur l'entrée standard**, jamais dans l'argv (un argv sudo apparaît dans `auth.log` et `ps`), forme et somme vérifiées, après l'ancre, les mains liées et la politique (`code invalide` sinon) ; box du propriétaire seulement (`box cliente : hors maillage`) ; le code attend dans l'état root (`rejoindre-<job>.code`, 0600), puis l'opération (`RuntimeMaxSec=300`) lance `_rejoindre <job>`. Jamais dans l'audit, les journaux, les sorties ni les notifications |
| `_rejoindre <job>` | **interne, local seulement** (unité transitoire) : code repris une fois (retiré aussitôt, et par `_fin`), déposé dans `/var/lib/secubox/p2p/automesh.code` (root 0600, par descripteur, sans lien ; l'ancien `automesh.json` est retiré, son `debut` ferait expirer le code neuf), puis `systemctl start secubox-automesh.service` (secubox-p2p : `sbx-mesh-join`, jeton par l'environnement) ; audit `maillage_rejoindre {job, resultat}` ; échec ⇒ code 1, fin `echec` |
| `support ouvrir <id> [<duree_min>]` | demande d'ouverture (maître) : support **en attente** de l'accord du détenteur, `{"ok": false, "refus": "consentement requis", "support": "<id>"}` ; `duree_min` entier de 1 à 240 (`^[1-9][0-9]{0,2}$`), 30 par défaut ; voir « Support » |
| `support <accepter\|refuser> <id>` | **local seulement** : le détenteur ouvre la session (pour la durée demandée, comptée à partir de l'accord) ou la refuse |
| `support fermer <id>` | permis **des deux côtés** (maître et détenteur) : ferme la session ouverte ou retire la demande en attente |
| `etat` | lecture, permise depuis l'agent, **non auditée** (sondée toutes les 5 min et après chaque Operate). En local : `{"ok": true, "box", "mains_liees", "canal", "consentements": [{id, action, unite, etat, cree, expire, decide}], "support": {id, etat, duree_min, cree, expire, ouvert, fin}\|null, "agent"}`. Depuis l'agent, le minimum (M1) : `{"ok", "mains_liees", "consentements": [{id, etat}], "support": {id, etat, fin}\|null}`, consentements en cours (`en_attente`, `accepte`) ou décidés depuis moins d'une heure (`decide`, posé aussi à l'expiration, l'annulation et l'utilisation). `mains_liees` est **toujours** rendu (état root illisible : `true`, par prudence) ; une section illisible vaut `"illisible"` sans faire échouer l'état (M2). Les expirations qu'elle constate sont écrites et auditées |
| `ancre-verifier <wg-mesh\|wg-autoload>` | lecture, permise depuis l'agent : `{"ok": true}` si le pair WireGuard de l'interface du canal de l'agent qui porte l'adresse du maître a la clé de l'ancre, sinon `{"ok": false, "raison": "absente"\|"differente"\|"illisible"}` (code 0, refus audité) ; voir « Ancre du maître » |
| `consentement <accepter\|refuser> <id>` | **local seulement** : décision du détenteur sur un consentement en attente |
| `mains-liees <on\|off>` | **local seulement** : lie ou délie les mains du maître |
| `fins-recentes` | lecture, permise depuis l'agent, **auditée** (`pilotage_lecture`) : `{"ok": true, "fins": [{job, verbe, resultat, rc}]}`, les 20 dernières fins enregistrées par `_fin` (`succes`/`echec` seulement, de la plus ancienne à la plus récente), rien d'autre ; lue une fois au démarrage de l'agent (I4, voir « Clôture des opérations ») |
| `etat-operation <job>` | lecture, permise depuis l'agent, **auditée** (`pilotage_lecture`) : `{"ok": true, "job", "etat": "en_cours"\|"termine"\|"inconnu"}`, avec `verbe`, `resultat` (`succes`/`echec`) et `rc` (entier, ou `null` pour un signal) une fois terminée. L'unité `--collect` est ramassée dès sa fin : `_fin` enregistre la fin dans l'état root (`fins.json`, 100 dernières) et ce verbe la relit |
| `_fin <job>` | **interne, local seulement** : `ExecStopPost` de chaque unité transitoire ; audite la fin (`succes`/`echec`, code de sortie numérique) et libère l'opération exclusive |
| `interface <locale\|distante>`, `interface confirmer <job>` | (#3302) bascule d'interface. `distante` : profil de retour mémorisé (celui d'avant, sinon `/etc/secubox/profiles/active` s'il n'est pas `distante`, sinon `profil_retour` de `/etc/secubox-pilotage/interface.toml` ; aucun ⇒ `profil de retour inconnu`, jamais d'apply sans profil), état root `interface.json`, unité `_interface <job>` (`RuntimeMaxSec=1800`) ; refusée pendant une attente de confirmation. `locale` : retour au profil mémorisé, garde de l'ancienne bascule désarmée. `confirmer <job>` : demande du maître après une bascule réussie, pour CE job ; désarme la garde (`{"ok": true, "confirme": true}`, sinon `rien à confirmer` ou `confirmation d'une autre bascule`). `locale` refusée sans interface distante en place (`aucune interface distante en place`), sauf box allégée à la main (marqueur de secubox-profiles). Opération exclusive ; box cliente : accord du détenteur (`interface-locale`, `interface-distante`) |
| `_interface <job>` | **interne, local seulement** : `secubox-profilectl apply --profile <cible> --yes --json`, `active` repointé ; vers `distante`, minuterie `secubox-pilotage-garde-<job>` armée **avant** l'apply (échéance : 900 s d'apply borné + `delai_garde_s`, 600 s par défaut, 120..3600), pour rattraper aussi une unité tuée en plein apply ; apply réussi ⇒ garde réarmée sur fin d'apply + délai ; garde non armée ⇒ pas de bascule ; apply en échec ⇒ garde désarmée, profil de retour rendu aussitôt, fin `echec`. Retour en locale : garde de ce retour armée avant l'apply (un retour coupé est repris par elle ou au démarrage) ; l'ancienne garde n'est désarmée qu'après l'apply réussi ; en échec, état `a_reprendre` et garde de ce job pour réessayer. `active` garde son propriétaire et son mode. Audit `interface_basculee`, `interface_retour` (`cause` apply\|garde\|demande\|homme-mort), `interface_echec` |
| `_interface-reprise` | **interne, local seulement** : unité `secubox-pilotage-interface-reprise.service` (oneshot, au démarrage) ; les gardes transitoires ne survivent pas au redémarrage : bascule inachevée ou échue ⇒ retour immédiat, sinon garde réarmée pour le temps restant (audit `interface_reprise`) |
| `_interface-garde <job>` | **interne, local seulement** (homme mort) : si la bascule `job` vers `distante` attend encore la confirmation ou n'a jamais fini, profil de retour rendu (`interface_retour`, `cause = homme-mort`) ; sinon rien |
| `politique <action>` | `{"autorise", "consentement", "raison"}` ; actions `releve`, `reboot`, `maj-paquets`, `service-demarrer`, `service-arreter`, `service-redemarrer`, `renommer`, `renouveler-secrets`, `support-ouvrir`, `support-fermer`, `maillage-rejoindre`, `interface-locale`, `interface-distante`, `interface-confirmer` |

« Local seulement » : refusé (et audité) quand l'appel vient du compte de l'agent par sudo (`SUDO_USER`/`SUDO_UID`).

- **Mains liées** : tout est refusé au maître sauf le relevé. État root `/var/lib/secubox-pilotagectl/mains-liees`,
  projection `/etc/secubox/pilotage/mains-liees` (root, 0644, posée par descripteur) ; l'un OU l'autre lie les mains.
  Les poser annule les consentements en attente ou acceptés non consommés, ferme la session de support ouverte et
  annule la demande en attente ; sous mains liées, aucune session ne s'ouvre, même en local.
- **Support** (tâche 4) : une seule session à la fois (état root `support.json`). Le maître la demande
  (`support_demande`), le détenteur l'accepte (`support_ouvert`, avec `fin`) ou la refuse (`support_refuse`) par
  `secubox-pilotage support accepter|refuser <id>` ; chacun la ferme (`support_ferme`, avec l'origine). Une demande
  non décidée expire à 24 h, une session ouverte à sa fin (`support_expire`, une fois), constatée à la lecture
  suivante (l'agent lit `etat` toutes les 5 min et après chaque Operate ; `secubox-pilotage etat` aussi). Le maître
  n'attend pas cette lecture : la notification d'ouverture porte `fin` et il expire la session lui-même. Le support **ne lance rien** sur la
  box (jamais de shell) : il dit au maître que le détenteur ouvre l'accès au catalogue d'actions et à la vue en
  direct ; chaque action reste soumise à la politique (mains liées, ancre, consentement d'une box cliente). Refus
  possibles : `support déjà en cours` (autre session), `support déjà ouvert`, `support inconnu`,
  `support déjà décidé`, `support annulé`, `support expiré`, `support déjà fermé`.
- **Ancre vérifiée exigée** (R-L2-21) : toute demande du maître (actions et `politique`) est refusée tant
  qu'aucune ancre n'est vérifiée (`{"ok": false, "refus": "ancre non vérifiée"}`, ou `"raison"` pour `politique`),
  refus audité avec le verbe. Chaque `ancre-verifier` réussi enregistre le canal vérifié (`ancre.json` dans l'état
  root, écriture atomique, valable 2 h ; l'agent revérifie toutes les heures) ; un échec le retire (R-L2-26).
- **Box cliente** (canal vérifié `wg-autoload` ; `wg-mesh` = box du propriétaire ; la nature se lit dans le canal
  enregistré, jamais dans la seule présence d'une interface, R-L2-26) : `reboot`, `maj-paquets`,
  `service demarrer|arreter|redemarrer` (R-L2-46 : démarrer aussi, gabarit ou non), `renommer`, `renouveler-secrets`
  exigent l'accord du détenteur. La demande crée un
  consentement en attente, valable 24 h (`{"ok": false, "refus": "consentement requis", "consentement": "<id>"}`) ;
  le détenteur l'accepte ou le refuse en local ; la demande suivante **identique** consomme l'accord, une fois.
  L'accord porte sur l'action, l'unité d'un service et le **nom** d'un renommage (I2, R-L2-47) : un accord donné pour
  `renommer gk5` ne vaut pas pour `renommer gk6` ; `secubox-pilotage consentements` affiche « renommer en gk5 ».
- **Services durables** (R-L2-46) : `service demarrer|arreter|redemarrer` ne s'applique qu'à un service durable, sur
  les deux natures de box et même en local. Avant toute action, le ctl lit
  `/usr/bin/systemctl show -p Id -p Type -p Names -p LoadState -- <unité>` (sans shell, 20 s au plus ; lignes
  `clé=valeur`, l'ordre de `--value` n'étant pas celui des `-p`) :
  - unité introuvable (`LoadState=not-found`) : « unité inconnue » ;
  - l'`Id` **résolu** (un alias pointe vers son unité réelle) et chacun des `Names` passent les mêmes contrôles que
    le nom demandé : unité de l'agent, `secubox-pilotage-op-*`, unité protégée (R-L2-15 refermé : gabarits et
    alias) ; un `Id` hors `secubox-*` est « unité hors périmètre » ;
  - `Type=oneshot`, ou une minuterie (sans `Type` : l'armer lance une action ponctuelle) : « unité ponctuelle :
    passez par l'action dédiée ». `secubox-systeme-redemarrer`, `secubox-systeme-eteindre`, `secubox-majauto*`,
    `secubox-premier-pas*`, `secubox-firstboot`, `secubox-eth2-*`… sont des actions root : les démarrer par ce
    chemin contournerait l'accord du détenteur, la confirmation forte du maître et « une opération longue à la
    fois ». Le reboot et la mise à jour ont leurs verbes.
- **Une seule opération longue à la fois** (`maj-paquets`, `renouveler-secrets`, et `reboot` pendant ses 5 s de
  délai), libérée par `_fin` ou quand l'unité a disparu : sinon
  `{"ok": false, "refus": "opération en cours", "job": "<id>"}`.
- Une demande locale (root sur la box, hors de l'agent) n'est soumise ni aux mains liées ni au consentement.
- Chaque action part par `systemd-run --collect --unit=secubox-pilotage-op-<job>
  --property=ExecStopPost=+/usr/sbin/secubox-pilotagectl _fin <job>` (« + » : hors du bac à sable de l'unité, R-L2-36), sans délai imposé ; la progression se lit dans le
  journal de l'unité, la fin est auditée (`pilotage_resultat`, `succes`/`echec`).
- **Audit** : une ligne JSON par demande, refus, consentement et résultat dans `/var/log/secubox/audit.log` (ouvert sans
  suivre de lien ; identifiants seulement, jamais une valeur secrète ni l'argv refusé). `politique` n'est pas auditée, sauf son refus faute d'ancre vérifiée ; `etat-operation` l'est (`pilotage_lecture`) ; `etat` ne l'est pas (lecture sondée), mais les expirations qu'elle constate le sont.
- État root `0700` `/var/lib/secubox-pilotagectl` (tmpfiles.d du paquet) : consentements, mains liées, opération en
  cours, canal vérifié (`ancre.json`), support (`support.json`), opérations lancées et finies (`fins.json`). Non fiable (propriétaire, droits,
  lien) : tout est refusé.
  Une écriture d'état qui échoue **avant** le lancement refuse (rien ne part) ; **après** un lancement réussi
  (`fins.json`, `operation.json`, consommation d'un consentement), elle est journalisée et la réponse reste
  `{"ok": true, "job"}` (R-L2-29). Un accord qui n'a pu être marqué utilisé est audité `consentement_non_consomme`
  (il pourrait resservir) ; une opération exclusive qui n'a pu être enregistrée n'empêche alors pas une seconde opération longue.
  De même pour l'audit (I5, R-L2-47) : après un lancement réussi, un audit `lance`, `consentement_utilise` ou
  `consentement_non_consomme` manqué est rattrapé, l'anomalie écrite sur stderr (journal de l'agent), et la réponse
  reste `{"ok": true, "job"}` ; avant le lancement, un audit manqué refuse toujours (`audit impossible`, rien ne part).
- `SBX_RACINE` (tests seulement) n'est honorée que si l'appelant est le processus lui-même ; jamais sous sudo depuis un
  autre compte.

## Operate d'action (L2)

Avec l'ancre vérifiée, l'agent accepte cette **liste fermée** de commandes ; il valide les paramètres **avant** tout
appel au ctl (paramètre manquant, inconnu, mal typé ou hors motif : refus, le ctl n'est pas appelé) :

| Commande | Paramètres | Verbe du ctl |
|---|---|---|
| `Device.Reboot()` | aucun | `reboot` |
| `Device.X_SECUBOX_Packages.MettreAJour()` | aucun | `maj-paquets` |
| `Device.X_SECUBOX_Services.Agir()` | `unite` (`^secubox-[a-z0-9][a-z0-9@.-]{0,62}\.(service\|timer)$`), `action` (`demarrer`/`start`, `arreter`/`stop`, `redemarrer`/`restart`) | `service <demarrer\|arreter\|redemarrer> <unite>` |
| `Device.X_SECUBOX_Nom.Renommer()` | `nom` (libellé DNS) | `renommer <nom>` |
| `Device.X_SECUBOX_Maillage.Rejoindre()` | `code` (`sbxmesh1.…`, forme et somme vérifiées ; jamais recopié dans un refus) | `maillage-rejoindre`, le code sur l'**entrée standard** du ctl (`sudo -n` avec une entrée, R-L2-2) ; sans lanceur à entrée, refus net |
| `Device.X_SECUBOX_Secrets.Renouveler()` | aucun | `renouveler-secrets` |
| `Device.X_SECUBOX_Support.Ouvrir()` | `id` (`^[a-z0-9][a-z0-9-]{0,63}$`), `duree_min` facultatif (entier 1 à 240, défaut 30) | `support ouvrir <id> <duree_min>` (rend `consentement` : accord du détenteur à donner en local) |
| `Device.X_SECUBOX_Support.Fermer()` | `id` | `support fermer <id>` (rend `accepte` sans `job` : rien n'est suivi) |
| `Device.X_SECUBOX_Releve.Mesurer()` | `duree_s` (10 à 300) | aucun : relevé de L1, fait par l'agent |

- Le corps de l'Operate peut porter `"acteur": "<login de l'admin du maître>"` (R-L2-14) : l'agent le passe au ctl en
  tête (`--acteur <login>`) s'il a la forme `^[a-z_][a-z0-9_.-]{0,63}$` ; invalide ou absent, il n'est pas transmis
  (l'acteur audité est alors le compte de l'agent) et la demande n'est pas refusée pour autant.
- **`OPERATE_RESP` immédiat** : `{"etat": "accepte"|"consentement"|"refuse", "job": "<id>"|"", "raison": "…"|""}`.
  `accepte` : le ctl a lancé l'opération `job`. `consentement` : le ctl a répondu « consentement requis » (box
  cliente, accord du détenteur à donner en local ; la demande identique suivante consomme l'accord, R-L2-10). `refuse` :
  refus de l'agent (commande inconnue, argument invalide) ou du ctl (`raison` = son refus : mains liées, ancre non
  vérifiée, unité protégée, opération en cours avec son `job`…) ; erreur ou sortie incohérente du ctl : `refuse`.
  Sans exécuteur (tests de L1), une commande autre que le relevé reçoit encore `ERROR` (« lecture seule »).
- **Suivi** d'une opération acceptée, en tâche de fond : `systemctl show -p ActiveState` du service et de la minuterie
  `secubox-pilotage-op-<job>` toutes les 5 s, **sans sudo** (lecture sur le bus système). NOTIFY
  `X_SECUBOX_OperationProgress {job, etape, pct}` : `lancee` (0), `en_cours` (50), `terminee` (100), une fois chacune.
  L'unité finie, l'agent demande le code au ctl (`etat-operation <job>`, une ligne d'audit par lecture), puis
  NOTIFY `X_SECUBOX_OperationDone {job, rc, resume}` : `resume` est court (« maj-paquets : succès »,
  « … : échec (code 100) », « … : échec (interrompu) »), jamais une sortie d'apt ni un secret ; `rc` vaut -1 quand le
  code n'est pas un nombre ou que la fin reste introuvable après 3 lectures (« résultat inconnu »). Au plus 32
  opérations suivies en même temps ; 12 lectures `systemctl show` en échec de suite (bus injoignable) donnent aussi
  « résultat inconnu » et libèrent l'emplacement. L'arrêt de l'agent (ou le reboot de la box) interrompt le suivi
  sans résultat ; la fin est rattrapée au démarrage suivant (ci-dessous).
- **Clôture des opérations interrompues** (I4, R-L2-47, révision de R-L2-27) : trois mécanismes, pour qu'aucune
  opération ne reste « en cours » à vie côté maître.
  1. **Fins récentes au démarrage** : à la première vérification réussie de l'ancre (une fois par démarrage, avant
     le premier bonjour ; `Config.ApresAncre` du canal), l'agent lit au ctl `fins-recentes` (20 dernières fins
     enregistrées par `_fin`, qui tourne en `ExecStopPost` même si l'agent est arrêté) et dépose une
     `X_SECUBOX_OperationDone` pour chacune dans la boîte des résultats. Le maître dédoublonne par job : une fin déjà
     remise ne change rien.
  2. **boot_id dans le bonjour** (`/proc/sys/kernel/random/boot_id`) : quand il change, le maître clôt chaque reboot
     de la box encore en cours « succès (redémarrée) » (la fin d'un reboot peut ne jamais être enregistrée).
  3. **Échéance côté maître** : une opération encore en cours 6 h après sa demande passe à « inconnu », auditée une
     fois.
- **Coupure du canal pendant une opération** (voulu par le brief) : l'opération continue sur la box (`systemd-run`),
  et son suivi aussi, maître joignable ou non ; la progression émise pendant la coupure suit la file ordinaire des
  notifications, la fin attend dans la boîte des résultats et est remise à la reconnexion.
- Si le ctl répond « ancre non vérifiée » alors que l'agent se croit ancré (canal enregistré périmé ou retiré),
  l'agent force une revérification de l'ancre, au plus une par lot et par minute (même limiteur que R-L2-24).
- Un exécuteur d'actions sans vérification d'ancre est une configuration refusée : l'agent ne se connecte pas.
- **Résultats non remis** : les `X_SECUBOX_OperationDone` sont gardés en mémoire (au plus **50** ; au-delà, le plus
  ancien est évincé et journalisé) jusqu'à un POST `/notifs` réussi (2xx), puis retirés : renvoyés à la reconnexion
  (chaque bonjour relance l'envoi), une seule fois chacun. La progression, elle, suit la file ordinaire des
  notifications (64, les plus anciennes tombent).

## Commande locale du détenteur : `secubox-pilotage`

En root sur la box (console, SSH local ; hors root : « à lancer en root », code 1). Texte en français ; simple
affichage au-dessus de `secubox-pilotagectl` (argv en liste, sans shell), aucune politique réimplémentée. Le login
sudo de l'humain est passé au ctl (`--acteur`) et audité ; jamais le compte de l'agent.

| Commande | Effet |
|---|---|
| `secubox-pilotage etat` | agent en marche ou non, ancre vérifiée et canal (box du propriétaire ou cliente), mains liées, consentements en attente, support |
| `secubox-pilotage consentements` | consentements en attente (temps restant avant l'expiration à 24 h), puis les 20 dernières décisions (accepté, refusé, utilisé, expiré, annulé) |
| `secubox-pilotage accepter\|refuser <id>` | décision sur un consentement (`consentement accepter\|refuser <id>`) |
| `secubox-pilotage mains-liees on\|off` | lie ou délie les mains du maître |
| `secubox-pilotage support accepter\|refuser <id>` | ouvre ou refuse la session demandée par le maître |
| `secubox-pilotage support fermer [<id>]` | ferme la session (en cours par défaut) |

Codes : 0 fait ; 1 refus du ctl (motif affiché), erreur, ou hors root ; 2 usage.

**Comment le maître l'apprend** (notifications des bascules locales). La commande tourne en root, l'agent non ; il
ne reçoit **aucun droit nouveau** : toutes les **5 minutes**, et juste après chaque Operate traité (R-L2-30 : une
ligne sudo par lecture dans `auth.log`), il lit l'état par le verbe de lecture `etat` du ctl, avec le sudo qu'il a
déjà (`secubox-pilotagectl *`), et compare au précédent. Il notifie alors `X_SECUBOX_HandsTied {etat: on|off}`,
`X_SECUBOX_Consent {id, decision: accepte|refuse|expire|annule}` et `X_SECUBOX_Support {id, etat, fin}` (en_attente,
ouvert, refuse, ferme, annule, expire ; `fin` en RFC 3339 UTC dès l'ouverture, pour que le maître expire la session
lui-même à sa borne, R-L2-33). Au **premier état lu** après le démarrage de l'agent, il notifie l'état des mains liées
et la session de support en cours (en attente ou ouverte) : un agent qui redémarre pendant une session la renotifie.
Une bascule faite puis défaite entre deux lectures n'est pas vue (l'audit local la garde). Une section illisible
(`"illisible"`) ne produit rien et garde la mémoire précédente ; HandsTied part quand même. Une sortie du ctl
inattendue ne produit aucune notification (journalisée une fois). Cette lecture fait aussi expirer, côté ctl, les
consentements à 24 h et le support à sa fin.

**Double notification (M3), sans conséquence.** Le même état peut être notifié deux fois : à chaque démarrage de
l'agent (mains liées et session en cours renotifiées), ou quand une notification est retentée après un échec de
remise. Le maître dédoublonne par `(type, id, etat|decision)` : une renotification identique ne change rien à sa vue.

## Ancre du maître (D1)

L'agent ne parle qu'au vrai maître : **au démarrage, puis toutes les heures**, il appelle
`sudo -n /usr/sbin/secubox-pilotagectl ancre-verifier <interface>`, où `<interface>` est celle du canal du maître
qu'il a retenu (R-L2-23) : `10.10.0.1` → `wg-mesh`, `10.64.0.1` → `wg-autoload`. Ce n'est jamais deviné d'après les
interfaces présentes : une box où `wg-mesh` existe sans adresse parle par `wg-autoload`, et c'est ce canal-là qui est
vérifié. Un maître hors de ces deux canaux (`PILOTAGE_MAITRE=127.0.0.1`, réservé aux essais) vaut `illisible` sans
appeler le ctl : le canal reste coupé. Le ctl rend toujours le code 0 et l'un de ces verdicts :

| Sortie du ctl | Cas | Comportement de l'agent |
|---|---|---|
| `{"ok": true}` | le pair du maître a la clé de l'ancre | canal ouvert, Operate traités |
| `{"ok": false, "raison": "absente"}` | aucune ancre posée : pas d'`ancre-maitre.json` sur une box du propriétaire, pas de configuration `wg-autoload` sur une box cliente | **canal ouvert en lecture** (comme en L1) ; **tout Operate est refusé** (`ancre absente : action refusée`) ; un lot de refus redemande la vérification au ctl, qui l'audite « ancre absente » (R-L2-19), **au plus une fois par lot et par minute** : les autres refus sont seulement comptés dans le journal de l'agent (R-L2-24). Une ancre absente **après** une vérification réussie vaut `illisible` (coupure, M1) |
| `{"ok": false, "raison": "differente"}` | le pair qui porte l'adresse du maître a une autre clé, ou aucun pair ne la porte | **canal coupé** |
| `{"ok": false, "raison": "illisible"}` | ancre en JSON invalide, clé mal formée, lien, droits ; `wg` en échec ou sortie illisible (non ASCII comprise) ; canal incohérent (seule l'ancre de l'autre canal est posée) ; toute erreur imprévue du ctl | **canal coupé** |

Côté agent, toute autre sortie, une erreur ou un code non nul vaut `illisible` (fermé par défaut).

- **Canal coupé** : ni bonjour, ni sondage, ni réponse, ni notification vers le maître, et aucun Operate traité.
  L'agent revérifie avec un recul doublé de 5 s jusqu'à 1 h (chaque échec écrit une ligne d'audit). Une revérification
  horaire qui échoue coupe le canal en cours de route. À la reconnexion suivante qui réussit, l'agent notifie la coupure
  au maître : événement `X_SECUBOX_AnchorFailed` (`value` = instant Unix de la coupure).
- Ce que vérifie le ctl (root), sur l'interface reçue en argument, et elle seule :
  - **`wg-mesh`** (box du propriétaire) : le pair de `wg-mesh` qui porte `10.10.0.1` doit avoir la
    clé `cle_publique` de `/etc/secubox/p2p/ancre-maitre.json` (ancre posée au flash ou à la jonction, #3100). Le
    fichier appartient à root ou au compte `secubox` (premier-pas l'écrit sous ce compte) et n'est inscriptible ni par
    le groupe ni par les autres, sinon il est « illisible » (R-L2-20) ;
  - **`wg-autoload`** (box cliente) : le pair de `wg-autoload` qui porte `10.64.0.1` doit avoir la clé du hub reçue à
    l'enrôlement Auto-Load (le `hub.pub` du hub, rendu par HTTPS épinglé et écrit par `secubox-autoload-agent` dans
    `PublicKey` de `/etc/wireguard/wg-autoload.conf`, root 0600, un seul `[Peer]`) (R-L2-17).
  - Cohérence (R-L2-23) : `wg-mesh` suppose `ancre-maitre.json`, `wg-autoload` la configuration cliente. Si seule
    l'ancre de l'autre canal est posée, le verdict est `illisible` (coupure), jamais `absente`.
  - Le pair retenu est celui que WireGuard choisit pour l'adresse du maître (`wg show <interface> allowed-ips`, préfixe
    le plus long) : un pair qui s'approprie `10.10.0.1/32` l'emporte sur le `/24` du maître et la vérification échoue.
  - Comparaison en temps constant (`hmac.compare_digest`). `/usr/bin/wg` est lancé par chemin absolu, sans shell, et
    seulement si une ancre est posée. Aucune clé n'est recopiée dans l'audit ; une réussite n'est pas auditée.
- **Limites connues** :
  - box cliente (R-L2-17) : l'ancre et l'interface viennent du même fichier `wg-autoload.conf`. Le contrôle détecte un
    pair injecté à chaud ou un préfixe qui détourne `10.64.0.1`, pas une réécriture du fichier, qui exige root sur la
    box. Un `hub.pub` séparé posé par `secubox-autoload-agent` est une amélioration hors L2 ;
  - box sans ancre (R-L2-19) : la lecture reste servie au pair du maillage sans vérification de sa clé, comme en L1 ;
    les actions attendent qu'une ancre soit posée. Les refus d'Operate entre deux revérifications (une par minute au
    plus) ne sont pas dans l'audit du ctl, seulement dans le journal de l'agent (R-L2-24) ;
  - une coupure en cours n'est pas notifiée si l'agent redémarre entre-temps (l'audit du ctl garde chaque échec).

## Relais local du pilotage délégué (L5) : `sbx-pilotage-relais`

Sur une box légère, les pages d'administration sont servies par le maître ; leurs appels `/api/v1/…` arrivent à
l'agent par le canal, qui les remet au relais local. Le relais tourne sous son **propre** compte
`secubox-pilotage-relais`, seul lecteur de la clé privée : un agent compromis ne frappe pas de jeton lui-même.

- **Socket** `/run/secubox/pilotage-relais.sock` (`secubox-pilotage-relais.socket` : 0660, propriétaire
  `secubox-pilotage-relais`, groupe `secubox-pilotage-agent`) ; le relais exige en plus `SO_PEERCRED` = uid de
  `secubox-pilotage-agent`, sinon il ferme sans répondre (refus audité).
- **Entrée** : un objet JSON par connexion
  `{"methode", "chemin", "entetes", "corps_b64", "acteur", "maitre", "portee", "version_page"}` ;
  **sortie** `{"statut", "entetes", "corps_b64"}`, puis fermeture. `version_page` est acceptée et ignorée.
- **Chemin** : `/api/v1/<module>/<reste>[?requête]` ; le module reçoit `/<reste>[?requête]` sur
  `/run/secubox/<module>.sock` (préfixe retiré, comme nginx `proxy_pass …:/` et l'agrégateur ; `Host: localhost`).
  Refusés : hors de ce motif, `..`/`.` (même encodés), `%2F`, `%5C`, segment vide, non-ASCII (400) ; socket absente
  ou qui n'en est pas une (404) ; modules qui ne reconnaissent jamais le porteur délégué (`auth`, `vault`, `portal`,
  `assist`, `premier-pas`, `users`, `aggregator`, `pilotage*`) (403).
- **Jeton** (contrat de `secubox_core.auth`, R-L5-9) : EdDSA Ed25519, en-tête `{"alg":"EdDSA","typ":"JWT"}`,
  `aud` = nom court de l'hôte en minuscules, `sub` = `pilotage:<acteur>@<maître>`, `cible` = module, `iat`/`exp`
  entiers, `exp - iat` = 30 s, `pilotage = {acteur, maitre, portee}`, rien d'autre. Acteur et maître sont mis en
  minuscules ASCII puis refusés (400) hors `[a-z0-9._-]{1,64}` / `[a-z0-9-]{1,63}`.
- **Cible et alias** : la cible est le nom du dossier d'installation `/usr/lib/secubox/<module>/` (ce que voit
  `module_courant`). Seul écart relevé dans le dépôt : `waker.sock` est servi par `secubox-profiles` → cible
  `profiles`. Les modules installés ailleurs (`/usr/share/secubox/…`, paquets Python : picobrew, podcaster,
  voicestudio, voice, zia, eye-remote, soc-*, security-posture) n'ont pas d'identité de module : le vérificateur
  y refuse le porteur délégué. Un module seulement monté dans l'agrégateur n'a pas de socket : 404 (R-L5-7).
- **En-têtes** : seuls `Content-Type`, `Accept`, `If-*` passent ; `Authorization`, `Cookie`, `X-SecuBox-*` et le
  reste sont effacés ; le relais pose `Authorization: Bearer <jeton>` et `X-SecuBox-Pilotage-Relais`. En retour,
  jamais `Set-Cookie`.
- **Mains liées** : portée `lecture`, ou drapeau `/etc/secubox-pilotage/mains-liees` → toute méthode autre que
  GET/HEAD est refusée **423** avant tout appel. Ce drapeau est la projection du ctl root (`mains-liees on|off`),
  dans l'arbre root (R-L5-19) : jamais `/etc/secubox/pilotage`, que le compte partagé `secubox` peut modifier.
  Dossier ou drapeau douteux (absent, pas à root, inscriptible par d'autres, lien) : mains liées.
- **Bornes** : corps ≤ **4 Mio** dans les deux sens (413) — écart voulu au brief (8 Mio, R-L5-19) : deux appels
  simultanés de taille maximale tiennent sous `MemoryMax=64M` (~31 Mio de tas mesurés, `TestRelaisMemoireBornee`) ;
  délai 30 s (504) ; deux appels simultanés, huit connexions au plus (en cours ou en attente), demande lue en 10 s ;
  GET/HEAD avec corps et caractères de contrôle dans la requête (`%00`…) refusés (400).
- **Audit** : chaque refus, une ligne JSON ajoutée à `/var/log/secubox/audit.log` (fichier du compte `secubox`,
  jamais créé par le relais) grâce à l'ACL d'écriture seule posée par `secubox-pilotage-relais-acl` (root, fichier
  vérifié par descripteur ; postinst et `ExecStartPre=-+` à chaque démarrage, la rotation la retire) ; sans ACL, la
  même ligne au journal du service. Jamais le
  jeton, le corps, la requête ni les en-têtes.
- **Clés** (R-L5-13, R-L5-18) : clé privée PEM PKCS#8 `/var/lib/secubox-pilotage-relais/relais.key` (0600, dossier
  0700, compte du relais), créée par le postinst **sous le compte du relais** (`runuser … sbx-pilotage-relais
  cle-publique`, qui rend la clé publique par un tube) ; clé publique PEM SPKI `/etc/secubox-pilotage/relais.pub`
  (root:root 0644, dossier root 0755) posée par root. Le relais refuse de démarrer si elle ne correspond pas.

## Message HTTP du canal (L5, tâche 3)

Le maître sert les pages d'une box légère ; leurs appels d'API arrivent par le canal :

- requête `{"msg_id", "type": "HTTP", "body": <entrée du relais>}` (`methode`, `chemin` `/api/v1/<module>/…`,
  `entetes`, `corps_b64`, `acteur`, `maitre`, `portee`, `version_page`) ;
- l'agent appelle le relais (`/run/secubox/pilotage-relais.sock`, un objet JSON par connexion) et rend
  `{"msg_id", "type": "HTTP_RESP", "body": <sortie du relais>}` (`statut`, `entetes`, `corps_b64`) par
  **`POST /canal/v1/http`**, une réponse par POST (jusqu'à ~5,6 Mo : hors du plafond de 256 Kio de `/reponses`).
  Un sondage peut alors porter jusqu'à ~5,7 Mo (au lieu de 256 Kio) quand le relais est configuré.

**Portée recalculée par l'agent, jamais crue** : la portée du maître ne peut que réduire.

| Situation sur la box | Portée transmise au relais |
|---|---|
| maître demande `lecture` | `lecture` |
| mains liées (`/etc/secubox-pilotage/mains-liees`, vérification du relais réutilisée : `relais.MainsLieesDans`) | `lecture` (le relais refuse alors toute écriture : 423) |
| box cliente sans support ouvert (drapeau root `support-ouvert` absent, douteux ou échu) | `lecture` |
| box du propriétaire, ou box cliente pendant un support ouvert, maître demande `admin` | `admin` |

Tout est relu à CHAQUE message, sans sudo ni cache (R-L5-21), dans les drapeaux que le ctl root projette dans
`/etc/secubox-pilotage/` (mêmes vérifications que le relais : dossier et fichier root, sans lien, sans écriture
groupe/autres) : `mains-liees` (présence), `proprietaire` (canal wg-mesh vérifié : fin de validité de la
vérification, 2 h) et `support-ouvert` (fin de la session). Le ctl les recalcule de son état root après CHAQUE
verbe (accord, fermeture, refus, expiration constatée par `etat`, mains liées, `ancre-verifier` réussi ou non) ;
l'agent compare lui-même la fin à l'heure. Montée de version ou redémarrage : le postinst rejoue
`secubox-pilotagectl etat` (local) qui reprojette l'état ; si ce n'est pas fait, une box cliente en support
ouvert est servie en LECTURE jusqu'au verbe suivant (veille de l'agent : 5 min au plus). Ancre vérifiée exigée (`AncreOK`, sinon 403). `acteur` et `maitre` : motifs du
vérificateur (`_RE_ACTEUR`, `_RE_MAITRE` de `secubox_core.auth`, par `relais.Normaliser`), sinon 400 ; l'agent ne
connaît le maître que par son adresse dans le tunnel (ancrée) : il contrôle la forme de ces noms, pas leur vérité.
Refus rendus sous la forme du relais : corps > 4 Mio → 413 ; relais absent ou muet → 502 ; délai (relais 30 s
+ 5 s) → 504 ; plus de 4 messages HTTP à la fois, ou un second échange de plus de 256 Kio → 503 ; agent sans
relais → 501. Journal : une ligne par écriture ou refus (méthode, chemin sans requête, acteur, maître, portées
demandée/retenue, statut) ; une lecture réussie seulement avec `JournalDebug` ; jamais un jeton, un corps ni un en-tête. AppArmor : `/run/secubox/pilotage-relais.sock rw` est la seule socket jointe ; les trois drapeaux en lecture.

## Page d'état locale (L5, tâche 7)

L'agent écrit dès son démarrage, **sans attendre le maître**, puis toutes les 60 s, une page HTML statique
`/run/secubox/pilotage/etat.html` (dossier `RuntimeDirectory=secubox/pilotage` de l'unité, 0755 ; page 0644) :
nom de la machine (libellé DNS court), maître `joignable` / `injoignable` / `inconnu` (dernier tour du canal ; ancre
non vérifiée = injoignable), mains liées, mémoire disponible et swap, noms des unités en échec (32 au plus, noms
d'unité valides seulement). Rien d'autre : ni adresse, ni clé, ni jeton, ni numéro de série, ni nom d'utilisateur
(l'état est construit champ par champ, `internal/etat.Depuis`). Aucun script ; la seule feuille de style est autorisée
par son empreinte (`etat.EmpreinteStyle`, recopiée dans le gabarit nginx `etat` de secubox-profiles). Écriture
atomique (fichier de travail `.etat.html.tmp` ouvert sans suivre de lien, puis renommé) ; seules écritures permises
par AppArmor. La page est servie sur le LAN par le gabarit nginx `etat` du profil léger `distante` (secubox-profiles).

`Device.X_SECUBOX_Pilotage.Interface` vaut `distante` quand le marqueur root `/var/lib/secubox-profiles/allegement/actif` (allègement du profil `distante` réussi, R-L5-34) est présent et de confiance (le maître sert alors
`admin.<box>.secubox.in`, R-L5-27), `locale` sinon.

## Durcissement

Utilisateur `secubox-pilotage-agent`, `ProtectSystem=strict`, `ReadOnlyPaths=/`, aucune capacité ambiante,
`IPAddressDeny=any` (sauf `10.10.0.1`, `10.64.0.1`, localhost), `MemoryMax=48M` avec `GOMEMLIMIT=32MiB` (32M/24MiB avant L5 ; RSS réel mesuré à 34,5 Mio — VmHWM, GOGC par défaut — pour un échange HTTP de 4 Mio aller et retour en parallèle de trois de 200 Kio, `TestAgentRSSEchangesParalleles` ; tas 23,3 Mio ; marge ~13 Mio) (le ramasse-miettes
travaille avant le tueur du cgroup, M13), profil AppArmor enforce
(`apparmor/usr.sbin.sbx-pilotage-agent` : réseau `inet stream` qualifié, `unix stream`, `netlink raw` pour les adresses
des interfaces ; ni `inet6` ni écoute ; `/usr/bin/sudo Ux` seul passage privilégié).

Exception écrite (`.claude/RULES-CODE.md`) : `NoNewPrivileges=no`, seulement pour sudo vers `secubox-pilotagectl` ; les
options qui imposent NoNewPrivileges par seccomp sont absentes de l'unité ; `CapabilityBoundingSet` borné à ce que sudo
et le ctl demandent (dont `CAP_CHOWN` : création d'`audit.log` au compte `secubox` ; `CAP_NET_ADMIN` : le noyau
l'exige pour `wg show`, lecture de `ancre-verifier`) ; le ctl root hérite de l'espace de montage, d'où `ReadWritePaths=/var/log/secubox
-/var/lib/secubox-pilotagectl`.

## Développement

```
go vet ./... && go test -race ./...
pytest -q tests          # dont tests/test_pilotagectl.py : le vrai ctl sous SBX_RACINE, faux systemd-run/systemctl
dpkg-buildpackage -b -us -uc     # natif ; arm64 sur une box (pas de -a croisé : dh_strip)
```

**Contrat avec le maître.** `internal/canal/testdata/contrat/*.json` fige les enveloppes que le client émet réellement (bonjour,
GET_RESP avec `failed` et avec `tronque`, GET_SUPPORTED_DM_RESP, OPERATE_RESP, ERROR, NOTIFY) ; le maître les rejoue contre son vrai canal
(`packages/secubox-pilotage/tests/test_contrat_go.py`). Un changement de format fait échouer `TestContratEnveloppesEmises` ; après
vérification : `SECUBOX_CONTRAT_MAJ=1 go test ./internal/canal -run TestContratEnveloppesEmises`, puis les tests du maître.

**Contrat maître → agent (N5/M14).** `internal/canal/testdata/contrat/maitre/*.json` : les requêtes que le VRAI maître dépose (Get de la
relève et de la lecture, GetSupportedDM, relevé, Reboot, MettreAJour, Services.Agir ×3, Renommer, Renouveler, Support.Ouvrir/Fermer,
Maillage.Rejoindre avec un code factice), figées par `packages/secubox-pilotage/tests/test_contrat_maitre.py`.
`cmd/sbx-pilotage-agent/contrat_test.go` (`TestContratRequetesDuMaitre`) les sert au vrai client, avec le vrai exécuteur (ctl simulé :
l'argv reçu, `--acteur` compris, et l'entrée standard de Rejoindre sont vérifiés), le vrai opérateur du relevé et les vraies bascules, puis fige
dans `testdata/contrat/agent-l2/` ce que l'agent émet pour L2 (OPERATE_RESP, réponse du relevé, OperationProgress, OperationDone,
OperationDone rattrapée au démarrage par `fins-recentes` (I4), HandsTied, Consent, Support), que le maître rejoue à son tour. Une fixture altérée échoue des deux côtés
(`TestContratRequeteAltereeEchoue`, et `test_une_…_alteree_echoue` côté maître). Régénération : d'abord le maître
(`SECUBOX_CONTRAT_MAJ=1 python3 -m pytest tests/test_contrat_maitre.py -k figees`), puis
`SECUBOX_CONTRAT_MAJ=1 go test ./cmd/sbx-pilotage-agent -run TestContratRequetesDuMaitre`, puis les deux suites.

## Installer une app (#3338)

`installer <secubox-…>` (agent : `Device.X_SECUBOX_Packages.Installer() {paquet}` ; maître : action `installer`, confirmation forte) : `apt-get install --no-remove --no-install-recommends` sans délai dans une unité transitoire ; seulement une app publiée du catalogue de la boutique (jamais fonction/service, pilotage, exposure, assist, socle ou module protégé) dont la version candidate vient du dépôt SecuBox (`apt-cache policy`) ; formule de l'abonnement (fail-closed, sauf marqueur `/etc/secubox/abonnement-libre`), opération longue exclusive, accord du détenteur lié au paquet pour une box cliente, refus sous mains liées, audit (`nom` = paquet).
