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
  l'Operate `Device.X_SECUBOX_Releve.Mesurer()` (10 à 300 s, un seul à la fois).
- Rien ne part vers le maître tant que son ancre n'est pas vérifiée (voir « Ancre du maître »).
- Toute autre commande est refusée par l'agent tant que les Operate de L2 ne sont pas câblés (tâche 3). Jamais la ligne
  de commande d'un processus (`comm`).
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
| `service <demarrer\|arreter\|redemarrer> <unité>` | unité `^secubox-[a-z0-9][a-z0-9@.-]{0,62}\.(service\|timer)$`, jamais celle de l'agent (`secubox-pilotage-agent.*`, `@…` compris), ni une unité du ctl (`secubox-pilotage-op-*`), ni une unité inconnue de systemd, ni une unité protégée (`protected = true` dans `/etc/secubox/modules.d/*.toml`, ou socle : auth, aggregator, core, nginx, firewall, profiles, vault, autoload-agent) |
| `renouveler-secrets` | `secubox-renouvelle-secrets --tout --oui`, opération longue |
| `renommer <nom>`, `support <ouvrir\|fermer> <id>` | argv validé ; `{"ok": false, "refus": "non disponible"}` jusqu'aux tâches 5 et 4 |
| `ancre-verifier` | lecture, permise depuis l'agent : `{"ok": true}` si le pair WireGuard qui porte l'adresse du maître a la clé de l'ancre, sinon `{"ok": false, "raison": "absente"\|"differente"\|"illisible"}` (code 0, refus audité) ; voir « Ancre du maître » |
| `consentement <accepter\|refuser> <id>` | **local seulement** : décision du détenteur sur un consentement en attente |
| `mains-liees <on\|off>` | **local seulement** : lie ou délie les mains du maître |
| `_fin <job>` | **interne, local seulement** : `ExecStopPost` de chaque unité transitoire ; audite la fin (`succes`/`echec`, code de sortie numérique) et libère l'opération exclusive |
| `politique <action>` | `{"autorise", "consentement", "raison"}` ; actions `releve`, `reboot`, `maj-paquets`, `service-demarrer`, `service-arreter`, `service-redemarrer`, `renommer`, `renouveler-secrets`, `support-ouvrir`, `support-fermer` |

« Local seulement » : refusé (et audité) quand l'appel vient du compte de l'agent par sudo (`SUDO_USER`/`SUDO_UID`).

- **Mains liées** : tout est refusé au maître sauf le relevé. État root `/var/lib/secubox-pilotagectl/mains-liees`,
  projection `/etc/secubox/pilotage/mains-liees` (root, 0644, posée par descripteur) ; l'un OU l'autre lie les mains.
  Les poser annule les consentements en attente ou acceptés non consommés.
- **Box cliente** (pas d'interface `wg-mesh` : reliée par `wg-autoload`, ou sans maillage) : `reboot`, `maj-paquets`,
  `service arreter|redemarrer`, `renommer`, `renouveler-secrets`, et toute action sur une unité gabarit (`@`), même
  `demarrer`, exigent l'accord du détenteur. La demande crée un
  consentement en attente, valable 24 h (`{"ok": false, "refus": "consentement requis", "consentement": "<id>"}`) ;
  le détenteur l'accepte ou le refuse en local ; la demande suivante identique consomme l'accord, une fois.
- **Une seule opération longue à la fois** (`maj-paquets`, `renouveler-secrets`, et `reboot` pendant ses 5 s de
  délai), libérée par `_fin` ou quand l'unité a disparu : sinon
  `{"ok": false, "refus": "opération en cours", "job": "<id>"}`.
- Une demande locale (root sur la box, hors de l'agent) n'est soumise ni aux mains liées ni au consentement.
- Chaque action part par `systemd-run --collect --unit=secubox-pilotage-op-<job>
  --property=ExecStopPost=/usr/sbin/secubox-pilotagectl _fin <job>`, sans délai imposé ; la progression se lit dans le
  journal de l'unité, la fin est auditée (`pilotage_resultat`, `succes`/`echec`).
- **Audit** : une ligne JSON par demande, refus, consentement et résultat dans `/var/log/secubox/audit.log` (ouvert sans
  suivre de lien ; identifiants seulement, jamais une valeur secrète ni l'argv refusé). `politique` n'est pas auditée.
- État root `0700` `/var/lib/secubox-pilotagectl` (tmpfiles.d du paquet) : consentements, mains liées, opération en
  cours. Non fiable (propriétaire, droits, lien) : tout est refusé.
- `SBX_RACINE` (tests seulement) n'est honorée que si l'appelant est le processus lui-même ; jamais sous sudo depuis un
  autre compte.

## Ancre du maître (D1)

L'agent ne parle qu'au vrai maître : **au démarrage, puis toutes les heures**, il appelle
`sudo -n /usr/sbin/secubox-pilotagectl ancre-verifier`. Le ctl rend toujours le code 0 et l'un de ces verdicts :

| Sortie du ctl | Cas | Comportement de l'agent |
|---|---|---|
| `{"ok": true}` | le pair du maître a la clé de l'ancre | canal ouvert, Operate traités |
| `{"ok": false, "raison": "absente"}` | aucune ancre posée : pas d'`ancre-maitre.json` sur une box du propriétaire, pas de configuration `wg-autoload` sur une box cliente | **canal ouvert en lecture** (comme en L1) ; **tout Operate est refusé** (`ancre absente : action refusée`), et chaque refus redemande la vérification au ctl, qui l'audite « ancre absente » (R-L2-19) |
| `{"ok": false, "raison": "differente"}` | le pair qui porte l'adresse du maître a une autre clé, ou aucun pair ne la porte | **canal coupé** |
| `{"ok": false, "raison": "illisible"}` | ancre en JSON invalide, clé mal formée, lien, droits ; `wg` en échec ou sortie illisible | **canal coupé** |

Côté agent, toute autre sortie, une erreur ou un code non nul vaut `illisible` (fermé par défaut).

- **Canal coupé** : ni bonjour, ni sondage, ni réponse, ni notification vers le maître, et aucun Operate traité.
  L'agent revérifie avec un recul doublé de 5 s jusqu'à 1 h (chaque échec écrit une ligne d'audit). Une revérification
  horaire qui échoue coupe le canal en cours de route. À la reconnexion suivante qui réussit, l'agent notifie la coupure
  au maître : événement `X_SECUBOX_AnchorFailed` (`value` = instant Unix de la coupure).
- Ce que vérifie le ctl (root), sur l'interface choisie comme pour la politique (R-L2-9) :
  - **box du propriétaire** (interface `wg-mesh` présente) : le pair de `wg-mesh` qui porte `10.10.0.1` doit avoir la
    clé `cle_publique` de `/etc/secubox/p2p/ancre-maitre.json` (ancre posée au flash ou à la jonction, #3100). Le
    fichier appartient à root ou au compte `secubox` (premier-pas l'écrit sous ce compte) et n'est inscriptible ni par
    le groupe ni par les autres, sinon il est « illisible » (R-L2-20) ;
  - **box cliente** (sans `wg-mesh`) : le pair de `wg-autoload` qui porte `10.64.0.1` doit avoir la clé du hub reçue à
    l'enrôlement Auto-Load (le `hub.pub` du hub, rendu par HTTPS épinglé et écrit par `secubox-autoload-agent` dans
    `PublicKey` de `/etc/wireguard/wg-autoload.conf`, root 0600, un seul `[Peer]`) (R-L2-17).
  - Le pair retenu est celui que WireGuard choisit pour l'adresse du maître (`wg show <interface> allowed-ips`, préfixe
    le plus long) : un pair qui s'approprie `10.10.0.1/32` l'emporte sur le `/24` du maître et la vérification échoue.
  - Comparaison en temps constant (`hmac.compare_digest`). `/usr/bin/wg` est lancé par chemin absolu, sans shell, et
    seulement si une ancre est posée. Aucune clé n'est recopiée dans l'audit ; une réussite n'est pas auditée.
- **Limites connues** :
  - box cliente (R-L2-17) : l'ancre et l'interface viennent du même fichier `wg-autoload.conf`. Le contrôle détecte un
    pair injecté à chaud ou un préfixe qui détourne `10.64.0.1`, pas une réécriture du fichier, qui exige root sur la
    box. Un `hub.pub` séparé posé par `secubox-autoload-agent` est une amélioration hors L2 ;
  - box sans ancre (R-L2-19) : la lecture reste servie au pair du maillage sans vérification de sa clé, comme en L1 ;
    les actions attendent qu'une ancre soit posée ;
  - une coupure en cours n'est pas notifiée si l'agent redémarre entre-temps (l'audit du ctl garde chaque échec).

## Durcissement

Utilisateur `secubox-pilotage-agent`, `ProtectSystem=strict`, `ReadOnlyPaths=/`, aucune capacité ambiante,
`IPAddressDeny=any` (sauf `10.10.0.1`, `10.64.0.1`, localhost), `MemoryMax=32M`, profil AppArmor enforce
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
