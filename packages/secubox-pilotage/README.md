<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
Source-Disclosed License — All rights reserved except as expressly granted.
See LICENCE-CMSD-1.0.md for terms.
-->
# secubox-pilotage — maître du pilotage distant (#3126, L1 « Voir », L2 « Agir »)

Reçoit des agents (`secubox-pilotage-agent`) des box du maillage et d'Auto-Load leurs relevés TR-181 et leurs notifications, tient l'inventaire
par box (SQLite) et l'expose à l'administrateur. Get, GetSupportedDM, Notify et `Device.X_SECUBOX_Releve.Mesurer()` ; en L2, les actions
du catalogue fermé, le journal des opérations et les sessions de support (voir « Actions »).

## Exécution
| Élément | Valeur |
|---|---|
| Service | `secubox-pilotage.service`, utilisateur `secubox-pilotage`, `/usr/sbin/secubox-pilotage-api` (lance par `secubox-pilotage.socket` et `secubox-pilotage-canal.socket`) |
| Administration | `/run/secubox/pilotage.sock` (0660, groupe `secubox`, créée par systemd) ; nginx `/api/v1/pilotage/` (`secubox-routes.d/pilotage.conf`), toutes les routes `require_jwt` ; module dédié de l'agrégateur (`DEDICATED_MODULES`) |
| Canal | `/run/secubox/pilotage-canal.sock` (0660, groupe `www-data`, créée par systemd), jamais exposée hors de l'écouteur nginx ; `/canal/v1/bonjour` : un par box et par 10 s (429 au-delà) |
| Processus | une seule boucle asyncio, les deux applis en `lifespan="on"` (les files sont en mémoire, la relève est partagée) ; code de sortie 1 si l'une ne démarre pas (le code d'un `SystemExit` d'uvicorn est journalisé) |
| Données | `/var/lib/secubox/pilotage/` (0750 `secubox-pilotage`), préparé par le postinst par descripteur (`init_donnees.py`) : systemd-tmpfiles refuse ce chemin ; SQLite en `temp_store=MEMORY` (le profil ne donne pas `/tmp`) |
| Audit | `/var/log/secubox/audit.log` (propriétaire et droits inchangés) ; AppArmor en ajout seul ; ACL `u:secubox-pilotage:rw-` posée par `secubox-pilotage-audit-acl` (reposée après chaque rotation par l'unité de l'écouteur), retirée par le postrm au `remove` et au `purge` (journal courant et journaux tournés, jamais à travers un lien ; rien à l'`upgrade`) |
| AppArmor | `secubox-pilotage-api` et `secubox-pilotage-invite` (assistant de jonction), enforce ; déchargés par le postrm au `remove` |
| Menu | aucune entrée propre : le panneau « Pilotage » est dans la page Flotte de secubox-annuaire ; paquet `hors-arbre` des méta-paquets (installé à la demande) |

## Écouteurs de tunnel
`secubox-pilotage-ecoute` (root) rend `/etc/nginx/conf.d/secubox-pilotage-canal.conf` : un `server` par IP de tunnel présente,
`10.10.0.1:8472` (wg-mesh) et `10.64.0.1:8472` (wg-autoload), `client_max_body_size 256k`, `proxy_read_timeout 60s`, 4 connexions par adresse.
L'identité d'une box est `X-Real-IP` = l'adresse du pair TCP (`$realip_remote_addr`) ; le realip hérité de `secubox-hub` / `secubox-realip`
est neutralisé dans le `server` (sinon un `X-Forwarded-For` forgé usurperait n'importe quelle box). Fichier retiré si `nginx -t` échoue
(sans rechargement) ; nginx rechargé seulement si le rendu change. `net.ipv4.ip_nonlocal_bind=1` est livré par le paquet.

Le gabarit pose aussi `X-SecuBox-Pilotage-Tunnel: 1`, et il est le seul : `secubox-proxy.conf` (secubox-core) le vide sur tout autre proxy, et
l'agrégateur ne relaie jamais `/api/v1/pilotage-canal/…`. Le canal refuse (403, audit `pilotage_identite_refusee`, `motif: hors_tunnel`) toute
requête qui ne le porte pas exactement une fois, avant de chercher l'identité (L2, M6). Il arrête un relais qui transmettrait les en-têtes du
client (agrégateur, toute autre entrée nginx) ; il ne protège pas contre un processus qui joint directement la socket, qui forge le marqueur
comme l'adresse : contre lui, la barrière reste la socket (0660, groupe `www-data`, nginx seul).

Il pose, dans la chaîne `input` de `inet filter` (base unifiée de secubox-hardening) ET de `inet secubox_filter`, juste avant la règle `drop`
(donc après les règles de ban), à chaud (`nft insert ... handle`) et dans `/etc/nftables.conf` :

    iifname "wg-mesh" ip saddr 10.10.0.0/24 tcp dport 8472 accept
    iifname "wg-autoload" ip saddr 10.64.0.0/16 tcp dport 8472 accept

Aucune table connue : le script le dit sur stderr et ne pose rien. `secubox-pilotage-ecoute --retirer` (appelé par le prerm) retire fichier nginx
et règles. Déclencheurs : `secubox-pilotage-ecoute.path` (changement de `wg_mesh.json` ou de `pairs-publics.json`) et `.timer` (5 min).

## Inventaire
Toutes les 60 s, un GET `Device.` par box en ligne. Une passe complète remplace l'inventaire de la box (chemins disparus purgés) ; une passe
tronquée, en erreur, avec une source en échec (`failed`) ou au-delà de 5 000 paramètres ajoute sans rien effacer (`inventaire_partiel`).
Un paramètre refusé seul (chemin hors `Device.` ou de plus de 256 caractères, valeur non JSON) n'entre pas, sans rendre la passe partielle.
Une valeur de plus de 64 Kio de JSON est **tronquée**, jamais jetée (début d'une liste, d'un objet ou d'une chaîne) ; son chemin figure dans
`inventaire_tronques` de `GET /boxes/{x}`. Seules les lignes changées sont écrites (une relève identique n'écrit que `inventaire_le`).
Au plus 10 000 lignes et 1 Mio de valeurs sérialisées (en octets UTF-8) par box : au-delà, les plus anciennes parmi celles absentes de la passe
courante partent (R39).

Une box sans aucun contact depuis 30 jours (dernier sondage ou bonjour, dernière relève rangée, dernière notification reçue : le plus récent)
est **oubliée** une fois par heure (M12) : sa ligne `boites`, son inventaire, ses événements et son relevé partent ; le journal des opérations et
des supports reste (borné par box). Audit `pilotage_box_oubliee` {box, cle, reseau, dernier_contact, jours}. Une box en ligne n'est jamais
touchée ; si elle revient, elle réapparaît comme une box neuve.
Garde contre un saut de l'horloge du maître (R-L2-45) : si un passage emporterait plus de la moitié des box connues (au moins 2), il
n'oublie rien, journalise et audite `pilotage_oubli_suspendu {candidates, total}` (une ligne par heure au plus) ; il est réévalué au passage
suivant. Une box seule vraiment muette depuis 30 jours reste oubliée normalement.

Refus d'identité du canal (`pilotage_identite_refusee`) : une ligne par adresse et par minute ; les refus tus entre deux lignes sont écrits
à chaque tour d'inventaire et à l'éviction d'une adresse de la table bornée (1 024), en ligne de décompte seul `{tus, vidage: tour|eviction}`
(M7) : aucun décompte n'est perdu.

## Actions (L2, tâche 6)
Toutes les routes portent `require_jwt` (administrateur réel), aucune route d'usager. Une box se désigne comme en L1 (clé ou nom unique).

| Route | Corps | Effet |
|---|---|---|
| `POST /boxes/{x}/actions/{action}` | `{"args": {...}, "confirmation"?: "<nom>", "support"?: "<id>"}` | Operate de l'agent ; réponse `{operation, box, cle, action, etat, job, raison, operation_etat}`, où `etat`/`job`/`raison` sont l'`OPERATE_RESP` **tel quel** (`accepte`, `consentement`, `refuse`) |
| `GET /operations?nom=&limite=` | | journal des opérations (200 par défaut, 1 000 au plus), le plus récent d'abord |
| `POST /boxes/{x}/support` | `{"duree_min": 1..240}` (30 par défaut) | `Device.X_SECUBOX_Support.Ouvrir() {id, duree_min}` ; réponse `{id, etat, job, raison, …}` (la box rend `consentement` : accord du détenteur en local) |
| `GET /boxes/{x}/support` | | sessions de la box |
| `DELETE /boxes/{x}/support/{id}` | | fermée sur le maître tout de suite, puis `Support.Fermer()` envoyé si la box est en ligne (`etat: hors_ligne` sinon) |

## Temps réel (L2, tâche 7)
`GET /api/v1/pilotage/boxes/{x}/flux` (`require_jwt`) : `text/event-stream`, à lire côté page par `fetch` + `ReadableStream` (l'en-tête
`Authorization` reste possible). Premier événement `etat {box, cle, connecte, en_ligne, support}`, puis :

| Événement | Contenu |
|---|---|
| `notify` | toute notification de la box (forme épurée du canal : `type`, `unit`, `value`, `job`, `etape`, `pct`, `rc`, `resume`, `id`, `etat`, `decision`, `fin`, `ts`) + `box`, `cle` |
| `operation` | `X_SECUBOX_OperationProgress` / `OperationDone` de la box, et la réponse à une action lancée (`operation`, `action`, `args`, `acteur`, `etat`, `job`, `raison`) |
| `etat` | `X_SECUBOX_HandsTied`, `Consent`, `Support` ; ouverture/fermeture de support demandée au maître ; `{perte: n}` (file pleine : n événements abandonnés, relire `GET /operations`) ; `{support: "termine"}` (fin de session d'une box cliente, le flux se ferme) |

Un commentaire `: battement` est envoyé toutes les 15 s sans événement. Chaque événement est une ligne `event:` et UNE ligne `data:` de JSON
(`ensure_ascii` : un saut de ligne, U+2028 ou un caractère de contrôle dans `resume`, `raison`, `args` ou `nom` est échappé). Les
notifications reçues « au moins une fois » peuvent se répéter : la page dédoublonne par `job` (et `id`).
- **Limite** : 4 flux au plus par login d'administrateur et 32 au total ; le suivant reçoit `429`. L'abonnement est libéré à la déconnexion, à la fin du flux, à
  une écriture en échec ou à l'arrêt du service. Files de 64 événements par abonné ; un abonné lent perd ses plus vieux, jamais un autre n'attend.
- **Box cliente (R-L2-31)** : `403` hors session de support ouverte et non échue ; vérifié à la connexion et à chaque battement. Box du
  propriétaire (maillage) : toujours servie à l'administrateur. Un événement `X_SECUBOX_Support` fait relire la session avant tout autre
  événement ; la fin annoncée de la session arme aussi l'échéance. Pendant un support, une box cliente est visible par **tout** administrateur du
  maître (la spec ne lie pas un administrateur à un client).
- **Session** : à chaque battement, et à l'échéance du jeton (`exp`), le flux revérifie dans un thread `secubox_core.auth.session_toujours_admin`
  (jeton non échu, `jti` vivant, administrateur réel actif) ; sinon `etat {session: "expiree"}` puis fermeture.
- **Arrêt du service** : le lanceur ferme la diffusion dès le signal d'arrêt (les flux se terminent), `timeout_graceful_shutdown=5`.
- **nginx** : `proxy_buffering off` et `proxy_read_timeout` (30 s au moins) du snippet `secubox-proxy.conf` suffisent (battement 15 s) ; l'application
  envoie `X-Accel-Buffering: no`. L'agrégateur qui sert ce module en interne doit relayer le flux sans tampon.

Catalogue fermé (`pilotage/operations.py`) :

| Action | Commande | `args` | Confirmation forte |
|---|---|---|---|
| `reboot` | `Device.Reboot()` | aucun | oui |
| `maj-paquets` | `Device.X_SECUBOX_Packages.MettreAJour()` | aucun | non |
| `service-demarrer`, `service-redemarrer` | `Device.X_SECUBOX_Services.Agir()` | `unite` (`^secubox-[a-z0-9][a-z0-9@.-]{0,62}\.(service\|timer)$`) | non |
| `service-arreter` | `Device.X_SECUBOX_Services.Agir()` | `unite` | oui |
| `renommer` | `Device.X_SECUBOX_Nom.Renommer()` | `nom` (libellé DNS) ; nom déjà porté par une box connue, un pair enrôlé de `peers.json` ou le maître : 409 | oui |
| `renouveler` | `Device.X_SECUBOX_Secrets.Renouveler()` | aucun | oui |

- **Confirmation forte** (box du propriétaire, réseau `maillage`) : `confirmation` doit être **exactement** le nom de la box, sinon 400,
  rien n'est audité ni envoyé. Sur une box cliente, l'accord du détenteur, donné sur la box, en tient lieu (la réponse est
  `consentement`, renvoyée telle quelle ; l'identifiant du consentement n'est pas transmis). Une confirmation fausse est refusée partout.
- **Acteur** : le login de l'administrateur (`sub` du JWT) part dans le champ `acteur` de l'Operate s'il a la forme
  `^[a-z_][a-z0-9_.-]{0,63}$` (R-L2-14) ; il est audité sur le maître dans tous les cas.
- **Délais et erreurs** : box hors ligne → 409 ; audit impossible → 503 (rien n'est envoyé) ; pas d'`OPERATE_RESP` en 90 s (plus que les 60 s que l'agent accorde au ctl) → 504,
  opération `sans_reponse` (si la box l'a exécutée quand même, son suivi la rattache par son job) ; `ERROR` de l'agent → `refuse`.
- **Support (R-L2-31)** : une action demandée **dans le cadre d'une session de support** porte `"support": "<id>"` ; le maître la
  refuse (409) tant que cette session n'est pas `ouvert` sur cette box, ou dès qu'elle a passé sa fin. Une action ordinaire de
  l'administrateur sur une box du propriétaire ne porte pas ce champ. **Box cliente** (réseau autre que `maillage`, I3, R-L2-47) :
  le catalogue n'est servi que pendant une session de support ouverte et non échue de cette box ; sans `support`, ou avec une
  session qui n'est pas la sienne, pas ouverte ou échue, 409, rien d'audité ni d'envoyé (la garde est côté serveur, pas
  seulement dans la page). La fin d'une session est la plus proche de la `fin` annoncée par la box
  (`X_SECUBOX_Support`, RFC 3339) et de la réception de `ouvert` plus la durée demandée (240 min pour une session que le maître
  n'a pas demandée) : passée cette fin, la session devient `expire` sans attendre de notification (R-L2-33). Un état terminal
  (`refuse`, `ferme`, `annule`, `expire`) ne se rouvre pas. `ouvert` n'est accepté que pour une session demandée par le maître,
  à l'état `demande` ou `en_attente` : une session inconnue du maître est rangée `inconnu` et ne s'ouvre jamais. Pas de réponse
  à `POST …/support` (504) : `sans_reponse`.
- **Audit maître** (`/var/log/secubox/audit.log`, jamais une valeur secrète) : `pilotage_action {box, cle, action, acteur, args,
  job, etat, operation?, support?}` (`args` : les paramètres validés, en JSON) à la demande (`etat: demande`, `job: null`) puis à la
  réponse ; `pilotage_action_resultat {box, cle, action, job, rc, resultat}` à la première fin d'une opération **rattachée** à une
  demande (une fin arrivée avant l'`OPERATE_RESP` est auditée à la fusion, avec son action, une seule fois) ; `pilotage_support {box, cle, acteur, id, duree_min, etat}` ;
  `pilotage_support_fermeture {box, cle, acteur, id}` ; `pilotage_rejoindre_envoye`, `pilotage_rejoindre_resultat`,
  `pilotage_rejoindre_echec {…, raison}` ; `pilotage_action_echue {box, cle, action, job, operation, demande_le, resultat:
  "inconnu", heures: 6}` (I4, une fois par opération).

### Table `operations` et suivi
Une ligne par demande (`id`), reliée au `job` de la box par l'`OPERATE_RESP`. Les notifications `X_SECUBOX_OperationProgress {job,
etape, pct}` et `X_SECUBOX_OperationDone {job, rc, resume}` arrivent « au moins une fois », parfois avant la réponse ou pour un job
inconnu : une ligne orpheline (`action: null`) est créée puis fusionnée dans la demande à la réponse ; seule la **première** fin
compte (une renotification ne réaudite rien et ne relance aucune suite) ; une progression ne recule jamais. `resultat` :
`succes` (`rc` 0), `echec`, `inconnu` (`rc` -1 ou absent : fin introuvable sur la box, `fins.json` évincé ou bus injoignable).
États : `demande`, `accepte`, `consentement`, `refuse`, `sans_reponse`, `en_cours`, `inconnu`, `termine`. 1 000 demandes gardées par box ;
les orphelines (jobs inconnus) ont leur propre plafond de **100** par box et n'évincent jamais une demande. Une fin non rattachée
n'est **pas auditée** (une box qui inventerait des jobs ne gonfle pas l'audit) : au plus une ligne de journal agrégée par box et
par minute.
Les fins ont leur propre fenêtre dans le plafond de 60 notifications par minute (l'agent retire une fin de sa boîte au 2xx).

**Clôture des opérations interrompues** (I4, R-L2-47, révision de R-L2-27). Une opération ne reste jamais « en cours » à vie :
1. **Fins récentes** : l'agent, à son démarrage (ancre vérifiée), relit au ctl les 20 dernières fins enregistrées sur la box
   (`fins-recentes`) et renvoie une `X_SECUBOX_OperationDone` pour chacune ; le maître dédoublonne par job (la première fin fait foi).
2. **boot_id** : le bonjour porte le `boot_id` de la box, gardé par box (`boites.boot_id`, migration au démarrage). Quand il change
   (un boot_id déjà connu, puis un autre), chaque `reboot` de la box encore `accepte` ou `en_cours` est clos `termine`, `rc` 0,
   « reboot : succès (redémarrée) », remis au suivi (audit `pilotage_action_resultat`) une fois ; un sondage sans boot_id ne change
   rien.
3. **Échéance** : à la passe horaire de l'inventaire, une opération encore `demande`, `accepte` ou `en_cours` **6 h** après sa
   demande passe à l'état `inconnu` (`resultat: inconnu`), auditée une fois (`pilotage_action_echue`) ; une orpheline y passe sans
   audit. Une fin réelle qui arrive ensuite l'emporte encore (`termine`).
Les autres notifications de L2 (`X_SECUBOX_HandsTied`, `X_SECUBOX_Consent`, `X_SECUBOX_Support`) vont dans `GET /evenements`
(colonnes `ident`, `etat`), dédoublonnées par `(type, id, état)`.

## Retour au maillage après un renommage (L2, tâches 5 et 6)
`pilotage/renommage.py` : après le `X_SECUBOX_OperationDone` **réussi** (`rc` 0) d'un `Renommer` sur une box du maillage,
`envoyer_rejoindre(files, box, operation, fin)` émet un code lié au nouveau nom (`/usr/bin/sbx-mesh-invite --code --nom
<nouveau> --json`, borné à 30 s, sortie vérifiée : forme, somme, nom) et le dépose dans la file de la box :
`OPERATE Device.X_SECUBOX_Maillage.Rejoindre() {"code"}`. La box le passe à son ctl sur l'entrée standard (R-L2-2) puis à
`secubox-automesh` ; la jonction sous le nouveau nom renomme le pair (#3213). Box cliente (Auto-Load), échec ou autre
action : rien n'est envoyé. Le code ne transite que par la file (le tunnel) : jamais dans un journal, l'audit
(`pilotage_rejoindre_envoye {box, nouveau, msg_id}`) ni une erreur (`ErreurRejoindre`), ni la base.

Câblage (tâche 6) : `pilotage.operations.Suivi`, partagé par le canal et l'API, reçoit la première fin du job et réclame la
suite en base (une seule fois, que la fin arrive avant ou après l'`OPERATE_RESP`). Le service du maître n'a ni sudo ni le compte
des jetons (`secubox`, propriétaire de `master-link/tokens.json`) : il écrit le seul **nom** sur
`/run/secubox-pilotage/invite.sock` (0600, `secubox-pilotage`) ; `secubox-pilotage-invite.socket` (`Accept=yes`) lance
`secubox-pilotage-invite@.service` au compte `secubox`, qui valide le nom et exécute l'argv fixe
`/usr/bin/sbx-mesh-invite --code --nom <nom> --ttl 600 --json` (jamais `--flash` ni `--adresse` ; code valable 10 min), au plus
**20 fois par heure** (compteur `master-link/pilotage-emissions.json`, 0600, sous verrou ; illisible ou lien : refus), puis rend
sa sortie sur la seule connexion (`{"erreur": "plafond"}` au-delà du plafond, audité par le maître en
`pilotage_rejoindre_echec {raison: "plafond"}` ; rien en cas d'autre échec ; le journal n'a que le code de sortie). L'assistant audite lui-même
`pilotage_code_emis {nom, ttl}` (ajout sans création ; audit impossible : rien n'est rendu). Unité durcie (socle § 10,
`ReadWritePaths=-/var/lib/secubox/p2p/master-link /var/log/secubox`, `AF_UNIX AF_NETLINK`, `IPAddressDeny=any`, 60 s au plus) et
profil AppArmor **enforce** `secubox-pilotage-invite` (`AppArmorProfile=`, chargé par le postinst) : python3, `sbx-mesh-invite` et
`ip` en `ix`, arbre p2p en lecture, `master-link` en écriture, audit en ajout seul, netlink, aucun shell ni réseau IP.
Échec d'émission : `pilotage_rejoindre_echec` (sans le code). Le pair est renommé côté p2p par la jonction sous le nouveau nom
(#3213) ; la box réapparaît alors sous sa nouvelle clé `maillage:<nouveau>`, l'ancienne passe hors ligne avec son historique.

## Tests
`cd packages/secubox-pilotage && python3 -m pytest -q`. `tests/test_contrat_go.py` rejoue contre le vrai canal (et le vrai stockage) les
enveloppes figées par le client Go (`packages/secubox-pilotage-agent/internal/canal/testdata/contrat/`, régénérées par son test
`TestContratEnveloppesEmises`).

Contrat maître → agent (N5/M14), `tests/test_contrat_maitre.py`, dans les deux sens :

- le VRAI contrôleur (tour d'inventaire, `GET /boxes/{x}/lire`, `POST …/releve`, les sept actions, ouverture et fermeture du support, Rejoindre
  après un renommage réussi, avec un code **factice** au bon format) produit chaque requête déposée pour la box ; elle doit être octet pour
  octet la fixture de `…/testdata/contrat/maitre/`, que le test Go `TestContratRequetesDuMaitre` (cmd/sbx-pilotage-agent) rejoue contre le
  vrai client et le vrai exécuteur de l'agent. GetSupportedDM a pour producteur `pilotage.files.requete_modele()` : le maître ne l'émet pas
  encore en production (le bonjour porte le modèle) ;
- ce que le vrai agent émet en retour pour L2 (`…/contrat/agent-l2/` : OPERATE_RESP des actions, réponse du relevé de performance,
  OperationProgress, OperationDone, HandsTied, Consent, Support) est rejoué contre le vrai canal, le vrai stockage, le suivi et les routes ;
- une fixture altérée échoue des deux côtés (tests `…alteree_echoue`).

Régénération après un changement voulu : `SECUBOX_CONTRAT_MAJ=1 python3 -m pytest tests/test_contrat_maitre.py -k figees`, puis
`SECUBOX_CONTRAT_MAJ=1 go test ./cmd/sbx-pilotage-agent -run TestContratRequetesDuMaitre` dans l'agent, puis les deux suites.
