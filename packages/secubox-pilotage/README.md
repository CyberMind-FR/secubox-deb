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
| Identité | adresse source du tunnel : `10.10.0.0/24` → projection `/var/lib/secubox/p2p-public/pairs-enroles.json` publiée par secubox-p2p (pairs enrôlés seulement ; `/var/lib/secubox/p2p` est 0700 et n'est jamais lu) ; `10.64.0.0/16` → `/var/lib/secubox/autoload-public/pairs-publics.json`. Fichier absent ou illisible : aucune box identifiée (403), une ligne de journal par changement d'état |
| Audit | `/var/log/secubox/audit.log` (propriétaire et droits inchangés) ; AppArmor `w` (pas `a` seul, qui refuse `write()` après l'ouverture `O_APPEND`, banc gk2) et ajout seul tenu par le code (ni création ni troncature) ; ACL `u:secubox-pilotage:rw-` posée par `secubox-pilotage-audit-acl` (reposée après chaque rotation par l'unité de l'écouteur), retirée par le postrm au `remove` et au `purge` (journal courant et journaux tournés, jamais à travers un lien ; rien à l'`upgrade`) |
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

`GET /boxes` (résumé par box) porte aussi `interface` (L5 tâche 7) : `distante` si l'agent déclare
`Device.X_SECUBOX_Pilotage.Interface = "distante"` (profil léger de secubox-profiles), `locale` sinon (agent plus ancien,
valeur absente ou hors liste). Le panneau « Flotte » (secubox-annuaire, `/fleet/`) en tire le lien d'ouverture de la box :
`distante` ⇒ `/api/v1/pilotage/boxes/<box>/connexion-vhost` sans `retour` (racine ; `retour=/` est refusé, 422 : seul
`/<module>/` est admis), ouvert dans un nouvel onglet, donc authentifié par le **cookie de session** du maître (GET :
`require_jwt` l'accepte sans garde d'origine ; test `test_emission_du_code_par_la_seule_session_cookie`) ;
`locale` ⇒ `https://admin.<box>.secubox.in/`.

## Actions (L2, tâche 6)
Toutes les routes portent `require_jwt` (administrateur réel), aucune route d'usager. Une box se désigne comme en L1 (clé ou nom unique).

| Route | Corps | Effet |
|---|---|---|
| `POST /boxes/{x}/actions/{action}` | `{"args": {...}, "confirmation"?: "<nom>", "support"?: "<id>"}` | Operate de l'agent ; réponse `{operation, box, cle, action, etat, job, raison, operation_etat}`, où `etat`/`job`/`raison` sont l'`OPERATE_RESP` **tel quel** (`accepte`, `consentement`, `refuse`) |
| `POST /boxes/{x}/oublier` | `{"confirmation": "<nom>", "force"?: true}` | #3335 « Oublier ce nœud » : retire la box de la Flotte (boites, inventaire, événements, relevé) ; 400 si le nom retapé diffère, 409 si vue depuis moins de 10 min sans `force` ; audit `pilotage_box_oubliee` |
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
| `renommer` | `Device.X_SECUBOX_Nom.Renommer()` | `nom` (libellé DNS) ; nom déjà porté par une box connue, un pair enrôlé de la projection `p2p-public/pairs-enroles.json` ou le maître : 409 | oui |
| `renouveler` | `Device.X_SECUBOX_Secrets.Renouveler()` | aucun | oui |
| `interface-distante`, `interface-locale` | `Device.X_SECUBOX_Pilotage.Interface.Basculer()` | aucun (`sens` posé par le maître) — #3302 | oui |

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

## Bascule d'interface locale ⇄ distante (#3302)

Depuis la Flotte, `interface-distante` fait appliquer à la box son profil léger `distante` (webui retirée, servie par le maître
sur `admin.<box>`), `interface-locale` lui rend le profil d'avant. La box ne garde « distante » qu'à la **confirmation du
maître** : après le `X_SECUBOX_OperationDone` réussi (`rc` 0) d'`interface-distante`, `Suivi` envoie une fois
`OPERATE Device.X_SECUBOX_Pilotage.Interface.Confirmer() {"job"}` (le job de la bascule ; audit `pilotage_interface_confirmation` : `envoyee`, puis
`accepte`, `refuse` avec la raison, ou `sans_reponse` au bout de 120 s). Sans confirmation sous `delai_garde_s` (600 s par
défaut, `/etc/secubox-pilotage/interface.toml` de la box), l'homme mort de la box rend l'interface locale ; la reprise du nom
`admin.<box>` suit ensuite l'interface déclarée par l'inventaire (basculement de `secubox-pilotage-vhost`, inchangé).

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

## Pilotage HTTP des box légères (L5, tâche 3)

`pilotage.files.demander_http(files, box_cle, methode=, chemin=, acteur=, maitre=, portee=, agent_version=, audit=, entetes=,
corps=, version_page=, delai=40)` (`agent_version` et `audit` obligatoires) envoie un message `HTTP` à l'agent de la box et rend `{statut, entetes, corps}` (octets). Le corps du message
est l'entrée du relais local de la box (`methode`, `chemin` `/api/v1/<module>/…`, `entetes`, `corps_b64`, `acteur`, `maitre`,
`portee`, `version_page`) ; la réponse `HTTP_RESP` arrive par `POST /canal/v1/http` (6 Mio) ou, courte, par `/reponses`.

- Refus avant tout envoi : `DemandeHTTPInvalide` (400 forme, 413 corps > 4 Mio), `AgentTropAncien` (agent < 0.4.0 : rien n'est
  déposé dans sa file), `AgentHorsLigne` (aucun sondage depuis 10 s), `FileDeBoxPleine`, `AuditIndisponible` (écriture sans
  fonction d'audit, ou ligne d'audit non écrite).
- `POST /canal/v1/http` : 30 réponses inattendues par box et par minute au plus, puis 429 avant la lecture du corps.
- Ensuite : `DelaiHTTPDepasse` (504 ; requête retirée), `ReponseHTTPInvalide` (502 : ERROR d'un agent sans HTTP, forme bancale).
- **Portée** : `portee_permise(reseau, mains_liees, support_ouvert, demandee)` — `demandee` est ce que la session du maître
  autorise ; mains liées (ou inconnues) ⇒ `lecture` ; box cliente ⇒ `admin` seulement pendant un support ouvert. L'agent la
  recalcule (mains liées, ctl root) et ne peut que la réduire encore.
- Audit : chaque écriture (POST/PUT/PATCH/DELETE) `pilotage_http` avant l'envoi (`etat: demande`) et à la réponse
  (`etat: rendu`, `statut`) ; jamais le corps ni la requête `?…`. Le corps d'une page n'est jamais rangé en base.

## Pages des box sans tête (L5, tâche 4)

`/usr/sbin/secubox-pilotage-www` (root, lancé par le seul ctl root `secubox-pilotage-vhost` ; aucune règle sudoers depuis 0.5.3) prépare,
pour chaque version de paquet déclarée par une box, les pages de **cette** version (spec D5 : une page ne parle qu'à l'API de
sa version). Sortie : une ligne JSON sans chemin ; codes 0, 1 (refus/erreur), 2 (argv ou configuration).

- `extraire [--acteur A] <paquet> <version>` : paquet `^secubox-[a-z0-9-]{1,60}$`, version `^[0-9][A-Za-z0-9.+~:-]{0,62}$`.
  Chaîne de confiance : `dists/<suite>/InRelease` vérifié par `gpgv` avec le trousseau des clients apt SecuBox
  (`/usr/share/keyrings/secubox.gpg`, clé TOML `trousseau`), chaque `Packages` vérifié par sa somme dans ce Release, puis le
  `.deb` par la sienne dans `Packages` (index divergents pour une même version : refus). Trousseau absent : **repli annoncé**
  sur stderr et dans la sortie (`"verification": "proprietaire"`) : tout le chemin lu (racine, dists/, Packages, pool/,
  .deb) doit appartenir à root sans écriture groupe/autres, sinon refus. Le dépôt est parcouru par descripteur (O_NOFOLLOW) :
  un lien dans le chemin du pool est refusé.
  Le `.deb` est trouvé par `dists/<suite>/main/binary-*/Packages` du dépôt local (`Filename` sous `pool/`, `SHA256`, `Size`),
  recopié dans un fichier privé et vérifié (somme ou taille différente : refus, rien sur disque), puis lu en ar + `data.tar`
  (xz, gz, bz2, sans compression ; zst par `/usr/bin/zstd`) **sans dpkg** : aucun script de mainteneur. Seul
  `usr/share/secubox/www/` est copié (chemin des pages vérifié sur secubox-dns, secubox-admin, secubox-ad-guard) vers
  `/var/lib/secubox-pilotage-pages/www/<paquet>/<version>/` (root, parents tous root 0755 — I5, T5 — fichiers 0644, dossiers 0755 ; manifeste `.<version>.json` à côté).
  Dossier temporaire frère puis renommage ; version présente et intacte (manifeste, sommes, modes) : `{"deja": true}`.
- `purger [--acteur A]` : lit sur **stdin** `{"en_usage": [{"paquet": …, "version": …}, …]}` (≤ 1 Mio, motifs entiers ; clé
  ou champ en trop : code 2) ; supprime les versions extraites qu'aucune box ne déclare depuis **7 jours**. Horodatage « dernière
  déclaration » tenu par root dans `www/.vu.json` (une version extraite inconnue de l'état reçoit un délai complet).
- `lister` : `{"versions": [{paquet, version, taille, date}]}`, non audité.
- Audit (`acteur` déclaré par `--acteur` et `appelant` = SUDO_USER validé, « inconnu » sinon) : `pilotage_www_extraire` (`resultat` ok, deja, refus, erreur ; `motif` ; `verification` signature|proprietaire) et `pilotage_www_purger` (`purgees`) dans
  `/var/log/secubox/audit.log`, ouvert sans suivre de lien ; audit impossible ⇒ échec.
- Refus : chemin absolu ou `..`, nom non UTF-8 ou à caractère de contrôle (toute l'archive) ; sous les pages : lien symbolique
  absolu ou contenant `..`, écriture à travers un lien de dossier, lien dur vers un fichier hors des pages, fichier spécial, setuid/setgid, entrée en double, plus de
  20 000 entrées ou 64 Mio ; `.deb` > 512 Mio.
- Configuration facultative `/etc/secubox/pilotage-www.toml` (root, non inscriptible par d'autres) : `depot_apt` (défaut
  `/data/apt`, R-L5-1), `trousseau`, `suite` (`trixie`), `taille_max_mio`, `fichiers_max`, `deb_max_mio`.
- `www/` est créé par le ctl lui-même, par descripteur (pas de tmpfiles : « unsafe path transition » sous
  `/var/lib/secubox/<module>/`), refusé s'il est un lien ou n'appartient pas à root. Pas de profil AppArmor propre au ctl
  (comme les autres assistants root du paquet).

**Contrat pour T5** (service du maître) : le service appelle `sudo -n /usr/sbin/secubox-pilotage-www extraire --acteur
<admin de la session require_jwt> <paquet> <version>` pour chaque paquet déclaré dans `Device.X_SECUBOX_Packages`, et, une fois
par jour au moins, `purger` avec sur stdin l'union des versions déclarées par toutes les box connues. La liste passe par stdin
(et non par un fichier que root relirait dans un dossier du service) : aucun chemin choisi par un compte non root n'est ouvert
par root, et l'entrée est validée en entier avant toute suppression. Le service ne peut, au pire, qu'avancer la purge d'une
version non déclarée (jamais toucher hors de `www/<paquet>/<version>`). `--acteur` est déclaré par l'appelant : l'audit
porte aussi `appelant` (le compte sudo réel). Accepté (M5, R-L5-23) : un appelant autorisé peut faire extraire n'importe
quelle version publiée du dépôt (bornée par les limites) ; ce n'est pas une élévation.

Exigences pour T5 (I5, R-L5-23) : les pages sont servies depuis un chemin dont **tous les parents appartiennent à root**
(pas sous `/var/lib/secubox/pilotage`, possédé par le service : déplacer ou recopier `www/`) ; nginx refuse les fichiers en
point (`.vu.json`, `.<version>.json`, `.tmp-*`) et ne sert que `www/<paquet>/<version>/` ; CSP stricte ; origine distincte
de l'admin du maître ; la route qui sert les pages prend acteur et portée dans la session `require_jwt` (exigence M3 de T3).

## Vhost `admin.<box>.secubox.in` d'une box légère (L5 tâche 5)

Une box légère (inventaire : `Device.X_SECUBOX_Pilotage.Interface = "distante"`, posé par le profil léger — T6) n'a pas d'interface
d'administration : le maître la sert sous une **origine à elle**, jamais celle de son admin, par la chaîne normale
HAProxy TLS 1.3 → sbxwaf → nginx.

- **Plan d'exposition** (L5 tâche 6, E4) : à chaque tour d'inventaire, le service écrit aussi `/var/lib/secubox/pilotage/exposition.json` (0640, atomique, seulement s'il change) : `{"version": 1, "boxes": [{adresse, box, distante, noms, ports, releve_le}]}` pour les box du maillage au nom et à l'adresse uniques, depuis `Device.X_SECUBOX_Exposure.Names|Ports` (noms `<svc>.<box>.secubox.in` seulement, 64 au plus ; ports entiers 1..65535, 256 au plus ; valeur tronquée : box absente). Relu par `secubox-relais-maillage` (root) ; aucune route sans jeton.
- **Plan** : à chaque tour d'inventaire, le service écrit `/var/lib/secubox/pilotage/vhosts.json` (0640, atomique, seulement s'il change) :
  box « distante » de nom unique et valide (`^[a-z0-9-]{1,40}$`), versions déclarées (`Device.X_SECUBOX_Packages.{i}.Name/Version` ;
  un paquet déclaré avec deux versions n'est pas servi). 64 box et 256 paquets par box au plus.
- **`secubox-pilotage-vhost`** (root, `python3 -I`, verbes fermés `poser|retirer [--acteur A] <box>`, `synchroniser`, `lister`) :
  lancé par `secubox-pilotage-vhost.path` (plan changé) et `.timer` (toutes les heures), **jamais par le service** — celui-ci tourne
  `NoNewPrivileges` sans sudo (le sudoers de `secubox-pilotage-www` livré en T4, qui ne lui servait pas, est retiré en 0.5.3 par `rm_conffile`).
  `synchroniser` lit le plan à chemin fixe (sans lien, ≤ 1 Mio, validé en entier, sinon code 2 et rien touché), extrait chaque version
  (`secubox-pilotage-www extraire --acteur pilotage`), pose chaque vhost, retire ceux des box sorties du plan, puis `purger`.
  `poser` : server nginx `/etc/nginx/conf.d/secubox-pilotage-admin-<box>.conf` rendu par `pilotage/vhosts.py` sur les versions déjà
  extraites (modules listés par descripteur, arbre root vérifié), **double tampon** : tampon validé seul (`nginx -t -c` d'une enveloppe)
  → échange atomique → `nginx -t` complet → sinon ancien fichier rétabli (ou retiré) ; certificat exact ou joker `*.<box>.secubox.in`
  (sinon certbot webroot ; échec ⇒ aucun vhost public) ; `haproxyctl vhost add <dom> sbxwaf_inspector true` (jamais `waf_bypass`) ;
  `secubox-waf-route <dom> 9080` (adresse des voisins du port des vhosts nginx) ; `haproxyctl generate` + reload. `retirer` : server
  nginx (même garde), route sbxwaf (table réécrite atomiquement, voisins intacts), vhost HAProxy (`generate --allow-shrink`).
  Audit `pilotage_vhost_poser` / `pilotage_vhost_retirer` (`resultat` ok|deja|echec, `motif`). **Propriété** (C2) : noms
  réservés (nom du maître, `www`, `api`, `admin`, `apt`, modules de `/usr/share/secubox/www`) ; un domaine déjà présent dans HAProxy
  (`haproxyctl vhost list`), la table des routes ou un server nginx étranger est refusé ; ce que le pilotage crée est marqué dans le
  registre root `/var/lib/secubox-pilotage-pages/registre.json` (0644, dossier root 0755, lu par descripteur sans lien ; R-L5-26) AVANT création ; registre absent alors que des vhosts du pilotage existent : état incohérent signalé, rien fait ; l'ancien `/etc/secubox/pilotage-vhosts.json` est repris s'il est root et non inscriptible, et `retirer` refuse tout domaine non marqué. Nom de table
  HAProxy lu par `vhost list` (I5), codes retour de `vhost remove` et `cert sync` vérifiés. Échec certbot : pas de nouvel essai avant
  6 h pour ce domaine ; deux synchronisations espacées d'au moins 60 s ; attente hors verrou ; `.path` sans limite de déclenchement (elle le figerait), service à 6
  démarrages par 30 min (I4). HAProxy en mode `lxc` : refusé avec un message clair (M5). Joker et regex des `server_name` étrangers,
  nom public du maître (`[global] domain`) et certificat exact existant comptent comme « déjà servi » (M4). Unité en `ProtectSystem=strict` avec `ReadWritePaths` limités (M10). Au `remove` du paquet, le prerm retire tous les vhosts.
- **Server nginx** : `listen 0.0.0.0:9080`, `server_name admin.<box>.secubox.in` ; `/<module>/` → `alias
  /var/lib/secubox-pilotage-pages/www/<paquet>/<version>/<module>/` (jamais `www/` entier) ; CSP `default-src 'none'` + `script-src`,
  `style-src` limités aux chemins des pages servies (`https://admin.<box>/<module>/`, `/pilotage-connexion/`), jamais `/api/`
  (C1b) ; `connect-src`, `img-src`, `font-src` à `'self'`, `form-action 'none'`, `frame-ancestors 'none'` ; `nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Cache-Control: no-store` ; fichiers en point → 404 (au niveau du serveur ET dans chaque location de
  pages : `^~` coupe la recherche des regex) ; `disable_symlinks if_not_owner` ; `/api/v1/<module>/` → socket du service
  `/relais/<box>/api/v1/<module>/` avec `X-SecuBox-Version-Page: <paquet>=<version>` et `X-SecuBox-Pilotage-Box` posés, `Cookie` et
  marques `X-SecuBox-*` du client effacés, `Set-Cookie` masqué ; pas le snippet `secubox-proxy.conf` (il ajoute
  `Access-Control-Allow-Origin *`). Sur l'admin du maître, `/api/v1/pilotage/relais/` et `/vhost/` rendent 404 et ces en-têtes sont vidés.
- **Connexion** (R-L5-25 C1c) : les identifiants du maître ne sont saisis **que sur l'origine du maître**. L'administration du
  maître (`GET /api/v1/pilotage/boxes/<box>/connexion-vhost?retour=/<module>/`, `require_jwt`, donc 2FA du maître) émet un code à usage
  unique (≤ 60 s, en mémoire du contrôleur, lié à la box, à l'administrateur et à sa session `jti`, audit `pilotage_vhost_code`) et
  répond 303 vers `https://admin.<box>.secubox.in/pilotage-connexion/#code=…` (fragment : jamais envoyé ni journalisé). Cette page
  statique du paquet (aucun champ d'identifiants) poste le code à `/api/v1/auth/echanger` (seule route d'auth du vhost), qui le
  consomme à la première présentation (même refusée) et rend un **jeton à portée** : clé dérivée (HMAC de la clé du maître, M7),
  `aud = admin.<box>.secubox.in`, `iss = secubox-pilotage-vhost`, `scope = pilotage-vhost`, même `sub`/`jti`, `exp` ≤ maître et ≤ 4 h.
  Aucun cookie. Session du maître close ou administrateur déchu entre-temps : 401/403. Débit : 10 émissions par administrateur et
  10 échanges par adresse et par minute (429).
- **Basculement locale ⇄ distante** (R-L5-27) : jamais deux vhosts pour un nom. « Locale » : `secubox-relais-maillage` relaie
  `admin.<box>` vers le nginx de la box (vhost HAProxy vers sbxwaf_inspector, route sbxwaf vers l'IP maillée du pair `<box>`, celle que rend `secubox-relais-maillage pair-de <box>` : une route vers un autre pair, le maître ou une IP publique n'est pas reprise).
  « Distante » : le pilotage le sert. Source de vérité : la déclaration `Interface = "distante"` de l'inventaire (plan) + le
  registre root. `poser` d'un nom non marqué mais EXACTEMENT porté par relais-maillage (et par rien d'autre : aucun server nginx
  d'ici) : exclusion écrite d'abord (`/var/lib/secubox-pilotage-pages/exclusions-relais.json`, root 0644, que relais-maillage
  honore pour les seuls noms `admin.<box>.secubox.in`), marque avec `repris_de` et `route_avant`, `secubox-relais-maillage retirer
  <dom>` (vérifié), puis la pose normale ; échec à n'importe quelle étape ⇒ retour « locale » (retrait de ce que le pilotage a
  posé, exclusion levée, `secubox-relais-maillage relayer --sans-sonde <dom> <ip> <port>` — rétablissement direct, même pair muet —,
  marque ôtée ; chaque étape indépendante, erreur d'origine rendue). `retirer` d'un nom repris : retrait du vhost pilotage puis
  même retour ; s'il échoue, `retirer` échoue (`ok: false`, audit `resultat=echec`). Verrou commun avec relais-maillage
  (`verrou-relais.lock`, flock) tenu pendant tout le verbe, avant celui de conf.d ; relais-maillage le tient pendant toute sa passe.
  Verrou pris sans blocage jusqu'à 300 s (`SECUBOX_PILOTAGE_VERROU_S`), sinon sortie `{"ok": false, "occupe": true}` sans
  rien modifier (audit `pilotage_vhost_occupe`). Retour en échec : entrée gardée avec `etat = retour_en_attente`, reprise en tête
  de la passe suivante de `synchroniser`. Audit
  `pilotage_vhost_basculer` (`sens` distante|locale, `resultat`, `route`). Un nom porté par autre chose (vhost manuel, autre
  module, route vers une autre adresse) reste refusé (C2). Les autres noms de la box (hall, acces, waf…) ne sont jamais touchés.
- **Contrat pour T7 (panneau « Flotte » du maître, point d'entrée unique)** : box distante ⇒ ouvrir
  `https://<admin du maître>/api/v1/pilotage/boxes/<box>/connexion-vhost` (`?retour=/<module>/` facultatif ; la Flotte l'omet) ;
  box locale ⇒ lien direct actuel `https://admin.<box>.secubox.in/`.
- **Exceptions de garde** (M6, listées aussi dans `tests/publiques-assumees.txt`) : l'émission du code est un GET (lien de navigation
  porté par la session du maître) qui crée un état éphémère ; `POST /vhost/auth/echanger` n'a pas de garde (amorçage
  d'authentification) mais n'accepte qu'un code à usage unique ≤ 60 s émis sous `require_jwt`, avec un débit par adresse.
- **Relais** `GET|HEAD|POST|PUT|PATCH|DELETE /relais/{box}/api/v1/…` : Bearer à portée de CETTE box (401 sinon) ; en-tête de box de nginx
  = box du chemin (404 sinon) ; box inconnue, ambiguë ou non « distante » : 404 ; administrateur réel (403) ; box cliente : session de
  support ouverte requise (403, R-L2-31) ; 429 au-delà de 300 requêtes par minute par (administrateur, box) ; 409 si
  `X-SecuBox-Version-Page` ≠ version déclarée ; 501 agent < 0.4.0 ; 413 corps > 4 Mio (Content-Length ou flux). **Acteur = `sub` de la
  session, portée demandée = `admin`** réduite par `portee_permise` (mains liées ou inconnues ⇒ lecture) puis par l'agent : tout champ
  `acteur`/`portee` du client (corps, requête, en-tête) est ignoré. `demander_http` (audit obligatoire des écritures) ; en-têtes vers la
  box réduits à Content-Type/Accept/If-* (jamais Authorization ni Cookie) ; réponse : Content-Type, ETag, Last-Modified,
  réponse jamais exécutable (C1a) : JSON annoncé ⇒ `application/json`, tout autre type ⇒ `application/octet-stream` +
  `Content-Disposition: attachment` + `CSP: sandbox; default-src 'none'` ; `nosniff` partout ; ETag et Last-Modified seuls
  repris ; nginx pose aussi ces en-têtes (`always`) sur chaque location `/api/`. Le premier segment du chemin doit être un module
  du paquet annoncé par la version de page (I6, 409 sinon : modules lus dans l'arbre root des pages).
- **Limites** : la version comparée est celle que le server nginx sert pour le module (posée par nginx) ; une page chargée avant une
  régénération envoie la nouvelle version (le 409 couvre l'intervalle « box montée, vhost pas encore régénéré »). Une page malveillante
  d'un paquet signé ne voit jamais d'identifiants (saisis sur le maître seul) mais pourrait lire le jeton du vhost de sa box. Un
  module seulement monté dans l'agrégateur d'une box légère n'est pas joignable (R-L5-7). Pas de déconnexion côté vhost (jeton jeté
  par la page ; 4 h au plus). L'agrégateur du maître relaie `/api/v1/pilotage/…` en retirant le préfixe : un client pourrait y forger
  `X-SecuBox-Pilotage-Box` — sans effet utile : il faut les identifiants d'un administrateur du maître, et le relais exige le jeton à
  portée de la box.
- **Reste à T6/T7** : T6 pose `Interface = "distante"` (profil léger) et le DNS public `admin.<box>` (joker du pair) ; T7 : lien vers
  `https://admin.<box>.secubox.in/` dans la page Flotte, message « passez par les actions du pilotage » (R-L5-15), déconnexion.

## Modèle de confiance : un seul propriétaire

Le maillage a **un seul propriétaire**. Tout administrateur réel du maître (`require_jwt`, 2FA du maître) peut piloter
**toutes** les box du maillage dont il est propriétaire : il n'y a ni partage par box ni rôle intermédiaire. La portée
reste bornée sur chaque box (mains liées, routes déclarées dans `routes-ouvertes.d`, verbes fermés du ctl L2, accord du
détenteur pour les actions fortes). Une **box cliente** (détenue par un tiers) n'est pilotable que pendant une session de
**support ouverte** par son détenteur et avec son **accord** ; hors support : 403. Un maître compromis obtient donc la
portée administrateur sur les box du maillage, dans ces bornes.

Le code de connexion au vhost d'une box (`GET /boxes/{box}/connexion-vhost`) n'est émis qu'en `Sec-Fetch-Site`
`same-origin` ou `none` (403 sinon) ; sans cet en-tête (client non navigateur), la garde `require_jwt` seule s'applique.

## À vérifier au banc (T8)

- `nginx -t` réel dans l'unité `secubox-pilotage-vhost.service` : la configuration complète passe par
  `systemd-run --wait --pipe --collect --quiet /usr/sbin/nginx -t -q` ; la pré-validation du tampon reste dans le bac à sable.
- `ReadWritePaths` réels de cette unité (`haproxy.toml`, `waf/`, `conf.d`, dossiers HAProxy et certbot, `.well-known`) et
  `CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FOWNER` : `haproxyctl vhost add|generate|reload|cert sync`,
  `secubox-waf-route`, relais-maillage (le mode HAProxy LXC, `lxc-attach`, n'est pas couvert).
- certbot HTTP-01 en webroot depuis l'unité (`/usr/share/secubox/www/.well-known`).
- `/data/apt` lu en root et `gpgv` sur `InRelease` par `secubox-pilotage-www`.
- Basculement réel d'un nom avec `secubox-relais-maillage` (retrait du relais, pose du vhost, retour arrière).
- Mémoire du profil distant sur gk5 (box légère sans tête).

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

### Modules d'une box légère (#3324)

Sur `admin.<box>`, `GET /api/v1/pilotage-vhost/modules` (session du vhost) rend l'état des modules de la box, lu dans
l'inventaire (`Device.X_SECUBOX_Services`) ; les modules du groupe `distante` sont actifs avec `secubox-group@distante`.
`POST /api/v1/pilotage-vhost/modules/<module>/demarrer` émet l'action `service-demarrer` (`secubox-<module>.service`) avec les
mêmes gardes et le même audit que la Flotte (administrateur réel ; `auth`, `pilotage*` refusés). Page :
`/pilotage-connexion/modules.html`. La page Santé du hub appelle `/api/v1/health-doctor/`, relayé avec l'accueil.

Réponses sur place, sans relais (#3324) : `GET /api/v1/waf/stats` (si aucun module `waf` n'est servi) → `{"disponible": false}` ;
`GET /api/v1/hub/auth_mode` → `{"mode": "pilotage", "disponible": false}`. Modules exclus du pilotage qui livrent des pages
(`users`, `vault`, `portal`, `assist`, `premier-pas`) : `/<m>/` sert `/pilotage-connexion/reserve.html` (« réservé à
l'administration locale ») et `/api/v1/<m>/` répond 403 `{"detail": "réservé à l’administration locale", "reserve": true}`.
`/login.html` renvoie vers la connexion du maître.

## Installer une app (#3338)

`installer <secubox-…>` (agent : `Device.X_SECUBOX_Packages.Installer() {paquet}` ; maître : action `installer`, confirmation forte) : `apt-get install --no-remove` sans délai dans une unité transitoire, paquet connu des sources apt, profil de la formule si `/etc/secubox/abonnement.json` existe, opération longue exclusive, accord du détenteur lié au paquet pour une box cliente, refus sous mains liées, audit (`nom` = paquet).
