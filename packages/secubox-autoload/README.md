<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-autoload

Provisionnement réseau « Auto-Load », **côté infrastructure** (`admin.gk2.secubox.in`). Parent #2182, cadrage `docs/dossiers/provisionnement-auto-load.md`. Ce paquet ne s'installe pas sur une box cliente (l'agent côté box viendra en `secubox-autoload-agent`).

**État (0.3.0) :** le registre des jetons clients (#2185), le tunnel WireGuard côté infrastructure (#2189) et le service d'enrôlement et de panel (#2190). La WebUI (#2191) et le rapport final (#2192) sont livrés ; reste l'essai sur matériel (#2186).

## Jetons

- Un jeton **par box** : 128 bits aléatoires, préfixe `gk2_` (un jeton qui fuit se repère), soit `gk2_` + 32 caractères hexadécimaux, affichés **une seule fois** à l'émission, stockés sous forme d'**empreinte SHA-256**.
- **Usage unique** : la réclamation consomme le jeton et lie la box à sa **clé publique WireGuard** (générée sur la box, jamais dans l'image). Une même clé ne peut pas porter deux jetons.
- États : `emis` → `reclame`, ou `revoque` (à tout moment). Durée de vie avant réclamation : 90 jours par défaut, 365 au plus.
- **Abonnement par client** (`actif`, `suspendu`, `revoque`) : non actif = réclamation et nouvelles livraisons refusées. Une box déjà en service **garde toutes ses fonctions locales**.
- **Refus uniforme** : inconnu, expiré, déjà pris, révoqué, abonnement non actif, mauvaise clé : toujours « jeton refusé ». La vraie raison est dans l'audit.
- **Série préenregistrée** : un client « déjà pré-évalué » est préenregistré par numéro de série ; sa box reçoit son jeton à la volée (`reclamer_par_serie`), une seule fois.
- **Révocation** d'un jeton ou d'un lot ; sur un jeton déjà réclamé, rend la clé publique à retirer du tunnel (#2189).

## Tunnel (0.2.0, #2189)

Étoile : chaque box ouvre un tunnel WireGuard **sortant** vers ce hub (interface `wg-autoload`).

- Plage **10.64.0.0/16** (hub 10.64.0.1), **UDP 51830** ; distincte de `wg-mesh` (10.10.0.0/24, 51822) et `wg-ephemeral` (10.11.0.0/24, 51825).
- Un pair n'a droit qu'à **sa propre adresse /32** : les clients ne se voient pas.
- Adresses attribuées de façon idempotente et atomique ; une adresse ou une clé **retirée n'est jamais réattribuée** (une clé retirée exige un nouveau jeton).
- La clé privée du hub n'est **jamais** dans la configuration : `PostUp = wg set %i private-key /etc/secubox/secrets/autoload-hub.key` (0600).
- `autoloadctl tunnel-sync` valide (`wg-quick strip`), pose `wg-autoload.conf` atomiquement (0600) puis `wg syncconf` : aucun pair existant n'est coupé ; en cas d'échec l'ancienne configuration reste.
- Pare-feu : l'infrastructure ouvre UNIQUEMENT udp/51830 en entrée (règle à poser avec le service d'enrôlement, #2190).

## Service d'enrôlement et panel (0.3.0, #2190)

Deux applications dans un processus (`/usr/sbin/secubox-autoload-api`), utilisateur dédié `secubox-autoload`, unité durcie, profil AppArmor enforce.

**Publique** (socket `/run/secubox/autoload.sock`). Les routes sont **à la racine** : l'agrégateur relaie `/api/v1/autoload/…` vers la socket en retirant le préfixe (convention de la plateforme ; aucune configuration nginx propre au module). Les chemins ci-dessous sont ceux du service ; publiquement, ajouter `/api/v1/autoload` :

| Route | Garde | Rôle |
|---|---|---|
| `POST /enrol` | **le jeton est la preuve** (publique assumée) | `{jeton|serie, cle_pub}` → `{client, profil, lot, tunnel}` ; refus uniforme 403 ; 10 essais refusés par 10 min et par source (429) ; la même clé peut rejouer après une coupure |
| `GET /health` | sonde | `{ok}` |
| `GET /boxes`, `/jetons`, `/prerapports`, `/prerapports/{empreinte}` | `require_jwt` (même la lecture : identité des clients) | suivi : statut (en attente, préparation, en cours, terminé, révoqué) et progression en %, jamais la valeur d'un jeton |
| `POST /jetons` | `require_jwt` | `{client, profil, lot?, serie?, duree_jours}` → la valeur `gk2_…`, montrée **une seule fois** |
| `POST /jetons/{id}/revoquer` | `require_jwt` | révoque, retire le pair du tunnel et relance `tunnel-sync` (même sans pair) ; rend `tunnel_applique` |
| `POST /clients/{client}/abonnement` | `require_jwt` | `{statut, mois?, formule?}` (échéance calendaire) ; relance `tunnel-sync`, qui republie la projection (#3126) ; rend `tunnel_applique` |
| `POST /lots/{lot}/revoquer` | `require_jwt` | révoque tout un lot (jetons non réclamés et box déjà réclamées, dont les pairs sont retirés) ; relance `tunnel-sync` |
| `POST /series` | `require_jwt` | préenregistre un numéro de série |
| `POST /prerapports/{empreinte}/refuser` | `require_jwt` | refuse un pré-rapport pendant le délai de grâce |

**Tunnel** (TCP `10.64.0.1:8470`, uniquement dans WireGuard, `IP_FREEBIND`) : `POST /progression`, `POST /prerapport`, `GET /prerapport/{empreinte}/refus`. L'identité de la box est l'**adresse source de la connexion** (WireGuard ne laisse passer d'un pair que sa propre adresse) ; aucun en-tête n'est cru, et ces routes n'existent pas dans l'application publique.

Le service n'est pas root, et aucune nouvelle unité root n'existe : il applique le tunnel par **deux argv exacts** (`sudo -n /usr/sbin/autoloadctl tunnel-sync` pour l'enrôlement, qui monte l'interface ; `… tunnel-sync --sans-reactiver` pour la minuterie, les révocations et l'abonnement ; `sudoers.d/secubox-autoload`). `NoNewPrivileges=no` est requis pour cela (exception notée dans `.claude/RULES-CODE.md`) ; le profil AppArmor reste en enforce.

Pare-feu : `udp/51830` en entrée et `tcp/8470` depuis `wg-autoload` seulement (`/etc/nftables.d/zz-secubox-autoload.nft`). La **redirection udp/51830 de la Freebox vers gk2** est à faire à la main. Journal d'audit : `/var/log/secubox/autoload/audit.log`.

## Abonnements & profils (0.8.0, #3303)

Page `www/autoload/abonnements.html` (lien depuis l'atelier). L'abonnement est porté **par box** (un jeton = une box) : formule, échéance,
statut (`actif`, `suspendu`, `revoque`, état calculé `echu`). Le client ne fait que regrouper. Aucune facturation, aucun prix.

- **Migration** (au démarrage du service, idempotente) : table `abonnements_box` ; toute box sans ligne hérite de l'abonnement **actuel**
  de son client ; une ligne existante n'est jamais touchée. Une box émise ou réclamée par série plus tard hérite de même.
- **Compatibilité** : `POST /clients/{client}/abonnement` fixe le client **et toutes ses box non révoquées**.
- **Formules** : table `formules` (nom → libellé, profil réel parmi `minimal, lite, isp, full, secure-gateway, media-lab, distante`,
  durée 1-120 mois). Changer le profil d'une formule ne touche aucune box : l'écart est signalé.
- **Profil appliqué** : lu dans `/var/lib/secubox/pilotage-public/profils-appliques.json`
  (`{"version": 1, "boxes": [{"adresse": "10.64.x.y", "profil": "<profil réel>"}]}`, 256 Kio au plus, publié par le pilotage) par l'adresse
  tunnel de la box. Absent ou mal formé : `profil_applique = null` (« inconnu »), jamais un écart inventé. « Appliquer le profil » est
  désactivé dans la page jusqu'à la bascule de profil du pilotage (#3302).
- **Projection du pilotage** : `abonnement` y est désormais celui de la **box** (celui du client si la base n'est pas encore migrée).

| Route | Garde | Rôle |
|---|---|---|
| `GET /abonnements` | `require_jwt` | une ligne par box : `id, box, client, serie, lot, jeton, formule, formule_libelle, expire_le, jours_restants, statut, motif, profil_commande, profil_formule, profil_applique, ecart` |
| `GET /formules` · `POST /formules` | `require_jwt` | catalogue ; `{nom, libelle, profil, mois}` (création ou mise à jour) |
| `POST /boxes/{id}/abonnement/prolonger` | `require_jwt` | `{mois}` : depuis l'échéance en cours, ou d'aujourd'hui si elle est passée ; 409 si révoquée |
| `POST /boxes/{id}/abonnement/formule` | `require_jwt` | `{formule}` du catalogue (422 sinon) |
| `POST /boxes/{id}/abonnement/suspendre` | `require_jwt` | `{motif}` obligatoire (3 à 200 caractères) |
| `POST /boxes/{id}/abonnement/reprendre` | `require_jwt` | `{motif?}` |
| `POST /boxes/{id}/abonnement/revoquer` | `require_jwt` | `{motif, confirmation}` : la confirmation est le nom de la box (série, sinon id) ; révoque son **seul** jeton et retire son pair |

Chaque action est auditée (`abonnement-box`, `formule`) et relance `tunnel-sync --sans-reactiver` (projection du pilotage à jour).

## Audit

Chaque émission, réclamation, refus (avec la raison), révocation et changement d'abonnement est ajouté à `/var/log/secubox/autoload/audit.log` (JSON, module `autoload`, logrotate hebdomadaire sur 52 semaines). **Jamais la valeur d'un jeton.**

## Commandes (root)

    autoloadctl emettre --client client-042 --profil lite [--lot lot-2026-10] [--serie S] [--duree-jours 90]   # la valeur est imprimée une fois
    autoloadctl preenregistrer --serie SBX-0001-AB --client client-042 --profil isp
    autoloadctl lister [--etat emis|reclame|revoque] [--client C] [--lot L] [--json]
    autoloadctl revoquer (--id N | --lot L) --motif "…"
    autoloadctl abonnement --client client-042 --statut suspendu
    autoloadctl tunnel-init      # clé du hub (0600) ; affiche sa clé publique
    autoloadctl tunnel-sync      # applique les pairs actifs (wg syncconf), puis exporte la projection publique (même si WireGuard échoue)
    autoloadctl tunnel-sync --sans-reactiver   # idem, sans relancer un wg-autoload dont l'unité est désactivée (minuterie, révocations, abonnement)
    autoloadctl exporter-pairs   # (re)publie pairs-publics.json (code non nul en cas d'échec)

**Projection publique des pairs (#3126).** `exporter-pairs` écrit `/var/lib/secubox-autoload-public/pairs-publics.json` (root, 0644, renommage atomique par descripteur ; dossier root:root 0755 créé par `autoloadctl` s'il manque, refusé s'il est un lien, n'appartient pas à root ou est inscriptible par le groupe ou les autres ; hors du dossier 0750 du service, qui n'y a aucune prise) pour que le maître de pilotage sache à quel client appartient l'adresse d'une box :

    {"version": 1, "pairs": [{"adresse": "10.64.0.9", "client": "lgm", "lot": null, "serie": null, "profil": "lite", "abonnement": "actif"}]}

Seuls figurent les pairs non retirés dont le jeton est réclamé ; `abonnement` est l'état calculé de `lister` (`actif`, `suspendu`, `revoque` ou `echu`) ; `lot` et `serie` valent `null` s'ils sont absents ; aucune clé, empreinte ni valeur de jeton. Base absente : `{"version":1,"pairs":[]}`. `tunnel-sync` l'appelle en dernier, **même si WireGuard a échoué** (une révocation atteint toujours la projection ; le code de retour dit l'échec du tunnel) ; l'échec de l'export est journalisé sur stderr sans faire échouer `tunnel-sync`.

**Un passage à la fois (#3126, L2).** `tunnel-sync` et `exporter-pairs` prennent un verrou (`flock` sur `/run/secubox-autoload/autoload-sync.lock` ; dossier à root seul, 0700, posé par `tmpfiles.d/secubox-autoload.conf` et créé au premier usage, jamais dans `/run/secubox` (1777) où n'importe quel compte pouvait bloquer toute révocation ; fichier ouvert sans suivre de lien, refusé s'il n'est pas un fichier ordinaire de root) : un passage horaire qui a lu les pairs avant une révocation ne repose plus le pair révoqué après la synchronisation de la révocation. Toute écriture du registre (enrôlement, révocation, abonnement) par l'API est suivie d'un `tunnel-sync` : le dernier passage voit toujours le dernier état.

**Fraîcheur (#3126, R37).** Toute révocation ou tout changement d'abonnement par l'API relance `tunnel-sync --sans-reactiver`, donc l'export : une box `revoque` ou `suspendu` n'est plus pilotée. Le service relance aussi `tunnel-sync --sans-reactiver` une minute après son démarrage puis toutes les heures (minuterie interne, pas d'unité de plus) : un abonnement dont l'échéance passe devient `echu` dans l'heure. Ces passages (minuterie, révocations, abonnement) ne relancent jamais `wg-quick@wg-autoload` si l'exploitant a **désactivé** l'unité (`systemctl disable --now`) : il pose la configuration et publie la projection ; une unité activée mais tombée est relancée. Un `tunnel_applique: false` signifie que le changement est enregistré et sera publié au passage suivant. En ligne de commande (`autoloadctl abonnement`, `revoquer`), la projection suit au prochain `tunnel-sync`, au plus tard dans l'heure.

Données : `/var/lib/secubox/autoload/jetons.db` (0600, dossier 0750). Variables : `SECUBOX_AUTOLOAD_DB`, `SECUBOX_AUTOLOAD_AUDIT`, `SECUBOX_AUTOLOAD_VERROU` (tests ; sudo les efface).

## Banc de bout en bout sans matériel (#2193)

`tests/test_banc_2193.py` fait tourner **ensemble** le vrai moteur de l'agent, le vrai client HTTP, le vrai service d'enrôlement (applications publique et tunnel), de vrais jetons, un fichier de réponses signé avec un vrai gpg et de vraies clés WireGuard ; seuls apt, systemctl et wg-quick sont des faux. Huit scénarios : parcours zero-touch complet (délai de grâce attendu, progression, audit sans valeur de jeton), refus de l'opérateur pendant la grâce (rien d'installé), infrastructure injoignable puis reprise sans rejouer l'enrôlement, jeton révoqué, abonnement suspendu puis réactivé, fichier de réponses modifié après signature, profil `isp`, box révoquée après coup (pair et livraisons retirés). Il ne remplace pas l'essai sur une vraie carte (#2186).

## Tests

    python3 -m pytest packages/secubox-autoload/tests

## Droits du maillage (#3305)

Un service du maillage n'est rendu à une box que si son abonnement est **actif** et que sa **formule l'inclut**.

- **Services** (liste fermée, `SERVICES_MAILLAGE`) : `annuaire-offres`, `bans-waf` (openpgp et macro viendront quand leur
  fournisseur sera câblé). Une formule porte
  `services` (`POST /formules`, champ facultatif, vide par défaut).
- **Formule `atelier`** semée à la première migration (profil `full`, 120 mois, tous services), jamais écrasée ensuite : gk2 et
  les box de l'atelier.
- **Pairs du maillage** (nom de `p2p-public/pairs-enroles.json`, empreinte facultative vérifiée par le fournisseur si posée) :
  `autoloadctl maillage --nom gk5 --formule atelier [--empreinte sbx-…] [--statut suspendu --motif …] [--mois N]`, ou
  `POST /maillage/<pair>` (`require_jwt`) ; lecture `GET /maillage`. La CLI écrit sous l'utilisateur du service puis republie
  aussitôt la projection (root).
- **Atelier inscrit d'office** : le postinst du maître lance `autoloadctl maillage-atelier`, qui inscrit en formule `atelier`
  (avec leur empreinte) les pairs enrôlés de `p2p-public/pairs-enroles.json` sans abonnement ; idempotent, audité
  (`maillage-atelier`) ; une ligne existante n'est jamais touchée. Suspension et révocation : motif obligatoire ; audit `maillage`.
- **Grâce** : un pair sans ligne garde ses services 5 jours après la première migration (`meta.grace_debut`), puis plus rien.
- **Projection** `/var/lib/secubox-autoload-public/droits-maillage.json` (root 0644, sans secret, écrite avec `pairs-publics.json`
  par `tunnel-sync`/`exporter-pairs`) :
  `{"version": 1, "grace_jusqu_a": <epoch>, "services": [...], "pairs": [{"nom", "empreinte", "formule", "statut", "expire_le", "services"}]}`
  (`statut` calculé, `echu` après l'échéance ; `services` vide si le pair n'est pas actif). Base illisible : le fichier n'est pas réécrit.
  Lu par l'annuaire du maître (`secubox-annuaire`, `annuaire/droits.py`).
