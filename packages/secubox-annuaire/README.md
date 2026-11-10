<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-annuaire

SecuBox Annuaire-Miroir — federated self-certifying trust substrate.

The Annuaire-Miroir is the trust directory for SecuBox-DEB, providing a BLAKE2b-chained, CONIKS-style append-only audit journal with four protocols: AUTO-ADD (provisional discovery), INVITE (capability-based membership), PROPOSAL (anti-plutocratic governance), and EMANCIPATE (staged anchor removal). All objects are Ed25519-signed, RFC 3339-timestamped, and access-gated by the can() resolver. Served on /run/secubox/annuaire.sock, JWT-gated.

Paquet Debian : version `0.18.2-1~trixie1`, architecture `all`.

## Contenu

- `annuaire/` : fichiers du module
- `api/` : API FastAPI
- `conf/` : configuration livrée
- `menu.d/` : entrée de menu
- `nginx/` : route nginx
- `sbin/` : exécutables
- `sysctl/` : fichiers du module
- `systemd/` : unités systemd
- `tests/` : tests
- `www/` : interface web

## Exécution

Socket Unix : `/run/secubox/annuaire.sock`, `/run/secubox/openpgp.sock`.
- `secubox-annuaire-apply.service` : SecuBox Annuaire — apply replicated config via 4R (gondwana P2, #768), lance `annuairectl`
- `secubox-annuaire-apply.timer` : SecuBox Annuaire — periodic config apply (gondwana P2, #768)
- `secubox-annuaire-bans-apply.service` : SecuBox Annuaire — enforce the federated ban union into nft (#768), lance `annuairectl`
- `secubox-annuaire-bans-apply.timer` : SecuBox Annuaire — periodic threatmesh ban enforcement (#768)
- `secubox-annuaire-noms.service` : SecuBox — la box se fait connaître : Bonjour + noms <box>.lan/.mesh (#1556), lance `secubox-annuaire-noms`
- `secubox-annuaire-noms.timer` : SecuBox — rafraîchir l'annonce Bonjour et les noms du maillage (#1556)
- `secubox-annuaire.service` : SecuBox Annuaire-Miroir — federated trust substrate API (utilisateur `secubox`), lance `python3`
- `secubox-metrics-publish.service` : SecuBox Annuaire — publish this node's signed fleet metrics snapshot (fleet-metrics) (utilisateur `secubox`), lance `sbx-fleetctl`
- `secubox-metrics-publish.timer` : SecuBox Annuaire — periodic fleet metrics publish (fleet-metrics)

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/health` | aucune |
| `GET` | `/status` | require_lecture |
| `GET` | `/log` | require_lecture |
| `GET` | `/verify-chain` | require_lecture |
| `GET` | `/merkle-root` | require_lecture |
| `GET` | `/can` | require_lecture |
| `GET` | `/proposal/{proposal_id}` | require_lecture |
| `POST` | `/auto-add` | require_jwt |
| `POST` | `/invite` | require_jwt |
| `POST` | `/join` | require_jwt |
| `POST` | `/proposal` | require_jwt |
| `POST` | `/proposal/{proposal_id}/vote` | require_jwt |
| `POST` | `/revoke` | require_jwt |
| `POST` | `/emancipate` | require_jwt |
| `GET` | `/services` | aucune |
| `POST` | `/service/offer` | require_jwt |
| `POST` | `/service/{service_id}/revoke` | require_jwt |
| `POST` | `/service/{service_id}/subscribe` | require_jwt |
| `GET` | `/subscriptions` | require_lecture |
| `POST` | `/subscription/{subscription_id}/approve` | require_jwt |
| `POST` | `/subscription/{subscription_id}/reject` | require_jwt |
| `POST` | `/self/service/offer` | require_jwt — offre de CE nœud signée par node.key (MirrorNet, #3647) |
| `POST` | `/self/service/{service_id}/subscribe` | require_jwt — abonnement de CE nœud (tarif de l'offre, échéance = maintenant + `duree_s`) |
| `POST` | `/self/subscription/{subscription_id}/renew` | require_jwt — `SERVICE_RENEW`, avant l'échéance |
| `POST` | `/self/subscription/{subscription_id}/cancel` | require_jwt — résiliation (abonné) ou révocation de l'abonné (fournisseur) |
| `POST` | `/self/subscription/{subscription_id}/approve`, `/reject` | require_jwt — décision du fournisseur sur une demande (#3651) |
| `POST` | `/services/pull` | require_jwt |
| `GET` | `/nodes` | require_lecture |
| `GET` | `/config` | require_lecture |
| `GET` | `/bans` | require_lecture |
| `GET` | `/log/export` | aucune |
| `POST` | `/node/publish` | require_jwt |
| `POST` | `/config/publish` | require_jwt |
| `POST` | `/config/revoke` | require_jwt |
| `POST` | `/log/pull` | require_jwt |
| `GET` | `/fleet/self` | aucune |
| `GET` | `/fleet` | require_jwt |
| `GET` | `/fleet/modules/self` | aucune (écoute du maillage :8799) — relevé de validation signé de cette box (#3212) |
| `GET` | `/fleet/modules` | require_jwt — relevés vérifiés de toutes les box + `indisponibles` (raison) |
| `GET` | `/centers` | require_lecture |
| `GET` | `/centers/ownership` | require_lecture |
| `GET` | `/centers/proposals` | require_lecture |
| `GET` | `/centers/effective/{scope}` | require_lecture |
| `POST` | `/centers/grant` | require_jwt |
| `POST` | `/centers/revoke` | require_jwt |
| `POST` | `/centers/proposal/accept` | require_jwt |

**Relevé de validation des modules (#3212)** : `sbx-fleetctl publish-modules` (à la suite de `publish`, dans
`secubox-metrics-publish.service`) signe `/var/lib/secubox/profiles/validation/releve.json` (secubox-profiles) en
`ModulesSnapshot` — modèle séparé de `MetricSnapshot`, borné (400 paquets, 16 unités, 5 erreurs de 200 caractères) —
et l'écrit en `/var/lib/secubox/annuaire/fleet/modules.json`. Saute si le relevé est absent ou inchangé.
`fleet.verify_modules` vérifie la signature ET la forme : un relevé bien signé mais hors bornes est refusé.
`/fleet/modules` tire chaque pair de `wg_mesh.json` en parallèle et nomme les box sans relevé lisible
(`injoignable`, `version trop ancienne` — 404, `signature invalide`, `relevé non publié`). Lu par
`/profiles/comparatif.html#parc`.

La page `/fleet/` (WebUI) lit `GET /fleet` (nœuds du maillage à annuaire) et, séparément, trois autres sources : `GET /api/v1/autoload/boxes` (box enrôlées par Auto-Load, #2840) et
`GET /api/v1/p2p/peers` (pairs `wg-mesh`, statut mesuré par poignée de main, #2842) ; `GET /api/v1/pilotage/boxes` (panneau « Pilotage », #3126 L1 : inventaire relevé par le maître, lecture seule, rafraîchi toutes les 30 s et au retour sur l'onglet, onglet masqué suspendu, valeur absente affichée « — », `mains_liees` absent « inconnu »). L2 : une ligne ouvre la page de la box (`/api/v1/pilotage/boxes/{x}/actions/{action}`, `/support`, `/releve`, `/operations`, `/flux`) : actions du catalogue, confirmation forte par retape du nom, journal des opérations, support, vue en direct par flux SSE (fetch + `Authorization`, dédoublonnage par `job`/`id`) ; boutons désactivés sous mains liées, box cliente sans catalogue hors support ouvert ; données en `textContent`). Décision R-L2-42 : sous mains liées (ou mains liées inconnues, ou box hors ligne), les boutons d'action sont affichés mais **désactivés, avec le motif** (ils ne sont pas retirés) ; seul le relevé reste. Le dernier « lié » reçu en direct (`X_SECUBOX_HandsTied`) prime sur un inventaire plus ancien ; la confirmation forte et l'argument sont vidés après chaque envoi ; un nom de box vide ne confirme rien ; le délai de reconnexion du flux ne repart de 3 s qu'après un événement reçu. #3302 : la page de la box propose aussi la bascule d'interface utile (« Passer en interface distante » depuis une box locale, « Revenir à l’interface locale » depuis une box distante), avec confirmation forte ; la box ne reste en distante que si le maître la confirme (automatique), sinon elle revient seule en locale. Un panneau est masqué si son module est absent ou si sa liste est vide.

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-core`.

## Tests

45 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-annuaire`.

## Services des pairs : domaines admis (#3146)

Le cache `services-pairs.json` ne retient qu'un pair dont le domaine ddns est `<un libellé>.secubox.in`.
Pour en admettre d'autres, lister un domaine par ligne (`#` = commentaire) dans
`/etc/secubox/annuaire/domaines-pairs.txt` (facultatif). Le cache est reconstruit à la prochaine passe de `annuairectl pairs-cache`.

## Offres du Hall et Flotte (#3335)

- Une carte du Hall (`FEATURED`) n'est publiée comme offre `app` que si son hôte est un vhost déclaré par CE nœud (`domain = "…"` de `/etc/secubox/haproxy.toml`) : la curation est la même sur chaque nœud, seul celui qui sert le domaine l'offre ; sans `haproxy.toml` lisible, aucune offre `app`. Les offres `sync` disparues sont révoquées à la synchronisation suivante.
- Flotte, tableau des pairs : bouton « Oublier » (nom retapé, « forcer » pour un nœud actif) → `POST /api/v1/p2p/master-link/oublier` SEUL : secubox-p2p enchaîne tous les nettoyages, Flotte du pilotage comprise (#3362) ; l'oubli répond 202 avec une opération, que la page suit jusqu'à « termine » ; une réponse « partiel » affiche les étapes restantes.
- `secubox-annuaire-noms` (#3362) : un passage à la fois (`/run/secubox-annuaire-noms.lock`), et le contrôle d'Unbound (checkconf, reload, restart) sous le verrou commun d'Unbound (`/var/lib/secubox-dns-listes/verrou`, celui de secubox-dns-listes). `--sans-redemarrage` (appel de l'oubli) ne redémarre jamais Unbound : si une adresse n'est pas écoutée, code 3, et l'oubli est « partiel » avec un message pour l'administrateur.

## Droits du maillage (#3305)

Le maître (qui héberge Auto-Load) ne rend un service du maillage à un pair que si son abonnement l'inclut
(`annuaire/droits.py`, projection `/var/lib/secubox-autoload-public/droits-maillage.json` de secubox-autoload ; pair désigné par l'adresse
source de l'écouteur wg-mesh, nom et empreinte lus dans `p2p-public/pairs-enroles.json`).

- `GET /services` (pair du maillage) : 403 sans `annuaire-offres`, refus écrit dans `/var/log/secubox/audit.log`
  (`droit_maillage_refus`, pair, service, raison).
- `GET /log/export` (pair du maillage) : opérations `ban_*` retirées sans `bans-waf`, `service_*` sans `annuaire-offres` ;
  le socle (identités, nœuds, configs, assistance) n'est jamais coupé.
- `GET /droits/self` (écouteur :8799 seulement, sinon `require_lecture`) : `{"politique": bool, "services": [...]}` de l'appelant.
- Sans projection et sans Auto-Load (box qui n'est pas le maître) : aucune politique, tout est rendu. Auto-Load installé
  (`/var/lib/secubox/autoload`) mais projection absente, ou projection illisible : fermé (refus audités).
  Pair sans abonnement : rendu jusqu'à la fin de la grâce (5 jours), puis refusé. Empreinte posée et différente : refus.
- Côté box : la synchronisation complète relève `droits/self` auprès du SEUL maître désigné (pair du maillage portant le nom
  de l'ancre `/etc/secubox/p2p/ancre-maitre.json` ; sans ancre, personne n'est interrogé) et garde sa réponse
  (`/var/lib/secubox/annuaire/droits-self.json`, écriture atomique sans suivre de lien) ; `annuairectl bans-apply` n'applique
  l'union fédérée que si le dernier droit connu inclut `bans-waf`, sinon les seules bans publiées par la box. Une réponse de
  plus de 48 h reste valable (audit `droits_self_perimes`). Jamais de réponse : comme avant.


## Status Live v2 — relevé d'état signé (#3626)

- `StatusSnapshot` (annuaire/model.py) : contrat distinct de `ModulesSnapshot`, `extra="forbid"`, borné — états,
  compteurs de modules, disponibilité 30 j, frise 24 h ; jamais de ressources, d'adresses ni de détail interne.
- `sbx-fleetctl publish-status` (minuterie `secubox-metrics-publish`, 60 s) : signe le relevé de secubox-status avec
  `node.key` → `/var/lib/secubox/annuaire/fleet/status.json`, servi aux pairs sur l'écoute du maillage
  `GET /api/v1/annuaire/fleet/status/self` (`lecture_ou_pair`).
- `sbx-fleetctl collect-status` (agrégateur seul, `status.toml`) : lit chaque pair (sans proxy ni redirection,
  256 Kio et 5 s au plus), exige signature, forme, fiche signée UNIQUE pour l'adresse et DID correspondant (sinon
  « box non liée »), horodatage plausible, séquence croissante (mémoire `status-sequences.json`, monotone ; une
  séquence plus basse n'est acceptée qu'avec un `ts` signé plus récent : box réinitialisée) → `status-pairs.json`
  (0640, écriture atomique), lu par secubox-status.

## MirrorNet v1 — abonnements (#3647)

- `ServiceOffer` : champs **facultatifs** `version`, `compat`, `tarif` (`modele` ∈ gratuit, forfait, usage, palier,
  reciproque, parraine ; `credits` entier), `quotas`, `classe` (public, communaute, prive), `duree_s`, `grace_s`,
  `sonde`. `Subscription` : `version`, `tarif_accepte`, `expire_le`. Absents, ils ne figurent pas dans la charge
  signée (`model.charge_signee`) : une offre ancienne garde sa signature, et un nœud ancien lit les nouvelles par le
  journal.
- Opérations `service_renew` (abonné) et `service_revoke_offer_sub` (fournisseur) ; `service_revoke_sub` a enfin un
  écrivain (`verbs.cancel_subscription`). Un nœud ancien rejette ces opérations à l'import (compteur `rejected`),
  sans casser sa réplication. Échéance : `verbs.echeance_abonnement` (renouvellement compté s'il est signé avant
  l'échéance en cours).
- Niveaux de confiance calculés (`annuaire/confiance.py`) : REVOKED, OBSERVER, LIMITED ; PARTNER/TRUSTED au socle A21.
- Export `/var/lib/secubox/annuaire/mirrornet-export.json` (0640, atomique, réécrit seulement s'il change) après chaque
  passe de synchronisation, et joignabilité des pairs (`mesh_sync.sync_once(suivi=…)`, sonde `/health` quand l'export
  échoue : un export lent n'est pas une absence). Les opérations `service_` suivent la passe complète (300 s).
- Routes `/self/...` : signées dans le processus propriétaire de `node.key` ; chaque geste écrit dans `audit.log`
  (`mirrornet_*`, avec l'administrateur `par`).
