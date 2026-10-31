<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-annuaire

SecuBox Annuaire-Miroir — federated self-certifying trust substrate.

The Annuaire-Miroir is the trust directory for SecuBox-DEB, providing a BLAKE2b-chained, CONIKS-style append-only audit journal with four protocols: AUTO-ADD (provisional discovery), INVITE (capability-based membership), PROPOSAL (anti-plutocratic governance), and EMANCIPATE (staged anchor removal). All objects are Ed25519-signed, RFC 3339-timestamped, and access-gated by the can() resolver. Served on /run/secubox/annuaire.sock, JWT-gated.

Paquet Debian : version `0.17.0-1~trixie1`, architecture `all`.

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
- Flotte, tableau des pairs : bouton « Oublier » (nom retapé, « forcer » pour un nœud actif) → `secubox-p2p` puis `secubox-pilotage`.

## Droits du maillage (#3305)

Le maître (qui héberge Auto-Load) ne rend un service du maillage à un pair que si son abonnement l'inclut
(`annuaire/droits.py`, projection `autoload-public/droits-maillage.json` de secubox-autoload ; pair désigné par l'adresse
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
