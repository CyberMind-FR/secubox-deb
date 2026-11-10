<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-mirrornet

MirrorNet v1 — plan de contrôle des **services**, des **données** et des **contributions** du maillage SecuBox.
Conception : `docs/MIRRORNET_ARCHITECTURE.md` (et `NETWORK`, `SERVICE_EXCHANGE`, `DATA_EXCHANGE`, `ECONOMY`,
`SECURITY`, `DATA_MODEL`), audit `docs/MIRRORNET_AUDIT.md`.

**Phase 3 (#3647) : cycle de vie des abonnements.** Phase 2 (#3645) : modèle de données et squelette.

Paquet Debian : version `0.2.1-1~trixie1`, architecture `all`. Demande `secubox-annuaire` ≥ 0.18.0 (export, routes
`/self/...`).

## Principe

MirrorNet ne détient aucune clé. L'annuaire (compte `secubox`, propriétaire du journal et de `node.key`) :

1. dépose après chaque synchronisation (passe complète du journal toutes les 300 s ; voie rapide de 20 s pour l'assistance)
   `/var/lib/secubox/annuaire/mirrornet-export.json` : offres de tous, abonnements où CE nœud est abonné ou
   fournisseur, niveaux de confiance calculés, joignabilité des pairs ;
2. signe les gestes ordonnés par MirrorNet (`/self/...`, jeton de l'administrateur relayé) et les écrit dans
   `audit.log` avec l'administrateur auteur (`par`).

MirrorNet relit l'export toutes les 60 s, **revérifie** chaque entrée (liaison did ↔ clé, signature Ed25519, auteur à la
bonne place, champs bornés ; un `service_id` reste à son premier fournisseur), puis dérive l'état de chaque abonnement
(`secubox_mirrornet/abonnements.py`, fonction pure) et n'ajoute un événement qu'au changement.

## Contenu

- `secubox_mirrornet/schema.py` : schéma SQLite versionné (`PRAGMA user_version`), migrations idempotentes, chacune
  dans une transaction ; une base plus récente que le code n'est jamais touchée. Ledger, relevés d'usage, historique des
  abonnements et règles de répartition en **ajout seul** (déclencheurs).
- `secubox_mirrornet/ledger.py` : transaction en partie double (≥ 2 écritures entières non nulles, Σ = 0), idempotente
  par identifiant, chaînée (BLAKE2b-256, contenu de la transaction compris), correction par `inverser` seulement (une
  fois, identifiant `inv:<tx>`) ; `verifier_integrite` ; `tete` (à ancrer hors de la base en phase 5 : une troncature
  de queue ou une chaîne recalculée ne se voit qu'ainsi).
- `secubox_mirrornet/repartition.py` : règle versionnée (producteur, relais, infrastructure, réserve ; Σ = 100) et
  découpage exact au centième.
- `secubox_mirrornet/lanceur.py` : migration du schéma puis uvicorn, dans le processus principal de l'unité (code 3
  si la base est plus récente que le code : `RestartPreventExitStatus=3`, pas de boucle).
- `secubox_mirrornet/verif.py` : sérialisation canonique, did:plc, signature Ed25519 (mêmes règles que l'annuaire).
- `secubox_mirrornet/catalogue.py` : lecture bornée de l'export, index vérifié, synchronisation en une transaction.
- `secubox_mirrornet/abonnements.py` : états dérivés (Demande, Refuse, Actif, Grace, Suspendu, Expire, Resilie).
- `secubox_mirrornet/annuaire.py` : client des routes `/self/...` de l'annuaire local (socket Unix).
- `api/main.py` : API locale et boucle de synchronisation.

## Exécution

- `secubox-mirrornet.service` : compte `secubox-mirrornet` (groupe `secubox`), socket `/run/secubox/mirrornet.sock`
  (0660), base `/var/lib/secubox-mirrornet/mirrornet.db` (0700/0600 : ledger privé, illisible par le groupe `secubox` ; créée ou migrée au démarrage, code 3 sans redémarrage en boucle si elle est plus récente que le code), AppArmor enforce
  (`apparmor/secubox-mirrornet`), aucun réseau IP, aucune capacité.

## API

Préfixe `/api/v1/mirrornet/` (nginx `nginx/mirrornet.conf`, jamais de vhost public).

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/health` | aucune |
| `GET` | `/status` | require_lecture |
| `GET` | `/schema` | require_lecture |
| `GET` | `/services` | require_lecture (offres présentables + les miennes) |
| `GET` | `/services/{service_id}` | require_lecture (404 si non présentable) |
| `GET` | `/datasets` | require_lecture |
| `GET` | `/subscriptions`, `/subscriptions/{id}` | require_jwt (relations privées ; historique des états) |
| `POST` | `/services/publish` | require_jwt — offre de CE nœud (`kind=dataset` : phase 4) |
| `POST` | `/services/{service_id}/subscribe` | require_jwt — évaluation locale puis abonnement signé |
| `POST` | `/subscriptions/{id}/renew` | require_jwt — abonné, état Actif ou Grace, avant l'échéance |
| `POST` | `/subscriptions/{id}/approve`, `/reject` | require_jwt — fournisseur, demande en attente (#3651) |
| `DELETE` | `/subscriptions/{id}?motif=` | require_jwt — résiliation (abonné) ou révocation (fournisseur) |
| `GET` | `/economy/distribution-rules` | require_lecture |
| `GET` | `/economy/account` | require_jwt (ledger privé) |
| `GET` | `/economy/ledger` | require_jwt (écritures + contrôle d'intégrité) |

Écritures : idempotence par l'en-tête `X-Idempotence` (8 à 64 caractères ; la clé est réservée avant le geste,
rejouée telle quelle ensuite, libérée en cas d'échec). Refus d'évaluation (409) : offre retirée, propre offre,
fournisseur OBSERVER/REVOKED ou sous `confiance_min`, LIMITED autre que gratuit et public, architecture incompatible.
Niveaux : PARTNER et TRUSTED (grants) arrivent avec le socle A21 ; d'ici là tout membre est LIMITED.

## Interface web (#3651)

`/mirrornet/` sur l'hôte d'administration (`www/mirrornet/index.html`, profil Aurora, entrée de menu `menu.d`) :
synchronisation, catalogue, abonnements et abonnés avec historique, publication ; actions réelles confirmées dans la page,
une clé `X-Idempotence` par geste ; `?demo=1` (aucune écriture), `?embed=1`. Phase 4 annoncée, aucune donnée inventée.

## Configuration

`/etc/secubox/mirrornet.toml` (0640 root:secubox, semé une fois depuis `conf/mirrornet.toml`) : `[catalogue]
confiance_min`, `[abonnements] grace_s` (défaut si l'offre n'en déclare pas), `[synchro] intervalle_s`,
`[economie] disponibilite_min` (phase 5). Valeur absente ou hors bornes : défaut.

## Retour arrière

Désinstaller le paquet n'affecte ni `secubox-p2p` ni `secubox-annuaire`. La base n'est retirée qu'à la purge, après une copie datée dans `/var/backups/secubox-mirrornet/`.
Une version plus ancienne du paquet refuse de démarrer sur une base plus récente (message explicite) : restaurer la
sauvegarde ou réinstaller la version correspondante.

## Tests

`python3 -m pytest packages/secubox-mirrornet` : schéma et montée v1 → v2, contraintes, ajout seul, partie double,
idempotence, altération détectée, répartition exacte (2 000 tirages), gardes de l'API ; phase 3 : transitions à horloge
simulée, signature falsifiée, clé d'autrui, vol de `service_id`, gestes de la mauvaise partie, catalogue par niveau,
relais du jeton, idempotence des écritures.
