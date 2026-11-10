<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-mirrornet

MirrorNet v1 — plan de contrôle des **services**, des **données** et des **contributions** du maillage SecuBox.
Conception : `docs/MIRRORNET_ARCHITECTURE.md` (et `NETWORK`, `SERVICE_EXCHANGE`, `DATA_EXCHANGE`, `ECONOMY`,
`SECURITY`, `DATA_MODEL`), audit `docs/MIRRORNET_AUDIT.md`.

**Phase 2 (#3645) : modèle de données et squelette en lecture seule.** Rien n'est encore synchronisé avec l'annuaire,
aucune route n'écrit ; les tables sont vides tant que la phase 3 (abonnements) n'est pas livrée.

Paquet Debian : version `0.1.0-1~trixie1`, architecture `all`.

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
- `api/main.py` : API locale.

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
| `GET` | `/services` | require_lecture |
| `GET` | `/datasets` | require_lecture |
| `GET` | `/subscriptions` | require_jwt (relations privées entre nœuds) |
| `GET` | `/economy/distribution-rules` | require_lecture |
| `GET` | `/economy/account` | require_jwt (ledger privé) |
| `GET` | `/economy/ledger` | require_jwt (écritures + contrôle d'intégrité) |

## Configuration

`/etc/secubox/mirrornet.toml` (0640 root:secubox, semé une fois depuis `conf/mirrornet.toml`) : `[catalogue]
confiance_min`, `[abonnements] grace_s`, `[economie] disponibilite_min`. Phase 2 : aucun réglage n'a encore d'effet.

## Retour arrière

Désinstaller le paquet n'affecte ni `secubox-p2p` ni `secubox-annuaire`. La base n'est retirée qu'à la purge, après une copie datée dans `/var/backups/secubox-mirrornet/`.
Une version plus ancienne du paquet refuse de démarrer sur une base plus récente (message explicite) : restaurer la
sauvegarde ou réinstaller la version correspondante.

## Tests

`python3 -m pytest packages/secubox-mirrornet` : schéma, contraintes, ajout seul, partie double, idempotence,
altération détectée, répartition exacte (2 000 tirages), gardes de l'API.
