<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-openpgp — OpenPGP de box, lié à l'identité canonique

Phase 1 de l'épopée OpenPGP (#1736) : chaque box a une clé OpenPGP, et les box
liées échangent des messages **signés et chiffrés** sur le maillage WireGuard.

## Aucune identité de plus

L'identité d'une box reste `node.key` (Ed25519, `did:plc`) — audit
`docs/AUDIT_SBX_IDENTITY.md`. La clé OpenPGP est **distincte** (primaire
ed25519 [signer], sous-clé cv25519 [chiffrer] : deux secrets, comme l'exige
`docs/POLITIQUE-CRYPTO.md`) et **liée** au did par une entrée d'annuaire
`openpgp_bind` **signée par `node.key`**, répliquée par la synchronisation de
l'annuaire. La confiance en l'empreinte d'un pair vient de là — pas d'un
serveur de clés ni d'une toile de confiance. `openpgp_revoke` retire une
empreinte, définitivement.

## Ce que fait le démon

`secubox-openpgp.service`, utilisateur `secubox-openpgp`, socket
`/run/secubox/openpgp.sock` (`/api/v1/openpgp/…`). Le trousseau
(`/var/lib/secubox/openpgp/node`, 0700) est à lui seul ; `node.key` lui est
inaccessible.

| Route | Garde | Rôle |
|---|---|---|
| `GET /health` | — | sonde |
| `GET /status`, `/pairs`, `/cle` | lecture | did, clé, liaison, pairs liés, notre clé publique |
| `POST /envoyer` | admin | enveloppe signée + chiffrée vers un pair lié |
| `GET /boite`, `/boite/{id}` | admin | messages reçus ; lecture déchiffrée, tracée |
| `POST /boite/depot` | maillage | dépôt d'un pair via l'écoute `:8799` (10.10.0.0/24) |

**Pas d'oracle** (#1417, S8) : aucune route ne signe ni ne déchiffre des octets
fournis par l'appelant. La box ne signe que l'enveloppe
`{v, de, a, emis, nonce, objet, contenu}`, avec la notation
`usage@secubox.in=interbox`.

À la réception, tout est vérifié : signataire = empreinte **liée** à `de`,
`a` = cette box, fraîcheur ±15 min, nonce inédit. Un refus ne dit pas
pourquoi au déposant (le motif va au journal). Les messages sont conservés
**chiffrés** (0600), jamais en clair ; `journal.jsonl` ne garde que des
métadonnées.

## CLI

```
sbx-openpgp init                 # clé de box si elle manque
sbx-openpgp lier                 # publie la liaison did ↔ empreinte (node.key)
sbx-openpgp etat | pairs | cle
sbx-openpgp envoyer gk3 "objet" "texte"
sbx-openpgp boite [ID]
```

Le postinst fait `init` puis `lier`. Les pairs voient une nouvelle liaison à
leur prochaine synchronisation de l'annuaire (≤ 5 min).

## Suite

Phase 2 : clés personnelles (jamais dans le journal public — RGPD). Phase 3 :
webmail, client de cette même brique.
