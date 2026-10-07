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

## Phase 2 — l'annuaire des clés personnelles (#1738)

La clé **secrète** d'une personne vit dans **son** compartiment du Coffre
(« Mon coffre », #1367 P5) ; ce démon ne la voit jamais. Il tient l'annuaire
des clés **publiques** de la box : un fichier par personne, **hors du journal
de l'annuaire** (public et indélébile — RGPD), retirable à tout moment.

| Route | Garde | Rôle |
|---|---|---|
| `GET /moi` | personne | ma clé publiée, les boîtes que la box m'a confiées |
| `POST /moi/cle`, `DELETE /moi/cle` | personne | publier (ou remplacer) ma clé publique ; la retirer |
| `GET /annuaire`, `/annuaire/{empreinte}.asc` | personne | clés de cette box et des box liées |
| `GET /annuaire/export` | maillage | l'annuaire signé par la clé de box (notation `annuaire-cles`) |
| `GET /wkd/{domaine}/hu/{hash}`, `/wkd/{domaine}/policy` | public | Web Key Directory |

- **La personne vient de la session** (`capacites.personne_du_porteur`), jamais
  d'un paramètre ni d'un en-tête.
- **Seule une clé publique, unique, valide et qui chiffre entre.** Elle est
  réexportée en `export-minimal` dans un trousseau jetable : la box ne sert
  jamais le texte soumis tel quel.
- **Adresse vérifiée = boîte confiée par la box** à cette personne
  (`sbx_app_links`, app `email`). Une autre adresse portée par la clé reste
  « déclarée ». **WKD ne sert que le vérifié** : personne ne publie une clé au
  nom de la boîte d'un autre.
- **Box liées** : toutes les 30 min, chaque box va chercher l'annuaire signé de
  ses pairs sur leur écoute `:8799` et n'en garde rien sans signature de la
  clé liée au did, notation `annuaire-cles`, auteur et fraîcheur (±1 h)
  vérifiés. Une rotation ou un retrait y figure (`retirees`).
- **WKD public : DÉSACTIVÉ par défaut** (conffile `/etc/secubox/openpgp.toml` livré éteint ; gk2 l'a allumé le 2026-10-01 à la demande de l'exploitant ; « Mon coffre » dit à la personne si sa clé devient publique) (décision #1738 — l'annuaire est servi
  aux box liées, pas au monde). Avec `[wkd] actif = true` dans
  `/etc/secubox/openpgp.toml`, le postinst crée `openpgpkey.<domaine>` pour
  chaque domaine **public** que le conteneur `mail` sert (ou `[wkd] domaines`),
  par HAProxy → sbxwaf → nginx ; éteint, le démon répond 404 et le postinst
  retire le vhost. Le certificat reste un geste d'exploitation
  (`acme.sh --issue -d openpgpkey.<domaine> -w /usr/share/secubox/www`, puis
  `certsctl deploy --apply`).

## Phase 3 — le webmail

Par **Mailvelope**, dans le navigateur : `mailctl webmail-openpgp` règle
Roundcube sur le trousseau principal de Mailvelope et refuse si le greffon
`enigma` (clés tenues côté serveur) est actif. La personne importe sa clé
secrète depuis « Mon coffre » dans Mailvelope ; les clés de ses
correspondants de la box et des box liées se téléchargent depuis l'annuaire. Aucune clé privée n'est prêtée au webmail, aucune
route ne signe ni ne déchiffre pour lui.
