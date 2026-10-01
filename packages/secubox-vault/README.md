<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🔐 Coffre (secubox-vault 2.0)

Le Coffre garde ce qui ne doit jamais traîner en clair sur un disque. **Scellé
par défaut** : sa clé maîtresse (MK) n'existe qu'en mémoire, entre une
ouverture et le scellement suivant. Conception : [`docs/design/coffre/`](../../docs/design/coffre/README.md) (#1364) ;
phase P1 : #1367.

## Modèle

- **MK** : 256 bits aléatoires, en mémoire verrouillée (mlock), effacée au
  scellement (commande, 15 min d'inactivité, arrêt du démon). Jamais écrite.
- **Serrures** : chaque serrure emballe la MK (Argon2id 64 Mio / 3 / 4 →
  AES-256-GCM). Une phrase (12 caractères au moins) et **5 codes de secours à
  usage unique**. Ajouter ou retirer une serrure ne rechiffre rien ; la
  dernière phrase ne se retire pas.
- **Compartiments** : `box` (système) et `p-<user_uuid>` (une personne —
  jamais un compte système). Clé dérivée de la MK (HKDF-SHA256).
- **Secrets** : AES-256-GCM, liés à leur compartiment, leur nom et leur
  version — déplacé, un secret ne se déchiffre plus.
- **Journal chaîné** : `/var/log/secubox/coffre.journal`, chaque ligne porte
  le SHA-256 de la précédente ; jamais une valeur, une phrase ni un code.

## Processus

`secubox-vault.service` tourne sous **`secubox-coffre`** (ni root, ni
`secubox` : les modules partagent cet utilisateur), sans vidage mémoire, et
n'est **jamais monté dans l'agrégateur**. Deux sockets :

| Socket | Qui | Ce qu'elle permet |
|---|---|---|
| `/run/secubox/vault.sock` | administrateurs réels, via l'agrégateur | état, ouvrir (LAN), sceller, **noms** des secrets, poser, retirer, journal — jamais une valeur |
| `/run/secubox-coffre/racine.sock` (répertoire 0700) | root, par `coffrectl` | tout, dont initialiser, **lire** une valeur, serrures, codes |

API publique : `GET /api/v1/vault/etat`, `POST /ouvrir`, `POST /sceller`,
`GET /secrets`, `POST /secrets`, `DELETE /secrets/{compartiment}/{nom}`,
`GET /journal`. L'ouverture depuis l'extérieur du LAN (TOTP frais, alerte)
est la phase P4.

## coffrectl (root)

```
coffrectl etat
coffrectl initialiser            # phrase, puis 5 codes de secours (une seule fois)
coffrectl ouvrir [--secours]
coffrectl sceller
coffrectl secrets [COMPARTIMENT]
coffrectl poser COMPARTIMENT NOM
coffrectl lire COMPARTIMENT NOM
coffrectl retirer COMPARTIMENT NOM
coffrectl serrure-ajouter [LIBELLE] | serrure-retirer ID | codes
coffrectl compartiment ID [LIBELLE]
coffrectl journal [N] [--verifier]
```

Phrases, codes et valeurs ne passent jamais par la ligne de commande : invite
masquée, ou entrée standard.

## Sauvegarde

`/var/lib/secubox/coffre/coffre.db` (0600) est sans valeur sans une serrure ;
il se sauvegarde par `sqlite3 … ".backup …"`, jamais par `cp` (WAL).

## Depuis 1.x

L'ancien coffre (Fernet, clé posée à côté des données) n'est pas repris : ses
fichiers restent dans `/var/lib/secubox/vault`.
