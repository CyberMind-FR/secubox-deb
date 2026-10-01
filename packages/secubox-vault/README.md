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
  usage unique**. Une **clé d'appareil** (FIDO, Touch ID, téléphone —
  extension WebAuthn PRF) peut s'y ajouter : sa sortie PRF, dérivée par
  HKDF-SHA256 avec un sel propre à la serrure, emballe la MK de la même façon.
  Ajouter ou retirer une serrure ne rechiffre rien ; la dernière phrase ne se
  retire pas.
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
| `/run/secubox/vault.sock` | administrateurs réels, via l'agrégateur | état, ouvrir, sceller, **noms** des secrets, poser, retirer, journal — jamais une valeur |
| `/run/secubox-coffre/racine.sock` (répertoire 0700) | root, par `coffrectl` | tout, dont initialiser, **lire** une valeur, serrures, codes |

API publique : `GET /api/v1/vault/etat`, `POST /ouvrir`, `POST /sceller`,
`GET /secrets`, `POST /secrets`, `DELETE /secrets/{compartiment}/{nom}`,
`GET /journal`, et pour les clés d'appareil `GET /serrures/appareil`,
`POST /serrures/appareil/preparer` (un sel neuf), `POST /serrures/appareil`,
`DELETE /serrures/appareil/{id}`.

**Hors du LAN**, `POST /ouvrir` exige un code TOTP du compte de la session
(champ `otp`). C'est l'**agrégateur** qui le vérifie — lui seul tient le
plancher anti-rejeu — puis pose `X-SecuBox-Second-Facteur: verifie` ; celui
d'un client est toujours retiré. Cinq échecs par heure, puis 429. Chaque
ouverture distante envoie une alerte à la boîte de la box (relais du
conteneur `mail`, seule adresse IP que l'unité peut joindre).

Le Hall montre une carte **Coffre** : l'état seul, relayé par l'agrégateur aux
administrateurs réels ; agrandie, elle ouvre la console `/vault/`.

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

# P2 — clé qui signe le dépôt apt
coffrectl depot etat [--porcelaine]     # protégée ? en cache ?
coffrectl depot proteger                # phrase aléatoire, rangée au Coffre AVANT d'être posée
coffrectl depot session [--minutes N]   # la donne à gpg-agent, N ≤ 60, oubli planifié
coffrectl depot fin

# P3 — niveau 0 : secrets de démarrage par systemd-creds
coffrectl niveau0 etat
coffrectl niveau0 migrer NOM CHEMIN UNITE.service   # chiffre + drop-in LoadCredentialEncrypted
coffrectl niveau0 retirer-clair NOM                 # seulement si l'unité tourne AVEC la crédence
coffrectl niveau0 lire NOM
```

Phrases, codes et valeurs ne passent jamais par la ligne de commande : invite
masquée, ou entrée standard.

## Sauvegarde

`/var/lib/secubox/coffre/coffre.db` (0600) est sans valeur sans une serrure ;
il se sauvegarde par `sqlite3 … ".backup …"`, jamais par `cp` (WAL).

## Depuis 1.x

L'ancien coffre (Fernet, clé posée à côté des données) n'est pas repris : ses
fichiers restent dans `/var/lib/secubox/vault`.
