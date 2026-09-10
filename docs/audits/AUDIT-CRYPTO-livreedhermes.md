<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Audit cryptographique — `anibaledel/livreedhermes`

| | |
|---|---|
| Dépôt audité | https://github.com/anibaledel/livreedhermes |
| Passage 1 | commit `6ce3985` (2026-09-10, « SPN 5 couches double référent ») |
| Passage 2 | commit `16539cc` (2026-09-10, après refonte hybride géométrique + AEAD) |
| Périmètre | `disk/disk_lib.py`, `stegano/stegano_lib.py`, `stegano/carter.py`, `encodeur.html` (stégano, vault, échange X25519), worker Cloudflare `worker/src/index.js`, scripts de gating |
| Méthode | Revue manuelle + vérification empirique (scripts rejoués sur le code, Python 3 et Node 22) |
| Hors périmètre | Contenu éditorial, SEO, brevet FR2865054, prépublication IACR citée dans les en-têtes (non consultée) |
| Correctifs | Fusionnés dans le fork : https://github.com/CyberMind-FR/livreedhermes/pull/2 |

## 1. Résumé exécutif

Ce rapport couvre deux passages. Le premier portait sur des primitives « maison »
présentées comme supérieures à AES-256. Le dépôt a été refondu le jour même en
architecture hybride : couche géométrique cantonnée à la diversification de clé,
chiffrement confié à des primitives standard. Le second passage porte sur cette
refonte.

**État après refonte.** La confidentialité et l'intégrité reposent désormais sur
ChaCha20-Poly1305, AES-256-GCM, HKDF, X25519 et PBKDF2, c'est-à-dire sur des
primitives éprouvées et non plus sur la construction géométrique. Les
affirmations d'espace de clés fantaisistes ont disparu du code au profit de
mentions honnêtes. Les treize constats critiques et élevés du premier passage
sont corrigés, à une exception documentaire près.

**Ce que le second passage a trouvé.** Cinq défauts subsistaient ou avaient été
introduits par la refonte, dont deux sérieux :

- Le durcissement du KDF du chiffrement disque était **entièrement contournable** :
  le MAC global était calculé avec la clé maître brute et vérifié avant toute
  dérivation, ramenant le coût d'un essai de passphrase hors ligne de 203 ms à
  5,35 µs.
- Les cellules porteuses de la stéganographie étaient **repérables sans aucune
  clé** : les octets étaient écrits en nibbles, donc dans `[0..15]`, dans une
  grille de bruit couvrant `[0..43]`.

S'y ajoutaient une perte de message à la capacité annoncée, un vault dont la clé
maître était dérivée sans sel, et une clé privée X25519 exportable sans raison.

**Correctifs.** Les cinq sont corrigés et vérifiés par exécution, fusionnés dans
le fork CyberMind-FR. Trois points restent ouverts côté auteur : le sel fixe de
la grille Carter, la permutation Ref256 dont l'entropie réelle est huit fois plus
faible qu'annoncé, et le débit.

Gravité résiduelle après correctifs : **Faible**. La couche géométrique n'est
plus sur le chemin critique de la sécurité, ce qui était la recommandation
principale du premier passage.

## 2. Passage 1 — constats et état actuel

Constats relevés sur `6ce3985`, avec leur état sur `16539cc` et après correctifs.

| # | Constat initial | Gravité | État |
|---|-----------------|---------|------|
| D1 | Permutation Ref256 constante : 12 288 configurations → 1 seule permutation (offsets calculés puis ignorés) | Critique | **Partiel** — offsets utilisés, mais 288 permutations distinctes seulement (cf. §4.6) |
| D2 | Diffusion incomplète après 4 tours ; 19 chunks sur 84 diffusent complètement | Critique | **Sans objet** — le SPN ne chiffre plus, il dérive une clé |
| D3 | Queue de secteur en two-time pad malléable | Critique | **Corrigé** — plus de flux XOR, AEAD sur le secteur entier |
| D4 | Aucune authentification | Élevée | **Corrigé** — Poly1305 par secteur + HMAC global |
| D5 | Chiffrement déterministe, ECB au niveau du chunk | Élevée | **Corrigé** — sel et nonce aléatoires par fichier |
| D6 | Sel PBKDF2 codé en dur | Élevée | **Corrigé** — sel aléatoire, `passphrase_to_key` le retourne |
| D7 | `security_stats()` annonçait 2^159 432 bits | Moyenne | **Corrigé** — remplacé par `description()`, sans compteur de bits |
| D8 | PBKDF2 comme PRF de tour, 3,5 Ko/s | Moyenne | **Amélioré** — 44 Ko/s (cf. §4.8) |
| D9 | `MixBlock` triangulaire sans diffusion inter-groupes | Élevée | **Corrigé** — ShiftRows + MixColumns MDS |
| D10 | Ref360 : 342 entrées pour 116 permutations | Faible | **Subsiste** — documenté |
| S1 | Message stocké en clair dans la grille | Critique | **Corrigé** — AEAD avant dissimulation |
| S2 | Blocs 6×6 cassables en 4096 essais sans clé | Critique | **Corrigé** — conséquence de S1 |
| S3 | Clé A redondante avec Clé 2 | Critique | **Corrigé** — Clé A retirée |
| S4 | Distingueur 0/44 entre message et bruit | Élevée | **Remplacé** par un distingueur plus fort (cf. §4.2) |
| S5 | PRNG non cryptographiques | Élevée | **Corrigé** — `secrets` et `crypto.getRandomValues` |
| S6 | Clé A sur 31 bits | Élevée | **Sans objet** — Clé A retirée |
| S7 | « Fausse lecture plausible » non vérifiée | Moyenne | **Corrigé** — échec explicite par key commitment |
| S8 | Chemins des référents cassés | Faible | **Corrigé** — `_find_ref()` |
| W1..W5, G1 | Worker Stripe et gating | Faible à Moyenne | **Inchangés** (cf. §5) |

## 3. Architecture actuelle

**Chiffrement disque.** Passphrase → PBKDF2-SHA256 300 000 itérations → clé
géométrique. Par secteur de 512 octets : la couche géométrique (S-box GF(2⁸),
permutation Ref256, MixColumns MDS, permutation Ref360, 4 tours) dérive une clé
de session, puis ChaCha20-Poly1305 chiffre et authentifie le secteur. Un
HMAC-SHA256 couvre l'ensemble. Format : sel 32 octets, nonce global 24 octets,
secteurs authentifiés, MAC 32 octets.

**Stéganographie.** Le message est chiffré (XChaCha20-Poly1305 par extension de
nonce HKDF) et engagé par un HMAC de commitment, puis dissimulé aux positions
désignées par les clés B, C et 2. La confidentialité ne dépend plus de la
géométrie.

**Navigateur.** `encodeur.html` substitue AES-256-GCM à ChaCha20, absent de
WebCrypto, et implémente en natif X25519, HKDF et PBKDF2. Le vault chiffre par
entrée, avec manifest chiffré et HMAC global.

Cette séparation est saine : la construction géométrique reste originale et
visible, sans porter la charge de la sécurité.

## 4. Passage 2 — constats sur `16539cc`

### 4.1 Le KDF de 300 000 itérations était contournable (critique, corrigé)

```python
mac = _hmac.new(master_key, payload, hashlib.sha256).digest()
```

Le MAC global était keyé par la clé maître brute et vérifié **avant** toute
dérivation. Un attaquant tenant un fichier chiffré testait donc les passphrases
contre le MAC sans jamais exécuter PBKDF2.

| Chemin d'attaque | Coût par essai |
|---|---|
| via le MAC global | 5,35 µs |
| via PBKDF2 300 000 | 203 ms |

Facteur d'environ 38 000 sur une attaque par dictionnaire hors ligne : le
durcissement ne servait à rien. Vérifié en retrouvant la passphrase d'un fichier
de test par simple recalcul du HMAC.

Correctif : clé de MAC dédiée dérivée par HKDF de la sortie du KDF, et KDF
appliqué avant la vérification. Coût par essai mesuré après correctif : 210 ms.

### 4.2 Les cellules porteuses étaient repérables sans clé (élevée, corrigé)

Le premier passage signalait un distingueur 0/44. La refonte l'a supprimé mais en
a introduit un plus fort : les octets étaient écrits en nibbles, donc dans
`[0..15]`, alors que le bruit couvre `[0..43]`. Mesures sur une grille 60×60 :

- les 226 cellules porteuses avaient toutes une valeur ≤ 15, aucune au-dessus ;
- toute cellule > 15 était prouvablement du bruit, ce qui élimine d'emblée 64 %
  de la grille ;
- une forme dont les 6 cellules valent ≤ 15 n'a qu'une chance sur 432 d'être du
  bruit. Sur les 12 premiers blocs testés, les 12 blocs porteurs ressortaient.

Le message restait chiffré, mais sa présence et son emplacement étaient
détectables sans clé, ce qui est l'inverse du but d'un système stéganographique.
La note d'en-tête annonçant « pas de distingueur trivial » ne visait que
l'ancien tell.

Correctif : encodage base-44 avec rembourrage aléatoire, écart à l'uniformité
inférieur à 2⁻⁶⁴. Après correctif, sur 60 grilles, les symboles porteurs
couvrent 44 valeurs sur 44 avec χ² = 45,1 pour 43 degrés de liberté, seuil à 5 %
de 59,3. Effet de bord favorable : 1,47 symbole par octet au lieu de 2.

### 4.3 Perte de message à la capacité annoncée (élevée, corrigé)

`max_message_len` comptait 32 octets de surcoût là où le format en consomme 72,
soit 32 de commitment, 24 de nonce et 16 de tag. Un message de la taille
annoncée passait l'encodage, était tronqué faute de positions, puis rejeté au
décodage :

```
capacité annoncée : 268
ÉCHEC au décodage d'un message pourtant accepté : Positions insuffisantes : 600 < 688
```

Correctif : capacité calculée depuis le format réel. Un message à la capacité
maximale fait l'aller-retour, un caractère de plus est refusé à l'encodage.

### 4.4 Le vault dérivait sa clé maître sans sel (élevée, corrigé)

```js
salt: new TextEncoder().encode('SecuBox-Vault-KDF-v1')
```

Ce libellé est identique pour tous les vaults et tous les utilisateurs. Une seule
table précalculée passphrase vers clé maître ouvrait n'importe quel fichier, quel
que soit le nombre d'itérations. Le format embarquait pourtant déjà un sel
aléatoire de 32 octets dans son en-tête, à l'offset 8, utilisé pour les sous-clés
HKDF. La justification inscrite dans le code, éviter de conserver un sel séparé,
ne tenait donc pas.

Correctif : version 2 du format, PBKDF2 salé par le sel de l'en-tête, lu avant la
dérivation. Les vaults v1 restent lisibles et repassent en v2 au prochain export.
Vérifié sous Node : création, export, relecture, rejet d'une mauvaise passphrase,
et deux vaults créés avec la même passphrase donnent bien des clés maîtres
distinctes.

### 4.5 Clé privée X25519 exportable (faible, corrigé)

`generateKey({name:'X25519'}, true, …)` rendait la clé privée éphémère
exportable. Le drapeau ne concerne que la clé privée, la clé publique restant
exportable par spécification : `false` ne change rien à l'échange.

### 4.6 Permutation Ref256 : 288 permutations, pas 12 288 (moyenne, ouvert)

Les offsets de quadrant sont désormais utilisés, ce qui corrige le bug du premier
passage. Mais la table de 12 288 entrées ne produit que **288 permutations
distinctes**, soit environ 8 bits au lieu des 13,6 attendus. Cause : les
positions des 256 formes du référent sont déjà triées par ordre croissant, et
`_perm_from_seq` trie par position absolue. L'identité de la forme est donc
effacée, seul l'ordre des quadrants compte.

```
perms distinctes par ordre de quadrant : 12   |  nombre d'ordres : 24
formes dont les positions sont déjà triées : 256/256
```

Rendre la forme signifiante suppose de revoir la construction de la permutation,
ce qui relève de l'auteur. Corrigé en documentation seulement. Sans conséquence
sur la sécurité effective, la couche n'étant plus qu'une diversification de clé.

### 4.7 Nommage de l'algorithme (faible, corrigé en documentation)

`disk_lib.py` annonçait XChaCha20-Poly1305 et un nonce de 192 bits alors qu'il
utilise `ChaCha20Poly1305` de `cryptography`, soit le variant IETF à nonce de
96 bits. Sans conséquence pratique, le nonce par secteur étant dérivé par HKDF
d'un nonce global de 192 bits et la clé changeant à chaque secteur, mais
l'écart de nommage nuit à la relecture. `stegano_lib.py` implémente de son côté
une extension de nonce par HKDF, saine mais non conforme à XChaCha20 standard :
les deux implémentations ne sont pas interopérables avec une bibliothèque tierce.

### 4.8 Débit (moyenne, ouvert)

44 Ko/s sur le chiffrement disque, contre 3,5 Ko/s avant refonte. Le coût est
dominé par la reconstruction de 8 S-box par secteur dans la couche géométrique.
Un cache de S-box par tour, ou une dérivation unique par fichier, y remédierait
sans changer la sécurité.

### 4.9 Grille Carter : sel de dérivation fixe (moyenne, ouvert)

Le mode Carter dérive sa clé maître depuis une passphrase avec le sel fixe
`SecuBox-Carter-KDF-v1`, même défaut que §4.4. Corriger suppose d'embarquer un
sel avec la grille, donc un changement de format laissé à l'auteur.

### 4.10 Échange X25519 non authentifié (information)

Un attaquant actif qui substitue les clés publiques pendant l'échange obtient une
session valide des deux côtés. L'empreinte de session affichée par la page est la
parade prévue, à condition d'être comparée hors bande. À énoncer explicitement
dans l'interface. Par ailleurs les clés de session sont conservées en clair dans
`localStorage`, ce que la page documente.

## 5. Worker Cloudflare et gating (inchangés depuis le passage 1)

Points corrects : `stripe.webhooks.constructEventAsync` avec secret dédié ;
secrets hors dépôt ; prix Pro non lu depuis le client ; jetons
`crypto.randomUUID()` ; `payment_status` vérifié.

- **W1** : `currency` vient du client et `STRIPE_MIN_AMOUNT_CENTS` est comparé
  sans conversion. Forcer `eur` ou une liste blanche côté worker.
- **W2** : les jetons n'ont pas de TTL, et les événements `charge.refunded` /
  `charge.dispute.created` ne sont pas traités. Prévoir expiration ou révocation.
- **W3** : préférer `POST` avec le jeton dans le corps ou un en-tête ; raccourcir
  le TTL de `session:<id>` et invalider après le premier `claim`.
- **W4** : refuser la requête si `ALLOWED_ORIGIN` n'est pas défini plutôt que
  `*` ; ne pas dériver `success_url` de l'en-tête `Origin`.
- **G1** : le verrou « Pro » est côté client et les fichiers sont publics, ce que
  le code documente. Toute promesse commerciale d'exclusivité est à relativiser.

## 6. Recommandations restantes

1. Reprendre la construction de la permutation Ref256 pour que la forme
   choisie influe réellement, ou assumer les 8 bits dans la documentation.
2. Embarquer un sel aléatoire dans le format de la grille Carter.
3. Mettre en cache les S-box de la couche géométrique pour le débit.
4. Énoncer dans l'interface que l'échange X25519 n'est pas authentifié et que la
   comparaison d'empreinte hors bande est nécessaire.
5. Durcir le worker Stripe selon W1 à W4.
6. Ajouter des tests de non-régression sur les propriétés vérifiées ici :
   uniformité des symboles porteurs, coût d'un essai de passphrase, unicité des
   sels de vault.
7. Faire relire la couche géométrique par un tiers avant toute revendication
   formelle. Elle n'est plus sur le chemin critique, ce qui rend cette relecture
   souhaitable mais non bloquante.

## 7. Reproduction

Python 3 avec `cryptography`, et Node 22 pour le vault.

- **Permutations distinctes** : `set(tuple(v[0]) for v in GeoSPN(...).pt256.values())`
  → 1 au passage 1, 288 au passage 2.
- **Contournement du KDF** : recalculer `hmac.new(candidat, payload, sha256)` sur
  les octets d'un fichier chiffré privés de ses 32 derniers, et comparer au MAC.
- **Distingueur stégano** : reconstituer les cellules porteuses depuis les clés,
  comparer leur maximum à celui du bruit, puis compter les blocs où une forme
  donne 6 valeurs ≤ 15.
- **Perte de message** : encoder un message de `max_message_len` caractères, puis
  le décoder.
- **Vault** : dériver la clé maître avec deux sels distincts pour une même
  passphrase et comparer.
