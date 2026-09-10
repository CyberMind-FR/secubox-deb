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
| Commit audité | `6ce3985838d312a83ba4f6758428e849308877e8` (2026-09-10, « Passe le chiffrement disque à un SPN 5 couches double référent (256+360) ») |
| Date de l'audit | 2026-09-10 |
| Périmètre | `disk/disk_lib.py`, `stegano/stegano_lib.py`, port JavaScript des deux dans `encodeur.html`, worker Cloudflare `worker/src/index.js`, scripts de gating `assets/soutien-gate.js` / `assets/pro-gate.js` |
| Méthode | Revue de code manuelle + vérification empirique (scripts Python rejoués sur le code du dépôt) |
| Hors périmètre | Contenu éditorial, SEO, brevet FR2865054, prépublication IACR citée dans les en-têtes (non consultée) |

## 1. Résumé exécutif

Le dépôt contient deux primitives « maison » présentées comme supérieures à AES-256
(« 2^159 432 bits par secteur », « 2^2259 bits vs AES-256 »), plus un petit backend
de paiement Stripe. Verdict :

- **`disk_lib.py` (GeoSPN, chiffrement de disque)** : **ne doit pas être utilisé pour
  protéger des données.** Une des cinq couches est inerte (permutation constante à
  cause d'un bug), la diffusion est incomplète après 4 tours (sur certains chunks un
  octet chiffré ne dépend que d'un seul octet clair), les 8 derniers octets de
  chaque secteur sont chiffrés par un masque réutilisé (two-time pad), il n'y a
  aucune intégrité, et le débit mesuré est de l'ordre de 3,5 Ko/s. Les métriques de
  sécurité affichées sont sans rapport avec l'entropie réelle (256 bits au mieux).
- **`stegano_lib.py` (stéganographie 4 clés)** : **n'offre aucune confidentialité.**
  Les caractères du message sont écrits **en clair** (index alphabétique) dans la
  grille ; les clés ne décident que *de l'emplacement*. Chaque bloc 6×6 se casse
  indépendamment en 4096 essais sans aucune clé. La « Clé A » (annoncée à 2^1684
  bits) est mathématiquement redondante avec la « Clé 2 ». Les générateurs
  aléatoires utilisés (`random` Mersenne Twister côté Python, LCG 32 bits côté JS)
  ne sont pas cryptographiques.
- **Worker Stripe** : correct dans l'ensemble (signature webhook vérifiée, jetons
  `crypto.randomUUID()`, prix Pro fixé côté serveur). Quelques points de durcissement
  (devise non contrôlée sur le palier libre, jetons sans expiration ni révocation,
  jeton transmis en query string, CORS permissif par défaut).
- Le verrou « Pro » / « Soutien » est purement côté client, ce que le code assume ;
  les fichiers verrouillés (PDF du livre) sont dans le dépôt public.

Gravité globale : **Critique** pour les deux primitives cryptographiques si elles
sont employées pour un usage réel ; **Faible à Moyenne** pour le backend de paiement.

## 2. Tableau des constats

| # | Composant | Constat | Gravité |
|---|-----------|---------|---------|
| D1 | disk_lib | Couche « Permutation Ref256 » constante : 12 288 configurations → 1 seule permutation (bug : offsets calculés puis ignorés) | Critique |
| D2 | disk_lib | Diffusion incomplète après 4 tours : sur 84 chunks testés, seuls 19 diffusent complètement ; 4 chunks ont un octet chiffré fonction d'un seul octet clair | Critique |
| D3 | disk_lib | Queue de secteur (8 octets) = XOR avec un masque dépendant uniquement de (clé, secteur) → réutilisation de masque, malléabilité bit à bit | Critique |
| D4 | disk_lib | Aucune authentification (pas de MAC / AEAD) ; le format `encrypt_data` est malléable et la longueur en clair est non protégée | Élevée |
| D5 | disk_lib | Mode déterministe par (secteur, chunk) : ECB au niveau du chunk de 24 octets, et `encrypt_data` repart toujours du secteur 0 → deux fichiers chiffrés avec la même clé sont comparables bloc à bloc | Élevée |
| D6 | disk_lib | Sel PBKDF2 codé en dur (`LaLivreeDHermes2026`) pour la dérivation depuis passphrase | Élevée |
| D7 | disk_lib | Métriques `security_stats()` fausses : compte `log2(256!)` pour une S-box entièrement dérivée de la clé ; l'entropie réelle est bornée par la clé maître (256 bits) | Moyenne (honnêteté des claims) |
| D8 | disk_lib | PBKDF2 (1000 itérations) utilisé comme PRF de tour, 84 appels par secteur + reconstruction de S-box : ~145 ms / secteur (3,5 Ko/s) | Moyenne (inutilisable en pratique, DoS) |
| D9 | disk_lib | `MixBlock` : le groupe 3 ne reçoit jamais de contribution des groupes 0-2 et l'octet 5 de chaque groupe ne dépend que de lui-même | Élevée (cause de D2) |
| D10 | disk_lib | Ref360 : 342 entrées → 116 permutations distinctes seulement ; « 57×6 » est déjà surcompté | Faible |
| S1 | stegano | Le texte est stocké en clair (valeur de cellule = index alphabétique). Les clés ne font que choisir les cellules | Critique |
| S2 | stegano | Blocs 6×6 indépendants → recherche exhaustive par bloc en 256×2×8 = 4096 essais, sans clé. Fragments de clair récupérés empiriquement avec un scoring naïf | Critique |
| S3 | stegano | Clé A (mélange du référent) redondante avec Clé 2 : pour toute Clé A' il existe une Clé 2' produisant la même grille → entropie apportée = 0, pas 2^1684 | Critique (claim) |
| S4 | stegano | Fuite structurelle : le bruit est tiré dans 1..44 et l'alphabet dans 0..43 → toute cellule à 0 est un espace du message, toute cellule à 44 est du bruit | Élevée |
| S5 | stegano | PRNG non cryptographiques : `random.Random` / `random.seed` global (MT19937) en Python, LCG 32 bits `s*1664525+1013904223` en JS, `Math.random()` comme graine par défaut | Élevée |
| S6 | stegano | Clé A générée par `random.randint(0, 2**31)` → 31 bits d'entropie, pas 1684 | Élevée |
| S7 | stegano | Propriété annoncée « une Clé C fausse donne une lecture plausible » non vérifiée : la lecture fausse est majoritairement du bruit visiblement non-textuel (`DYESJ9-B.?WV0FE?T.IT AU PONT DYB0OXRF`), avec des fragments de clair | Moyenne (claim) |
| S8 | stegano/disk | `REF256_PATH` pointe dans le dossier du module alors que les JSON sont dans `data/` → `FileNotFoundError` à l'exécution telle quelle | Faible |
| W1 | worker | `/create-checkout-session` : `currency` contrôlée par le client, le minimum est vérifié en « centimes » sans tenir compte de la devise → jeton « soutien » obtenable pour un montant dérisoire dans une devise faible | Moyenne |
| W2 | worker | Jetons d'accès sans expiration, sans lien avec un remboursement/chargeback, non révocables | Moyenne |
| W3 | worker | Jeton et `session_id` transmis en query string GET (logs, historique, Referer) ; `/claim-token` réclamable 24 h par quiconque connaît le `session_id` | Faible |
| W4 | worker | `Access-Control-Allow-Origin: *` par défaut si `ALLOWED_ORIGIN` absent ; `success_url` construit depuis l'en-tête `Origin` de la requête | Faible |
| W5 | worker | `integration_identifier` généré avec `Math.random()` (non sensible, mais inutile) | Info |
| G1 | gating | Verrou entièrement côté client (`localStorage`, attributs `data-pro-*`) ; le contenu « Pro » et les PDF sont des fichiers statiques publics | Info (assumé dans le code) |

## 3. Détail — `disk/disk_lib.py` (GeoSPN)

### 3.1 Architecture revue

Par chunk de 24 octets et par tour (4 tours) :
S-box GF(2^8) dérivée de la clé → permutation Ref256 → `_mix` → permutation Ref360 →
XOR d'une clé de tour de 24 octets. Tous les paramètres de tour sont dérivés par
`PBKDF2-HMAC-SHA256(master_key, salt=(secteur, chunk, tour, 0xDEADBEEF), 1000 it.)`.
Les 8 octets restants du secteur (512 = 21×24 + 8) sont XORés avec un masque PBKDF2
dérivé de (clé, secteur).

### 3.2 D1 — La permutation Ref256 est constante (bug)

```python
for slot in order:
    dr, dc = OFFSETS_12[slot]          # calculé…
    for r, c in form[ck]: seq.append(r*12+c)   # …jamais utilisé
```

`seq` est donc la même liste de 6 positions répétée 4 fois, quel que soit `order`.
`sorted()` étant stable, le tri produit toujours le même entrelacement
`[0,6,12,18,1,7,13,19,…]`. Vérification :

```
pt256 entries 12288   distinct P256 perms: 1
P256 independent of 'order' oi: True
```

Le port JavaScript (`diskBuildTables` dans `encodeur.html`) reproduit exactement le
bug. La « couche 2 » revendiquée (12 288 configurations) est une transposition fixe
et publique.

### 3.3 D2 / D9 — Diffusion incomplète

`_mix` est triangulaire dans les deux sens : dans chaque groupe de 6, l'octet
`base+5` ne dépend que de lui-même, et le groupe 3 (octets 18-23) ne reçoit jamais
les groupes 0-2. Combiné à une permutation Ref256 constante et à un Ref360 à
116 permutations, 4 tours ne suffisent pas à garantir une diffusion complète.
Mesure (matrice de dépendance par flip de bit, 84 chunks, clé aléatoire) :

```
chunks avec diffusion complète (pt→ct et ct→pt sur 24 octets) : 19 / 84
min #octets chiffrés influencés par UN octet clair : 1 (3 chunks), 2, 3, 5 (5 chunks)…
min #octets clairs influençant UN octet chiffré    : 1 (4 chunks), 6 (3 chunks), 10…
avalanche moyenne : 50,2 %
```

Sur les chunks concernés, l'octet chiffré fautif est une **substitution
mono-alphabétique fixe** de l'octet clair correspondant : analyse fréquentielle
directe, fuite d'égalité entre secteurs. La moyenne d'avalanche de 50 % annoncée
dans la docstring masque ce défaut structurel : un test d'avalanche moyen ne
remplace pas une preuve de branche minimale (branch number) par tour.

### 3.4 D3 — Queue de secteur en two-time pad

```python
tk = pbkdf2_hmac('sha256', master_key, pack('>QI', sector_num, 99), 1000, 8)
out.extend(b ^ k for b, k in zip(tail, tk))
```

`tk` ne dépend que de (clé, secteur). Vérification :

```
tail: C1^C2 == P1^P2 (two-time pad) : True
bit-flip in tail decrypts to flipped plaintext : True
```

Toute réécriture d'un secteur, ou tout fichier chiffré avec la même clé (voir D5),
révèle le XOR des clairs de la queue, et un attaquant peut modifier ces octets à
volonté.

### 3.5 D4 / D5 — Pas d'intégrité, déterminisme

Aucun MAC. `encrypt_data` préfixe la longueur en clair, non authentifiée, puis
chiffre les secteurs à partir de 0 pour chaque fichier. Deux fichiers chiffrés avec
la même clé partagent donc les mêmes clés de tour : chunks identiques → chiffrés
identiques (ECB par chunk, vérifié), et queues en two-time pad.

Pour un chiffrement de disque, un mode à tweak (XTS) tolère le déterminisme par
secteur, mais pas la réutilisation à travers des fichiers différents, et jamais un
flux XOR sur une partie du secteur.

### 3.6 D6 — Sel fixe

`passphrase_to_key` utilise un sel constant. Toutes les passphrases identiques
donnent la même clé partout : tables précalculées possibles, pas d'isolation entre
utilisateurs. 100 000 itérations PBKDF2-SHA256 est aussi en dessous des
recommandations actuelles (OWASP : 600 000) ; Argon2id est préférable.

### 3.7 D7 / D8 — Claims et performance

`security_stats()` additionne `log2(256!)` (S-box) + permutations + 192 bits XOR par
tour, ×4 tours, ×21 chunks = « 2^159 432 bits ». Tous ces éléments sont **dérivés
de la clé maître** : l'entropie effective est ≤ 256 bits. Le nombre affiché n'a pas
de sens cryptographique. La S-box `M·inv(x) ⊕ c` avec `M` triangulaire à diagonale
unitaire a bien une uniformité différentielle 4 (affinement équivalente à
l'inversion), mais c'est une propriété de la classe, pas une contribution de clé.

PBKDF2 est un KDF de mot de passe, pas une PRF de tour : 84 appels à 1000
itérations plus 84 constructions de S-box (256 produits matrice-vecteur) par
secteur donnent **~145 ms par secteur de 512 octets** (≈ 3,5 Ko/s). Un HKDF /
HMAC unique par secteur, ou un vrai key schedule, est attendu.

## 4. Détail — `stegano/stegano_lib.py` et port JS

### 4.1 S1 / S2 — Le message est en clair

```python
grid[gr][gc] = msg_nums[msg_idx]     # index alphabétique brut, aucune substitution
```

Les quatre « clés » ne déterminent que *quelles* cellules portent le message. Les
blocs 6×6 sont traités indépendamment (forme, couleur, orientation propres) : un
attaquant sans aucune clé énumère 256 formes × 2 couleurs × 8 orientations = 4096
lectures par bloc et retient celle qui ressemble à du texte. Avec un scoring naïf
(fréquence de lettres françaises) sur `RENDEZ VOUS A MINUIT AU PONT DES ARTS` :

```
récupéré sans clé : 'RSMENH SU VOI EAT.LAI  AN T,OOES ARTO'
```

Un modèle de langue rudimentaire suffit à finir le travail. L'espace de recherche
réel est **2^12 par bloc**, pas « 2^3084 ».

### 4.2 S3 — La Clé A n'apporte rien

`form = ref_s[form_id % 256]` : composer un mélange du référent (Clé A) avec un index
(Clé 2) revient à choisir une forme. Pour toute Clé A' on trouve une Clé 2'
équivalente. Vérifié : grille strictement identique avec une Clé A arbitraire et
une Clé 2 ré-indexée. L'affirmation « 2^1684 bits » pour la Clé A est fausse ; de
plus la graine réelle est `random.randint(0, 2**31)` : 31 bits.

### 4.3 S4 — Distingueur trivial

Bruit tiré dans `[1, 44]`, alphabet indexé `[0, 43]` : chaque `0` de la grille est un
espace du message (7 zéros pour 7 espaces dans le test), chaque `44` est du bruit.
Cela localise les blocs porteurs et découpe les mots.

### 4.4 S5 / S6 — Aléa non cryptographique

- Python : `random.Random(seed)`, `random.seed(seed)` (état global), MT19937.
- JS : `mkRng` est un LCG 32 bits (`s*1664525+1013904223`), gradé par `Math.random()`
  si aucune graine n'est fournie. Les deux implémentations sont explicitement
  non interopérables (commentaire dans le code), ce qui contredit l'idée d'un
  « algorithme » spécifié.

Pour tout usage sérieux : `secrets` / `crypto.getRandomValues()`, et un KDF pour
dériver les paramètres depuis une clé.

### 4.5 S7 — « Fausse lecture plausible »

Avec une Clé C fausse, `decode` lit d'autres cellules (l'orientation déplace les
positions), donc majoritairement du bruit : la sortie contient des chiffres et de
la ponctuation aléatoires, entrecoupés de fragments corrects (`AU PONT`). Elle
n'est pas « indiscernable d'un message valide ».

## 5. Détail — Worker Cloudflare et gating

Points corrects : `stripe.webhooks.constructEventAsync` avec secret dédié ; secrets
hors dépôt ; prix Pro non lu depuis le client ; jetons `crypto.randomUUID()`
(122 bits) ; `payment_status` vérifié.

- **W1** : `currency` vient du client et `STRIPE_MIN_AMOUNT_CENTS` est comparé sans
  conversion. Forcer `eur` (ou une liste blanche) côté worker.
- **W2** : les jetons `token:<uuid>` n'ont pas de TTL et aucun traitement des
  événements `charge.refunded` / `charge.dispute.created`. Prévoir une expiration
  ou une révocation.
- **W3** : préférer `POST` avec le jeton dans le corps, ou un en-tête ; raccourcir le
  TTL de `session:<id>` (24 h) et invalider après le premier `claim`.
- **W4** : refuser la requête si `ALLOWED_ORIGIN` n'est pas défini plutôt que
  `*` ; ne pas dériver `success_url` de l'en-tête `Origin`.
- **G1** : le code documente lui-même que le verrou est UX ; toute promesse
  commerciale d'exclusivité du contenu « Pro » est à relativiser tant que les
  fichiers sont servis statiquement et versionnés publiquement.

## 6. Recommandations

1. **Ne pas présenter ces primitives comme du chiffrement.** Pour la protection de
   données : AES-256-GCM / XChaCha20-Poly1305 (fichiers) ou AES-XTS (secteurs),
   clé dérivée par Argon2id avec sel aléatoire par volume, via une bibliothèque
   auditée (`cryptography`, libsodium, WebCrypto). Les motifs géométriques peuvent
   rester une couche de *présentation* (rendu visuel d'un chiffré), pas de
   *sécurité*.
2. Si l'objectif est la stéganographie : chiffrer d'abord (AEAD), puis cacher le
   chiffré ; supprimer le distingueur 0/44 ; ne pas revendiquer d'espace de clés.
3. Retirer les affirmations « supérieur à AES-256 » et les compteurs de bits du code,
   des pages `encodeur.html` et de la documentation, ou les remplacer par l'entropie
   réelle de la clé.
4. Si le SPN est conservé à titre expérimental : corriger l'usage des offsets, remplacer
   `_mix` par une couche à branch number connu (ex. matrice MDS), passer à ≥ 10
   tours, remplacer PBKDF2 par HKDF/HMAC pour le schedule, supprimer le flux XOR de
   queue (padding au secteur ou ciphertext stealing), ajouter un MAC, et soumettre
   à une cryptanalyse indépendante avant tout usage.
5. Worker : liste blanche de devises, TTL/révocation des jetons, jeton hors URL,
   `ALLOWED_ORIGIN` obligatoire.
6. Corriger les chemins `REF256_PATH`/`REF360_PATH` (ou déplacer les JSON) et
   ajouter des tests qui échouent sur les propriétés ci-dessus (permutation
   constante, dépendance mono-octet, réutilisation de masque).

## 7. Reproduction

Les vérifications ont été faites avec Python 3 standard, après copie de
`data/referent_*.json` dans `disk/` et `stegano/` :

- Permutations distinctes : `set(tuple(v[0]) for v in GeoSPN(...).pt256.values())` → 1.
- Diffusion : matrice 24×24 de dépendance obtenue en inversant un bit par position
  d'entrée sur 10 clairs aléatoires, pour 84 couples (secteur, chunk), avec
  `_derive_round` mémoïsé pour la vitesse.
- Two-time pad : `encrypt_sector(b'A'*512, 5, k)[504:] ^ encrypt_sector(b'B'*512, 5, k)[504:]`.
- Stégano : `encode` d'un message, comptage des cellules à 0, ré-encodage avec Clé A
  arbitraire et Clé 2 ré-indexée (`ref_s2.index(ref_s1[form_id])`), énumération
  4096 lectures par bloc.
