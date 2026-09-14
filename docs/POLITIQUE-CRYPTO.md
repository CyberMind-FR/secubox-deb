# Politique cryptographique — SecuBox-Deb

> Document de référence pour l'évaluation CSPN. Il énonce ce que le produit
> emploie, pourquoi, et les rares exceptions — avec leur justification.

**Règle unique : aucun algorithme maison, aucun assemblage original.** Chaque
primitive est publiée et implémentée par OpenSSL (via `pyca/cryptography` côté
Python, `EVP_*` côté C, la bibliothèque standard côté Go). Le seul argument
recevable devant un évaluateur est « c'est la norme, et voici sa référence ».

---

## 1. Catalogue

| Usage | Algorithme | Référence | Où |
|---|---|---|---|
| Accord de clés | **X25519** | RFC 7748 · NIST SP 800-186 | `secubox_core.crypto` |
| Signature | **Ed25519** | RFC 8032 · FIPS 186-5 (2023) | `secubox_core.crypto`, identity |
| Dérivation de clés | **HKDF-SHA256** | RFC 5869 · SP 800-56C | `secubox_core.crypto` |
| Chiffrement authentifié | **AES-256-GCM** | NIST SP 800-38D · ISO/IEC 19772 | sessions, clés au repos |
| Mots de passe, phrases secrètes | **Argon2id** | RFC 9106 (PHC) | `user_store`, billets, identity |
| Empreintes, identifiants | **SHA-256** | FIPS 180-4 | `secubox_core.crypto.empreinte` |
| Jetons imprévisibles | **CSPRNG système** | `secrets` / `getrandom(2)` | partout |
| Jetons de session web | **JWT HS256** | RFC 7519 · RFC 7518 | `secubox_core.auth` |
| Preuve à divulgation nulle | **SHA3-256** | FIPS 202 | `zkp-hamiltonian` |
| Transport | **TLS 1.3** | RFC 8446 | HAProxy (frontal) |

### Ce que le produit n'emploie nulle part

Vérifié par balayage du dépôt : aucun **MD5**, aucun **DES/3DES**, aucun
**RC4**, aucun **Blowfish**, aucun mode **ECB**, aucun **TLS < 1.2**, et aucun
`random` non cryptographique sur un chemin de sécurité. Les seules occurrences
de noms d'algorithmes faibles sont dans un **classifieur qui les détecte** chez
les autres (`secubox_core/classifiers/security_quality.py`) — c'est un usage
défensif, pas une utilisation.

---

## 2. Décisions qui méritent une justification

### AES-256-GCM plutôt que ChaCha20-Poly1305

Les deux sont des AEAD respectables et normalisés. AES l'emporte pour deux
raisons :

1. l'ANSSI prend AES pour référence dans son guide de sélection d'algorithmes
   cryptographiques — s'en écarter demande une justification que nous n'avons
   pas ;
2. **le matériel cible la porte.** Les cœurs Armada exposent les extensions
   cryptographiques ARMv8 (`aes`, `pmull`, vérifié dans `/proc/cpuinfo` de la
   box) : AES-GCM y est exécuté par le silicium, ChaCha20 par le logiciel. Le
   choix conforme est ici aussi le choix rapide.

### Nonces compteur et clés directionnelles

AES-GCM est impitoyable sur la réutilisation de nonce : deux messages chiffrés
sous la même clé avec le même nonce livrent la clé d'authentification, pas
seulement le clair.

La parade usuelle — nonce aléatoire de 96 bits, plafonné à 2³² messages — est
correcte mais **probabiliste**. Nous appliquons la *construction déterministe*
du NIST SP 800-38D §8.2.1 : un compteur, qui ne peut pas se répéter.

Pour que deux pairs ne comptent pas en parallèle sous la même clé, deux clés
**directionnelles** sont dérivées du même secret ECDH, comme le font TLS 1.3 et
Noise :

```
clé A→B = HKDF(secret, info ‖ "|A>B")
clé B→A = HKDF(secret, info ‖ "|B>A")
```

Le rôle A ou B ne se négocie pas : il se déduit de l'ordre lexicographique des
deux clés publiques, que les deux pairs connaissent. La collision de nonce
devient **structurellement impossible**, et non plus simplement improbable.

Le plafond de 2³² invocations par clé reste appliqué et **lève une erreur** :
au-delà, l'analyse de sécurité du mode ne couvre plus cette clé.

### Argon2id pour les clés privées au repos

Les clés privées exportables étaient protégées par `Scrypt(n=2¹⁴, r=8, p=1)` —
16 Mio, le paramètre « interactif » de l'article de 2009 — puis par Fernet,
c'est-à-dire AES-**128**-CBC + HMAC-SHA256.

Le produit hachait déjà ses **mots de passe** en Argon2id. Protéger une clé
privée plus faiblement qu'un mot de passe est une incohérence qu'un évaluateur
relève avant nous. Désormais : **Argon2id (64 Mio, 3 passes, 4 voies** — profil
RFC 9106 §4**) → AES-256-GCM**, le sel étant authentifié en AAD pour qu'une
substitution fasse échouer le tag plutôt que produire un clair douteux.

### Deux clés par identité, jamais une

Une clé Ed25519 peut mathématiquement être convertie en X25519. Nous nous y
refusons : réutiliser un même secret pour signer **et** pour négocier fait que
la compromission d'un usage emporte l'autre, et complique toute rotation. Deux
clés coûtent 32 octets.

### Empreintes : une fonction, pas vingt-trois

Une vingtaine d'endroits fabriquaient un identifiant avec un hachage hérité
tronqué. Aucun n'était une faute — ce sont des étiquettes (identifiant de
webhook, de politique de cookies, de pair), pas des preuves.

Mais un évaluateur qui cherche ce nom d'algorithme en trouvait vingt-trois, et
devait examiner vingt-trois cas pour conclure qu'aucun n'était grave. Tout est
passé par `secubox_core.crypto.empreinte.ident()` — **SHA-256 tronqué**, relu
une fois, avec séparation non ambiguë des parties.

> La troncature de SHA-256 est normalisée (FIPS 180-4 §7 ; c'est le principe de
> SHA-224/384). À 48 bits, il faudrait ~17 millions d'entrées pour une chance
> sur deux de collision, là où ces tables en comptent des dizaines.

---

## 3. Exceptions imposées par un protocole

Deux, toutes deux documentées **dans le code** à l'endroit concerné.

### `secubox-turn` — HMAC-SHA1

Le mécanisme d'identifiants temporaires TURN (« TURN REST API »,
`static-auth-secret` de coturn) définit le mot de passe comme
`base64(HMAC-SHA1(secret, username))`. Un serveur qui calculerait un HMAC-SHA256
**refuserait tous les clients WebRTC existants** : ils vérifient SHA-1 et ne
négocient rien.

Les attaques connues sur SHA-1 sont des **collisions** (SHAttered, 2017).
HMAC-SHA1 n'en dépend pas : sa sécurité repose sur la résistance à la préimage
sous clé, non entamée — c'est pourquoi la RFC 6151 déconseille SHA-1 pour les
signatures tout en laissant HMAC-SHA1 en service. La protection réelle tient au
secret (long, aléatoire) et à l'expiration de l'identifiant.

### `secubox-p2p` — identifiant de nœud Kademlia sur 160 bits

Kademlia définit un espace d'identifiants de 160 bits et une distance XOR sur
cet espace ; table de routage, k-buckets et convergence des recherches en
dépendent. Passer à SHA-256 ne renforcerait rien : cela produirait un espace
incompatible avec tout pair existant, et il faudrait tronquer — donc revenir à
160 bits.

**Aucune propriété de sécurité ne repose sur ce hachage** : il répartit des
identifiants, il n'authentifie personne. L'authentification d'un pair se fait
par sa clé Ed25519, pas par sa place dans l'anneau.

---

## 4. Points ouverts

| Sujet | État | Remarque |
|---|---|---|
| **JWT HS256** | standard, symétrique | RFC 7519/7518. Un passage à **EdDSA** (RFC 8037) permettrait de distribuer une clé publique de vérification sans partager le pouvoir de signer. Non bloquant ; à arbitrer. |
| **ZKP hamiltonien** (`zkp-hamiltonian`) | primitives standard | SHA3-256 (FIPS 202) via OpenSSL EVP, aléa par `getrandom(2)`. Le protocole est celui de Blum (1986), publié. **Il n'est dans aucun chemin d'authentification en production** — le paquet installé est un tableau de bord. |
| **Courbes** | Curve25519 | X25519/Ed25519 sont désormais couverts par NIST (SP 800-186, FIPS 186-5). Si l'évaluation exige une courbe de la liste historique ANSSI (FRP256v1, Brainpool), le point est à rouvrir — le code isole déjà les primitives dans un seul module. |

---

## 5. Vérifier soi-même

```bash
# Aucun algorithme faible employé (les seuls hits doivent être le classifieur
# défensif et les deux exceptions documentées ci-dessus) :
grep -rn "hashlib.md5\|hashlib.sha1\|MODE_ECB\|RC4\|Blowfish" \
  --include=*.py --include=*.go --include=*.c common/ packages/

# Aucun aléa non cryptographique sur un chemin de sécurité :
grep -rn "random\.\(choice\|randint\|random\|sample\)" --include=*.py \
  common/ packages/ | grep -i "token\|secret\|key\|nonce\|salt\|password"

# La suite du cœur cryptographique :
cd common && python3 -m pytest secubox_core/crypto/tests/ -v
```

---

*Gérald Kerma — CyberMind · <devel@cybermind.fr>*
