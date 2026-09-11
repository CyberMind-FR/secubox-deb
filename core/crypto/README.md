<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# `core/crypto` — cœur cryptographique souverain (Hermes)

Backend crypto **souverain** de SecuBox, adapté de l'implémentation **Hermes**
(dépôt `anibaledel/livreedhermes`, commit d'origine `d4abc757`). Il fournit
l'identité, les sessions et le chiffrement authentifié pour l'identité device
(#1263), le mesh/MirrorNet et l'invitation (#1262).

> ⚠️ **État actuel : PLACEHOLDER.** Ce paquet ne contient que `__init__.py`, qui
> ré-exporte `Identity, Session, derive_key_material` depuis un module `.hermes`
> **pas encore présent**. Donc `import core.crypto` **échoue** aujourd'hui, et le
> module n'est **ni packagé ni installé** (non importable au runtime). Les
> consommateurs (voir plus bas) utilisent un **backend enfichable** qui retombe
> sur `cryptography` (stdlib) tant que ce portage n'est pas fait. Voir *À faire*.

---

## Principe

L'API sépare délibérément trois responsabilités (cf. docstring de `__init__.py`) :

| Objet | Rôle | Primitive |
|-------|------|-----------|
| `Identity` | identité **long-terme** d'un device | **X25519** (+ Ed25519 pour la signature, cf. `secubox-identity`) |
| `Session` | session **éphémère** entre deux pairs | **X25519 ECDH → HKDF-SHA256** |
| `derive_key_material` | dérivation de clés | **HKDF-SHA256** |
| (chiffrement symétrique authentifié) | confidentialité + intégrité | **ChaCha20-Poly1305 / XChaCha**, **AES-256-GCM** |

Ces primitives sont **standard et éprouvées**. La couche « géométrique » de
Hermes (Ref256 / Carter) sert **uniquement à la diversification de clé** et
**n'est PAS sur le chemin critique** de la sécurité — c'était la recommandation
centrale de l'audit (voir ci-dessous).

## Lignée & audit

- Origine : `anibaledel/livreedhermes` (Hermes), fork durci
  `CyberMind-FR/livreedhermes`.
- Audit interne : **[`docs/audits/AUDIT-CRYPTO-livreedhermes.md`](../../docs/audits/AUDIT-CRYPTO-livreedhermes.md)**
  — passages 1 & 2 (13 constats critiques/élevés corrigés ; gravité résiduelle
  **Faible**), passage 3 en cours sur la refonte `crypto_core.py`.
- Règle : **on ne réinvente rien.** La sécurité repose sur les primitives
  ci-dessus, pas sur une construction maison.

## Consommateurs

- **`secubox-identity` (#1263)** : clé device **X25519** + route `/identity/x25519`.
  Backend **enfichable** — préfère `core.crypto` (hermes) quand il est importable,
  sinon repli `cryptography` (**même primitive X25519**, aucune dégradation
  d'algorithme). Le seam adopte hermes automatiquement dès qu'il est disponible.
- **mesh / MirrorNet** : `Session` (ECDH X25519 + HKDF) pour l'accord de clés.
- **invitation (#1262)** : jetons signés + onboarding.

## À faire (pour rendre le souverain effectif)

1. **Porter `hermes.py`** depuis `livreedhermes/stegano/crypto_core.py` (primitives
   isolées) vers ce paquet, en implémentant réellement `Identity`, `Session`,
   `derive_key_material`.
2. **Packager `core/crypto`** en module **importable au runtime** (p. ex. sous
   `secubox_core.crypto`) via un `debian/*.install`, pour que les daemons le
   voient (aujourd'hui `No module named 'core'` sur la board).
3. **Tests** : keygen/persistance (0600), ECDH (secret partagé identique), AEAD
   round-trip, vecteurs.
4. Basculer le seam de `secubox-identity` sur le vrai backend une fois 1-2 faits.

## Règles de sécurité (rappel CSPN)

- Clés privées : hors code, `chmod 600`, jamais exportées telles quelles.
- Jamais de primitive « maison » sur le chemin critique.
- Séparer signature (Ed25519) et accord de clés (X25519) — deux clés distinctes.
