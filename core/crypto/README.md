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

> ✅ **État actuel : effectif (2026-09-11).** Le portage est fait et fusionné
> (**PR #1272**, ref #1263) : le vrai module vit dans **`common/secubox_core/crypto/`**
> (`hermes.py` + tests), packagé dans **`secubox-core` 1.4.1** et donc **importable
> au runtime** (`from secubox_core.crypto import hermes`) ; `core/crypto/hermes.py`
> est un shim de ré-export. **Déployé sur gk2** : le seam de `secubox-identity`
> rapporte `hermes-souverain`. Les primitives ont été **auditées** (passages 3 & 4,
> crypto saine) et **benchmarkées sur matériel réel** (Annexe A de l'audit :
> session ~0,5 ms, AEAD ~200 MB/s sur Cortex-A72).

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
  (+ PDF) — passages 1 & 2 (13 constats critiques/élevés corrigés), passage 3
  (`d590010`, crypto saine), passage 4 (`aede483` : Carter-18/Hybrid sains, N2
  corrigé upstream, aucun nouveau constat exploitable). Gravité résiduelle
  **Faible**. **Annexe A** : benchmark matériel réel (gk2/Cortex-A72).
  Contributions durcissement upstream : `CyberMind-FR/livreedhermes#5` (N1/W1/W2),
  `#6` (perf remplissage CSPRNG).
- Règle : **on ne réinvente rien.** La sécurité repose sur les primitives
  ci-dessus, pas sur une construction maison.

## Consommateurs

- **`secubox-identity` (#1263)** : clé device **X25519** + route `/identity/x25519`.
  Backend **enfichable** — préfère `core.crypto` (hermes) quand il est importable,
  sinon repli `cryptography` (**même primitive X25519**, aucune dégradation
  d'algorithme). Le seam adopte hermes automatiquement dès qu'il est disponible.
- **mesh / MirrorNet** : `Session` (ECDH X25519 + HKDF) pour l'accord de clés.
- **invitation (#1262)** : jetons signés + onboarding.

## À faire

1. ~~Porter `hermes.py`~~ **fait** (PR #1272) : `Identity`/`Session`/`derive_key_material`
   implémentés dans `common/secubox_core/crypto/hermes.py`.
2. ~~Packager en module importable~~ **fait** : `secubox-core` 1.4.1, `from
   secubox_core.crypto import hermes` OK au runtime, déployé sur gk2.
3. ~~Tests~~ **fait** : keygen/persistance 0600, ECDH secret partagé, AEAD
   round-trip (`common/secubox_core/crypto/tests/test_hermes.py`).
4. **Reste** : le seam de `secubox-identity` **détecte** le backend souverain
   (rapporte `hermes-souverain`) mais `ensure_x25519_pubkey` **génère encore la
   clé via `cryptography` stdlib** — même primitive X25519, aucune dégradation.
   Câbler la génération sur `hermes.Identity.generate()` pour fermer la boucle.

## Règles de sécurité (rappel CSPN)

- Clés privées : hors code, `chmod 600`, jamais exportées telles quelles.
- Jamais de primitive « maison » sur le chemin critique.
- Séparer signature (Ed25519) et accord de clés (X25519) — deux clés distinctes.
