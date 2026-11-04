<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# USB Master — publication locale depuis une clé USB (#3429, phase B)

CONCEPTION, non implémentée. Alpha 21. Marquage : EXISTANT / À ÉTENDRE / NOUVEAU.

Vision du 2026-11-03 (`architecture.md` § 0, fait foi) : une clé USB branchée sur un nœud est une **publication locale
de ce nœud** (`toto.<nœud>.secubox.in`), diffusée ensuite automatiquement comme toute publication
(`distributed-hosting.md` § 5) : nom court, miroir d'office, répartition. **Aucune signature** (décision 3 reportée),
**aucun geste d'adoption**. L'authenticité est celle du nœud qui lit la clé.

Ce qui reste de la règle « jamais de confiance parce que branché » : la clé n'est jamais **exécutée** ni analysée en
root ; son contenu passe par l'adaptateur du module comme une archive quelconque (refus d'une archive hostile).

## 1. Existant réutilisé

| Élément | Statut | Référence |
|---|---|---|
| Clé reconnue par étiquette, montée en lecture seule le temps de la lecture | EXISTANT | `secubox-premier-pas/systemd/secubox-premier-pas.service:16-17` (`SBXPROFIL`) |
| Schéma strict | EXISTANT (modèle) | `secubox-premier-pas/premier_pas/provision.py:12-20` |
| Vérification `gpgv` | EXISTANT, **non utilisée en A21** (chantier ultérieur de signature) | `provision.py:128-139` |

## 2. Contenu d'une clé `SBXSITE` (NOUVEAU)

```
/ (étiquette SBXSITE, vfat ou ext4)
├── support.toml           # id aléatoire (128 bits), cree_le ; aucun secret
└── sites/<nom>/
    ├── site.toml          # module (défaut metablogizer), type (défaut statique)
    └── contenu.tar        # ou un répertoire contenu/ que l'unité archive à la copie
```

Le numéro de série USB est relevé à titre indicatif et journalisé, jamais décisif.

## 3. Cycle de lecture

```
udev (étiquette SBXSITE) ─▶ unité root oneshot mirrornet-usb@<dev>  (NOUVEAU)
   montage ro,nodev,nosuid,noexec sous /run/secubox-mirrornet/usb
   copie bornée (quota) vers /data/mirrornet/entree/<id>/, démontage
   ──▶ secubox-mirrornet (non root) : schéma de support.toml / site.toml, BLAKE2b de l'archive
   ──▶ adaptateur du module : installer + activer sur CE nœud (refus d'archive hostile → rien publié, audit)
   ──▶ publication locale : toto.<nœud>.secubox.in, puis annonce de nom et de version (distributed-hosting.md § 5)
```

- L'unité root ne fait que monter, copier, démonter (argv fixe, `ProtectSystem=strict`, `ReadWritePaths` limité à
  `/data/mirrornet/entree` et `/run/secubox-mirrornet`) ; aucune analyse en root. Exception RULES-CODE § 10 à écrire,
  modèle `sbx-autoflash.service`.
- Une box sans `/data` refuse la lecture.
- `origine = usb:<nœud>:<id-support>` dans le descripteur (`replication.md` § 2) ; le nœud lecteur est le nœud source.
- Réglage par nœud `mirrornet.toml` `[usb] publication = true` (défaut proposé : vrai, conforme à la vision ; un
  administrateur peut le couper sur une box exposée à des tiers). Audit de chaque lecture.

## 4. Nouvelle version depuis la clé

Une clé relue avec le même `<nom>` sur le **même nœud** produit une version suivante de sa chaîne (parent = tête
locale). Lue sur un **autre** nœud : publication de cet autre nœud, donc soit miroir (même contenu), soit conflit de
nom (`distributed-hosting.md` § 6) : la clé ne transporte aucune titularité.

## 5. Écriture sur la clé

Hors A21 : la clé est préparée hors box (copie de fichiers). Un script d'aide `mirrornet-cle-preparer` est documenté.

## 6. Support perdu

Sans signature, une clé perdue ne porte aucun pouvoir hors d'un nœud qui publie ce qu'on y branche. Un administrateur
peut **refuser localement** un `id` de support (`mirrornet.toml` `[usb] refuses = [...]`, audit). Révocation fédérée
d'un support et versions « à revérifier » : chantier ultérieur (avec la signature de site).

## 7. Tests

Clé sans étiquette → ignorée ; `support.toml` hors schéma → refus audité ; `..`, lien sortant, périphérique, chemin
absolu dans l'archive → refus par l'adaptateur avant écriture ; clé plus grosse que le quota → refus ; `[usb]
publication = false` → rien ; support refusé localement → rien ; clé valide → `toto.<nœud>.secubox.in` servi sans geste,
puis nom court après convergence, puis copie sur un autre nœud ; même clé lue sur un second nœud → miroir.
Banc : **gk9** (matériel NON VÉRIFIÉ), à défaut gk6.
