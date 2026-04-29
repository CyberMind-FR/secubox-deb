# SecuBox Profile Generator — Architecture

**Status** : Draft v0.2 — aligné sur ROADMAP PHASE 12
**Cible** : SecuBox-Deb v1.5+, ANSSI CSPN 2027, Campagne 1 Ulule (4 juin 2026)
**Auteurs** : Gandalf (CyberMind)
**Repo cible** : `CyberMind-FR/secubox-deb` → `docs/architecture/profile-generator.md`

**Changelog**
- v0.2 (2026-04-29) : Aligné sur PHASE 12 du ROADMAP. CLI éclatée en 3 outils
  (`secubox-gen` / `secubox-build` / `secubox-fetch`). Ajout §10 (registry +
  participation), §11 (scope MVP). Cross-walk P12-XX intégré.
- v0.1 (2026-04-29) : Squelette initial.

---

## 0. Décisions ouvertes (à trancher avant figeage)

| # | Décision | Options | Recommandation provisoire | Bloque |
|---|----------|---------|---------------------------|--------|
| D1 | Sémantique d'héritage `inherits:` | Merge récursif simple / Typé strict NixOS-like / Hybride | Hybride : merge récursif + schema typé sur clés CSPN-critiques | P12-01 |
| D2 | Modules canoniques (AUTH/…/MESH) dans le moteur | Axe orthogonal résolu / Narratif & graphique uniquement | Axe orthogonal résolu | P12-01 |
| D3 | Langage des CLI | Python 3.11+ / Go / mixte | Python pour `secubox-gen` (logique riche) ; Go envisageable pour `secubox-fetch` (binaire portable) | P12-04/05/06 |
| D4 | Performance profiles board (idle/normal/busy/stressed) | Build-time presets / Runtime adaptive (`tuned-adm` style) | Runtime adaptive → service ROOT, sort du périmètre P12 | P12-02 |
| D5 | Flavors orthogonaux (stage/locale/persona) | MVP minimal (stage seul) / Tous dès v2.0.0 | MVP : `stage` seul. Locale + persona en v2.1 | P12-01 |
| D6 | Migration in-place vs reflash | Reflash systématique / apt-bundle in-place avec PARAMETERS 4R | apt-bundle pour MINOR/PATCH ; reflash pour MAJOR | hors P12, PHASE 14 |
| D7 | Secrets dans profils | Refs externes uniquement / SOPS / age | age + refs externes, jamais en clair | P12-01 |
| D8 | Audit CSPN du moteur lui-même | In-scope / Out-of-scope (outil de build) | Out-of-scope, mais sortie auditée (lockfile signé) | hors P12 |

---

## 1. Hiérarchie des profils (Gigogne / Nested)

> **Mapping ROADMAP** : P12-01 (hiérarchie), P12-02 (boards)

```
profiles/
├── base/                    # Core SecuBox (tous devices)
│   ├── profile.yaml         # Configuration de base
│   └── services/            # Services minimaux
├── tier-lite/               # Devices contraints (≤1GB RAM, ≤2 cores)
│   ├── profile.yaml         # inherits: base
│   └── tweaks/              # Optimisations mémoire/CPU
├── tier-standard/           # Devices standards (RPi4, VM)
│   ├── profile.yaml         # inherits: tier-lite
│   └── services/            # Set complet de services
├── tier-pro/                # Haute performance (MOCHAbin, bare metal)
│   ├── profile.yaml         # inherits: tier-standard
│   └── features/            # Features avancées
├── boards/                  # Tweaks hardware-specific (P12-02)
│   ├── rpi-zero-w/
│   │   ├── tweaks.yaml      # USB OTG, memory limits
│   │   └── dts/             # Device tree overlays
│   ├── espressobin-v7/
│   ├── mochabin/
│   └── vm-x64/
├── modules/                 # Modules canoniques transverses (D2)
│   ├── auth/                # NIZK + G rotate 24h (L1 ZKP)
│   ├── wall/                # nftables + CrowdSec
│   ├── boot/                # secure boot, LUKS
│   ├── mind/                # nDPId, mitmproxy bridge (L2 partiel)
│   ├── root/                # base system, kernel, perf profiles
│   └── mesh/                # WireGuard, Tailscale, MirrorNet (L3)
└── flavors/                 # Axes orthogonaux (D5, MVP = stage seul)
    └── stage/               # dev / staging / cspn-frozen
        # locale/  → v2.1
        # persona/ → v2.1
```

**Principe directeur** : un build = `tier × board × {flavors}` aplati en un
manifest unique versionné via lockfile. `modules/<name>/levels.yaml` expanse
les niveaux d'activation (`disabled`/`minimal`/`standard`/`full`) en
listes de paquets et configs.

**Auto-sélection (P12-01)** : `secubox-gen --auto` détecte le board
(`/proc/device-tree/model`, DMI, etc.), mesure RAM/CPU/storage, propose un
`tier` minimal et liste les `boards/<id>/tweaks.yaml` compatibles.

---

## 2. Sémantique d'héritage et résolution

> **Mapping ROADMAP** : implicite dans P12-01 (`inherits:`) — à préciser.

### 2.1 Modèle hybride proposé (D1)

Chaque clé d'un `profile.yaml` est typée par le **schema central**
(`schema/profile.schema.json`) qui déclare son **mode de combinaison** via
l'extension `x-secubox-merge:` :

| Mode | Sémantique | Exemple de clé |
|------|------------|----------------|
| `replace` | Le fils écrase le parent (default scalar) | `system.hostname` |
| `merge` | Merge récursif clé à clé (default object) | `services.config` |
| `union` | Union de listes, dédupliquée | `packages.install` |
| `intersect` | Intersection (le fils restreint) | `kernel.modules.allowed` |
| `frozen` | Le fils ne peut PAS modifier (CSPN) | `auth.zkp.curve`, `auth.zkp.rotation_hours` |
| `additive` | Append uniquement, jamais retirer | `audit.rules` |

**Pour MVP** (P12-01 v2.0.0) : on peut shipper avec `replace`/`merge`/`union`
uniquement, et ajouter `frozen`/`intersect`/`additive` en v2.1 quand le
durcissement CSPN devient prioritaire. Cette dette est acceptable si elle est
explicitement tracée.

### 2.2 Ordre de résolution (precedence)

```
base
  → tier-{lite|standard|pro}
    → board-{rpi-zero-w|espressobin-v7|mochabin|vm-x64}
      → modules.{auth,wall,boot,mind,root,mesh}.activation
        → flavors.stage={dev|staging|cspn-frozen}
          → CLI override (ex: --enable crowdsec,wireguard --tweak low-memory)
```

Le dernier en lice gagne, sous réserve des contraintes `frozen`/`intersect`.

### 2.3 Détection de violations

Le résolveur DOIT échouer (build break) si :
- Un fils tente de modifier une clé `frozen` héritée
- Une clé `intersect` produit un ensemble vide
- Le board déclare des `capabilities` incompatibles avec le `tier` (ex.
  `tier-pro` sur `espressobin-v7` 1GB RAM)
- Un composant `requires:` un autre composant absent ou en conflit (P12-03)

### 2.4 Versionnage des composants (P12-03)

Format de version SecuBox : `<upstream>-sb<N>` (ex. `1.7.7-sb3`).

```yaml
# components/secubox-crowdsec/component-version.yaml
name: secubox-crowdsec
version: 1.7.7-sb3
upstream_version: 1.7.7
secubox_patch_level: 3
tags: [security, ids, optional]
compatibility:
  min_memory: 512M
  min_cores: 1
  requires: [secubox-nftables]
  conflicts: [secubox-suricata]
modules: [wall]              # ownership module canonique
cspn_sensitivity: info       # none | info | eal2 | eal4
```

---

## 3. Modules canoniques et niveaux d'activation

> **Mapping ROADMAP** : à ajouter à PHASE 12 (absent du roadmap actuel — D2).

### 3.1 Mapping aux 6 modules SecuBox

| Module | Couleur Light 3 | Couche ZKP | Responsabilité |
|--------|-----------------|------------|----------------|
| AUTH | `#C04E24` | L1 | NIZK Hamiltonian, G rotation 24h, PFS |
| WALL | `#9A6010` | — | nftables, CrowdSec, rate limiting |
| BOOT | `#803018` | — | secure boot, LUKS, dm-verity |
| MIND | `#3D35A0` | L2 (partiel) | nDPId, mitmproxy bridge, DPI dual-stream |
| ROOT | `#0A5840` | — | base Debian, kernel, systemd, perf profiles |
| MESH | `#104A88` | L3 | WireGuard, Tailscale, MirrorNet, did:plc |

### 3.2 Niveaux d'activation par profil-tier

```yaml
# tier-lite/profile.yaml
modules:
  auth:   minimal      # NIZK only, pas de HamCoin
  wall:   standard
  boot:   minimal      # LUKS optionnel
  mind:   disabled     # pas de DPI sur ressources contraintes
  root:   minimal
  mesh:   minimal      # WireGuard seul, pas de MirrorNet
```

`modules/<name>/levels.yaml` définit ce que chaque niveau expanse en
paquets/services/configs.

### 3.3 Hamiltonian path comme contrainte fonctionnelle

Le chemin canonique `AUTH→WALL→BOOT→MIND→ROOT→MESH` (charte SPIRITUALCEPT)
sert à deux usages dans le moteur :
1. **Ordre de boot/reload des services** au runtime
2. **Rétrogradation automatique** : si un module amont est `disabled`, les
   modules aval qui en dépendent sont automatiquement rétrogradés
   (`full` → `standard` → `minimal`)

À débattre (cf. v0.1 §3 commentaire) : si trop ésotérique pour un dev
extérieur, retomber sur un simple DAG de dépendances explicite. La charte
graphique reste cohérente même sans contrainte fonctionnelle adossée.

---

## 4. Toolchain — Trois CLI Unix-style

> **Mapping ROADMAP** : P12-04 (`secubox-gen`), P12-05 (`secubox-build`),
> P12-06 (`secubox-fetch`)

Découpage en 3 outils suivant la philosophie « do one thing well ». Chacun
consomme/produit des fichiers texte versionnables (YAML, lock).

### 4.1 `secubox-gen` — Manifest generator (P12-04)

Génère un `manifest.yaml` aplati à partir d'un choix profile + board + flavors
+ overrides CLI.

```bash
# Mode déclaratif
secubox-gen \
  --profile tier-lite \
  --board espressobin-v7 \
  --enable crowdsec,wireguard \
  --tweak low-memory \
  --stage cspn-frozen \
  --output manifest.yaml

# Mode interactif avec auto-détection
secubox-gen --auto

# Validation seule (pas de génération)
secubox-gen --validate --profile tier-pro --board mochabin

# Diff entre deux manifests
secubox-gen diff old.yaml new.yaml
```

**Responsabilités** :
- Charge profils + flavors + board tweaks
- Résout l'héritage (§2)
- Vérifie contraintes (`frozen`, `intersect`, `requires`, `conflicts`)
- Émet `manifest.yaml` aplati
- Émet `secubox.lock` (§6) en parallèle

### 4.2 `secubox-build` — Image builder (P12-05)

Consomme un `manifest.yaml` + `secubox.lock` et produit un artefact bootable.

```bash
secubox-build \
  --manifest manifest.yaml \
  --lock secubox.lock \
  --format iso-live \              # iso-live | debootstrap | chroot-tar | qcow2 | apt-bundle
  --output secubox-mochabin-1.5.3.iso

# Build incrémental depuis cache
secubox-build --manifest manifest.yaml --incremental --cache /var/cache/secubox-build
```

**Responsabilités** :
- Build reproductible bit-pour-bit (modulo timestamps signés)
- Multi-stage avec checkpoints (P12-05) → reprise si échec
- Cache de couches debootstrap / chroot
- Signature GPG de l'artefact final

**Formats de sortie** :

| Format | Cas d'usage | Backend |
|--------|-------------|---------|
| `iso-live` | Démo, install bare metal, démo Ulule | live-build |
| `debootstrap` | Provisioning client | debootstrap + post-install hooks |
| `chroot-tar` | CI/CD, tests | tar.zst d'un chroot |
| `qcow2` | VM, dev | virt-builder |
| `apt-bundle` | Upgrade in-place via `apt.secubox.in` | apt repo metadata |

### 4.3 `secubox-fetch` — Pre-built downloader (P12-06)

Pour les clients qui ne buildent pas eux-mêmes (cas dominant attendu post-Ulule).

```bash
# Liste des images disponibles pour un board
secubox-fetch list --board mochabin

# Téléchargement avec vérification automatique
secubox-fetch download \
  --board mochabin \
  --version 1.5.3 \
  --tier pro \
  --output ~/Downloads/

# Vérification GPG + SHA256 d'une image locale
secubox-fetch verify secubox-mochabin-1.5.3.iso
```

**Responsabilités** :
- Catalogue les releases GitHub `CyberMind-FR/secubox-deb`
- Vérifie signature GPG (clé CyberMind release)
- Vérifie SHA256 publié dans la release
- Match automatique des versions selon hardware détecté

**Note D3** : `secubox-fetch` est un bon candidat pour Go (binaire unique
portable, exécutable sur Mac/Win sans Python). À trancher en T-1 sprint.

---

## 5. Validation de schéma et CI gates

> **Mapping ROADMAP** : à ajouter à PHASE 12 ou en transverse.

### 5.1 JSON Schema central

`schema/profile.schema.json` (Draft 2020-12) déclare :
- Toutes les clés autorisées
- Le type de chacune
- Le **mode de combinaison** (`x-secubox-merge`)
- Le **module owner** (AUTH/WALL/BOOT/MIND/ROOT/MESH)
- La **CSPN sensitivity** (none/info/eal2/eal4)

### 5.2 CI gates (3 niveaux)

1. **Lint** (chaque PR) : YAML valide + JSON Schema OK + lint des
   `component-version.yaml`
2. **Resolve** (chaque PR) : aplatissement réussit pour la matrice canonique
   `{lite,standard,pro} × {rpi-zero-w,espressobin-v7,mochabin,vm-x64}` (avec
   exclusions cohérentes : pas de `pro × rpi-zero-w`)
3. **Build smoke** (nightly) : ISO live boot test sur QEMU pour
   `tier-standard/vm-x64` ; au moins un boot test hardware réel par release
   sur MOCHAbin

### 5.3 Audit CSPN

Pour chaque release `stage=cspn-frozen`, génération automatique d'un rapport :
- Diff vs. dernier profil certifié
- Liste des clés `frozen` touchées (DOIT être vide)
- Empreinte SHA-256 du profil aplati canonique
- Liste des composants avec `cspn_sensitivity >= eal2`

---

## 6. Lockfile et fingerprint

> **Mapping ROADMAP** : P12-08 (manifest JSON pour bug reports — fusionné ici)

### 6.1 Format `secubox.lock`

Le lockfile sert simultanément à :
- **Reproductibilité** des builds
- **Audit CSPN** (empreinte du profil)
- **Bug reports** (P12-08, exporté en JSON pour automation)
- **Update notifications** (P12-11, comparaison avec registry)

```yaml
schema_version: 1
generated_at: 2026-04-29T10:23:00Z
profile_source:
  tier: pro
  board: mochabin
  flavors: { stage: cspn-frozen }
  git_ref: v1.5.3
  profile_hash: sha256:a1b2...
resolved_hash: sha256:c3d4...   # = "version fingerprint" P12-08
fingerprint_short: c3d4e5f6     # 8 hex chars, pour bug reports lisibles
packages:
  - name: secubox-crowdsec
    version: 1.7.7-sb3
    upstream: 1.7.7
    sha256: ...
  - name: secubox-nftables
    version: 1.0.6-sb1
    sha256: ...
modules_activation:
  auth: full
  wall: full
  boot: standard
  mind: standard
  root: standard
  mesh: full
hamiltonian_path_check: passed
cspn_audit:
  frozen_keys_modified: []
  sensitivity_changes: []
hardware_capabilities:           # snapshot pour bug reports
  ram_mb: 8192
  cores: 4
  storage_gb: 32
  detected_board: mochabin
```

### 6.2 Export JSON pour automation (P12-08)

```bash
secubox-gen export-lock secubox.lock --format json --output report.json
```

Utilisé par les templates d'issues GitHub (P12-12) pour donner aux mainteneurs
un contexte machine-readable sans exposer de secrets.

### 6.3 Politique de versionnage

| Niveau | Quand bumper | Stratégie de migration |
|--------|--------------|------------------------|
| `schema_version` | Format de profil incompatible | Migration script obligatoire |
| `profile MAJOR` | Changement frozen (re-CSPN) | Reflash recommandé |
| `profile MINOR` | Ajout module/feature | apt-bundle in-place |
| `profile PATCH` | Bugfix, package bump | apt-bundle in-place automatique |

---

## 7. README appliance auto-généré

> **Mapping ROADMAP** : P12-07

À chaque build, `secubox-build` produit un `APPLIANCE-README.md` embarqué dans
l'image (`/etc/secubox/APPLIANCE-README.md`) et publié à côté de l'artefact.

Contenu :
- Hardware profile résolu (board, tier, capabilities)
- Tableau des composants avec versions et statuts
- Tweaks appliqués (kernel, systemd, network)
- Modules activés et niveau (avec couleurs Light 3 en HTML companion)
- Empreinte courte (`fingerprint_short`) pour support
- Liens : doc support, issue tracker, registry status

Format : Markdown + variante HTML (charte SPIRITUALCEPT·PRINT, light bg, pas
de noir).

---

## 8. Stratégie de migration entre profils

> **Mapping ROADMAP** : absent — proposition pour PHASE 14.

### 8.1 Cas d'usage

| Scénario | Stratégie | Outil |
|----------|-----------|-------|
| Patch (1.5.2→1.5.3) | apt upgrade + config refresh | `secubox-update` (PHASE 14) |
| Minor (1.5→1.6) | apt-bundle + module activation diff | `secubox-update --plan` |
| Major (1.x→2.0) | Reflash recommandé (frozen touché) | `secubox-fetch` puis flash |
| Tier change (lite→standard) | Reflash obligatoire | `secubox-fetch` puis flash |

### 8.2 Procédure `secubox-update` (PHASE 14)

```
[device]
  ↓ fetch nouveau lock (secubox-fetch)
[apt.secubox.in]
  ↓ diff avec lock local
[plan]                              ← humain valide
  ↓ apt + config rendering
[reload services par module]        ← ordre Hamiltonian inverse
[health check par module]
  ↓ ok ?
[swap PARAMETERS double-buffer 4R]  ← mécanisme existant
```

### 8.3 Rollback

Le mécanisme PARAMETERS double-buffer 4R existant couvre le rollback :
- Buffer A = lock courant
- Buffer B = lock précédent
- Swap atomique en cas d'échec health check

---

## 9. Intégration CI/CD

> **Mapping ROADMAP** : transverse, pas un ticket P12 dédié.

### 9.1 Pipeline existant comme vue dérivée

Le pipeline actuel (10 phases / 93 paquets) devient une **vue dérivée du
moteur** : chaque phase porte un tag `min_tier:` et `module:` qui détermine
son inclusion dans un build donné.

```
profil → secubox-gen → manifest → liste de phases activées → exécution
```

### 9.2 GitHub Actions (esquisse)

```yaml
name: profile-build
on: [pull_request, push]
jobs:
  validate:
    strategy:
      matrix:
        tier: [lite, standard, pro]
        board: [rpi-zero-w, espressobin-v7, mochabin, vm-x64]
        exclude:
          - { tier: pro, board: rpi-zero-w }
          - { tier: pro, board: espressobin-v7 }
    steps:
      - run: secubox-gen --validate --profile ${{ matrix.tier }} --board ${{ matrix.board }}
  build-smoke:
    needs: validate
    if: github.event_name == 'schedule'
    steps:
      - run: secubox-build --format iso-live --manifest <(secubox-gen --profile standard --board vm-x64)
      - run: qemu-system-x86_64 -boot d -cdrom out.iso -m 2048 ...
```

---

## 10. Registry API et participation communautaire

> **Mapping ROADMAP** : P12-11 (registry API), P12-12 (participation)

### 10.1 Registry API FastAPI (P12-11)

Service `registry.secubox.in` (FastAPI, cohérent avec stack existant) exposant :

| Endpoint | Méthode | Usage |
|----------|---------|-------|
| `/components` | GET | Liste des composants disponibles avec versions |
| `/components/{name}/compat` | POST | Check compatibilité (lock en input) |
| `/profiles/{tier}/{board}` | GET | Profil canonique pré-résolu |
| `/updates/notify` | POST | Subscribe (opt-in) aux notifs sécurité |
| `/stats/usage` | POST | Stats d'usage opt-in (board + tier + version) |

**Privacy** : tout opt-in. Pas de fingerprint device sans consentement
explicite. Conformité RGPD, hébergement EU.

### 10.2 Workflow de participation (P12-12)

- **Issue templates** GitHub avec champ `secubox-fingerprint:` auto-rempli
  via `secubox-gen export-lock --format json | jq .fingerprint_short`
- **Feature requests** structurés avec contexte profil
- **Matrix de tests automatisée** : un report d'install réussie par board
  alimente la liste des « boards supportés »
- **Vote communautaire** sur les boards à supporter en priorité

---

## 11. Scope MVP et phasage

> **Question ouverte critique** : périmètre PHASE 12 vs Campagne 1 (4 juin 2026).

### 11.1 Risque identifié

PHASE 12 actuelle inclut **P12-09 (Electron/Tauri desktop app)** et
**P12-10 (web-based generator)**. Ce sont deux livrables UI à part entière,
chacun probablement aussi lourd que toute la fondation CLI/registry réunie.

**Si PHASE 12 livre les 12 tickets en bloc**, risque sérieux de glissement
au-delà de la Campagne 1.

### 11.2 Proposition de phasage

| Phase | Tickets | Cible |
|-------|---------|-------|
| **PHASE 12 — Foundations** | P12-01 à P12-08, P12-11, P12-12 | Avril → Juin 2026 (Campagne 1) |
| **PHASE 13 — Distribution UX** | P12-09 (Electron/Tauri), P12-10 (web) | Été 2026, post-Ulule |
| **PHASE 14 — In-place Update** | `secubox-update`, PARAMETERS 4R intégration | Q3 2026 |

### 11.3 MVP critique pour Campagne 1

Pour démo Ulule, le minimum viable est :
1. `secubox-gen` opérationnel sur 4 boards
2. `secubox-build` produisant ISO live démontrable sur MOCHAbin
3. `secubox-fetch` permettant aux backers « Le Sérieux » (690€) de récupérer
   leur image pré-buildée
4. README appliance auto-généré dans l'image

Le reste (registry API, web app, Electron) peut suivre.

---

## 12. Ouverts pour la suite

- **Annexe A** : `schema/profile.schema.json` complet (Draft 2020-12)
- **Annexe B** : Mapping détaillé des 93 paquets actuels → modules canoniques
  + `min_tier` + `cspn_sensitivity`
- **Annexe C** : Spec lockfile en JSON Schema + exemple JSON de bug report
- **Annexe D** : `manifest.yaml` exemple complet pour
  `mochabin × tier-pro × stage=cspn-frozen` (à drafter ensuite, cf. proposition 3)
- **Annexe E** : Audit CSPN du moteur lui-même (in-scope ou tooling externe ?)

---

## 13. Cross-walk PHASE 12 → §archi

| Ticket | Section principale | Sections complémentaires |
|--------|---------------------|--------------------------|
| P12-01 Profile hierarchy | §1 | §2 (héritage), §5 (validation) |
| P12-02 Board tweaks | §1 (`boards/`) | D4 (perf profiles) |
| P12-03 Component versioning | §2.4 | §6 (lockfile) |
| P12-04 `secubox-gen` | §4.1 | §6 (émet lock) |
| P12-05 `secubox-build` | §4.2 | §7 (README), §9 (CI) |
| P12-06 `secubox-fetch` | §4.3 | §8 (reflash path) |
| P12-07 Appliance README | §7 | §6 (fingerprint) |
| P12-08 Manifest JSON bug reports | §6.2 | §10.2 (issue templates) |
| P12-09 Electron/Tauri app | **PHASE 13** | hors §archi v0.2 |
| P12-10 Web generator | **PHASE 13** | hors §archi v0.2 |
| P12-11 Registry API | §10.1 | §6 (compat checks) |
| P12-12 Participative workflow | §10.2 | §6.2 (fingerprint) |

---

*Fin du squelette v0.2. Prochaine itération suggérée : Annexe D (manifest
exemple complet) puis Annexe A (JSON Schema).*
