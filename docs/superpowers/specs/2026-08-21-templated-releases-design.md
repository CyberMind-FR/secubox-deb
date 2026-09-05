<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Releases templatés — profils `isp` / `full` × cibles — Design

**Goal :** produire des images d'installation PROPRES (aucun module non fini,
désactivé ou non installé) en deux profils — `isp` (socle routeur/FAI) et `full`
(isp + les apps *working* de all.gk2.secubox.in) — déclinées par cible : USB
installer, VirtualBox (amd64), amd64 réel, boards arm64 (mochabin/espressobin).

**Architecture (résumé) :** on N'ajoute PAS un second pipeline. On réutilise
`image/build-image.sh` (déjà multi-arch), on ajoute UN méta-paquet `secubox-isp`
(calqué sur `secubox-lite`), on RE-CURE `secubox-full` sur le working-set réel,
on corrige la ligne qui code en dur `secubox-full`, et on ajoute une porte de
vérification qui refuse toute image dont un profil référence un module
inexistant ou non-working.

**Tech Stack :** Debian meta-packages (`Architecture: all`), `debootstrap`,
`image/build-image.sh` (bash), `board/*/config.mk`, GitHub Actions
(build-packages.yml + build-image.yml), Go cross-compile (`GOARCH`).

**Spec source :** cet audit + snapshot board gk2 (services `enabled`) + catalogue
all.gk2.secubox.in.

## Global Constraints

- **Working = board, pas markdown.** La vérité « module fini/working » vient du
  board de référence (gk2 : services `systemctl enabled` + catalogue
  all.gk2.secubox.in), JAMAIS de `.claude/MIGRATION-MAP.md` (optimiste, tout ✅).
- **Additif, zéro régression.** Aucune modification ne doit casser les builds
  existants (mochabin/espressobin/vm-x64 restent en `secubox-full` par défaut si
  non changés). Le seul changement de comportement est volontaire et opt-in par
  `SECUBOX_PROFILE`.
- **Un profil est une allowlist explicite.** Un méta-paquet (`Depends`) EST le
  profil. Rien n'entre dans une image sans être dans la chaîne `Depends` d'un
  méta-paquet curé — un module non fini ne peut pas « fuiter ».
- **`Architecture: all` par défaut.** Tout nouveau méta-paquet est arch:all.
- Pas de secret en clair ; provisioning au firstboot (déjà en place).

---

## 1. Architecture actuelle (ce qui existe déjà)

### 1.1 Pipeline d'image (réutilisable tel quel)
- `image/build-image.sh` — point d'entrée UNIQUE, **arm64 ET amd64**
  (`DEBIAN_ARCH` vient du board). Debootstrap → installe des paquets de base →
  installe le profil SecuBox → boot (GRUB EFI pour x64/VM, U-Boot+DTB Marvell
  pour les boards) → sort un `.img` (+ `.vdi` VirtualBox, `.qcow2` QEMU).
- **BUG à corriger :** `image/build-image.sh` installe en DUR `secubox-full`
  (~ligne 672) au lieu de `${SECUBOX_PROFILE}` que les `board/*/config.mk`
  définissent déjà. C'est la clé de voûte : un seul mot à remplacer débloque
  tout le reste.
- `board/*/config.mk` définit déjà `DEBIAN_ARCH` + `SECUBOX_PROFILE`
  (`secubox-full` | `secubox-lite`) :
  - `mochabin` (arm64, full), `espressobin-v7`/`ultra` (arm64, lite),
    `vm-x64` (**amd64**, full, `.vdi`), `vm-arm64` (qemu), `rpi400` (usb).
- USB : `image/build-live-usb.sh`, `image/build-installer-iso.sh`,
  `image/build-rpi-usb.sh`. VirtualBox : `board/vm-x64` + `image/create-vbox-vm.sh`.
- CI : `build-packages.yml` (matrice {package × arch} d'après `Architecture:`)
  → artefact `secubox-debs-all` → `build-image.yml` (`--slipstream`) →
  `*.img.gz` + Release GitHub sur tag `v*`.

### 1.2 Mécanisme de profil (partiel)
- Méta-paquets `packages/secubox-{full,lite,core,defaults}/debian/control`
  (Architecture: all, chaînes `Depends`). `secubox-lite` = le plus proche d'un
  socle ISP (core, hub, portal, crowdsec, wireguard, netmodes, nac, system,
  hardening ; « DPI/QoS/CDN exclus »). `secubox-full` = 49 modules (dont
  beaucoup non finis → À RE-CURER).
- `debian/secubox.yaml` par paquet (132 présents) : `category`, `tier`. Trop
  grossier pour trancher isp vs app (`misc`=73, `tier:lite`=113) → on n'en
  dépend PAS pour la sélection ; on garde l'allowlist explicite.
- `image/profiles/*.conf` : `get_secubox_modules()` avec cas full/lite/network/
  custom — mais consommé uniquement par `image/multiboot/build-fullsize-usb.sh`,
  PAS par `build-image.sh`. Fork à unifier (ajouter un cas `isp`).

### 1.3 Faisabilité amd64
- `packages/*/debian/control` : **169 `all`, 6 `any`, 5 `arm64`**.
- Bloquants pour un profil ISP amd64 : **`secubox-dpi` et `secubox-waf-ng`** sont
  `Architecture: arm64`. Tout le reste du socle est arch:all.
- `secubox-daemon`, `zkp-hamiltonian`, `secubox-radio` sont `any` (déjà amd64).

---

## 2. Architecture proposée

### 2.1 Deux méta-paquets = deux profils

**`packages/secubox-isp/debian/control`** (NOUVEAU, `Architecture: all`) — le
socle routeur/FAI propre. `Depends` (dérivé du working-set réseau/sécurité
`enabled` sur gk2, calqué sur `secubox-lite` élargi) :

```
secubox-core, secubox-defaults, secubox-hub, secubox-portal, secubox-system,
secubox-auth, secubox-users, secubox-identity,
secubox-netmodes, secubox-nac, secubox-wireguard, secubox-dns,
secubox-vortex-dns, secubox-dns-provider, secubox-modem, secubox-routes,
secubox-netdiag, secubox-traffic,
secubox-waf, secubox-vortex-firewall, secubox-haproxy, secubox-crowdsec,
secubox-ipblock, secubox-hardening, secubox-certs, secubox-exposure,
secubox-qos, secubox-vhost, secubox-mediaflow, secubox-cdn, secubox-netdata,
secubox-watchdog, secubox-health-doctor
```

`Recommends` (présents mais non essentiels au boot routeur) :
`secubox-dpi, secubox-waf-ng, secubox-tor, secubox-mesh, secubox-p2p,
secubox-meshname, secubox-security-posture`.
*Rationale Recommends :* dpi/waf-ng sont arch-spécifiques (cf. §2.3) — en
`Recommends` un build amd64 sans build amd64 de ces paquets n'échoue pas.

**`packages/secubox-full/debian/control`** (RE-CURÉ, `Architecture: all`) —
`secubox-isp` + UNIQUEMENT les apps *working* du catalogue all.gk2 :

```
Depends: secubox-isp,
  secubox-bbs, secubox-billets, secubox-nextcloud, secubox-gitea,
  secubox-jellyfin, secubox-lyrion, secubox-peertube, secubox-podcaster,
  secubox-torrent, secubox-webmail, secubox-mail, secubox-ytsas,
  secubox-zigbee, secubox-metablogizer, secubox-publish, secubox-radio
```

> Les modules `enabled` mais HORS catalogue all.gk2 et non stabilisés
> (matrix, mastodon, jitsi, homeassistant, domoticz, frigate, openclaw,
> spiderfoot, streamlit, redroid, voip, simplex, localai, ollama, …) restent
> INSTALLABLES depuis apt.secubox.in à la demande, mais NE SONT PAS dans l'image
> `full`. C'est le sens de « propre ».

### 2.2 Débloquer le pipeline (1 ligne + configs)
- `image/build-image.sh` : remplacer le `secubox-full` codé en dur par
  `${SECUBOX_PROFILE:-secubox-full}`.
- `image/profiles/x64-live.conf` : `get_secubox_modules()` gagne un cas `isp`
  → `secubox-isp`.
- Nouveaux `board/*/config.mk` (ou variable `SECUBOX_PROFILE` surchargée par
  `--profile`) pour la matrice cible × profil (cf. §2.4).

### 2.3 amd64 : dpi + waf-ng
**Décision (recommandée) :** basculer `secubox-dpi` et `secubox-waf-ng` en
`Architecture: any` et activer le cross-build amd64 (Go : `GOARCH=amd64`, déjà
trivial ; `build-packages.yml` construit déjà `any`→amd64+arm64). Alors le profil
`isp` est COMPLET sur amd64/VirtualBox.
**Repli :** si le cross-build C de waf-ng pose problème, les garder en
`Recommends` (§2.1) → l'image amd64 tombe proprement sur `secubox-waf` (arch:all)
sans dpi natif. À trancher à l'implémentation, non bloquant pour la structure.

### 2.4 Matrice cible × profil

| cible | board/config | arch | profils | sortie |
|---|---|---|---|---|
| arm64 mochabin | `mochabin` | arm64 | isp, full | `.img` |
| arm64 espressobin | `espressobin-v7/ultra` | arm64 | isp (défaut), full | `.img` |
| VirtualBox | `vm-x64` | amd64 | isp, full | `.vdi` (+raw) |
| amd64 réel | `x64-live` | amd64 | isp, full | `.img` |
| USB installer | `build-installer-iso.sh` / `rpi400` | amd64/arm64 | isp, full | `.iso`/`.img` |

`SECUBOX_PROFILE` porte le profil ; `--profile isp|full` en argument de
`build-image.sh` le surcharge (défaut = valeur du board).

```
                    ┌────────────── secubox-core (+defaults) ──────────────┐
                    │            requis par TOUS les modules               │
                    └──────────────────────────────────────────────────────┘
      secubox-isp  = core + réseau/firewall/dns/waf/wireguard/nac/… (allowlist)
      secubox-full = secubox-isp + { 13 apps working de all.gk2 }  (allowlist)

   build-image.sh --board <b> --profile <isp|full>
        └─ debootstrap(arch du board) → apt install ${SECUBOX_PROFILE}
              └─ slipstream output/debs/*_all.deb|*_${arch}.deb  (CI frais)
                    └─ .img / .vdi / .iso  →  Release GitHub
```

### 2.5 Porte « fini » (le cœur de « propre »)
Nouveau `scripts/verify-profile.sh <isp|full>` (lancé en CI AVANT le build image)
qui, pour chaque module de la chaîne `Depends` du méta-paquet :
1. vérifie qu'un paquet buildable existe (`packages/<m>/debian/control`) ;
2. vérifie qu'il est *working* sur le board de référence — comparaison à un
   snapshot versionné `image/profiles/working-set.gk2.txt` (liste des services
   `enabled` + catalogue all.gk2, régénérable par
   `scripts/snapshot-working-set.sh root@gk2`).
Échec CI si un profil référence un module inexistant ou hors working-set → un
module non fini ne peut littéralement pas entrer dans une image.

---

## 3. Modèle de données / fichiers

- **Nouveau :** `packages/secubox-isp/` (control, changelog, rules, compat) —
  méta-paquet.
- **Modifié :** `packages/secubox-full/debian/control` (Depends re-curé).
- **Modifié :** `image/build-image.sh` (1 ligne), `image/profiles/x64-live.conf`
  (cas `isp`).
- **Modifié (décision §2.3) :** `packages/secubox-dpi/debian/control`,
  `packages/secubox-waf-ng/debian/control` (`Architecture: any`) +
  `build-packages.yml` (cross amd64 pour ces 2).
- **Nouveau :** `scripts/verify-profile.sh`, `scripts/snapshot-working-set.sh`,
  `image/profiles/working-set.gk2.txt`.
- **Modifié :** `.github/workflows/build-image.yml` (axe `profile: [isp, full]`
  dans la matrice ; garde `verify-profile.sh`).
- **Nouveaux :** `board/x64-live/config.mk` (compléter), entrées profil.

## 4. Compatibilité / migration
- Purement additive : les boards existants gardent leur `SECUBOX_PROFILE`
  actuel ; l'image `full` d'aujourd'hui reste `full` (juste re-curée — les
  modules retirés ne cassent rien, ils ne sont plus tirés).
- `secubox-lite` conservé (rétro-compat) ; `secubox-isp` est le nouveau nom
  canonique du socle (peut, à terme, faire de `secubox-lite` un alias
  `Depends: secubox-isp`).

## 5. Tests
- `scripts/verify-profile.sh isp|full` : refuse un module absent/non-working
  (test unitaire avec un working-set factice + une chaîne Depends factice).
- Build CI d'au moins `vm-x64` (amd64) en profils isp ET full — boot smoke
  (GRUB → login) via QEMU headless si dispo.
- `dpkg-buildpackage` de `secubox-isp` (arch:all) + résolution de deps
  (`apt-get install -f`) dans un chroot de test.
- Régression : `build-image.sh --board mochabin` (défaut) inchangé.

## 6. Wireframe — sélecteur de release (page catalogue, optionnel)
```
┌ SecuBox — Télécharger ────────────────────────────────┐
│  Profil : ( ) isp  (•) full        Cible : [ VirtualBox ▾]│
│  ────────────────────────────────────────────────────  │
│  secubox-full-vm-x64-bookworm.vdi     amd64 · 2.4 Go     │
│  [ Télécharger ]   sha256 · signature GPG               │
│  Inclus : socle ISP + bbs, billets, cloud, gitea,       │
│           jellyfin, lyrion, peertube, podcaster,        │
│           torrent, webmail, ytsas, zigbee               │
└─────────────────────────────────────────────────────────┘
```
