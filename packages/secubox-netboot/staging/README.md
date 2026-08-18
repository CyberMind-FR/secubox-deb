<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Staging des artefacts (#737)

Un sous-dossier par version d'image : `/var/lib/secubox/netboot/staging/<image>/`.
`secubox-netboot-publish` (via l'API /publish) y lit selon le `boot_level` du profil :

| Niveau | Fichiers attendus dans `staging/<image>/` |
|--------|-------------------------------------------|
| B1 | `Image`, `board.dtb`, `initrd.img` (bruts, TFTP) |
| B2 | `boot.fit` (kernel+dtb+initrd **signé**) |
| B3 | `boot.fit` + `secubox-<image>.img` + `secubox-<image>.img.sig` |

Production :
- `boot.fit` signé → `secubox-netboot-publish --sign` (template `boot/boot-fit.its.tmpl`)
  ou directement par la CI `image/build-image.sh` + étape de signature.
- L'overlay 2e U-Boot (`sbx-uboot.fit`) se build via `scripts/build-uboot-overlay.sh`.
