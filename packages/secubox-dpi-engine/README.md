<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-dpi-engine

Moteur DPI de SecuBox : **nDPId** + **nDPIsrvd** (nDPI 5.x, libre), empaquetés
depuis les sources amont [`utoni/nDPId`](https://github.com/utoni/nDPId).

Ce paquet a été **reconstitué en source** : le `.deb` déployé sur gk2
(`1.7.0~gitpre`) n'avait aucune source dans le dépôt (orphelin). Les units, la
conf `ndpi.env` et les tmpfiles sont capturés à l'identique du live ; le binaire
se reconstruit via `debian/rules`.

## Chaîne

    nDPId (capture ${DPI_IFACE}=eth2) --framed JSON--> collector.sock
      --> nDPIsrvd --distributor.sock--> sbxdpi (secubox-toolbox-ng)
      --> /run/secubox/dpi-live.sock --> carte DPI du Hall

`Provides: ndpid`.

## Construire

nDPId embarque libnDPI 5.x (`BUILD_NDPI=ON`). Le cross-build fonctionne
techniquement (nDPId propage `CC`/`AR`/`--host` à libnDPI, cf.
`scripts/get-and-build-libndpi.sh`, `HOST_TRIPLET`), **MAIS il faut cibler l'ABI
de la cible = Debian bookworm** (glibc 2.36, `libpcap0.8`).

⚠️ **NE PAS cross-builder depuis Ubuntu noble/trixie** : le binaire se lie alors
à `GLIBC_2.38+` et `libpcap0.8t64`, et **refuse de tourner sur bookworm**
(`GLIBC_2.38 not found`, deps `libc6 (>= 2.38)` / `libpcap0.8t64`
insatisfaisables). Leçon apprise à la dure — un `.deb` ainsi produit s'installe
mais laisse dpkg `iU` et le moteur cassé.

**Méthode correcte — build sur base bookworm arm64** :
- **Natif** sur un arm64 bookworm (runner CI arm64, ou la box si ≥ 2 Go libres —
  attention au piège disque) : `dpkg-buildpackage -b -us -uc`.
- **Cross depuis amd64** via un **chroot/sysroot bookworm arm64** (debootstrap
  `bookworm` + qemu-user, ou `sbuild`/`mmdebstrap` avec base bookworm-arm64) :
  installer dedans `crossbuild-essential-arm64 libpcap-dev:arm64 cmake git
  autoconf automake libtool pkg-config flex bison`, puis
  `dpkg-buildpackage -a arm64 -b -us -uc`. Les libs arm64 DOIVENT venir de
  bookworm (`deb.debian.org bookworm`), pas d'un Ubuntu récent.

`debian/rules` détecte le cross (`architecture.mk`) et passe le toolchain à
cmake + à libnDPI, clone `utoni/nDPId` au commit épinglé, `cmake -DBUILD_NDPI=ON`
→ `make nDPId nDPIsrvd`, installe binaires + units + conf + tmpfiles, nettoie.

### Épinglage (reproductibilité)

Le commit amont est figé dans **`debian/ndpid.ref`** (nDPId `0cc9aeb` →
nDPId 1.7.0-release ; libnDPI submodule `326b64c`). Modifier ce fichier pour
changer de version.

### Piège disque

La build de libnDPI laisse plusieurs centaines de Mo (~450 Mo observés).
`override_dh_auto_clean` nettoie `.ndpid-src`/`.ndpid-build`. Sur la box (eMMC
15 Go) c'est risqué → **cross-builder depuis amd64** de préférence.

## Conf runtime

`/etc/secubox/ndpi.env` (conffile) : `DPI_IFACE` (défaut eth2, le WAN),
`DPI_BPF`, et les chemins des sockets collector/distributor. nDPId tourne root
pour la capture puis droppe sur `secubox-toolbox`.
