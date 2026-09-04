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

Remplace **netifyd** (retiré comme CrowdSec). `Provides: ndpid`,
`Conflicts: netifyd`.

## Construire

nDPId embarque libnDPI 5.x (`BUILD_NDPI=ON`). Le **cross-build arm64 est
supporté** (vérifié) : nDPId propage `CC`/`AR`/`RANLIB` au build de libnDPI et
pose `--host` lui-même (`scripts/get-and-build-libndpi.sh`, `HOST_TRIPLET`).

**Cross depuis amd64** (recommandé — pas le piège disque de la box) :

    sudo dpkg --add-architecture arm64
    # sources ports arm64 si besoin (ports.ubuntu.com), puis :
    sudo apt-get install -y crossbuild-essential-arm64 libpcap-dev:arm64 \
        cmake git autoconf automake libtool pkg-config flex bison
    cd packages/secubox-dpi-engine
    dpkg-buildpackage -a arm64 -b -us -uc

**Natif arm64** : `dpkg-buildpackage -b -us -uc`.

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
