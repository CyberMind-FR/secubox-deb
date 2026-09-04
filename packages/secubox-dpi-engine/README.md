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

⚠️ **Build NATIF arm64 uniquement.** nDPId embarque libnDPI 5.x
(`BUILD_NDPI=ON`) : le cross-build de libnDPI n'est pas supporté ici. Compiler
sur un hôte arm64 (un runner CI arm64, PAS la box — voir le piège disque) :

    cd packages/secubox-dpi-engine
    dpkg-buildpackage -b -us -uc

`debian/rules` clone `utoni/nDPId` (récursif, submodule libnDPI), lance
`cmake -DBUILD_NDPI=ON` puis `make nDPId nDPIsrvd`, installe les deux binaires +
units + conf + tmpfiles, et nettoie l'arbre de build.

### Épinglage (reproductibilité)

Le binaire déployé est **nDPId 1.7.0-pre**. Pour une build reproductible,
figer le commit amont exact dans **`debian/ndpid.ref`** (une seule ligne, le
SHA). Sans ce fichier, la build tombe sur `main` (NON reproductible).

### ⚠️ Piège disque (cf. mémoire dpi-live-sbxdpi)

La build de libnDPI laisse ~1,1 Go d'arbre. Sur la box (eMMC 15 Go) ça remplit
la racine → « disk I/O error » SQLite en cascade. `override_dh_auto_clean`
nettoie `.ndpid-src`/`.ndpid-build`, mais **ne pas builder sur la box** :
utiliser un runner arm64 avec de la marge disque.

## Conf runtime

`/etc/secubox/ndpi.env` (conffile) : `DPI_IFACE` (défaut eth2, le WAN),
`DPI_BPF`, et les chemins des sockets collector/distributor. nDPId tourne root
pour la capture puis droppe sur `secubox-toolbox`.
