#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox :: construction NATIVE de nDPId + nDPIsrvd (#1345).
#
# À exécuter SUR LA BOX. La compilation croisée demanderait une chaîne arm64
# complète pour du C plus une libndpi croisée — beaucoup de machinerie pour un
# binaire qu'on ne rebâtit qu'à une montée de version.
set -euo pipefail

TRAVAIL="${TRAVAIL:-/data/build}"
SRC="$TRAVAIL/nDPId"
VERSION="${VERSION:-1.7.0}"
REVISION="${REVISION:-1~bookworm1}"

command -v cmake >/dev/null || { echo "cmake absent" >&2; exit 1; }
command -v dpkg-deb >/dev/null || { echo "dpkg-dev absent : apt install dpkg-dev" >&2; exit 1; }

mkdir -p "$TRAVAIL"
[ -d "$SRC" ] || git clone --depth 50 https://github.com/utoni/nDPId "$SRC"

cd "$SRC"
git submodule update --init libnDPI

# GÉNÉRATEUR MAKEFILES, PAS NINJA. Le script de compilation de nDPI suppose la
# sémantique de make et fabrique une commande `ninja - install` invalide quand
# on lui impose Ninja — l'erreur est « loading 'build.ninja': No such file »,
# qui se lit comme un problème de configuration alors qu'il n'en est rien.
#
# BUILD_NDPI=ON embarque nDPI 6.x en statique : nDPId exige ≥ 5.0.0 et la box
# a 4.2 en système. Remplacer la lib système casserait tout ce qui s'appuie
# dessus ; l'embarquer ne coûte que 4 Mo.
rm -rf build
cmake -S . -B build -DBUILD_NDPI=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"

test -x build/nDPId && test -x build/nDPIsrvd

# ── assemblage du paquet ────────────────────────────────────────────────────
PKG="$TRAVAIL/pkg-ndpid-engine"
rm -rf "$PKG"
install -d "$PKG/DEBIAN" "$PKG/usr/sbin" "$PKG/lib/systemd/system" "$PKG/etc/secubox"
install -m 0755 build/nDPId build/nDPIsrvd "$PKG/usr/sbin/"

ICI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install -m 0644 "$ICI"/systemd/*.service "$PKG/lib/systemd/system/"
install -m 0644 "$ICI"/conf/ndpid-engine.env "$PKG/etc/secubox/"
sed -e "s/@VERSION@/$VERSION-$REVISION/" \
    -e "s/@TAILLE@/$(du -sk "$PKG" | cut -f1)/" \
    "$ICI/debian/control.in" > "$PKG/DEBIAN/control"
install -m 0755 "$ICI/debian/postinst" "$PKG/DEBIAN/postinst"
install -m 0755 "$ICI/debian/prerm" "$PKG/DEBIAN/prerm"
echo "/etc/secubox/ndpid-engine.env" > "$PKG/DEBIAN/conffiles"

DEB="$TRAVAIL/secubox-ndpid-engine_${VERSION}-${REVISION}_arm64.deb"
dpkg-deb --build --root-owner-group "$PKG" "$DEB"
echo "→ $DEB"
