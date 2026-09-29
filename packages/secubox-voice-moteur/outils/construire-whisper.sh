#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: secubox-voice-moteur/construire-whisper — compile whisper-cli
# (whisper.cpp, version épinglée) SUR un hôte Debian bookworm arm64 (#1646).
# Pourquoi pas en croisé : la chaîne croisée du poste lie contre une glibc plus
# récente (2.38) que celle de bookworm (2.36) ; le binaire refuse de démarrer.
# Usage : construire-whisper.sh [hote_arm64]   (défaut : root@192.168.1.200)
set -euo pipefail
readonly MODULE="construire-whisper" VERSION_WHISPER="v1.7.6"
HOTE="${1:-root@192.168.1.200}"
ICI="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
git clone -q --depth 1 --branch "$VERSION_WHISPER" https://github.com/ggml-org/whisper.cpp.git "$TMP/whisper.cpp"
tar czf "$TMP/src.tgz" -C "$TMP" --exclude=.git whisper.cpp
scp -q "$TMP/src.tgz" "$HOTE:/data/wbuild-src.tgz"
ssh "$HOTE" 'set -e; rm -rf /data/wbuild && mkdir -p /data/wbuild && cd /data/wbuild && tar xzf /data/wbuild-src.tgz && cd whisper.cpp &&
  cmake -B b -DBUILD_SHARED_LIBS=OFF -DGGML_NATIVE=OFF -DGGML_CPU_ARM_ARCH=armv8-a -DWHISPER_BUILD_TESTS=OFF -DWHISPER_SDL2=OFF -DCMAKE_BUILD_TYPE=Release >/dev/null &&
  nice -n 15 cmake --build b --target whisper-cli -j2 >/dev/null && b/bin/whisper-cli --help >/dev/null 2>&1 || test $? -le 1'
scp -q "$HOTE:/data/wbuild/whisper.cpp/b/bin/whisper-cli" "$ICI/vendor/whisper-cli"
ssh "$HOTE" 'rm -rf /data/wbuild /data/wbuild-src.tgz'
echo "$MODULE : vendor/whisper-cli ($VERSION_WHISPER, bookworm arm64)"
