#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# Construit llama-server / llama-cli amd64 STATIQUES (CPU seul, AVX2) dans bin/amd64/.
# Cible : gk3 (Intel i3-7100T, AVX2, Debian trixie). Statique = aucune dépendance
# glibc/libstdc++. Étiquette épinglée, identique à build-arm64.sh (R24).
#
# Pré-requis (machine de build) : cmake, g++, git.
set -euo pipefail
LLAMA_TAG="${LLAMA_TAG:-v0.9.0}"
LLAMA_COMMIT="cd959ba"
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
git clone --depth 1 --branch "$LLAMA_TAG" https://github.com/ggml-org/llama.cpp "$T/llama.cpp"
case "$(git -C "$T/llama.cpp" rev-parse HEAD)" in
  "$LLAMA_COMMIT"*) ;;
  *) echo "ERREUR : $LLAMA_TAG ne pointe pas sur $LLAMA_COMMIT" >&2; exit 1 ;;
esac
cmake -S "$T/llama.cpp" -B "$T/build" \
  -DGGML_NATIVE=OFF -DGGML_AVX2=ON -DGGML_FMA=ON -DGGML_F16C=ON \
  -DLLAMA_CURL=OFF -DLLAMA_OPENSSL=OFF -DGGML_OPENMP=OFF -DBUILD_SHARED_LIBS=OFF \
  -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_SERVER=ON -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_EXE_LINKER_FLAGS="-static -static-libgcc -static-libstdc++"
cmake --build "$T/build" -j"$(nproc)" --target llama-server llama-cli
mkdir -p "$HERE/bin/amd64"
install -m0755 "$T/build/bin/llama-server" "$T/build/bin/llama-cli" "$HERE/bin/amd64/"
strip --strip-unneeded "$HERE/bin/amd64/"* || true
echo "OK -> $HERE/bin/amd64/ ($(du -sh "$HERE/bin/amd64" | cut -f1))"
