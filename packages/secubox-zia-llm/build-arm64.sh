#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# Reproduit les binaires arm64 STATIQUES de bin/ — cross-compilés HORS box (le
# build sur la MOCHAbin saturait la RAM, cf. #1245). Statique = aucune dépendance
# glibc/libstdc++ : tourne sur Debian bookworm arm64 quelle que soit la version.
#
# Pré-requis (machine de build) : cmake, g++-aarch64-linux-gnu, git.
#   sudo apt-get install -y cmake g++-aarch64-linux-gnu
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
git clone --depth 1 https://github.com/ggml-org/llama.cpp "$T/llama.cpp"
cmake -S "$T/llama.cpp" -B "$T/build" \
  -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=aarch64 \
  -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++ \
  -DGGML_NATIVE=OFF -DLLAMA_CURL=OFF -DGGML_OPENMP=OFF -DBUILD_SHARED_LIBS=OFF \
  -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_SERVER=ON -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_EXE_LINKER_FLAGS="-static -static-libgcc -static-libstdc++"
cmake --build "$T/build" -j"$(nproc)" --target llama-server llama-cli
mkdir -p "$HERE/bin"
install -m0755 "$T/build/bin/llama-server" "$T/build/bin/llama-cli" "$HERE/bin/"
aarch64-linux-gnu-strip --strip-unneeded "$HERE/bin/"* || true
echo "OK -> $HERE/bin/ ($(du -sh "$HERE/bin" | cut -f1))"
