#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: secubox-voice-moteur/recuperer — télécharge les éléments
# ÉPINGLÉS du moteur vocal dans vendor/ et vérifie leur sha256 (#1646).
# Rien de tout cela n'entre dans git.
set -euo pipefail
readonly MODULE="voice-moteur"
cd "$(dirname "$0")/.."
mkdir -p vendor
HF=https://huggingface.co
declare -A URL=(
  [piper_linux_aarch64.tar.gz]=https://github.com/rhasspy/piper/releases/download/2023.11.14-2/piper_linux_aarch64.tar.gz
  [ggml-base-q5_1.bin]=$HF/ggerganov/whisper.cpp/resolve/main/ggml-base-q5_1.bin
  [ggml-tiny-q5_1.bin]=$HF/ggerganov/whisper.cpp/resolve/main/ggml-tiny-q5_1.bin
  [fr_FR-siwis-medium.onnx]=$HF/rhasspy/piper-voices/resolve/v1.0.0/fr/fr_FR/siwis/medium/fr_FR-siwis-medium.onnx
  [fr_FR-siwis-medium.onnx.json]=$HF/rhasspy/piper-voices/resolve/v1.0.0/fr/fr_FR/siwis/medium/fr_FR-siwis-medium.onnx.json
  [vosk-0.3.45-py3-none-manylinux2014_aarch64.whl]=https://files.pythonhosted.org/packages/a4/23/3130a69fa0bf4f5566a52e415c18cd854bf561547bb6505666a6eb1bb625/vosk-0.3.45-py3-none-manylinux2014_aarch64.whl
  [vosk-model-small-fr-0.22.zip]=https://alphacephei.com/vosk/models/vosk-model-small-fr-0.22.zip
  [MODEL_CARD]=$HF/rhasspy/piper-voices/resolve/v1.0.0/fr/fr_FR/siwis/medium/MODEL_CARD
)
for f in "${!URL[@]}"; do
  [ -f "vendor/$f" ] || curl -fsSL --retry 3 -o "vendor/$f" "${URL[$f]}"
done
( cd vendor && sha256sum -c ../outils/SHA256SUMS )
[ -x vendor/whisper-cli ] || { echo "$MODULE : vendor/whisper-cli absent — lancer outils/construire-whisper.sh sur un hôte bookworm arm64" >&2; exit 1; }
echo "$MODULE : éléments vérifiés"
