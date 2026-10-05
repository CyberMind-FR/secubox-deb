<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-voice-moteur

SecuBox — moteur vocal local de Lexie (piper + whisper.cpp).

Synthèse (piper, voix française « lexie-fr » tirée de fr_FR-siwis-medium, CC-BY 4.0) et reconnaissance (whisper.cpp v1.7.6, modèle ggml-base-q5_1) exécutées sur la box, sans réseau, en sous-processus à la demande. Remplace le paquet Debian « piper » homonyme (configurateur de souris).

Paquet Debian : version `1.1.0-1~bookworm1`, architecture `arm64`.

## Contenu

- `outils/` : fichiers du module
