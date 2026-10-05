<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-voice

SecuBox Voice — Lexie: local speech synthesis and recognition.

The ears and mouth of SBXOS. This module understands nothing: it transcribes and it speaks. Intent, role policy and action belong to ZIA, whose action layer already turns "pause the radio" into media.pause on the radio service — adding a second voice brain would duplicate the one place allowed to decide.

Voice is not a second API. It adds two capability families to the existing bus, voice.speak and voice.listen, declared in a capabilities.d manifest like any other module.

The engine is pluggable behind the OpenAI-compatible audio contract (/v1/audio/speech, /v1/audio/transcriptions): either a local backend (Piper plus whisper.cpp, arm64, loaded on demand so the box keeps its RAM) or any remote host serving that contract. Engine unreachable is reported as such — never a fallback voice, never an approximate transcription.

Paquet Debian : version `0.1.8-1~bookworm1`, architecture `all`.

## Contenu

- `api/` : API FastAPI
- `capabilities.d/` : fichiers du module
- `conf/` : configuration livrée
- `nginx/` : route nginx
- `sbin/` : exécutables
- `systemd/` : unités systemd
- `tests/` : tests

## Exécution

Socket Unix : `/run/secubox/voice.sock`.
- `secubox-voice.service` : SecuBox Voice — Lexie : synthèse et reconnaissance locales [#1287] (utilisateur `secubox`), lance `python3`

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/health` | aucune |
| `GET` | `/moteur` | require_jwt |
| `GET` | `/profils` | require_jwt |
| `POST` | `/tts` | require_personne |
| `POST` | `/asr` | require_personne |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-core`.

## Tests

5 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-voice`.
