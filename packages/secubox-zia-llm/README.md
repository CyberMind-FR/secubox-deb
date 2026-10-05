<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-zia-llm

ZIA Hall — local llama.cpp runtime (prebuilt static arm64).

Ships a statically-linked aarch64 llama.cpp (llama-server + llama-cli), cross-compiled OFF the box (building on the MOCHAbin exhausts RAM). No glibc dependency, so it runs on Debian bookworm arm64 as-is. With a GGUF model under /data/models, ZIA switches from its heuristic responder to real local generation over the same tools — the objects still come from the bus, never from the model.

Fetch a model with `secubox-zia-getmodel <url.gguf>`; the llama-server unit is memory-capped (1.4G) to protect the rest of the parc, and only starts once a model is present. Rebuild the binaries with build-arm64.sh.

Paquet Debian : version `0.1.0-1~bookworm1`, architecture `arm64`.

## Contenu

- `sbin/` : exécutables
- `systemd/` : unités systemd

## Exécution

Socket Unix : `/run/secubox/zia.sock`.
- `secubox-zia-llm.service` : SecuBox ZIA — llama.cpp server (GGUF local, arm64 statique) [#1245] (utilisateur `secubox`), lance `llama-server`

## Dépendances SecuBox

`secubox-zia`.
