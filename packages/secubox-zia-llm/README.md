<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-zia-llm

ZIA Hall — local llama.cpp runtime (prebuilt static arm64).

Ships a statically-linked aarch64 llama.cpp (llama-server + llama-cli), cross-compiled OFF the box (building on the MOCHAbin exhausts RAM). No glibc dependency, so it runs on Debian bookworm arm64 as-is. With a GGUF model under /data/models, ZIA switches from its heuristic responder to real local generation over the same tools — the objects still come from the bus, never from the model.

Fetch a model with `secubox-zia-getmodel <url.gguf>`; the llama-server unit is memory-capped (1.4G) to protect the rest of the parc, and only starts once a model is present. Rebuild the binaries with build-arm64.sh.

Paquet Debian : version `0.3.0-1~trixie1`, architectures `arm64` et `amd64`.

## Binaires (hors dépôt, hors CI)

`bin/` est ignoré par git et le paquet est construit hors CI. `debian/rules` installe `bin/$(DEB_HOST_ARCH)/`.
- `./build-amd64.sh` : llama.cpp épinglé (`LLAMA_TAG=v0.9.0`, commit `cd959ba`), CPU, AVX2/FMA/F16C, statique, vers `bin/amd64/`.
- `./build-arm64.sh` : même étiquette, cross-compilation, vers `bin/arm64/`.
- Binaires arm64 existants (à plat dans `bin/`) : `mkdir -p bin/arm64 && mv bin/llama-server bin/llama-cli bin/arm64/`.
- Construire : `dpkg-buildpackage -us -uc -b -aamd64` (ou `-aarm64`).

## Contenu

- `sbin/` : exécutables
- `systemd/` : unités systemd

## Exécution

Socket Unix : `/run/secubox/zia.sock`.
- `secubox-zia-llm.service` : SecuBox ZIA — llama.cpp server (GGUF local, arm64 statique) [#1245] (utilisateur `secubox`), lance `llama-server`

## Dépendances SecuBox

`secubox-zia`.
