<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Sentinel — packaging, YARA variant & WebUI follow-up (#823)

The Sentinel defensive threat engine ships inside `secubox-toolbox-ng`:

| Artifact | Installed path | Role |
|----------|----------------|------|
| `sbxmitm` | `/usr/sbin/sbxmitm` | inline IOC gate (neutralize + mirror) |
| `sbx-sentinel` | `/usr/sbin/sbx-sentinel` | async analyzer daemon (spyware/behavioral/YARA) |
| `secubox-sentinel-feeds` | `/usr/sbin/secubox-sentinel-feeds` | fail-safe live-feed → overlay fetcher |
| base pack | `/usr/share/secubox/sentinel/packs/base/*.json` | shipped IOC/YARA content |
| config | `/etc/secubox/sentinel.env` (conffile) | shared `SENTINEL_*` |
| units | `sbx-sentinel.service`, `secubox-sentinel-feeds.{service,timer}` | DARK (installed, not enabled) |

All of it is **DARK by design**, exactly like the `worker@` unit: the package
installs everything and reloads the unit catalogue but does **not** enable or
start anything. Nothing changes at install time.

## Default build (cgo-free, YARA stub)

`debian/rules` builds with `CGO_ENABLED=0`, `-mod=vendor`, `GOPROXY=off`. The
YARA engine linked in is the **no-op stub** (`internal/sentinel/yara_stub.go`,
build tag `!yara`): `sbx-sentinel` runs the spyware + behavioral analyzers, and
the YARA analyzer is present but always returns no matches. This keeps the
standard `.deb` free of any `libyara` dependency and lets CI build without it.

## YARA-enabled build (opt-in, cgo)

To ship real YARA scanning, build the daemon with the `yara` tag against an
installed `libyara-dev`:

```sh
# Build-Depends (add for this variant only): libyara-dev, pkg-config
CGO_ENABLED=1 go build -tags yara -trimpath -o sbx-sentinel ./cmd/sbx-sentinel
```

This links `internal/sentinel/yara.go` (build tag `cgo && yara`, the
`github.com/hillu/go-yara/v4` wrapper) instead of the stub. The rest of the
engine is identical. Rule files are passed via `SENTINEL_YARA_RULES` (a
`:`-separated list) in `/etc/secubox/sentinel.env`. This variant is **not** the
default `.deb` and is not built by `debian/rules` as shipped — enabling it means
adding `libyara-dev` + `pkg-config` to `Build-Depends`, dropping `CGO_ENABLED=0`,
and adding `-tags yara` to the build in `override_dh_auto_build`.

## Cutover (human-gated, #823)

```sh
# 1. Turn the inline gate on for the workers (same SENTINEL_* names):
#    add SENTINEL_ENABLED=1 + the SENTINEL_PACK_DIR/OVERLAY_DIR/MIRROR_SOCK
#    values to /etc/secubox/toolbox-ng.env (or point its EnvironmentFile at
#    /etc/secubox/sentinel.env), then restart the ng workers.
# 2. Start the analyzer + the feed refresh:
systemctl enable --now sbx-sentinel.service
systemctl enable --now secubox-sentinel-feeds.timer
systemctl start  secubox-sentinel-feeds.service   # first overlay pull now
```

Verify: the base pack loads, a known-bad test domain is neutralized, a benign
flow is untouched (hot-path budget), the overlay lands in
`/var/lib/secubox/sentinel/overlay`, and a detection produces a verdict.

## Operator surface

### In-daemon (this package, read-only, optional)

Set `SENTINEL_HTTP_ADDR=127.0.0.1:8790` in `sentinel.env` to expose:

- `GET /stats`    → `{"detections":N,"blocked":N,"spyware":N}` (sidebar line)
- `GET /verdicts` → recent verdicts, each with its rendered `report` string

Read-only, GET-only, no PII beyond `mac_hash`, no WAF bypass.

### Portal WebUI/API (separate Python package — FOLLOW-UP, not in this package)

The rich operator UI belongs in the `secubox-toolbox` **Python** portal, which
is a separate package; it is intentionally NOT built here. Intended routes to
add there (plain authenticated handlers, no `waf_bypass`), backed either by the
in-daemon `SENTINEL_HTTP_ADDR` endpoint above or by reading the bbolt store:

- `GET /api/v1/toolbox/sentinel/verdicts`   → recent verdict list
- `GET /api/v1/toolbox/sentinel/report/{id}` → one rendered proposal/solution report
- `GET /api/v1/toolbox/sentinel/stats`       → `{detections, blocked, spyware}` for the
  sidebar metrics line (mirror the existing `/frigate`-style widget)

Plus a WebUI verdicts panel mirroring an existing toolbox list view. This is the
documented follow-up for a dedicated Python-portal session.
