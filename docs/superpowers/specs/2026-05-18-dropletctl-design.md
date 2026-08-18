<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# dropletctl CLI — Design Spec

**Issue:** [#196](https://github.com/CyberMind-FR/secubox-deb/issues/196)
**Author:** Claude (Opus 4.7, 1M context)
**Date:** 2026-05-18
**Status:** Awaiting user review before invoking `superpowers:writing-plans`

---

## Context

`packages/secubox-droplet/api/main.py` (839 lines) is a comprehensive FastAPI app
that shells out to a `dropletctl` binary for `publish` / `remove` / `rename`:

```python
subprocess.run(["dropletctl", "publish", file_path, name, domain], ...)
subprocess.run(["dropletctl", "remove", req.name], ...)
subprocess.run(["dropletctl", "rename", req.old, req.new], ...)
```

The `dropletctl` CLI **does not exist** anywhere in the Debian repo — every
upload/remove/rename API call fails at runtime. `secubox-droplet 1.0.1-1~bookworm1`
is installed live on `192.168.1.200` (`gk2`); the service is active; `which
dropletctl` returns nothing.

The OpenWrt counterpart `secubox-app-droplet` ships a working 349-line bash CLI
at `package/secubox/secubox-app-droplet/files/usr/sbin/dropletctl` in
https://github.com/gkerma/secubox-openwrt. This spec ports that CLI to Debian,
narrowed to static-only content and the Debian peer-CLI ecosystem.

## Scope (v1.1.0)

**In:**
- `publish`, `remove`, `rename`, `list` subcommands
- Static content: single HTML, `.zip`, `.tar.gz` / `.tgz`, plain directory
- Idempotent `publish` (overwrite semantics on the docroot)
- Full delegation of nginx vhost + HAProxy ACL + mitmproxy route work to
  `metablogizerctl site publish` (single source of truth)
- Bats unit tests with PATH-shimmed `metablogizerctl` / `logger` stubs
- Debian packaging update + changelog bump to `1.1.0-1~bookworm1`

**Out (deferred to ≥ v1.2.0):**
- Streamlit content type (would require Debian `streamlitctl` parity check)
- Hexo content type
- Gitea git-versioning (OpenWrt does `git init + commit` per publish)
- Atomic publish rollback (currently: rsync overwrites; failure leaves staged
  content on disk, caller must `dropletctl remove` to clean up)
- TLS certificate provisioning (out of dropletctl scope; `metablogizerctl` /
  `vhostctl` own that)

## Architecture

`dropletctl` is a thin bash orchestrator at `/usr/sbin/dropletctl`. It owns:
input validation, name sanitization, file staging (HTML / ZIP / tarball
extraction), site metadata writing into `/etc/secubox/droplet.toml`, and
delegation to peer CLIs. It does NOT touch nginx, HAProxy, or mitmproxy
directly.

```
┌─────────────────┐         ┌─────────────────────────────┐
│  POST /upload   │────────▶│  api/main.py (FastAPI)      │
│  (multipart)    │         │  subprocess.run(dropletctl…)│
└─────────────────┘         └────────────┬────────────────┘
                                         │
                            ┌────────────▼─────────────┐
                            │  dropletctl publish      │
                            │  ────────────────────    │
                            │  1. sanitize name        │
                            │  2. extract → /tmp/      │
                            │  3. detect_type (static) │
                            │  4. rsync → /srv/        │
                            │  5. write droplet.toml   │
                            │  6. exec metablogizerctl │
                            └────────────┬─────────────┘
                                         │
                            ┌────────────▼──────────────────┐
                            │  metablogizerctl site publish │
                            │  (does nginx + haproxy +      │
                            │   mitmproxy sync — owned by   │
                            │   metablogizer package)       │
                            └───────────────────────────────┘
```

**Rejected alternative — absorb metablogizer logic in-line:** would violate the
"handle one time only" principle the user articulated on 2026-05-17 during the
ckwa.gk2.secubox.in 502 debug. If `metablogizerctl`'s nginx / HAProxy / mitmproxy
plumbing ever changes, dropletctl would drift silently.

**Rejected alternative — Python module reusing `secubox_core.config`:** adds a
Python dependency to a CLI typically invoked as root via subprocess; harder to
debug from a tty.

## Components & interfaces

### File layout in the repo

```
packages/secubox-droplet/
├── sbin/dropletctl                           ← new bash CLI (~180 lines)
├── tests/
│   ├── test_dropletctl.bats                  ← new bats suite
│   └── fixtures/
│       ├── simple.html
│       ├── simple.zip                        ← 1 nested dir, index.html + style.css
│       ├── simple.tar.gz                     ← same shape as simple.zip
│       └── bin/
│           ├── metablogizerctl               ← stub (echo + exit 0)
│           └── logger                        ← stub
└── debian/
    ├── rules                                 ← + install line for sbin/
    ├── control                               ← + Depends: secubox-metablogizer (>= 2.0.0)
    └── changelog                             ← bump 1.0.1 → 1.1.0
```

### CLI surface

| Command | Args | Behavior | Output (success) |
|---|---|---|---|
| `publish` | `<path>` `<name>` `[<domain>]` | Stage `<path>` (HTML / .zip / .tar.gz / .tgz / dir) → `/srv/metablogizer/sites/<name>/`. Write `[sites.<name>] domain=…` into `/etc/secubox/droplet.toml`. Exec `metablogizerctl site publish <name>`. Idempotent overwrite. | `[OK] Published: https://<vhost>/` then `<vhost>` on stdout last line (API parses this) |
| `remove` | `<name>` | Delete `/srv/metablogizer/sites/<name>/`. Remove from `droplet.toml`. Exec `metablogizerctl site unpublish <name>` then `metablogizerctl site delete <name>`. | `[OK] Removed: <name>` |
| `rename` | `<old>` `<new>` | `mv` docroot. Update `droplet.toml` (`old → new` section + new domain). Exec `metablogizerctl site delete <old>` then `metablogizerctl site publish <new>`. | `[OK] Renamed: <old> -> <new>` |
| `list` | — | Read `droplet.toml` sites, print `name  [ON/OFF]  https://<domain>/` one per line | the table |

### Inputs / disk surface

- **Reads:** `/etc/secubox/droplet.toml` (defaults: `upload_dir=/srv/droplet`,
  `default_domain` mirrors API config; the CLI's TOML reader is ~20 lines of
  grep/sed for the few keys it needs).
- **Reads:** `<path>` argument (file or directory).
- **Writes:** `/srv/metablogizer/sites/<name>/`, `/etc/secubox/droplet.toml`.
- **Execs:** `metablogizerctl` (must exist in PATH; CLI fails with `[ERROR]`
  if missing).

### Output contract for the API

`[OK]` substring in stdout + final stdout line = `<vhost>`. The API already
parses these:

```python
if result.returncode == 0 and "[OK]" in result.stdout:
    vhost = result.stdout.strip().split("\n")[-1]
```

## Data flow

Happy path for `dropletctl publish /tmp/foo.html bar gk2.secubox.in`:

```
1. validate_args            ─→ <path> exists, <name> non-empty, <domain> may default
2. sanitize_name            ─→ awk tolower + sed s/[^a-z0-9_-]/_/g  (matches OpenWrt)
3. mktemp -d /tmp/droplet.XXXXXX
4. extract_to_staging       ─→ case ext in
                                  .html|.htm) cp $path $staging/index.html
                                  .zip)       unzip -q $path -d $staging
                                  .tgz|.tar.gz) tar -xzf $path -C $staging
                                  *)          [ERROR] unsupported ext
                                end
                                # for .zip and tarballs: unwrap single-nested top dir
5. detect_type              ─→ require index.html OR index.htm → "static"
                                else → [ERROR] (no streamlit/hexo in v1.1.0)
6. fix_perms                ─→ find -type f -exec chmod 644; -type d -exec chmod 755
7. rsync -a --delete $staging/ /srv/metablogizer/sites/<name>/
8. write_droplet_toml       ─→ [sites.<name>] domain="<domain>" type="static"
9. exec metablogizerctl site publish <name>
                            ─→ on success: echo "[OK] Published: https://<domain>/"
                                          echo "<domain>"   ← API parses this line
10. rm -rf $staging         ─→ via trap EXIT
```

## Error handling

| Exit code | Trigger | stderr | Recovery |
|---|---|---|---|
| 0 | success | — | — |
| 1 | bad args / unsupported ext / file missing | `[ERROR] <msg>` | caller fixes args |
| 2 | sanitization rejects name (empty after strip) | `[ERROR] Invalid name '<orig>'` | caller picks new name |
| 3 | staging extract fails | `[ERROR] Failed to extract <ext>: <stderr>` | log details to journald via `logger -t droplet -p user.error` |
| 4 | metablogizerctl missing in PATH | `[ERROR] metablogizerctl not found — install secubox-metablogizer` | install dep |
| 5 | metablogizerctl returncode != 0 | `[ERROR] metablogizerctl failed: <stderr 200ch tail>` | troubleshoot metablogizer; staging already deleted (no half-published state) |

### Idempotency invariants (publish called twice with same name)

- `rsync -a --delete` overwrites the docroot atomically — old content removed,
  new written.
- `write_droplet_toml` rewrites the `[sites.<name>]` block in place via
  python3 stdlib `tomllib` + atomic `mv`.
- `metablogizerctl site publish` is called regardless — it's idempotent on its
  side (existing nginx vhost gets reloaded, HAProxy ACL is a no-op if present).
- `<domain>` arg ignored if `droplet.toml` already has it for this name — we
  DON'T silently swap domains on a republish. (User wants a domain change →
  `dropletctl remove` then re-`publish`.)

### Rollback

None for v1.1.0. If step 9 fails after step 7+8 succeeded, the docroot exists on
disk and the TOML entry exists, but no public vhost serves it. Caller can
`dropletctl remove` to clean up. (Adding atomic rollback would require staging
metadata to a separate file + on-failure unwind — punted to v1.2.0.)

### Logging

Every step logs to journald via `logger -t droplet -p user.{info,error}` +
echoes to stdout/stderr. Matches OpenWrt convention. `journalctl -u
secubox-droplet -t droplet` tails all CLI invocations on the board.

## Testing

### Bats unit suite

`packages/secubox-droplet/tests/test_dropletctl.bats`. Follows the
per-package bats convention used by `secubox-mail`
(`test_install_lib.bats`, `test_lxc_lib.bats`, `test_migrate_lib.bats`) and
`secubox-system` (`test_leasewatch.bats`) — invoke directly with
`bats packages/secubox-droplet/tests/`. Tests stub `metablogizerctl`,
`logger`, and the filesystem via PATH-shimmed fakes in `tests/fixtures/bin/`.

### Test cases (10)

| # | Case | Asserts |
|---|---|---|
| 1 | `publish` with no args | exit 1, stderr contains "Usage" |
| 2 | `publish file.html foo` with missing file | exit 1, stderr contains "not found" |
| 3 | `publish bad.xyz foo` | exit 1, stderr contains "Unsupported file type" |
| 4 | `publish fixture.html foo` happy path | exit 0, stdout last line == `foo.gk2.secubox.in`, docroot exists with `index.html` matching, fake `metablogizerctl site publish foo` was called |
| 5 | `publish fixture.zip foo` with nested single dir | docroot unwrapped (no `archive_name/index.html`, just `/srv/.../foo/index.html`) |
| 6 | `publish fixture.tar.gz foo` | same as #5 for tarball |
| 7 | `publish` twice for same name | second call rsync-overwrites, exit 0, no duplicate TOML entries |
| 8 | `publish foo.html FOO` (uppercase) | name sanitized to `foo`, vhost `foo.<domain>` |
| 9 | `remove foo` after publish | docroot gone, TOML entry gone, fake `metablogizerctl site delete foo` was called |
| 10 | `rename old new` | docroot renamed, TOML key renamed, delegates called in correct order |

### Fixtures

`tests/fixtures/` contains `simple.html`, `simple.zip` (1 nested dir with
`index.html` + `style.css`), `simple.tar.gz` (same shape), and
`tests/fixtures/bin/{metablogizerctl,logger}` shims that just `echo
"stub-call: $*" >> $BATS_TMPDIR/stub.log; exit 0`.

### Test isolation

Each test sets up `BATS_TMPDIR/srv/metablogizer/sites/`,
`BATS_TMPDIR/etc/secubox/droplet.toml`, `PATH=$BATS_TMPDIR/bin:$PATH`, and runs
dropletctl with `SITES_DIR=...`, `TOML_PATH=...`, `LOG_TAG=droplet-test` env
vars (CLI accepts these for test mode). No real filesystem writes outside the
temp dir.

### Lint gates also in CI

- `bash -n packages/secubox-droplet/sbin/dropletctl`
- `shellcheck packages/secubox-droplet/sbin/dropletctl tests/fixtures/bin/*`

### No netns / no end-to-end in this PR

End-to-end deferred to the manual gk2 bench step (issue acceptance #196 last
checkbox).

### Coverage target

10/10 green. No coverage % metric (bash without bashcov).

## Packaging

### `packages/secubox-droplet/debian/rules` — add one install block

```make
# Existing block (api/, www/, menu.d/, nginx/) stays as-is.

# NEW: install the CLI to /usr/sbin/
install -d debian/secubox-droplet/usr/sbin
install -m 0755 sbin/dropletctl debian/secubox-droplet/usr/sbin/dropletctl
```

### `packages/secubox-droplet/debian/changelog` — bump

```
secubox-droplet (1.1.0-1~bookworm1) bookworm; urgency=medium

  * Add dropletctl CLI at /usr/sbin/dropletctl (port from OpenWrt
    secubox-app-droplet 1.0.0). Subcommands: publish, list, remove,
    rename. Static-only (HTML / ZIP / tarball). Delegates HTTP-facing
    work (nginx vhost, HAProxy ACL, mitmproxy route) to
    metablogizerctl site publish.
  * Depends: secubox-metablogizer (>= 2.0.0)  — runtime dependency for
    publish/unpublish/delete.
  * Closes: #196

 -- Gerald KERMA <devel@cybermind.fr>  Mon, 18 May 2026 09:00:00 +0200
```

### `packages/secubox-droplet/debian/control` — add dependency

`Depends: secubox-metablogizer (>= 2.0.0)` so apt enforces it at install time.

## Deploy path on `gk2` (post-merge)

1. Build .deb locally: `cd packages/secubox-droplet && dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b`
2. `scp ../secubox-droplet_1.1.0-1~bookworm1_all.deb root@admin.gk2.secubox.in:/tmp/`
3. SSH: `apt install /tmp/secubox-droplet_1.1.0-1~bookworm1_all.deb`
4. Verify: `which dropletctl` → `/usr/sbin/dropletctl`
5. Smoke test: `curl -X POST -F "file=@simple.html" -F "name=smoke" https://admin.gk2.secubox.in/api/v1/droplet/upload` → expect 200 + job_id, then `dropletctl list` shows `smoke`, then `curl https://smoke.gk2.secubox.in/` returns the HTML content.

### Rollback if deploy goes wrong

`apt install secubox-droplet=1.0.1-1~bookworm1` (the previously-installed
pinned version) reverts the CLI. Site docroots remain on disk unaffected (the
CLI doesn't touch them on uninstall; that's `postrm`'s job which we don't change
in this PR).

### No systemd unit changes

The existing `secubox-droplet.service` (FastAPI process) is unaffected. The CLI
is invoked by the service via subprocess; once installed, it's available
immediately without a restart.

## References

- OpenWrt source: `https://github.com/gkerma/secubox-openwrt` →
  `package/secubox/secubox-app-droplet/files/usr/sbin/dropletctl` (349 lines)
- Debian API consumer: `packages/secubox-droplet/api/main.py` (839 lines)
- Sibling pattern: `packages/secubox-vhost/sbin/vhostctl` (Debian conventions
  for nginx vhost mgmt)
- Sibling delegate: `packages/secubox-metablogizer/sbin/metablogizerctl`
  (`site create|publish|unpublish|delete|list` surface)
- `sync-mitmproxy-routes.sh` regex fix the publish path depends on: master
  `531fd878`
