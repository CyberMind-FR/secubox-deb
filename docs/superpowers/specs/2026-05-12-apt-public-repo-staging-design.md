<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# APT Public Repo Staging — Design

**Date:** 2026-05-12
**Author:** Gandalf (CyberMind), with Claude
**Status:** Draft for approval
**Targets:** `apt.secubox.in` (production), `bookworm` suite, `arm64` (mochabin/Armada 7040) + `amd64`

## Goal

Produce a fully signed, validated APT repository tree under `output/repo/`
containing both `amd64` and `arm64` SecuBox packages for the `bookworm` suite.
The tree is ready to be `rsync`-ed to `apt.secubox.in` out-of-band by the user.

This run **does not** touch the production server, **does not** request TLS
certificates, and **does not** push any data over the network. It produces
artifacts (signed repo tree, nginx vhost, deploy recipe) the user pushes when
satisfied.

## Non-goals

- Provisioning the `apt.secubox.in` server itself (handled by
  [repo/scripts/setup-repo-server.sh](../../../repo/scripts/setup-repo-server.sh)
  when the user runs it on the VPS).
- Issuing the TLS certificate (certbot runs on the production host, post-rsync).
- Building anything for `trixie` (placeholder section only).
- Cross-building anything that genuinely needs native compilation against
  ARM-only libraries — fall back to a halt with a clear message.

## Inputs

| Input | Source |
|-------|--------|
| Package set per tier | `secubox gen --tier {tier-lite,tier-standard,tier-pro} --out manifests/` |
| Build script | [`scripts/build-packages.sh`](../../../scripts/build-packages.sh) `bookworm <arch>` |
| GPG key | `~/.gnupg/secubox/` (persistent across runs) |
| Reprepro driver | `secubox apt {init,publish,check}` via [`cmd/secubox/cmd/apt_server.go`](../../../cmd/secubox/cmd/apt_server.go) |
| Install script | [`repo/install.sh`](../../../repo/install.sh) |

## Outputs (`output/repo/`)

```
output/repo/
├── conf/
│   ├── distributions      Origin: SecuBox, SignWith: <fingerprint>
│   └── options            basedir + gnupghome → ~/.gnupg/secubox
├── db/                    reprepro state (gitignored)
├── dists/bookworm/
│   ├── Release
│   ├── InRelease          gpg-clearsigned
│   ├── Release.gpg        detached signature
│   └── main/{binary-arm64,binary-amd64,source}/Packages{,.gz,.xz}
├── pool/main/s/secubox-*/*.deb
├── secubox-keyring.gpg    public key, served as /secubox-keyring.gpg
├── install.sh             copy of repo/install.sh, served as /install.sh
├── FINGERPRINT.txt        plaintext fingerprint for verification
├── MANIFEST.txt           arch × tier counts + per-package version
├── nginx-apt.conf         drop-in for /etc/nginx/sites-available/
└── DEPLOY.md              certbot + rsync recipe
```

## Architecture

### Component 1 — GPG bootstrap

**Lives at:** `~/.gnupg/secubox/` (persistent home, **outside** the repo tree).
**Driver:** [`repo/scripts/generate-gpg-key.sh`](../../../repo/scripts/generate-gpg-key.sh)
with `GPG_HOME=~/.gnupg/secubox` and `EXPORT_DIR=output/repo`.

Key parameters (already in script): RSA 4096 + 4096 subkey, no passphrase,
`packages@secubox.in`, no expiry. Idempotent — exits early if a key for that
UID already exists in the keyring.

Produces:
- `output/repo/secubox-keyring.gpg` (ASCII-armored public key)
- `output/repo/FINGERPRINT.txt` (long fingerprint, used by `SignWith:`)

### Component 2 — Tier resolution

**Driver:** `secubox gen --tier <tier> --board mochabin --out manifests/<tier>/`

For each tier in order `base → tier-lite → tier-standard → tier-pro`, resolve
the package set from [`profiles/`](../../../profiles/) via the Go profile
engine ([`cmd/secubox/internal/profile/`](../../../cmd/secubox/internal/profile/)).

Tier 0 (base) is **implicit** — there is no `--tier base` flag. We build it
directly as the hardcoded set `{secubox-core, secubox-hub}`. Higher tiers are
resolved by `secubox gen` from `profiles/{tier-lite,tier-standard,tier-pro}.yaml`
which inherit transitively from `base.yaml`. Output is a manifest directory
per tier; the orchestrator extracts the `packages.required` list as the build
filter.

### Component 3 — Layered cross-build

**Driver:** [`scripts/build-packages.sh`](../../../scripts/build-packages.sh) with a `--filter <manifest>` flag
(new flag; passes filter through to the existing `PACKAGES=` array).

For each tier T in `[base, lite, standard, pro]`:
1. Run `build-packages.sh bookworm arm64 --filter manifests/tier-T.json`
2. Run `build-packages.sh bookworm amd64 --filter manifests/tier-T.json`
3. Collect `output/debs/*_arm64.deb`, `*_amd64.deb`, `*_all.deb` matching the
   filter. The `_all` packages only need to be built once (in the arm64 pass);
   amd64 pass skips packages with `Architecture: all` already built.
4. If **any** package in tier T fails, halt the pipeline. Tiers T-1 and lower
   are already published and remain usable. Record the failure in
   `MANIFEST.txt` and exit non-zero.

Cross-build dependencies (`crossbuild-essential-arm64`, `qemu-user-static`
for any `_arm64.deb` running maintainer scripts during build) are checked up
front; missing → halt with apt-install hint.

### Component 4 — Reprepro repository

**Driver:** `secubox apt init --base output/repo` then
`secubox apt publish output/debs/...`.

`conf/distributions` (production identity):
```
Origin: SecuBox
Label: SecuBox
Suite: bookworm
Codename: bookworm
Version: 12.0
Architectures: arm64 amd64 source
Components: main
Description: SecuBox Debian packages for Armada/x86_64
SignWith: <fingerprint from FINGERPRINT.txt>
Contents: percomponent nocompatsymlink
```

A `trixie` block is included with the same shape, but no packages are
published into it in this design.

`conf/options`:
```
verbose
basedir <abs path>/output/repo
gnupghome <abs path>/.gnupg/secubox
```

`reprepro` requires the `gnupghome` to be an absolute path; we resolve `~`
before writing.

After each tier publish: `secubox apt check` (wraps `reprepro check`). Clean
output is required before moving to the next tier.

### Component 5 — Deploy artifacts (no network)

`output/repo/nginx-apt.conf`:
- `server_name apt.secubox.in;`
- `root /var/www/apt.secubox.in;`
- ACME challenge location `/.well-known/acme-challenge/`
- MIME types: `application/vnd.debian.binary-package` for `.deb`,
  `application/pgp-keys` for `.gpg`
- `autoindex on` for `/dists/` and `/pool/`
- Listen 80 only (TLS added by certbot in-place on the server)

`output/repo/DEPLOY.md` documents:
1. `rsync -avz --delete output/repo/ deploy@apt.secubox.in:/var/www/apt.secubox.in/`
2. `ssh deploy@apt.secubox.in sudo cp /var/www/apt.secubox.in/nginx-apt.conf /etc/nginx/sites-available/apt.secubox.in`
3. `ssh apt.secubox.in sudo certbot --nginx -d apt.secubox.in --non-interactive --agree-tos -m packages@secubox.in`
4. Post-deploy: `openssl s_client -servername apt.secubox.in -connect apt.secubox.in:443 </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName` — must list `DNS:apt.secubox.in`.

### Component 6 — Validation gate

Before printing "done":

1. `reprepro -b output/repo check` — must be clean.
2. `gpg --homedir ~/.gnupg/secubox --verify output/repo/dists/bookworm/InRelease`
   — must report `Good signature` from the SecuBox UID.
3. Optional but recommended: debootstrap a throwaway `bookworm` chroot under
   `output/test-chroot/`, mount nothing, add `deb [trusted=no signed-by=...] file://<abs>/output/repo/ bookworm main` to `sources.list.d`, run
   `apt-get update` inside the chroot. Must succeed without warnings.
4. Write `output/repo/MANIFEST.txt` with the per-tier × per-arch table and
   the full `dpkg -I` summary of every published .deb.

If any step fails, the pipeline exits non-zero and the run is considered
incomplete — but `output/repo/` is left in place for the user to inspect.

## Error handling

| Failure | Behavior |
|---------|----------|
| Missing cross-build dep | Halt before any build, print exact `apt install` command |
| Single package build fails in tier T | Record in `MANIFEST.txt`, halt at end of tier T (lower tiers stay published) |
| Reprepro check fails | Halt; do not advance to next tier |
| GPG signature verify fails | Halt; this means the key is wrong or the repo is corrupt |
| Chroot validation fails | Warning, not halt — could be a local env issue, not a repo bug |

All halts are non-zero exit with a one-line summary plus a pointer to the
detailed log under `output/build.log`.

## Testing

This work is operational (it produces an artifact); no unit tests are added.
Instead the **chroot validation step is the test** — if a fresh `bookworm`
chroot can `apt update` against the staged repo, the artifact works.

For regressions, the manifest file is diffable: re-running with a new package
version produces a `MANIFEST.txt` that can be `diff`-ed against the last good
build.

## Open questions

None blocking. The mochabin board profile under
[`board/mochabin/`](../../../board/mochabin/) is already declared (Armada 7040,
arm64); no additional board work is needed for the publish step.

## Licensing

| Layer | License | Notes |
|-------|---------|-------|
| SecuBox-Deb source & packages | CMSD-1.0 (CyberMind Source-Disclosed) / ANSSI CSPN candidate | Per [`.claude/CLAUDE.md`](../../../.claude/CLAUDE.md). Each `.deb` carries `debian/copyright` declaring this. |
| Package signing key | SecuBox internal | UID `SecuBox Package Signing Key <packages@secubox.in>`. Not third-party; do not cross-sign. |
| Repository tooling (reprepro, nginx, certbot) | GPL / BSD / Apache (upstream) | Used as-is from Debian; no redistribution. |
| `install.sh` (served from repo root) | Proprietary / CyberMind | Header credits `https://github.com/gkerma/secubox-deb`. Includes terms-of-service hint pointing to `https://secubox.in/terms`. |
| TLS certificate | Let's Encrypt (ISRG) | Issued on the production host via certbot; subject CN = `apt.secubox.in`. |
| Public GPG key file | Proprietary distribution, free to redistribute the public half | Served at `/secubox-keyring.gpg`; SHA256 published in `FINGERPRINT.txt`. |

The staged tree MUST include:

- `output/repo/LICENCE-CMSD-1.0.md` — verbatim copy of the project root
  [`LICENCE-CMSD-1.0.md`](../../../LICENCE-CMSD-1.0.md) (authoritative French
  text).
- `output/repo/LICENSE-CMSD-1.0.en.md` — verbatim copy of the project root
  [`LICENSE-CMSD-1.0.en.md`](../../../LICENSE-CMSD-1.0.en.md) (informative
  English translation).

Both served at `https://apt.secubox.in/LICENCE-CMSD-1.0.md` and
`https://apt.secubox.in/LICENSE-CMSD-1.0.en.md`. The
[`install.sh`](../../../repo/install.sh) script references the French file
(authoritative) before any apt operation so users see the terms before
adding the repo. Per Article 13.5 of the license, the French text prevails
in any conflict.

Validation gate adds:

- `output/repo/LICENCE-CMSD-1.0.md` and `output/repo/LICENSE-CMSD-1.0.en.md`
  exist and byte-match the project root copies.
- `output/repo/FINGERPRINT.txt` contains exactly one fingerprint matching the
  key used by `SignWith:`.

## File-level changes

| Action | File | Purpose |
|--------|------|---------|
| Modify | `scripts/build-packages.sh` | Add `--filter <manifest.json>` flag |
| Create | `scripts/stage-apt-repo.sh` | Orchestrator: tiers × archs × reprepro |
| Create | `scripts/render-deploy-artifacts.sh` | Generate `nginx-apt.conf` + `DEPLOY.md` |
| Create | `scripts/validate-staged-repo.sh` | reprepro check + gpg verify + chroot test |
| Modify | `.gitignore` | Ignore `output/repo/db/`, `output/repo/pool/`, `output/test-chroot/` |
| Create | `output/repo/.gitkeep` | Keep dir structure |

The `secubox apt` Go CLI is **not** modified — we only call its existing
subcommands.
