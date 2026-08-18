<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# APT Public Repo Staging — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a fully signed APT repo tree at `output/repo/` containing both amd64 and arm64 (mochabin) SecuBox packages for bookworm, validated end-to-end, ready for the user to rsync to apt.secubox.in.

**Architecture:** Bash orchestrator (`stage-apt-repo.sh`) drives the existing Go CLI (`secubox gen`, `secubox apt`) and shell scripts (`build-packages.sh`, `generate-gpg-key.sh`). Tier-by-tier (`base → tier-lite → tier-standard → tier-pro`), with `reprepro check` gates between tiers. No network operations — output is local; user pushes when satisfied.

**Tech Stack:** Bash 5 (strict mode), reprepro, gpg, dpkg-buildpackage, debootstrap, Go (existing CLI), jq.

**Issue:** [#80](https://github.com/CyberMind-FR/secubox-deb/issues/80)

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `scripts/build-packages.sh` | Add `--filter <manifest>` flag; filter `PACKAGES=` array against a JSON manifest |
| Create | `scripts/lib/tier-manifest.sh` | Sourced helper: resolve a tier name → flat list of package names |
| Create | `scripts/stage-apt-repo.sh` | Main orchestrator: GPG → tier loop (gen → build × 2 archs → publish → check) |
| Create | `scripts/render-deploy-artifacts.sh` | Generate `output/repo/nginx-apt.conf` + `DEPLOY.md` |
| Create | `scripts/validate-staged-repo.sh` | reprepro check + gpg verify + chroot `apt update` smoke test |
| Create | `scripts/lib/test-helpers.sh` | Tiny bash assertion helpers (`assert_eq`, `assert_file`) — no framework |
| Create | `tests/scripts/test-build-filter.sh` | Smoke test for the `--filter` flag |
| Create | `tests/scripts/test-tier-manifest.sh` | Smoke test for tier resolution |
| Create | `tests/scripts/test-stage-smoke.sh` | End-to-end on a 2-package subset (`secubox-core` + `secubox-hub`) |
| Modify | `.gitignore` | Ignore `output/repo/{db,pool,gpg,dists}/`, `output/test-chroot/`, `output/manifests/` |

Tasks below build these in dependency order. Each task ends with a commit.

---

## Task 1: Install missing host dependencies

**Files:**
- None changed; environment-only.

- [ ] **Step 1: Detect what's missing**

```bash
for pkg in reprepro debootstrap gnupg jq crossbuild-essential-arm64 qemu-user-static dpkg-cross; do
  dpkg -l "$pkg" >/dev/null 2>&1 || echo "MISSING: $pkg"
done
```

Expected: prints any not-yet-installed packages. `crossbuild-essential-arm64` and `qemu-user-static` are already present per the build host audit, but the script must work on a fresh dev box too.

- [ ] **Step 2: Install missing packages**

```bash
sudo apt-get update
sudo apt-get install -y reprepro debootstrap gnupg jq crossbuild-essential-arm64 qemu-user-static dpkg-cross
```

- [ ] **Step 3: Verify**

```bash
reprepro --version | head -1
debootstrap --version
gpg --version | head -1
jq --version
```

Expected: all four print a version. No commit (environment only).

---

## Task 2: Add `--filter` flag to `build-packages.sh`

**Files:**
- Modify: [`scripts/build-packages.sh`](../../../scripts/build-packages.sh)
- Create: `tests/scripts/test-build-filter.sh`
- Create: `scripts/lib/test-helpers.sh`

- [ ] **Step 1: Create the tiny test-helper library**

```bash
# scripts/lib/test-helpers.sh
# Sourced by test scripts. No external deps.

assert_eq() {
  local expected="$1" actual="$2" msg="${3:-}"
  if [[ "$expected" != "$actual" ]]; then
    echo "FAIL: ${msg}"
    echo "  expected: $expected"
    echo "  actual:   $actual"
    return 1
  fi
}

assert_contains() {
  local haystack="$1" needle="$2" msg="${3:-}"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "FAIL: ${msg}"
    echo "  haystack: $haystack"
    echo "  needle:   $needle"
    return 1
  fi
}

assert_file() {
  local path="$1" msg="${2:-file missing}"
  if [[ ! -f "$path" ]]; then
    echo "FAIL: ${msg}: $path"
    return 1
  fi
}

pass() { echo "PASS: $*"; }
```

- [ ] **Step 2: Write the failing test**

```bash
# tests/scripts/test-build-filter.sh
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=../../scripts/lib/test-helpers.sh
source "$REPO/scripts/lib/test-helpers.sh"

# Build a tiny manifest with 2 packages
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo '["secubox-core","secubox-hub"]' > "$TMP/manifest.json"

# Dry-run: --filter must restrict the build set to those 2 packages
output="$(bash "$REPO/scripts/build-packages.sh" bookworm amd64 --filter "$TMP/manifest.json" --dry-run 2>&1 || true)"

assert_contains "$output" "secubox-core"  "core should be in dry-run output"
assert_contains "$output" "secubox-hub"   "hub should be in dry-run output"

# Negative: a known package NOT in the filter must be absent
if [[ "$output" == *"secubox-crowdsec"* ]]; then
  echo "FAIL: crowdsec was NOT filtered out"
  exit 1
fi
pass "filter restricts package set"
```

- [ ] **Step 3: Run the test, confirm it fails**

```bash
chmod +x tests/scripts/test-build-filter.sh
bash tests/scripts/test-build-filter.sh
```

Expected: FAIL — `--filter` flag doesn't exist yet, script errors out or ignores it.

- [ ] **Step 4: Modify `scripts/build-packages.sh` to accept `--filter` and `--dry-run`**

After the `SUITE=` / `ARCH=` lines (~line 11-12), add argument parsing:

```bash
# Parse positional + flags
SUITE="${1:-bookworm}"; shift || true
ARCH="${1:-$(dpkg --print-architecture)}"; shift || true

FILTER=""
DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --filter)   FILTER="$2"; shift 2 ;;
    --dry-run)  DRY_RUN=1; shift ;;
    *)          err "Unknown flag: $1"; exit 2 ;;
  esac
done
```

Then, just before the main `for PKG in "${PACKAGES[@]}"` loop, add filter resolution:

```bash
if [[ -n "$FILTER" ]]; then
  if [[ ! -f "$FILTER" ]]; then
    err "Filter manifest not found: $FILTER"
    exit 1
  fi
  mapfile -t ALLOWED < <(jq -r '.[]' "$FILTER")
  log "Filter active: ${#ALLOWED[@]} packages"
fi

is_allowed() {
  local pkg="$1"
  [[ -z "$FILTER" ]] && return 0
  for a in "${ALLOWED[@]}"; do [[ "$a" == "$pkg" ]] && return 0; done
  return 1
}
```

Inside the loop, before `log "Building ${BOLD}${PKG}${NC}..."`:

```bash
  if ! is_allowed "$PKG"; then
    continue
  fi
  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY-RUN would build: $PKG"
    continue
  fi
```

- [ ] **Step 5: Re-run the test, confirm it passes**

```bash
bash tests/scripts/test-build-filter.sh
```

Expected: `PASS: filter restricts package set`.

- [ ] **Step 6: Commit**

```bash
git add scripts/build-packages.sh scripts/lib/test-helpers.sh tests/scripts/test-build-filter.sh
git commit -m "feat(scripts): Add --filter and --dry-run to build-packages.sh (ref #80)"
```

---

## Task 3: Tier-manifest helper

**Files:**
- Create: `scripts/lib/tier-manifest.sh`
- Create: `tests/scripts/test-tier-manifest.sh`

The helper takes a tier name (`base`, `tier-lite`, `tier-standard`, `tier-pro`) and writes a JSON array of package names to a given path.

- `base` → hardcoded `["secubox-core","secubox-hub"]`.
- `tier-{lite,standard,pro}` → invoke `secubox gen --tier <tier> --board mochabin --out <tmpdir>` and parse the resulting manifest for `packages.required`.

- [ ] **Step 1: Write the failing test**

```bash
# tests/scripts/test-tier-manifest.sh
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO/scripts/lib/test-helpers.sh"
source "$REPO/scripts/lib/tier-manifest.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# base = hardcoded
tier_manifest "base" "$TMP/base.json"
assert_file "$TMP/base.json" "base manifest"
got="$(jq -r '. | sort | .[]' "$TMP/base.json" | tr '\n' ' ')"
assert_eq "secubox-core secubox-hub " "$got" "base packages"

# tier-lite must include base packages + at least one extra
tier_manifest "tier-lite" "$TMP/lite.json"
assert_file "$TMP/lite.json" "lite manifest"
count="$(jq 'length' "$TMP/lite.json")"
if [[ "$count" -lt 3 ]]; then
  echo "FAIL: tier-lite has only $count packages, expected >=3"
  exit 1
fi
# Inheritance check
if ! jq -e '. | index("secubox-core")' "$TMP/lite.json" >/dev/null; then
  echo "FAIL: tier-lite missing secubox-core (inheritance broken)"
  exit 1
fi

pass "tier-manifest base + tier-lite"
```

- [ ] **Step 2: Run, expect fail**

```bash
chmod +x tests/scripts/test-tier-manifest.sh
bash tests/scripts/test-tier-manifest.sh
```

Expected: FAIL — `scripts/lib/tier-manifest.sh` doesn't exist.

- [ ] **Step 3: Write `scripts/lib/tier-manifest.sh`**

```bash
# scripts/lib/tier-manifest.sh
# Resolve a tier name to a flat JSON array of package names.
# Usage (after sourcing): tier_manifest <tier> <out.json>

_secubox_bin() {
  local bin="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/cmd/secubox/secubox"
  if [[ -x "$bin" ]]; then echo "$bin"; return 0; fi
  command -v secubox 2>/dev/null && return 0
  echo "ERROR: secubox binary not found" >&2
  return 1
}

tier_manifest() {
  local tier="$1" out="$2"

  if [[ "$tier" == "base" ]]; then
    printf '["secubox-core","secubox-hub"]\n' > "$out"
    return 0
  fi

  local sb; sb="$(_secubox_bin)" || return 1
  local tmpdir; tmpdir="$(mktemp -d)"
  trap "rm -rf '$tmpdir'" RETURN

  "$sb" gen --tier "$tier" --board mochabin --out "$tmpdir" >/dev/null

  # secubox gen emits a manifest.json with packages.required
  local mf="$tmpdir/manifest.json"
  if [[ ! -f "$mf" ]]; then
    echo "ERROR: secubox gen did not produce manifest.json in $tmpdir" >&2
    return 1
  fi

  jq '[.packages.required[]?] | unique' "$mf" > "$out"
}
```

- [ ] **Step 4: Re-run test**

```bash
bash tests/scripts/test-tier-manifest.sh
```

Expected: `PASS: tier-manifest base + tier-lite`.

If `secubox gen` emits a different filename or shape than `manifest.json` with `.packages.required`, adjust the `jq` query and the path. The test will reveal the exact mismatch.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/tier-manifest.sh tests/scripts/test-tier-manifest.sh
git commit -m "feat(scripts): Add tier-manifest helper (ref #80)"
```

---

## Task 4: GPG bootstrap (persistent home)

**Files:**
- Modify: [`repo/scripts/generate-gpg-key.sh`](../../../repo/scripts/generate-gpg-key.sh) — make `GPG_HOME` and `EXPORT_DIR` already-overridable (they are; no change needed). Just verify.
- Create: `scripts/stage-gpg-bootstrap.sh` — thin wrapper that pins `GPG_HOME=~/.gnupg/secubox` and writes `FINGERPRINT.txt`.

- [ ] **Step 1: Write the wrapper**

```bash
# scripts/stage-gpg-bootstrap.sh
#!/usr/bin/env bash
# Initialize the SecuBox package signing key in ~/.gnupg/secubox/.
# Writes:
#   ~/.gnupg/secubox/                  - persistent gnupg home
#   $OUT_DIR/secubox-keyring.gpg       - public key, ASCII-armored
#   $OUT_DIR/FINGERPRINT.txt           - long fingerprint (no spaces)
# Idempotent: skips key creation if a key for packages@secubox.in already exists.

set -euo pipefail

OUT_DIR="${1:-output/repo}"
KEY_EMAIL="packages@secubox.in"
export GPG_HOME="${HOME}/.gnupg/secubox"
export EXPORT_DIR="$OUT_DIR"

mkdir -p "$OUT_DIR" "$GPG_HOME"
chmod 700 "$GPG_HOME"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SCRIPT_DIR")"

bash "$REPO/repo/scripts/generate-gpg-key.sh"

# Extract long fingerprint (no spaces) — used in conf/distributions SignWith.
gpg --homedir "$GPG_HOME" \
    --list-keys --with-colons "$KEY_EMAIL" \
  | awk -F: '/^fpr:/ {print $10; exit}' \
  > "$OUT_DIR/FINGERPRINT.txt"

if [[ ! -s "$OUT_DIR/FINGERPRINT.txt" ]]; then
  echo "ERROR: failed to extract fingerprint" >&2
  exit 1
fi

echo "GPG ready. Fingerprint: $(cat "$OUT_DIR/FINGERPRINT.txt")"
echo "Public key: $OUT_DIR/secubox-keyring.gpg"
```

- [ ] **Step 2: Run it**

```bash
chmod +x scripts/stage-gpg-bootstrap.sh
bash scripts/stage-gpg-bootstrap.sh output/repo
```

Expected: prints `GPG ready. Fingerprint: <40-hex-chars>`. Re-running must be a no-op (idempotent — the underlying script exits early on existing key).

- [ ] **Step 3: Verify**

```bash
test -s output/repo/FINGERPRINT.txt
test -s output/repo/secubox-keyring.gpg
gpg --homedir ~/.gnupg/secubox --list-keys packages@secubox.in
```

Expected: fingerprint file is non-empty, public key file is non-empty, key listing shows `SecuBox Package Signing Key (apt.secubox.in) <packages@secubox.in>`.

- [ ] **Step 4: Commit**

```bash
git add scripts/stage-gpg-bootstrap.sh
git commit -m "feat(scripts): Add GPG bootstrap wrapper for staged repo (ref #80)"
```

---

## Task 5: Main orchestrator — `stage-apt-repo.sh`

**Files:**
- Create: `scripts/stage-apt-repo.sh`

This script is the spine: it composes Tasks 2–4 plus the reprepro init/publish loop.

- [ ] **Step 1: Write the orchestrator**

```bash
# scripts/stage-apt-repo.sh
#!/usr/bin/env bash
# Stage a complete signed APT repo at output/repo/ for amd64 + arm64.
#
# Usage:
#   bash scripts/stage-apt-repo.sh [--tiers "base tier-lite tier-standard tier-pro"]
#                                  [--archs "arm64 amd64"]
#                                  [--suite bookworm]
#                                  [--out output/repo]
#                                  [--keep-going]
#
# Halt-on-tier-failure by default (lower tiers stay published).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SCRIPT_DIR")"
source "$REPO/scripts/lib/tier-manifest.sh"

TIERS=(base tier-lite tier-standard tier-pro)
ARCHS=(arm64 amd64)
SUITE="bookworm"
OUT="$REPO/output/repo"
KEEP_GOING=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tiers)       IFS=' ' read -ra TIERS <<< "$2"; shift 2 ;;
    --archs)       IFS=' ' read -ra ARCHS <<< "$2"; shift 2 ;;
    --suite)       SUITE="$2"; shift 2 ;;
    --out)         OUT="$2"; shift 2 ;;
    --keep-going)  KEEP_GOING=1; shift ;;
    *)             echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

LOG="$REPO/output/build.log"
mkdir -p "$OUT" "$REPO/output/manifests" "$(dirname "$LOG")"
: > "$LOG"

log() { printf '[stage] %s\n' "$*" | tee -a "$LOG" >&2; }
fail() { printf '[stage] FAIL %s\n' "$*" | tee -a "$LOG" >&2; exit 1; }

# ───── 1. GPG bootstrap ─────
log "GPG bootstrap → $OUT"
bash "$REPO/scripts/stage-gpg-bootstrap.sh" "$OUT" >> "$LOG" 2>&1
FPR="$(cat "$OUT/FINGERPRINT.txt")"
[[ -z "$FPR" ]] && fail "fingerprint empty"
log "GPG fingerprint: $FPR"

# ───── 2. reprepro conf (production identity) ─────
log "Writing reprepro conf"
mkdir -p "$OUT/conf"
cat > "$OUT/conf/distributions" <<EOF
Origin: SecuBox
Label: SecuBox
Suite: $SUITE
Codename: $SUITE
Version: 12.0
Architectures: arm64 amd64 source
Components: main
Description: SecuBox Debian packages for Armada/x86_64
SignWith: $FPR
Contents: percomponent nocompatsymlink
EOF

cat > "$OUT/conf/options" <<EOF
verbose
basedir $OUT
gnupghome ${HOME}/.gnupg/secubox
EOF

# Initialize reprepro DB (idempotent — reprepro export creates dists/ if missing)
( cd "$OUT" && reprepro export "$SUITE" ) >> "$LOG" 2>&1 || fail "reprepro export failed"

# ───── 3. Tier loop ─────
declare -A TIER_RESULT
for tier in "${TIERS[@]}"; do
  log "────── Tier: $tier ──────"

  # 3a. Resolve manifest
  mf="$REPO/output/manifests/${tier}.json"
  if ! tier_manifest "$tier" "$mf"; then
    fail "tier-manifest failed for $tier"
  fi
  count="$(jq 'length' "$mf")"
  log "  packages: $count"

  tier_failed=0

  # 3b. Build per arch
  for arch in "${ARCHS[@]}"; do
    log "  build $tier × $arch"
    if ! bash "$REPO/scripts/build-packages.sh" "$SUITE" "$arch" --filter "$mf" >> "$LOG" 2>&1; then
      log "  build FAILED: $tier × $arch"
      tier_failed=1
      [[ $KEEP_GOING -eq 0 ]] && break
    fi
  done

  if [[ $tier_failed -eq 1 ]]; then
    TIER_RESULT[$tier]="FAILED"
    [[ $KEEP_GOING -eq 0 ]] && fail "tier $tier failed — halting (lower tiers remain published)"
    continue
  fi

  # 3c. Publish built debs that belong to this tier
  pkgs="$(jq -r '.[]' "$mf")"
  files=()
  while IFS= read -r p; do
    while IFS= read -r f; do
      files+=("$f")
    done < <(ls "$REPO/output/debs/${p}_"*"_arm64.deb" \
                "$REPO/output/debs/${p}_"*"_amd64.deb" \
                "$REPO/output/debs/${p}_"*"_all.deb" 2>/dev/null || true)
  done <<< "$pkgs"

  if [[ ${#files[@]} -eq 0 ]]; then
    log "  no .debs to publish for tier $tier (skipping)"
    TIER_RESULT[$tier]="EMPTY"
    continue
  fi

  log "  publishing ${#files[@]} files"
  for f in "${files[@]}"; do
    ( cd "$OUT" && reprepro --silent includedeb "$SUITE" "$f" ) >> "$LOG" 2>&1 || {
      log "  publish FAILED: $f"
      [[ $KEEP_GOING -eq 0 ]] && fail "publish of $f failed in tier $tier"
    }
  done

  # 3d. Check after every tier
  log "  reprepro check"
  ( cd "$OUT" && reprepro check "$SUITE" ) >> "$LOG" 2>&1 || fail "reprepro check failed after tier $tier"

  TIER_RESULT[$tier]="OK"
done

# ───── 4. Manifest summary ─────
log "Writing MANIFEST.txt"
{
  echo "SecuBox APT Repo Staging — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Suite: $SUITE"
  echo "Fingerprint: $FPR"
  echo ""
  echo "Per-tier result:"
  for t in "${TIERS[@]}"; do
    printf "  %-20s %s\n" "$t" "${TIER_RESULT[$t]:-SKIPPED}"
  done
  echo ""
  echo "Per-arch package count:"
  for a in arm64 amd64 all; do
    n=$(find "$OUT/pool" -name "*_${a}.deb" 2>/dev/null | wc -l)
    printf "  %-6s %s\n" "$a" "$n"
  done
} > "$OUT/MANIFEST.txt"

log "Done. See $OUT/MANIFEST.txt"
```

- [ ] **Step 2: Smoke-run on base tier only**

```bash
chmod +x scripts/stage-apt-repo.sh
bash scripts/stage-apt-repo.sh --tiers "base" --archs "amd64"
```

Expected: `[stage] Done.` and `output/repo/MANIFEST.txt` shows `base OK` with at least one `_all.deb` published (secubox-core + secubox-hub are both arch:all).

- [ ] **Step 3: Verify the published Release file**

```bash
test -f output/repo/dists/bookworm/Release
test -f output/repo/dists/bookworm/InRelease
grep -q "^Origin: SecuBox$" output/repo/dists/bookworm/Release
gpg --homedir ~/.gnupg/secubox --verify output/repo/dists/bookworm/InRelease
```

Expected: all four commands succeed; last one prints `Good signature`.

- [ ] **Step 4: Commit**

```bash
git add scripts/stage-apt-repo.sh
git commit -m "feat(scripts): Add stage-apt-repo.sh orchestrator (ref #80)"
```

---

## Task 6: Deploy artifacts — nginx vhost + DEPLOY.md

**Files:**
- Create: `scripts/render-deploy-artifacts.sh`

- [ ] **Step 1: Write the renderer**

```bash
# scripts/render-deploy-artifacts.sh
#!/usr/bin/env bash
# Generate the nginx vhost and the DEPLOY.md recipe inside output/repo/.
# No network access.

set -euo pipefail
OUT="${1:-output/repo}"
mkdir -p "$OUT"

FPR="$(cat "$OUT/FINGERPRINT.txt" 2>/dev/null || echo 'UNKNOWN')"

cat > "$OUT/nginx-apt.conf" <<'NGINX'
# /etc/nginx/sites-available/apt.secubox.in
# Drop in, symlink to sites-enabled/, then run certbot --nginx -d apt.secubox.in.

server {
    listen 80;
    listen [::]:80;
    server_name apt.secubox.in;

    root /var/www/apt.secubox.in;

    # Let certbot serve its challenge before TLS is in place.
    location /.well-known/acme-challenge/ {
        root /var/www/apt.secubox.in;
    }

    # MIME types for apt clients.
    types {
        application/vnd.debian.binary-package  deb;
        application/pgp-keys                   gpg;
        text/plain                             txt md sha256;
    }

    # Allow directory listing under /dists and /pool only.
    location /dists/ { autoindex on; }
    location /pool/  { autoindex on; }

    # Everything else is served as static.
    location / {
        try_files $uri $uri/ =404;
    }

    access_log /var/log/nginx/apt.secubox.in.access.log;
    error_log  /var/log/nginx/apt.secubox.in.error.log;
}
NGINX

cat > "$OUT/DEPLOY.md" <<EOF
# Deploying \`apt.secubox.in\`

Generated $(date -u +%Y-%m-%dT%H:%M:%SZ). Stage was built locally; this is the
out-of-band push recipe.

## 1. rsync the tree

\`\`\`bash
rsync -avz --delete \\
  --exclude='db/' --exclude='gpg/' --exclude='conf/' \\
  $(pwd)/$OUT/  deploy@apt.secubox.in:/var/www/apt.secubox.in/
\`\`\`

The \`db/\` and \`conf/\` directories are reprepro state and must NEVER leave
the staging host. The public keyring (\`secubox-keyring.gpg\`), the dists
tree, and the pool tree are all that need to ship.

## 2. Install the nginx vhost

\`\`\`bash
scp $(pwd)/$OUT/nginx-apt.conf apt.secubox.in:/tmp/
ssh apt.secubox.in sudo install -m 0644 /tmp/nginx-apt.conf \\
  /etc/nginx/sites-available/apt.secubox.in
ssh apt.secubox.in sudo ln -sf \\
  /etc/nginx/sites-available/apt.secubox.in \\
  /etc/nginx/sites-enabled/apt.secubox.in
ssh apt.secubox.in sudo nginx -t
ssh apt.secubox.in sudo systemctl reload nginx
\`\`\`

## 3. Issue the TLS certificate

\`\`\`bash
ssh apt.secubox.in sudo certbot --nginx \\
  -d apt.secubox.in \\
  --non-interactive --agree-tos \\
  -m packages@secubox.in
\`\`\`

## 4. Verify

\`\`\`bash
# Cert SAN must include apt.secubox.in (root cause of the previous failure)
openssl s_client -servername apt.secubox.in -connect apt.secubox.in:443 \\
  </dev/null 2>/dev/null \\
  | openssl x509 -noout -ext subjectAltName

# Repo install on a clean client
curl -fsSL https://apt.secubox.in/install.sh | sudo bash
sudo apt-get update
\`\`\`

## Fingerprint

GPG fingerprint of the publishing key: \`$FPR\`

The public key is served at:

    https://apt.secubox.in/secubox-keyring.gpg

License (CMSD-1.0, French authoritative):

    https://apt.secubox.in/LICENCE-CMSD-1.0.md

EOF

# Copy install.sh and licenses into the tree
cp "$(dirname "$(realpath "$0")")/../repo/install.sh" "$OUT/install.sh"
cp "$(dirname "$(realpath "$0")")/../LICENCE-CMSD-1.0.md"     "$OUT/" 2>/dev/null || true
cp "$(dirname "$(realpath "$0")")/../LICENSE-CMSD-1.0.en.md"  "$OUT/" 2>/dev/null || true

echo "Deploy artifacts written under $OUT:"
echo "  - nginx-apt.conf"
echo "  - DEPLOY.md"
echo "  - install.sh"
echo "  - LICENCE-CMSD-1.0.md (French, authoritative)"
echo "  - LICENSE-CMSD-1.0.en.md (English, informative)"
```

- [ ] **Step 2: Run it**

```bash
chmod +x scripts/render-deploy-artifacts.sh
bash scripts/render-deploy-artifacts.sh output/repo
```

- [ ] **Step 3: Verify**

```bash
test -f output/repo/nginx-apt.conf
test -f output/repo/DEPLOY.md
test -f output/repo/install.sh
test -f output/repo/LICENCE-CMSD-1.0.md
test -f output/repo/LICENSE-CMSD-1.0.en.md
grep -q "apt.secubox.in" output/repo/nginx-apt.conf
grep -q "Fingerprint" output/repo/DEPLOY.md
```

Expected: all six commands succeed.

- [ ] **Step 4: Commit**

```bash
git add scripts/render-deploy-artifacts.sh
git commit -m "feat(scripts): Render nginx vhost + DEPLOY.md + license artifacts (ref #80)"
```

---

## Task 7: Validation gate

**Files:**
- Create: `scripts/validate-staged-repo.sh`

- [ ] **Step 1: Write the validator**

```bash
# scripts/validate-staged-repo.sh
#!/usr/bin/env bash
# Validate output/repo/ end-to-end.
#   1. reprepro check
#   2. gpg --verify on InRelease
#   3. license files match project root byte-for-byte
#   4. (best-effort) chroot apt-get update against file:// URL

set -euo pipefail
OUT="${1:-output/repo}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SUITE="${SUITE:-bookworm}"

log() { echo "[validate] $*"; }
fail() { echo "[validate] FAIL: $*" >&2; exit 1; }

# 1. reprepro check
log "reprepro check"
( cd "$OUT" && reprepro check "$SUITE" ) || fail "reprepro check failed"

# 2. gpg verify
log "gpg --verify InRelease"
gpg --homedir "$HOME/.gnupg/secubox" --verify "$OUT/dists/$SUITE/InRelease" 2>&1 \
  | grep -q "Good signature" || fail "InRelease signature did not verify"

# 3. License sanity
log "license byte-match"
cmp "$REPO/LICENCE-CMSD-1.0.md"    "$OUT/LICENCE-CMSD-1.0.md"    || fail "French license differs"
cmp "$REPO/LICENSE-CMSD-1.0.en.md" "$OUT/LICENSE-CMSD-1.0.en.md" || fail "English license differs"

# 4. chroot apt-get update (best-effort)
CHROOT="$REPO/output/test-chroot"
if [[ -z "${SKIP_CHROOT:-}" ]]; then
  log "chroot apt update (best-effort)"
  if ! command -v debootstrap >/dev/null; then
    log "  debootstrap missing, SKIP_CHROOT=1 to silence — continuing"
  else
    sudo rm -rf "$CHROOT"
    if ! sudo debootstrap --variant=minbase "$SUITE" "$CHROOT" http://deb.debian.org/debian/ >/dev/null 2>&1; then
      log "  debootstrap failed (network?) — skipping chroot test"
    else
      sudo install -d "$CHROOT/etc/apt/sources.list.d" "$CHROOT/usr/share/keyrings"
      sudo install -m 0644 "$OUT/secubox-keyring.gpg" "$CHROOT/usr/share/keyrings/secubox.gpg"
      echo "deb [signed-by=/usr/share/keyrings/secubox.gpg] file://$OUT $SUITE main" \
        | sudo tee "$CHROOT/etc/apt/sources.list.d/secubox.list" >/dev/null
      sudo mount --bind "$OUT" "$CHROOT$OUT"
      sudo chroot "$CHROOT" apt-get update 2>&1 | tee "$REPO/output/chroot-update.log" \
        | grep -q "Get.*$SUITE" || fail "chroot apt-get update did not see SecuBox repo"
      sudo umount "$CHROOT$OUT"
      log "  chroot apt-get update OK"
    fi
  fi
fi

log "All validation checks passed"
```

- [ ] **Step 2: Run on the staged base tier from Task 5**

```bash
chmod +x scripts/validate-staged-repo.sh
SKIP_CHROOT=1 bash scripts/validate-staged-repo.sh output/repo
```

Expected: `[validate] All validation checks passed` (chroot skipped this round; we'll do it after the full run).

- [ ] **Step 3: Commit**

```bash
git add scripts/validate-staged-repo.sh
git commit -m "feat(scripts): Add validate-staged-repo.sh (ref #80)"
```

---

## Task 8: `.gitignore` for staged artifacts

**Files:**
- Modify: [`.gitignore`](../../../.gitignore)

The staged repo contains hundreds of MB of `.deb` + reprepro state. None of it belongs in git.

- [ ] **Step 1: Append to `.gitignore`**

```bash
cat >> .gitignore <<'EOF'

# APT staging artifacts (regenerated by scripts/stage-apt-repo.sh)
/output/repo/db/
/output/repo/pool/
/output/repo/dists/
/output/repo/gpg/
/output/repo/conf/
/output/test-chroot/
/output/manifests/
/output/chroot-update.log
/output/build.log
EOF
```

Note: `conf/` is ignored too because it contains the absolute path of the staging host in `options`, which is host-specific and not portable.

- [ ] **Step 2: Verify ignore works**

```bash
git check-ignore -v output/repo/db/version 2>/dev/null || echo "Hmm, db/ not yet ignored"
git check-ignore -v output/repo/pool/main/s/secubox-hub/secubox-hub_1.1.0-1~bookworm1_all.deb
```

Expected: both report the ignore rule. (`db/version` may not exist if reprepro hasn't created it yet — that's OK as long as the rule shows up.)

- [ ] **Step 3: Commit**

```bash
git add .gitignore
git commit -m "chore: Ignore APT staging artifacts (ref #80)"
```

---

## Task 9: Full pipeline run (no commit — validates work)

**Files:** None modified; this is a verification run.

- [ ] **Step 1: Wipe and re-stage from scratch**

```bash
rm -rf output/repo/db output/repo/pool output/repo/dists output/repo/conf
bash scripts/stage-apt-repo.sh
```

Expected runtime: 30–90 min depending on cross-build speed. The script halts on the first tier that fails to build entirely.

- [ ] **Step 2: Render deploy artifacts**

```bash
bash scripts/render-deploy-artifacts.sh output/repo
```

- [ ] **Step 3: Validate (this time with chroot)**

```bash
bash scripts/validate-staged-repo.sh output/repo
```

Expected: `[validate] All validation checks passed`, including `[validate]   chroot apt-get update OK`.

- [ ] **Step 4: Inspect the manifest**

```bash
cat output/repo/MANIFEST.txt
```

Expected output shape:

```
SecuBox APT Repo Staging — 2026-05-12T18:42:11Z
Suite: bookworm
Fingerprint: <40 hex chars>

Per-tier result:
  base                 OK
  tier-lite            OK
  tier-standard        OK
  tier-pro             OK

Per-arch package count:
  arm64  <N>
  amd64  <M>
  all    <K>
```

If any tier shows `FAILED`, that tier's packages need investigation before re-running. Lower tiers remain published — the repo is still usable for the tiers that succeeded.

- [ ] **Step 5: Comment on the issue**

```bash
gh issue comment 80 --body "Implementation complete. Staged at \`output/repo/\`; manifest:

\`\`\`
$(cat output/repo/MANIFEST.txt)
\`\`\`

Pending: rsync to apt.secubox.in per output/repo/DEPLOY.md, then certbot for TLS cert."
```

Do NOT close the issue — per CLAUDE.md the user closes after validation.

---

## Task 10: Update tracking files

**Files:**
- Modify: [`.claude/WIP.md`](../../../.claude/WIP.md), [`.claude/HISTORY.md`](../../../.claude/HISTORY.md), [`.claude/MIGRATION-MAP.md`](../../../.claude/MIGRATION-MAP.md)

Per CLAUDE.md, every completed feature updates the tracking files.

- [ ] **Step 1: Append a session entry to `HISTORY.md`**

```markdown
## 2026-05-12 — APT Public Repo Staging (Issue #80)

### Goal
Stage signed APT repo with amd64 + arm64 (mochabin) packages, GPG-signed, validated end-to-end. User pushes to apt.secubox.in out-of-band.

### Delivered
- `scripts/build-packages.sh --filter <manifest>` flag
- `scripts/lib/tier-manifest.sh` (base hardcoded; tier-{lite,standard,pro} via `secubox gen`)
- `scripts/stage-gpg-bootstrap.sh` (persistent `~/.gnupg/secubox/`)
- `scripts/stage-apt-repo.sh` (tier-by-tier with reprepro check gate)
- `scripts/render-deploy-artifacts.sh` (nginx vhost + DEPLOY.md + license copies)
- `scripts/validate-staged-repo.sh` (reprepro check + gpg verify + chroot smoke test)

### Files added
output/repo/{conf,db,dists,pool,gpg}/ (gitignored)
output/repo/{secubox-keyring.gpg,FINGERPRINT.txt,MANIFEST.txt,install.sh,nginx-apt.conf,DEPLOY.md,LICEN*.md}

### Next
- User: rsync to apt.secubox.in; certbot --nginx; verify SAN; close #80.
```

- [ ] **Step 2: Move WIP entry to "Fait"**

In `.claude/WIP.md`, add this under the most recent "✅ Fait" section:

```markdown
### ✅ Session 150: APT Public Repo Staging (Issue #80)

Staged signed APT repo at `output/repo/` for bookworm × {arm64, amd64} with
GPG signing, tier-layered build (base → lite → standard → pro), validation
gate (reprepro check + gpg verify + chroot smoke), and deploy artifacts
(nginx vhost + DEPLOY.md). User pushes to apt.secubox.in out-of-band.
```

- [ ] **Step 3: Update MIGRATION-MAP.md if needed**

Verify the APT repo row already shows ✅ (it does per the earlier audit). If new components are tracked there separately (arm64 cross-build, GPG signing), check those boxes.

- [ ] **Step 4: Commit**

```bash
git add .claude/HISTORY.md .claude/WIP.md .claude/MIGRATION-MAP.md
git commit -m "docs: Update WIP/HISTORY for APT public repo staging (ref #80)"
```

---

## Self-review

1. **Spec coverage:**
   - Component 1 (GPG bootstrap) → Task 4 ✓
   - Component 2 (tier resolution) → Task 3 ✓
   - Component 3 (layered cross-build) → Tasks 2 + 5 ✓
   - Component 4 (reprepro repo) → Task 5 (steps 2 + 3c + 3d) ✓
   - Component 5 (deploy artifacts) → Task 6 ✓
   - Component 6 (validation gate) → Task 7 + 9 ✓
   - Licensing requirement → Task 6 (license file copy) + Task 7 (cmp check) ✓
   - .gitignore → Task 8 ✓
   - GitHub issue workflow → Task 9 (comment), no auto-close → ✓

2. **Placeholder scan:** No TBDs. All code blocks are concrete. Task 9 runtime range is given as "30–90 min" — that's a real expectation, not a placeholder.

3. **Type consistency:**
   - `tier_manifest <tier> <out.json>` shape consistent in Tasks 3 and 5.
   - `output/repo/FINGERPRINT.txt` produced in Task 4, consumed in Task 5 (reprepro SignWith) and Task 6 (DEPLOY.md).
   - `--filter <manifest.json>` flag signature consistent in Tasks 2 and 5.
   - `SUITE`, `OUT` env defaults consistent across Tasks 5, 7.

No gaps identified.
