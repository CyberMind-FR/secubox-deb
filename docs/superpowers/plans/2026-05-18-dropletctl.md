<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# dropletctl CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `/usr/sbin/dropletctl` in the `secubox-droplet` Debian package — port the OpenWrt CLI to Debian conventions so the existing FastAPI consumer can finally publish, remove, rename, and list droplet sites.

**Architecture:** A ~180-line bash orchestrator at `packages/secubox-droplet/sbin/dropletctl`. It validates input, sanitizes names, stages content (HTML / `.zip` / `.tar.gz` / `.tgz`), writes a `[sites.<name>]` block to `/etc/secubox/droplet.toml`, then delegates all nginx + HAProxy + mitmproxy work to `metablogizerctl site publish <name>`. Tests are bats unit cases with PATH-shimmed delegate stubs in `tests/fixtures/bin/`. Packaging updates: install line in `debian/rules`, `Depends:` bump in `debian/control`, changelog bump `1.0.1 → 1.1.0`.

**Tech Stack:** bash 5 (strict mode), bats-core for tests, python3 stdlib (`tomllib` read + manual TOML emission for write), `rsync`, `unzip`, `tar`, `logger`, GNU `find`. Reference: OpenWrt source `/home/reepost/CyberMindStudio/secubox-openwrt/package/secubox/secubox-app-droplet/files/usr/sbin/dropletctl`. Spec: `docs/superpowers/specs/2026-05-18-dropletctl-design.md` (commit `5e6e1d83`).

---

## File structure

```
packages/secubox-droplet/
├── sbin/
│   └── dropletctl                            ← NEW: ~180-line bash CLI
├── tests/
│   ├── test_dropletctl.bats                  ← NEW: 10 bats cases
│   ├── helpers.bash                          ← NEW: setup_suite, stub bin dir, fixture gen
│   └── fixtures/
│       └── bin/
│           ├── metablogizerctl               ← NEW: stub (logs args, exit 0)
│           └── logger                        ← NEW: stub (no-op, exit 0)
└── debian/
    ├── rules                                 ← MODIFY: + sbin/ install block
    ├── control                               ← MODIFY: + secubox-metablogizer dep
    └── changelog                             ← MODIFY: bump 1.0.1 → 1.1.0
```

**Spec deviation noted:** the spec said `Depends: secubox-metablogizer (>= 2.0.0)` but live `metablogizer` is at `1.1.1-1~bookworm1`. This plan uses `>= 1.1` so apt doesn't refuse to install.

---

## Task 1: Bats infrastructure + fixtures + delegate stubs

**Files:**
- Create: `packages/secubox-droplet/tests/helpers.bash`
- Create: `packages/secubox-droplet/tests/fixtures/bin/metablogizerctl`
- Create: `packages/secubox-droplet/tests/fixtures/bin/logger`
- Create: `packages/secubox-droplet/tests/test_dropletctl.bats`

- [ ] **Step 1: Create the metablogizerctl stub**

```bash
mkdir -p packages/secubox-droplet/tests/fixtures/bin
cat > packages/secubox-droplet/tests/fixtures/bin/metablogizerctl <<'EOF'
#!/usr/bin/env bash
# Stub for bats tests — logs args to $STUB_LOG, exit 0 unless STUB_METABLOGIZERCTL_FAIL=1.
printf 'metablogizerctl %s\n' "$*" >> "${STUB_LOG:-/dev/null}"
if [[ "${STUB_METABLOGIZERCTL_FAIL:-0}" = "1" ]]; then
    echo "stub: forced failure" >&2
    exit 1
fi
exit 0
EOF
chmod +x packages/secubox-droplet/tests/fixtures/bin/metablogizerctl
```

- [ ] **Step 2: Create the logger stub**

```bash
cat > packages/secubox-droplet/tests/fixtures/bin/logger <<'EOF'
#!/usr/bin/env bash
# Stub for bats tests — logs args, exit 0.
printf 'logger %s\n' "$*" >> "${STUB_LOG:-/dev/null}"
exit 0
EOF
chmod +x packages/secubox-droplet/tests/fixtures/bin/logger
```

- [ ] **Step 3: Create the helpers.bash test fixture-bootstrap**

```bash
cat > packages/secubox-droplet/tests/helpers.bash <<'EOF'
#!/usr/bin/env bash
# Shared bats helpers for dropletctl tests.

# REPO_ROOT = top of the git checkout. PACKAGE_ROOT = packages/secubox-droplet/.
export REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../../.." && pwd)"
export PACKAGE_ROOT="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
export DROPLETCTL="$PACKAGE_ROOT/sbin/dropletctl"

setup() {
    # Per-test temp dir; gone after teardown.
    TMP="$(mktemp -d "${BATS_TMPDIR}/droplet.XXXXXX")"
    export TMP
    export STUB_LOG="$TMP/stub.log"
    export SITES_DIR="$TMP/srv/metablogizer/sites"
    export TOML_PATH="$TMP/etc/secubox/droplet.toml"
    mkdir -p "$SITES_DIR" "$(dirname "$TOML_PATH")"
    : > "$STUB_LOG"
    # Empty TOML scaffold — dropletctl creates [sites.<name>] sections in it.
    printf '[droplet]\ndefault_domain = "gk2.secubox.in"\n' > "$TOML_PATH"
    # PATH-shim the delegate stubs.
    export PATH="$PACKAGE_ROOT/tests/fixtures/bin:$PATH"
}

teardown() {
    rm -rf "$TMP"
}

# Generate a 1-file HTML fixture at $1.
make_html() {
    local out="$1"
    printf '<!doctype html><html><body><h1>fixture</h1></body></html>\n' > "$out"
}

# Generate a zip fixture with one nested top-level dir.
make_zip_nested() {
    local out="$1" workdir
    workdir="$(mktemp -d "$TMP/mkzip.XXXXXX")"
    mkdir "$workdir/site"
    make_html "$workdir/site/index.html"
    printf 'body { color: red; }\n' > "$workdir/site/style.css"
    ( cd "$workdir" && zip -qr "$out" site )
    rm -rf "$workdir"
}

# Generate a tarball fixture with one nested top-level dir.
make_tarball_nested() {
    local out="$1" workdir
    workdir="$(mktemp -d "$TMP/mktar.XXXXXX")"
    mkdir "$workdir/site"
    make_html "$workdir/site/index.html"
    printf 'body { color: red; }\n' > "$workdir/site/style.css"
    ( cd "$workdir" && tar -czf "$out" site )
    rm -rf "$workdir"
}
EOF
```

- [ ] **Step 4: Create the bats file with a single smoke test**

```bash
cat > packages/secubox-droplet/tests/test_dropletctl.bats <<'EOF'
#!/usr/bin/env bats

load helpers

@test "dropletctl with no args prints usage" {
    run "$DROPLETCTL"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Usage:" ]] || [[ "$output" =~ "dropletctl" ]]
}
EOF
```

- [ ] **Step 5: Verify bats picks up the suite (test will fail — dropletctl doesn't exist yet)**

Run: `cd packages/secubox-droplet && bats tests/test_dropletctl.bats`
Expected: 1 test ran, FAIL with "DROPLETCTL: command not found" or "permission denied". This proves the harness loads.

- [ ] **Step 6: Create the dropletctl skeleton so the smoke test passes**

```bash
mkdir -p packages/secubox-droplet/sbin
cat > packages/secubox-droplet/sbin/dropletctl <<'EOF'
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: dropletctl — droplet content publisher (port from OpenWrt)
set -euo pipefail

readonly MODULE="dropletctl"
readonly VERSION="1.1.0"

case "${1:-}" in
    "" | -h | --help)
        cat <<USAGE
Droplet Publisher — One-drop static-content publishing
Usage: dropletctl <command> [args]

Commands:
  publish <file> <name> [domain]   Publish HTML/ZIP/tarball as a site
  list                             List published droplets
  remove <name>                    Remove a droplet
  rename <old> <new>               Rename a droplet
USAGE
        exit 0
        ;;
    *)
        echo "[ERROR] unknown subcommand: $1" >&2
        exit 1
        ;;
esac
EOF
chmod +x packages/secubox-droplet/sbin/dropletctl
```

- [ ] **Step 7: Run bats to confirm green**

Run: `cd packages/secubox-droplet && bats tests/test_dropletctl.bats`
Expected: `1 test, 0 failures`

- [ ] **Step 8: Commit**

```bash
git add packages/secubox-droplet/sbin/dropletctl \
        packages/secubox-droplet/tests/helpers.bash \
        packages/secubox-droplet/tests/test_dropletctl.bats \
        packages/secubox-droplet/tests/fixtures/bin/metablogizerctl \
        packages/secubox-droplet/tests/fixtures/bin/logger
git commit -m "feat(droplet): scaffold dropletctl CLI + bats harness (ref #196)"
```

---

## Task 2: publish argument validation (TDD: 3 error cases)

**Files:**
- Modify: `packages/secubox-droplet/sbin/dropletctl`
- Modify: `packages/secubox-droplet/tests/test_dropletctl.bats`

- [ ] **Step 1: Add 3 failing tests for argument validation**

Append to `packages/secubox-droplet/tests/test_dropletctl.bats`:

```bash
@test "publish with no args exits 1 with Usage" {
    run "$DROPLETCTL" publish
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Usage" ]]
}

@test "publish with missing file exits 1" {
    run "$DROPLETCTL" publish "$TMP/does-not-exist.html" foo
    [ "$status" -eq 1 ]
    [[ "$output" =~ "not found" ]]
}

@test "publish with unsupported extension exits 1" {
    : > "$TMP/bad.xyz"
    run "$DROPLETCTL" publish "$TMP/bad.xyz" foo
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Unsupported file type" ]]
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/secubox-droplet && bats tests/test_dropletctl.bats`
Expected: 4 tests, 3 failures (the new ones — dropletctl returns "unknown subcommand").

- [ ] **Step 3: Implement publish dispatch + validation**

Replace the `case` block in `packages/secubox-droplet/sbin/dropletctl` with:

```bash
case "${1:-}" in
    "" | -h | --help)
        cat <<USAGE
Droplet Publisher — One-drop static-content publishing
Usage: dropletctl <command> [args]

Commands:
  publish <file> <name> [domain]   Publish HTML/ZIP/tarball as a site
  list                             List published droplets
  remove <name>                    Remove a droplet
  rename <old> <new>               Rename a droplet
USAGE
        exit 0
        ;;
    publish)
        shift
        cmd_publish "$@"
        ;;
    *)
        echo "[ERROR] unknown subcommand: $1" >&2
        exit 1
        ;;
esac
```

And add this function *above* the `case` block:

```bash
cmd_publish() {
    local file="${1:-}"
    local name="${2:-}"
    local domain="${3:-}"

    if [[ -z "$file" ]] || [[ -z "$name" ]]; then
        echo "[ERROR] Usage: dropletctl publish <file> <name> [domain]" >&2
        exit 1
    fi
    if [[ ! -e "$file" ]]; then
        echo "[ERROR] not found: $file" >&2
        exit 1
    fi

    local ext="${file##*.}"
    ext="${ext,,}"  # bash 4 lowercase
    # Handle .tar.gz double-extension
    if [[ "$file" == *.tar.gz ]]; then ext="tar.gz"; fi

    case "$ext" in
        html|htm|zip|tgz|tar.gz)
            : ;;
        *)
            echo "[ERROR] Unsupported file type: .$ext (expected .html .htm .zip .tar.gz .tgz)" >&2
            exit 1
            ;;
    esac

    # Stub — actual staging arrives in later tasks.
    echo "[OK] (stub) would publish $file as $name"
    echo "${name}.${domain:-gk2.secubox.in}"
}
```

- [ ] **Step 4: Run tests to verify the 3 new ones pass**

Run: `cd packages/secubox-droplet && bats tests/test_dropletctl.bats`
Expected: `4 tests, 0 failures`

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-droplet/sbin/dropletctl \
        packages/secubox-droplet/tests/test_dropletctl.bats
git commit -m "feat(droplet): publish arg validation (3 error cases) (ref #196)"
```

---

## Task 3: name sanitization + single HTML happy path

**Files:**
- Modify: `packages/secubox-droplet/sbin/dropletctl`
- Modify: `packages/secubox-droplet/tests/test_dropletctl.bats`

- [ ] **Step 1: Add 2 failing tests for HTML publish + name sanitization**

Append to `packages/secubox-droplet/tests/test_dropletctl.bats`:

```bash
@test "publish a single HTML stages it and delegates to metablogizerctl" {
    make_html "$TMP/page.html"

    run "$DROPLETCTL" publish "$TMP/page.html" mysite mydomain.test
    [ "$status" -eq 0 ]
    [[ "$output" =~ "[OK]" ]]
    # API parses last stdout line as vhost.
    last_line="$(printf '%s\n' "$output" | tail -1)"
    [ "$last_line" = "mysite.mydomain.test" ]
    # Docroot has the staged file.
    [ -f "$SITES_DIR/mysite/index.html" ]
    grep -q "fixture" "$SITES_DIR/mysite/index.html"
    # Delegate was called with the right args.
    grep -q "metablogizerctl site publish mysite" "$STUB_LOG"
}

@test "publish sanitizes uppercase + special chars in name" {
    make_html "$TMP/page.html"

    run "$DROPLETCTL" publish "$TMP/page.html" "MyCool Site!" mydomain.test
    [ "$status" -eq 0 ]
    last_line="$(printf '%s\n' "$output" | tail -1)"
    [ "$last_line" = "mycool_site_.mydomain.test" ]
    [ -d "$SITES_DIR/mycool_site_" ]
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/secubox-droplet && bats tests/test_dropletctl.bats`
Expected: 6 tests, 2 failures (the HTML stage / delegate / docroot checks fail because cmd_publish is still a stub).

- [ ] **Step 3: Implement name sanitization + HTML staging + delegate call**

Replace `cmd_publish` in `packages/secubox-droplet/sbin/dropletctl` with the full implementation:

```bash
# Environment overrides for tests (default to production paths if unset).
: "${SITES_DIR:=/srv/metablogizer/sites}"
: "${TOML_PATH:=/etc/secubox/droplet.toml}"
: "${LOG_TAG:=droplet}"

log_info()  { logger -t "$LOG_TAG" -p user.info  "$*" 2>/dev/null || true; echo "[INFO] $*"; }
log_error() { logger -t "$LOG_TAG" -p user.error "$*" 2>/dev/null || true; echo "[ERROR] $*" >&2; }
log_ok()    { echo "[OK] $*"; }

# Lowercase + replace non-[a-z0-9_-] with '_'. Empty result -> caller errors.
sanitize_name() {
    printf '%s' "$1" | awk '{print tolower($0)}' | sed 's/[^a-z0-9_-]/_/g'
}

# Read default_domain from droplet.toml. Falls back to gk2.secubox.in.
default_domain() {
    [[ -r "$TOML_PATH" ]] || { echo "gk2.secubox.in"; return; }
    local v
    v=$(grep -E '^default_domain\s*=' "$TOML_PATH" 2>/dev/null \
        | head -1 | sed -E 's/^default_domain\s*=\s*"?([^"]*)"?\s*$/\1/')
    echo "${v:-gk2.secubox.in}"
}

# Stage <src> into a fresh temp dir. Echoes the staging dir path.
stage_content() {
    local src="$1"
    local staging
    staging="$(mktemp -d /tmp/droplet.XXXXXX)"

    local ext="${src##*.}"
    ext="${ext,,}"
    if [[ "$src" == *.tar.gz ]]; then ext="tar.gz"; fi

    case "$ext" in
        html|htm)
            cp "$src" "$staging/index.html"
            ;;
        zip|tgz|tar.gz)
            log_error "extraction not implemented yet"
            rm -rf "$staging"
            exit 3
            ;;
    esac

    echo "$staging"
}

cmd_publish() {
    local file="${1:-}"
    local name_raw="${2:-}"
    local domain="${3:-$(default_domain)}"

    if [[ -z "$file" ]] || [[ -z "$name_raw" ]]; then
        echo "[ERROR] Usage: dropletctl publish <file> <name> [domain]" >&2
        exit 1
    fi
    if [[ ! -e "$file" ]]; then
        echo "[ERROR] not found: $file" >&2
        exit 1
    fi

    local ext="${file##*.}"; ext="${ext,,}"
    [[ "$file" == *.tar.gz ]] && ext="tar.gz"
    case "$ext" in
        html|htm|zip|tgz|tar.gz) : ;;
        *)
            echo "[ERROR] Unsupported file type: .$ext (expected .html .htm .zip .tar.gz .tgz)" >&2
            exit 1
            ;;
    esac

    local name; name="$(sanitize_name "$name_raw")"
    if [[ -z "$name" ]]; then
        echo "[ERROR] Invalid name '$name_raw'" >&2
        exit 2
    fi

    local vhost="${name}.${domain}"
    local staging; staging="$(stage_content "$file")"
    trap 'rm -rf "$staging"' EXIT

    log_info "Publishing: $file as $vhost"

    # Permissions: 644 files, 755 dirs.
    find "$staging" -type f -exec chmod 644 {} +
    find "$staging" -type d -exec chmod 755 {} +

    # Deploy to /srv/metablogizer/sites/<name>/ (idempotent overwrite).
    mkdir -p "$SITES_DIR/$name"
    rsync -a --delete "$staging"/ "$SITES_DIR/$name"/

    # Upsert TOML entry. Section format: [sites.<name>] domain="<d>" type="static".
    upsert_toml_site "$name" "$domain" "static"

    # Delegate the HTTP-facing work.
    if ! command -v metablogizerctl >/dev/null 2>&1; then
        log_error "metablogizerctl not found — install secubox-metablogizer"
        exit 4
    fi
    if ! metablogizerctl site publish "$name"; then
        log_error "metablogizerctl failed for $name"
        exit 5
    fi

    log_ok "Published: https://$vhost/"
    echo "$vhost"
}

# Upsert [sites.<name>] section. Uses python3 for safe TOML rewrite.
upsert_toml_site() {
    local name="$1" domain="$2" type="$3"
    python3 - "$TOML_PATH" "$name" "$domain" "$type" <<'PY'
import sys, re, os, tempfile

path, name, domain, type_ = sys.argv[1:]
section = f"[sites.{name}]"
new_block = f'{section}\ndomain = "{domain}"\ntype = "{type_}"\n'

if os.path.exists(path):
    with open(path) as f:
        content = f.read()
else:
    content = ""

# Match the section + its body up to the next [section] or EOF.
pattern = re.compile(
    rf'^{re.escape(section)}\s*\n(?:(?!^\[).*\n?)*',
    flags=re.MULTILINE,
)
if pattern.search(content):
    new_content = pattern.sub(new_block, content)
else:
    if content and not content.endswith('\n'):
        content += '\n'
    if content and not content.endswith('\n\n'):
        content += '\n'
    new_content = content + new_block

# Atomic write.
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or '.', prefix='.droplet.', suffix='.toml')
os.write(fd, new_content.encode())
os.close(fd)
os.replace(tmp, path)
PY
}
```

- [ ] **Step 4: Run tests to verify all 6 pass**

Run: `cd packages/secubox-droplet && bats tests/test_dropletctl.bats`
Expected: `6 tests, 0 failures`

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-droplet/sbin/dropletctl \
        packages/secubox-droplet/tests/test_dropletctl.bats
git commit -m "feat(droplet): name sanitization + HTML staging + metablogizerctl delegation (ref #196)"
```

---

## Task 4: ZIP extraction with nested-dir unwrap

**Files:**
- Modify: `packages/secubox-droplet/sbin/dropletctl`
- Modify: `packages/secubox-droplet/tests/test_dropletctl.bats`

- [ ] **Step 1: Add failing test for ZIP publish with nested top-level dir**

Append to `packages/secubox-droplet/tests/test_dropletctl.bats`:

```bash
@test "publish a zip with one nested top dir unwraps it" {
    make_zip_nested "$TMP/site.zip"

    run "$DROPLETCTL" publish "$TMP/site.zip" zipsite mydomain.test
    [ "$status" -eq 0 ]
    # Unwrapped: NOT $SITES_DIR/zipsite/site/index.html, but directly:
    [ -f "$SITES_DIR/zipsite/index.html" ]
    [ -f "$SITES_DIR/zipsite/style.css" ]
    # Nested wrapper dir is gone.
    [ ! -d "$SITES_DIR/zipsite/site" ]
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd packages/secubox-droplet && bats tests/test_dropletctl.bats`
Expected: 7 tests, 1 failure (the ZIP path hits the stubbed "extraction not implemented" exit 3).

- [ ] **Step 3: Implement ZIP extraction with unwrap**

Replace the `stage_content` function in `packages/secubox-droplet/sbin/dropletctl` with:

```bash
# Stage <src> into a fresh temp dir. Echoes the staging dir path.
stage_content() {
    local src="$1"
    local staging
    staging="$(mktemp -d /tmp/droplet.XXXXXX)"

    local ext="${src##*.}"
    ext="${ext,,}"
    if [[ "$src" == *.tar.gz ]]; then ext="tar.gz"; fi

    case "$ext" in
        html|htm)
            cp "$src" "$staging/index.html"
            ;;
        zip)
            if ! unzip -q "$src" -d "$staging"; then
                log_error "Failed to extract zip: $src"
                rm -rf "$staging"
                exit 3
            fi
            unwrap_single_nested "$staging"
            ;;
        tgz|tar.gz)
            log_error "tarball extraction not implemented yet"
            rm -rf "$staging"
            exit 3
            ;;
    esac

    echo "$staging"
}

# If $1 contains exactly one entry and it's a directory, move its contents up.
unwrap_single_nested() {
    local dir="$1"
    local entries=("$dir"/*)
    if [[ ${#entries[@]} -eq 1 ]] && [[ -d "${entries[0]}" ]]; then
        local nested="${entries[0]}"
        # Use a temp move to avoid name collision when nested basename matches dir.
        local stash; stash="$(mktemp -d "$dir/.unwrap.XXXXXX")"
        mv "$nested"/* "$nested"/.[!.]* "$stash"/ 2>/dev/null || true
        rmdir "$nested"
        mv "$stash"/* "$stash"/.[!.]* "$dir"/ 2>/dev/null || true
        rmdir "$stash"
    fi
}
```

- [ ] **Step 4: Run tests to confirm all 7 pass**

Run: `cd packages/secubox-droplet && bats tests/test_dropletctl.bats`
Expected: `7 tests, 0 failures`

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-droplet/sbin/dropletctl \
        packages/secubox-droplet/tests/test_dropletctl.bats
git commit -m "feat(droplet): ZIP extraction with single-nested-dir unwrap (ref #196)"
```

---

## Task 5: tarball extraction (.tar.gz / .tgz) + plain-directory input

**Files:**
- Modify: `packages/secubox-droplet/sbin/dropletctl`
- Modify: `packages/secubox-droplet/tests/test_dropletctl.bats`

- [ ] **Step 1: Add failing tests for tarball publish AND directory input**

Append to `packages/secubox-droplet/tests/test_dropletctl.bats`:

```bash
@test "publish a tarball with one nested top dir unwraps it" {
    make_tarball_nested "$TMP/site.tar.gz"

    run "$DROPLETCTL" publish "$TMP/site.tar.gz" tarsite mydomain.test
    [ "$status" -eq 0 ]
    [ -f "$SITES_DIR/tarsite/index.html" ]
    [ -f "$SITES_DIR/tarsite/style.css" ]
    [ ! -d "$SITES_DIR/tarsite/site" ]
}

@test "publish a plain directory copies its tree verbatim" {
    mkdir -p "$TMP/site_src"
    make_html "$TMP/site_src/index.html"
    printf 'body { color: blue; }\n' > "$TMP/site_src/style.css"

    run "$DROPLETCTL" publish "$TMP/site_src" dirsite mydomain.test
    [ "$status" -eq 0 ]
    [ -f "$SITES_DIR/dirsite/index.html" ]
    [ -f "$SITES_DIR/dirsite/style.css" ]
    grep -q "fixture" "$SITES_DIR/dirsite/index.html"
}
```

- [ ] **Step 2: Run to verify both new tests fail**

Run: `cd packages/secubox-droplet && bats tests/test_dropletctl.bats`
Expected: 9 tests, 2 failures (tarball still stubbed; directory hits the extension validation as "Unsupported file type: .site_src").

- [ ] **Step 3: Wire tarball extraction + add directory branch in cmd_publish**

(a) In `packages/secubox-droplet/sbin/dropletctl`, replace the `tgz|tar.gz)` branch inside `stage_content`:

```bash
        tgz|tar.gz)
            if ! tar -xzf "$src" -C "$staging"; then
                log_error "Failed to extract tarball: $src"
                rm -rf "$staging"
                exit 3
            fi
            unwrap_single_nested "$staging"
            ;;
        dir)
            # Caller passed a directory — rsync its contents verbatim.
            rsync -a "$src"/ "$staging"/
            ;;
```

(b) Adjust the extension-detection block in `cmd_publish` so that a directory short-circuits the `.ext` check. Replace the extension/case block in `cmd_publish` with:

```bash
    # If the path is a directory, skip extension validation entirely.
    local ext
    if [[ -d "$file" ]]; then
        ext="dir"
    else
        ext="${file##*.}"; ext="${ext,,}"
        [[ "$file" == *.tar.gz ]] && ext="tar.gz"
        case "$ext" in
            html|htm|zip|tgz|tar.gz) : ;;
            *)
                echo "[ERROR] Unsupported file type: .$ext (expected .html .htm .zip .tar.gz .tgz or directory)" >&2
                exit 1
                ;;
        esac
    fi
```

And in `stage_content`, the dispatch needs to also accept the `dir` synthetic ext, which the patch in (a) already wires. Confirm the `stage_content` `case "$ext" in` now reads:

```bash
    case "$ext" in
        html|htm) ... ;;
        zip)      ... ;;
        tgz|tar.gz) ... ;;
        dir)      ... ;;
    esac
```

(c) `stage_content`'s ext-detection block currently re-derives the extension from the filename. Update it so a directory also resolves to `ext=dir`:

```bash
    local ext
    if [[ -d "$src" ]]; then
        ext="dir"
    else
        ext="${src##*.}"; ext="${ext,,}"
        [[ "$src" == *.tar.gz ]] && ext="tar.gz"
    fi
```

- [ ] **Step 4: Run tests to confirm all 9 pass**

Run: `cd packages/secubox-droplet && bats tests/test_dropletctl.bats`
Expected: `9 tests, 0 failures`

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-droplet/sbin/dropletctl \
        packages/secubox-droplet/tests/test_dropletctl.bats
git commit -m "feat(droplet): tarball + plain-directory input (ref #196)"
```

---

## Task 6: idempotent re-publish (overwrite + no TOML duplicates)

**Files:**
- Modify: `packages/secubox-droplet/tests/test_dropletctl.bats`

- [ ] **Step 1: Add failing test for double-publish idempotency**

Append to `packages/secubox-droplet/tests/test_dropletctl.bats`:

```bash
@test "publish twice for same name overwrites docroot, no TOML dupes" {
    make_html "$TMP/v1.html"
    make_html "$TMP/v2.html"
    # Make v2 distinguishable.
    printf '<!doctype html><html><body><h2>v2</h2></body></html>\n' > "$TMP/v2.html"

    run "$DROPLETCTL" publish "$TMP/v1.html" rev mydomain.test
    [ "$status" -eq 0 ]
    grep -q "fixture" "$SITES_DIR/rev/index.html"

    run "$DROPLETCTL" publish "$TMP/v2.html" rev mydomain.test
    [ "$status" -eq 0 ]
    # v2 overwrote v1.
    grep -q "v2" "$SITES_DIR/rev/index.html"
    ! grep -q "fixture" "$SITES_DIR/rev/index.html"
    # Exactly one [sites.rev] block in the TOML.
    count="$(grep -c '^\[sites\.rev\]' "$TOML_PATH")"
    [ "$count" = "1" ]
}
```

- [ ] **Step 2: Run to verify the test passes already**

Run: `cd packages/secubox-droplet && bats tests/test_dropletctl.bats`
Expected: `10 tests, 0 failures`. The `upsert_toml_site` from Task 3 already handles the idempotency via its regex substitution + `rsync --delete` handles the overwrite. This test pins the behavior so future refactors don't regress.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-droplet/tests/test_dropletctl.bats
git commit -m "test(droplet): pin idempotent re-publish behavior (ref #196)"
```

---

## Task 7: remove subcommand

**Files:**
- Modify: `packages/secubox-droplet/sbin/dropletctl`
- Modify: `packages/secubox-droplet/tests/test_dropletctl.bats`

- [ ] **Step 1: Add failing test for remove after publish**

Append to `packages/secubox-droplet/tests/test_dropletctl.bats`:

```bash
@test "remove deletes docroot, TOML entry, and calls metablogizerctl unpublish + delete" {
    make_html "$TMP/page.html"
    run "$DROPLETCTL" publish "$TMP/page.html" doomed mydomain.test
    [ "$status" -eq 0 ]
    [ -d "$SITES_DIR/doomed" ]
    grep -q '^\[sites\.doomed\]' "$TOML_PATH"

    # Reset stub log so we only see remove's calls.
    : > "$STUB_LOG"
    run "$DROPLETCTL" remove doomed
    [ "$status" -eq 0 ]
    [[ "$output" =~ "[OK]" ]]
    [ ! -d "$SITES_DIR/doomed" ]
    ! grep -q '^\[sites\.doomed\]' "$TOML_PATH"
    grep -q "metablogizerctl site unpublish doomed" "$STUB_LOG"
    grep -q "metablogizerctl site delete doomed" "$STUB_LOG"
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd packages/secubox-droplet && bats tests/test_dropletctl.bats`
Expected: 11 tests, 1 failure (`unknown subcommand: remove`).

- [ ] **Step 3: Implement cmd_remove + TOML delete helper + dispatch**

In `packages/secubox-droplet/sbin/dropletctl`, add this function above the `case` block:

```bash
cmd_remove() {
    local name_raw="${1:-}"
    if [[ -z "$name_raw" ]]; then
        echo "[ERROR] Usage: dropletctl remove <name>" >&2
        exit 1
    fi
    local name; name="$(sanitize_name "$name_raw")"
    if [[ -z "$name" ]]; then
        echo "[ERROR] Invalid name '$name_raw'" >&2
        exit 2
    fi

    if ! command -v metablogizerctl >/dev/null 2>&1; then
        log_error "metablogizerctl not found — install secubox-metablogizer"
        exit 4
    fi
    metablogizerctl site unpublish "$name" || true
    metablogizerctl site delete "$name"    || true

    rm -rf "$SITES_DIR/$name"
    remove_toml_site "$name"
    log_ok "Removed: $name"
}

# Drop the [sites.<name>] block from droplet.toml. No-op if not present.
remove_toml_site() {
    local name="$1"
    [[ -e "$TOML_PATH" ]] || return 0
    python3 - "$TOML_PATH" "$name" <<'PY'
import sys, re, os, tempfile
path, name = sys.argv[1:]
with open(path) as f:
    content = f.read()
pattern = re.compile(
    rf'^\[sites\.{re.escape(name)}\]\s*\n(?:(?!^\[).*\n?)*',
    flags=re.MULTILINE,
)
new = pattern.sub('', content)
if new == content:
    sys.exit(0)
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or '.', prefix='.droplet.', suffix='.toml')
os.write(fd, new.encode())
os.close(fd)
os.replace(tmp, path)
PY
}
```

Add `remove)` to the dispatch `case`:

```bash
    remove)
        shift
        cmd_remove "$@"
        ;;
```

- [ ] **Step 4: Run tests to confirm all 11 pass**

Run: `cd packages/secubox-droplet && bats tests/test_dropletctl.bats`
Expected: `11 tests, 0 failures`

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-droplet/sbin/dropletctl \
        packages/secubox-droplet/tests/test_dropletctl.bats
git commit -m "feat(droplet): remove subcommand + TOML section delete (ref #196)"
```

---

## Task 8: rename subcommand

**Files:**
- Modify: `packages/secubox-droplet/sbin/dropletctl`
- Modify: `packages/secubox-droplet/tests/test_dropletctl.bats`

- [ ] **Step 1: Add failing test for rename**

Append to `packages/secubox-droplet/tests/test_dropletctl.bats`:

```bash
@test "rename moves docroot, swaps TOML entry, calls delete+publish on delegate" {
    make_html "$TMP/page.html"
    run "$DROPLETCTL" publish "$TMP/page.html" oldname mydomain.test
    [ "$status" -eq 0 ]
    [ -d "$SITES_DIR/oldname" ]

    : > "$STUB_LOG"
    run "$DROPLETCTL" rename oldname newname
    [ "$status" -eq 0 ]
    [[ "$output" =~ "[OK]" ]]
    [ ! -d "$SITES_DIR/oldname" ]
    [ -d "$SITES_DIR/newname" ]
    [ -f "$SITES_DIR/newname/index.html" ]
    ! grep -q '^\[sites\.oldname\]' "$TOML_PATH"
    grep -q '^\[sites\.newname\]' "$TOML_PATH"
    # Delegate called: delete old, then publish new.
    grep -q "metablogizerctl site delete oldname" "$STUB_LOG"
    grep -q "metablogizerctl site publish newname" "$STUB_LOG"
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd packages/secubox-droplet && bats tests/test_dropletctl.bats`
Expected: 12 tests, 1 failure (`unknown subcommand: rename`).

- [ ] **Step 3: Implement cmd_rename + dispatch**

In `packages/secubox-droplet/sbin/dropletctl`, add this function above the `case` block:

```bash
cmd_rename() {
    local old_raw="${1:-}" new_raw="${2:-}"
    if [[ -z "$old_raw" ]] || [[ -z "$new_raw" ]]; then
        echo "[ERROR] Usage: dropletctl rename <old> <new>" >&2
        exit 1
    fi
    local old new
    old="$(sanitize_name "$old_raw")"
    new="$(sanitize_name "$new_raw")"
    if [[ -z "$old" ]] || [[ -z "$new" ]]; then
        echo "[ERROR] Invalid name(s): '$old_raw' or '$new_raw'" >&2
        exit 2
    fi
    if [[ ! -d "$SITES_DIR/$old" ]]; then
        echo "[ERROR] not found: $old" >&2
        exit 1
    fi

    # Read old domain so the new site keeps the same default unless overridden.
    local domain
    domain=$(grep -A2 "^\[sites\.$old\]" "$TOML_PATH" 2>/dev/null \
        | grep -E '^domain\s*=' | head -1 \
        | sed -E 's/^domain\s*=\s*"?([^"]*)"?\s*$/\1/')
    domain="${domain:-$(default_domain)}"

    if ! command -v metablogizerctl >/dev/null 2>&1; then
        log_error "metablogizerctl not found — install secubox-metablogizer"
        exit 4
    fi

    mv "$SITES_DIR/$old" "$SITES_DIR/$new"
    remove_toml_site "$old"
    # Compute new domain by replacing the leading <old>. prefix if present, else use original.
    local new_domain="$domain"
    if [[ "$domain" == "${old}."* ]]; then
        new_domain="${new}.${domain#*.}"
    fi
    upsert_toml_site "$new" "$new_domain" "static"

    metablogizerctl site delete "$old"  || true
    metablogizerctl site publish "$new" || {
        log_error "metablogizerctl failed for $new"
        exit 5
    }
    log_ok "Renamed: $old -> $new"
}
```

Add `rename)` to dispatch:

```bash
    rename)
        shift
        cmd_rename "$@"
        ;;
```

- [ ] **Step 4: Run tests to confirm all 12 pass**

Run: `cd packages/secubox-droplet && bats tests/test_dropletctl.bats`
Expected: `12 tests, 0 failures`

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-droplet/sbin/dropletctl \
        packages/secubox-droplet/tests/test_dropletctl.bats
git commit -m "feat(droplet): rename subcommand (ref #196)"
```

---

## Task 9: list subcommand

**Files:**
- Modify: `packages/secubox-droplet/sbin/dropletctl`
- Modify: `packages/secubox-droplet/tests/test_dropletctl.bats`

- [ ] **Step 1: Add failing test for list**

Append to `packages/secubox-droplet/tests/test_dropletctl.bats`:

```bash
@test "list prints one row per [sites.<name>] in droplet.toml" {
    make_html "$TMP/page.html"
    run "$DROPLETCTL" publish "$TMP/page.html" first mydomain.test
    [ "$status" -eq 0 ]
    run "$DROPLETCTL" publish "$TMP/page.html" second mydomain.test
    [ "$status" -eq 0 ]

    run "$DROPLETCTL" list
    [ "$status" -eq 0 ]
    [[ "$output" =~ "first" ]]
    [[ "$output" =~ "first.mydomain.test" ]]
    [[ "$output" =~ "second" ]]
    [[ "$output" =~ "second.mydomain.test" ]]
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd packages/secubox-droplet && bats tests/test_dropletctl.bats`
Expected: 13 tests, 1 failure (`unknown subcommand: list`).

- [ ] **Step 3: Implement cmd_list + dispatch**

In `packages/secubox-droplet/sbin/dropletctl`, add this function above the `case` block:

```bash
cmd_list() {
    [[ -r "$TOML_PATH" ]] || { echo "(no droplets)"; return 0; }
    python3 - "$TOML_PATH" <<'PY'
import sys, re
path = sys.argv[1]
with open(path) as f:
    content = f.read()
# Capture [sites.<name>] then the immediate `domain = "..."` line in its block.
section_re = re.compile(r'^\[sites\.([^\]]+)\]\s*\n((?:(?!^\[).*\n?)*)', re.MULTILINE)
for m in section_re.finditer(content):
    name = m.group(1)
    body = m.group(2)
    dm = re.search(r'^domain\s*=\s*"?([^"\n]+)"?', body, re.MULTILINE)
    domain = dm.group(1).strip() if dm else "?"
    print(f"{name:<30s} [ON]  https://{domain}/")
PY
}
```

Add `list)` to dispatch:

```bash
    list)
        cmd_list
        ;;
```

- [ ] **Step 4: Run tests to confirm all 13 pass**

Run: `cd packages/secubox-droplet && bats tests/test_dropletctl.bats`
Expected: `13 tests, 0 failures`

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-droplet/sbin/dropletctl \
        packages/secubox-droplet/tests/test_dropletctl.bats
git commit -m "feat(droplet): list subcommand (ref #196)"
```

---

## Task 10: Debian packaging (rules + control + changelog)

**Files:**
- Modify: `packages/secubox-droplet/debian/rules`
- Modify: `packages/secubox-droplet/debian/control`
- Modify: `packages/secubox-droplet/debian/changelog`

- [ ] **Step 1: Add the install block in `debian/rules`**

Append to the existing `override_dh_auto_install:` target (after the last `cp` line):

```make
	# Install the dropletctl CLI to /usr/sbin/ (new in 1.1.0).
	install -d debian/secubox-droplet/usr/sbin
	install -m 0755 sbin/dropletctl debian/secubox-droplet/usr/sbin/dropletctl
```

- [ ] **Step 2: Add the metablogizer dependency in `debian/control`**

Replace the `Depends:` line:

```
Depends: ${misc:Depends}, secubox-core (>= 1.0), python3-uvicorn | python3-pip, python3-aiofiles, secubox-metablogizer (>= 1.1)
```

- [ ] **Step 3: Bump the changelog**

Prepend to `packages/secubox-droplet/debian/changelog`:

```
secubox-droplet (1.1.0-1~bookworm1) bookworm; urgency=medium

  * Add dropletctl CLI at /usr/sbin/dropletctl (port from OpenWrt
    secubox-app-droplet 1.0.0). Subcommands: publish, list, remove,
    rename. Static-only (HTML / ZIP / tarball). Delegates HTTP-facing
    work (nginx vhost, HAProxy ACL, mitmproxy route) to
    metablogizerctl site publish.
  * Depends: secubox-metablogizer (>= 1.1) — runtime dependency for
    publish/unpublish/delete.
  * Closes: #196

 -- Gerald KERMA <devel@cybermind.fr>  Mon, 18 May 2026 09:00:00 +0200

```

(The trailing blank line is required — preserve the existing changelog below it.)

- [ ] **Step 4: Sanity-check the build manifest**

Run: `cd packages/secubox-droplet && dpkg-buildpackage -us -uc -b 2>&1 | tail -20`
Expected: build succeeds; the manifest line lists `usr/sbin/dropletctl` (search the build output for `dropletctl`).

If the build host doesn't have the chroot, just lint:
Run: `cd packages/secubox-droplet && dpkg-checkbuilddeps`
Expected: no missing deps; if any, install them.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-droplet/debian/rules \
        packages/secubox-droplet/debian/control \
        packages/secubox-droplet/debian/changelog
git commit -m "build(droplet): ship dropletctl + Depends: metablogizer, bump to 1.1.0 (ref #196)"
```

---

## Task 11: lint + final test sweep

**Files:**
- Touch: nothing — pure verification + commit gate

- [ ] **Step 1: bash syntax check**

Run: `bash -n packages/secubox-droplet/sbin/dropletctl`
Expected: exit 0, no output.

- [ ] **Step 2: shellcheck**

Run: `shellcheck packages/secubox-droplet/sbin/dropletctl packages/secubox-droplet/tests/fixtures/bin/metablogizerctl packages/secubox-droplet/tests/fixtures/bin/logger`
Expected: exit 0. If shellcheck flags items: fix them inline and re-run. Common acceptable disables: `# shellcheck disable=SC2155` for `local x="$(…)"` patterns where capturing exit code isn't needed.

- [ ] **Step 3: full bats sweep**

Run: `cd packages/secubox-droplet && bats tests/test_dropletctl.bats`
Expected: `13 tests, 0 failures`

- [ ] **Step 4: confirm git tree is clean**

Run: `git status -s`
Expected: empty output (no uncommitted changes).

- [ ] **Step 5: commit a trivial CHANGELOG note marker if shellcheck required any disable comments**

(Skip if Step 2 was clean.) Otherwise:

```bash
git add packages/secubox-droplet/sbin/dropletctl
git commit -m "chore(droplet): shellcheck-clean dropletctl (ref #196)"
```

- [ ] **Step 6: Final sanity — print the diff stat**

Run: `git diff --stat origin/master..HEAD`
Expected: ~3 source files (dropletctl + helpers.bash + test_dropletctl.bats), 2 stub bin files, 3 debian/ files modified. Total around +500 / −10 lines.

---

## Hardware deploy (deferred, post-merge)

Not part of this plan. Once PR merges to master, deploy on `gk2` (192.168.1.200) per spec §"Deploy path on gk2":

```bash
cd packages/secubox-droplet
dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b
scp ../secubox-droplet_1.1.0-1~bookworm1_all.deb root@admin.gk2.secubox.in:/tmp/
ssh root@admin.gk2.secubox.in 'apt install /tmp/secubox-droplet_1.1.0-1~bookworm1_all.deb'

# Smoke test:
ssh root@admin.gk2.secubox.in 'which dropletctl'   # /usr/sbin/dropletctl
ssh root@admin.gk2.secubox.in 'echo "<h1>smoke</h1>" > /tmp/smoke.html && \
    dropletctl publish /tmp/smoke.html smoke gk2.secubox.in'
curl -sSI https://smoke.gk2.secubox.in/   # expect 200 OK
ssh root@admin.gk2.secubox.in 'dropletctl remove smoke'
```

If the live deploy uncovers issues, file a fix-followup against this branch before opening the PR for review.
