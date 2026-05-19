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
