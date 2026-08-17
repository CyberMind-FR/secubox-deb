#!/usr/bin/env bash
# Shared bats helpers for secubox-ytsas-conserve tests.

# REPO_ROOT = top of the git checkout. PACKAGE_ROOT = packages/secubox-ytsas/.
export REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../../.." && pwd)"
export PACKAGE_ROOT="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
export CONSERVE="$PACKAGE_ROOT/sbin/secubox-ytsas-conserve"

setup() {
    # Per-test temp dir; gone after teardown.
    TMP="$(mktemp -d "${BATS_TMPDIR}/ytsas-conserve.XXXXXX")"
    export TMP
    export STUB_LOG="$TMP/stub.log"
    : > "$STUB_LOG"

    export SECUBOX_YTSAS_DATA="$TMP/data/ytsas"
    mkdir -p "$SECUBOX_YTSAS_DATA/.conserve-queue"

    # Run as the current (non-root) test user: skip the LXC-idmap chown dance
    # entirely by pointing LXC_UID at ourselves (chown to self is a no-op).
    export SECUBOX_YTSAS_LXC_UID="$(id -u)"

    # Point the TOML reader at a scratch file the test can populate; a
    # missing file must fall back to hardcoded defaults (peertube/lyrion).
    export SECUBOX_YTSAS_TOML="$TMP/ytsas.toml"

    # PATH-shim the delegate stubs (peertubectl / lyrionctl / logger) from a
    # per-test COPY of fixtures/bin, never the shared source directory — a
    # test that hides a binary (mv-out) to simulate "not installed" must not
    # risk losing the real fixture permanently if it fails before restoring.
    export BINDIR="$TMP/bin"
    cp -r "$PACKAGE_ROOT/tests/fixtures/bin" "$BINDIR"
    export PATH="$BINDIR:$PATH"

    # Deterministic ffprobe seam for the ambiguous-container (.mkv) tests —
    # defaults to "not installed" so the fallback path is exercised unless a
    # test opts into one of the fixtures/bin/ffprobe-{video,audio} stubs.
    export SECUBOX_FFPROBE_BIN="$TMP/no-such-ffprobe"
}

teardown() {
    rm -rf "$TMP"
}

# make_file <path> — create a fixture file with placeholder content. Content
# is irrelevant for extension-based classification; only .mkv tests also
# stub ffprobe, which never reads the file (fully mocked).
make_file() {
    local path="$1"
    mkdir -p "$(dirname "$path")"
    printf 'fixture-content\n' > "$path"
}

# queue_item <id> <title> <file> — drop a conserve request in the queue.
queue_item() {
    local id="$1" title="$2" file="$3"
    jq -nc --arg id "$id" --arg t "$title" --arg f "$file" \
        '{id:$id, title:$t, file:$f}' \
        > "$SECUBOX_YTSAS_DATA/.conserve-queue/$id.json"
}

result_status() {
    jq -r '.status // empty' "$SECUBOX_YTSAS_DATA/.conserve-results/$1.json" 2>/dev/null
}
