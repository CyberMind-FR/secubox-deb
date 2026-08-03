#!/usr/bin/env bash
# Shared bats helpers for secubox-torrent-conserve tests.

# REPO_ROOT = top of the git checkout. PACKAGE_ROOT = packages/secubox-torrent/.
export REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../../.." && pwd)"
export PACKAGE_ROOT="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
export CONSERVE="$PACKAGE_ROOT/sbin/secubox-torrent-conserve"

setup() {
    # Per-test temp dir; gone after teardown.
    TMP="$(mktemp -d "${BATS_TMPDIR}/torrent-conserve.XXXXXX")"
    export TMP
    export STUB_LOG="$TMP/stub.log"
    : > "$STUB_LOG"

    export SECUBOX_TORRENT_DATA="$TMP/data/torrent"
    mkdir -p "$SECUBOX_TORRENT_DATA/.conserve-queue"

    # Run as the current (non-root) test user: skip the LXC-idmap chown dance
    # entirely by pointing LXC_UID at ourselves (chown to self is a no-op).
    export SECUBOX_TORRENT_LXC_UID="$(id -u)"

    # Point the TOML reader at a scratch file the test can populate; a
    # missing file must fall back to hardcoded defaults (peertube/lyrion).
    export SECUBOX_TORRENT_TOML="$TMP/torrent.toml"

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

# queue_item <infohash> <name> <file> — drop a conserve request in the queue.
queue_item() {
    local ih="$1" name="$2" file="$3"
    jq -nc --arg ih "$ih" --arg n "$name" --arg f "$file" \
        '{infohash:$ih, name:$n, file:$f}' \
        > "$SECUBOX_TORRENT_DATA/.conserve-queue/$ih.json"
}

result_status() {
    jq -r '.status // empty' "$SECUBOX_TORRENT_DATA/.conserve-results/$1.json" 2>/dev/null
}
