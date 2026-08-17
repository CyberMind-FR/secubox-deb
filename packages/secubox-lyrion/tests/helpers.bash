#!/usr/bin/env bash
# Shared bats helpers for lyrionctl ingest tests.

export REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../../.." && pwd)"
export PACKAGE_ROOT="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
export LYRIONCTL="$PACKAGE_ROOT/sbin/lyrionctl"

setup() {
    TMP="$(mktemp -d "${BATS_TMPDIR}/lyrionctl.XXXXXX")"
    export TMP
    export STUB_LOG="$TMP/stub.log"
    : > "$STUB_LOG"

    export BINDIR="$TMP/bin"
    cp -r "$PACKAGE_ROOT/tests/fixtures/bin" "$BINDIR"
    export PATH="$BINDIR:$PATH"

    export SECUBOX_LYRION_CONFIG="$TMP/lyrion.toml"
    cat > "$SECUBOX_LYRION_CONFIG" <<EOF
[lxc]
name = "lyrion"
path = "$TMP/lxc"

[library]
path = "$TMP/music"
EOF
    # lxc_exists()/lxc_running() key off $LXC_PATH/$LXC_NAME/rootfs existing —
    # lxc_running() itself is fully stubbed via lxc-info above, but lxc_exists()
    # (checked first, before lxc_running(), if ingest ever needs it) still
    # looks at the real filesystem, so give it something to find.
    mkdir -p "$TMP/lxc/lyrion/rootfs"
}

teardown() {
    rm -rf "$TMP"
}

make_file() {
    local path="$1"
    mkdir -p "$(dirname "$path")"
    printf '%s' "${2:-fixture-content}" > "$path"
}
