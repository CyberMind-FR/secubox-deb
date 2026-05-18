#!/usr/bin/env bats

load helpers

@test "dropletctl with no args prints usage" {
    run "$DROPLETCTL"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Usage:" ]] || [[ "$output" =~ "dropletctl" ]]
}

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
