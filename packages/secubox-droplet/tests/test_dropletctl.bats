#!/usr/bin/env bats

load helpers

@test "dropletctl with no args prints usage" {
    run "$DROPLETCTL"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Usage:" ]] || [[ "$output" =~ "dropletctl" ]]
}
