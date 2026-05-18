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
