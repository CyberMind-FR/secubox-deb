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

@test "rename fails when target name already exists" {
    make_html "$TMP/page.html"
    run "$DROPLETCTL" publish "$TMP/page.html" srcsite mydomain.test
    [ "$status" -eq 0 ]
    run "$DROPLETCTL" publish "$TMP/page.html" dstsite mydomain.test
    [ "$status" -eq 0 ]

    run "$DROPLETCTL" rename srcsite dstsite
    [ "$status" -eq 1 ]
    [[ "$output" =~ "already exists" ]]
    # Both docroots still present — no half-renamed state.
    [ -d "$SITES_DIR/srcsite" ]
    [ -d "$SITES_DIR/dstsite" ]
}

@test "rename fails when old and new are identical after sanitization" {
    make_html "$TMP/page.html"
    run "$DROPLETCTL" publish "$TMP/page.html" same mydomain.test
    [ "$status" -eq 0 ]

    # 'Same' sanitizes to 'same' — same as the existing 'same'.
    run "$DROPLETCTL" rename Same same
    [ "$status" -eq 2 ]
    [[ "$output" =~ "identical after sanitization" ]]
    # Original still intact.
    [ -d "$SITES_DIR/same" ]
}

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
