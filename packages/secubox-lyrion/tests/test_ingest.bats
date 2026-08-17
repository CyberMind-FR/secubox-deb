#!/usr/bin/env bats
# lyrionctl ingest tests (issue #967): the Lyrion-side half of the
# torrent/ytsas conserve partner pipeline.

load helpers

@test "ingest with no LXC running returns ok:false and touches nothing" {
    export STUB_LXC_STOPPED=1
    make_file "$TMP/song.mp3"

    run "$LYRIONCTL" ingest "$TMP/song.mp3"
    [ "$status" -eq 1 ]
    [[ "$output" == *'"ok":false'* ]]

    [ ! -d "$TMP/music" ]
}

@test "ingest with a missing source file returns ok:false" {
    run "$LYRIONCTL" ingest "$TMP/does-not-exist.mp3"
    [ "$status" -eq 1 ]
    [[ "$output" == *'"ok":false'* ]]
    [[ "$output" == *"source file not found"* ]]
}

@test "ingest copies the file into [library].path/conserve and reports ok:true" {
    make_file "$TMP/song.mp3" "hello"

    run "$LYRIONCTL" ingest "$TMP/song.mp3"
    [ "$status" -eq 0 ]
    [[ "$output" == *'"ok":true'* ]]

    found="$(find "$TMP/music/conserve" -type f -name 'song.mp3')"
    [ -n "$found" ]
    [ "$(cat "$found")" = "hello" ]
}

@test "ingest nudges a rescan (best-effort curl to LMS jsonrpc)" {
    make_file "$TMP/song.mp3"

    run "$LYRIONCTL" ingest "$TMP/song.mp3"
    [ "$status" -eq 0 ]

    grep -q "jsonrpc" "$STUB_LOG"
}

@test "two different sources sharing a basename do not collide (#967 review fix)" {
    make_file "$TMP/dlA/01 - Track.mp3" "contentA"
    make_file "$TMP/dlB/01 - Track.mp3" "contentB"

    run "$LYRIONCTL" ingest "$TMP/dlA/01 - Track.mp3"
    [ "$status" -eq 0 ]
    run "$LYRIONCTL" ingest "$TMP/dlB/01 - Track.mp3"
    [ "$status" -eq 0 ]

    # Both survive, with their original distinct content — neither cp -f
    # overwrote the other despite the identical basename.
    mapfile -t found < <(find "$TMP/music/conserve" -type f -name '01 - Track.mp3' | sort)
    [ "${#found[@]}" -eq 2 ]
    c1="$(cat "${found[0]}")"
    c2="$(cat "${found[1]}")"
    { [ "$c1" = "contentA" ] && [ "$c2" = "contentB" ]; } || { [ "$c1" = "contentB" ] && [ "$c2" = "contentA" ]; }
}

@test "re-ingesting the same source path is idempotent (overwrites its own prior copy, no dupes)" {
    make_file "$TMP/song.mp3" "v1"
    run "$LYRIONCTL" ingest "$TMP/song.mp3"
    [ "$status" -eq 0 ]

    make_file "$TMP/song.mp3" "v2"
    run "$LYRIONCTL" ingest "$TMP/song.mp3"
    [ "$status" -eq 0 ]

    mapfile -t found < <(find "$TMP/music/conserve" -type f -name 'song.mp3')
    [ "${#found[@]}" -eq 1 ]
    [ "$(cat "${found[0]}")" = "v2" ]
}
