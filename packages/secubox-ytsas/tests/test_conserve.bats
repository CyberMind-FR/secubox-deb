#!/usr/bin/env bats
# secubox-ytsas-conserve routing tests (issue #967): audio (mp3/flac/…) must
# go to Lyrion, video keeps going to PeerTube, unclassifiable media never
# goes to either, and an absent partner tool leaves the item queued instead
# of losing it or misrouting it.

load helpers

@test "empty queue: script exits cleanly, does nothing" {
    run "$CONSERVE"
    [ "$status" -eq 0 ]
}

@test "mp3 is routed to lyrion, never touches peertubectl" {
    make_file "$TMP/dl/song.mp3"
    queue_item "id-mp3" "Song" "$TMP/dl/song.mp3"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    grep -q "lyrionctl ingest $TMP/dl/song.mp3" "$STUB_LOG"
    ! grep -q "peertubectl" "$STUB_LOG"

    [ ! -f "$SECUBOX_YTSAS_DATA/.conserve-queue/id-mp3.json" ]
    [ "$(result_status id-mp3)" = "done" ]
}

@test "flac is routed to lyrion, never touches peertubectl" {
    make_file "$TMP/dl/album.flac"
    queue_item "id-flac" "Album" "$TMP/dl/album.flac"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    grep -q "lyrionctl ingest $TMP/dl/album.flac" "$STUB_LOG"
    ! grep -q "peertubectl" "$STUB_LOG"

    [ ! -f "$SECUBOX_YTSAS_DATA/.conserve-queue/id-flac.json" ]
    [ "$(result_status id-flac)" = "done" ]
}

@test "other common audio extensions (ogg/opus/m4a/wav) also route to lyrion" {
    for ext in ogg opus m4a wav; do
        make_file "$TMP/dl/track.$ext"
        queue_item "id-$ext" "Track" "$TMP/dl/track.$ext"
    done

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    for ext in ogg opus m4a wav; do
        grep -q "lyrionctl ingest $TMP/dl/track.$ext" "$STUB_LOG"
    done
    ! grep -q "peertubectl" "$STUB_LOG"
}

@test "mp4 video still goes to peertube, never touches lyrionctl" {
    make_file "$TMP/dl/movie.mp4"
    queue_item "id-mp4" "Movie" "$TMP/dl/movie.mp4"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    grep -q "peertubectl upload $TMP/dl/movie.mp4" "$STUB_LOG"
    ! grep -q "lyrionctl" "$STUB_LOG"

    [ ! -f "$SECUBOX_YTSAS_DATA/.conserve-queue/id-mp4.json" ]
    [ "$(result_status id-mp4)" = "done" ]
}

@test "unrecognised extension is not routed anywhere" {
    make_file "$TMP/dl/mystery.xyz"
    queue_item "id-xyz" "Mystery" "$TMP/dl/mystery.xyz"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    ! grep -q "peertubectl" "$STUB_LOG"
    ! grep -q "lyrionctl" "$STUB_LOG"

    # Terminal error recorded and dequeued — re-running would never change
    # the verdict for a genuinely unrecognised extension.
    [ ! -f "$SECUBOX_YTSAS_DATA/.conserve-queue/id-xyz.json" ]
    [ "$(result_status id-xyz)" = "error" ]
}

@test "extensionless file is not routed anywhere" {
    make_file "$TMP/dl/noext"
    queue_item "id-noext" "NoExt" "$TMP/dl/noext"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    ! grep -q "peertubectl" "$STUB_LOG"
    ! grep -q "lyrionctl" "$STUB_LOG"
    [ "$(result_status id-noext)" = "error" ]
}

@test "lyrionctl absent: mp3 item stays queued, not lost, not diverted to peertube" {
    mv "$BINDIR/lyrionctl" "$TMP/lyrionctl.hidden"

    make_file "$TMP/dl/song.mp3"
    queue_item "id-nolyr" "Song" "$TMP/dl/song.mp3"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    ! grep -q "peertubectl" "$STUB_LOG"
    # Request untouched — no result written, nothing removed from the queue.
    [ -f "$SECUBOX_YTSAS_DATA/.conserve-queue/id-nolyr.json" ]
    [ ! -f "$SECUBOX_YTSAS_DATA/.conserve-results/id-nolyr.json" ]

    mv "$TMP/lyrionctl.hidden" "$BINDIR/lyrionctl"
}

@test "lyrionctl present but reports ok:false: mp3 item stays queued" {
    export STUB_LYRIONCTL_FAIL=1

    make_file "$TMP/dl/song.mp3"
    queue_item "id-lyrfail" "Song" "$TMP/dl/song.mp3"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    grep -q "lyrionctl ingest $TMP/dl/song.mp3" "$STUB_LOG"
    ! grep -q "peertubectl" "$STUB_LOG"
    [ -f "$SECUBOX_YTSAS_DATA/.conserve-queue/id-lyrfail.json" ]
    [ ! -f "$SECUBOX_YTSAS_DATA/.conserve-results/id-lyrfail.json" ]
}

@test "peertubectl absent: mp4 item stays queued (existing degrade behaviour preserved)" {
    mv "$BINDIR/peertubectl" "$TMP/peertubectl.hidden"

    make_file "$TMP/dl/movie.mp4"
    queue_item "id-nopt" "Movie" "$TMP/dl/movie.mp4"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    [ -f "$SECUBOX_YTSAS_DATA/.conserve-queue/id-nopt.json" ]
    [ ! -f "$SECUBOX_YTSAS_DATA/.conserve-results/id-nopt.json" ]

    mv "$TMP/peertubectl.hidden" "$BINDIR/peertubectl"
}

@test "peertubectl absent does NOT block an mp3 in the same batch (audio routes independently)" {
    mv "$BINDIR/peertubectl" "$TMP/peertubectl.hidden"

    make_file "$TMP/dl/song.mp3"
    queue_item "id-mixed" "Song" "$TMP/dl/song.mp3"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    grep -q "lyrionctl ingest $TMP/dl/song.mp3" "$STUB_LOG"
    [ ! -f "$SECUBOX_YTSAS_DATA/.conserve-queue/id-mixed.json" ]
    [ "$(result_status id-mixed)" = "done" ]

    mv "$TMP/peertubectl.hidden" "$BINDIR/peertubectl"
}

@test "mkv with a video stream (ffprobe available) goes to peertube" {
    export SECUBOX_FFPROBE_BIN="$BINDIR/ffprobe-video"
    make_file "$TMP/dl/clip.mkv"
    queue_item "id-mkv-v" "Clip" "$TMP/dl/clip.mkv"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    grep -q "peertubectl upload $TMP/dl/clip.mkv" "$STUB_LOG"
    ! grep -q "lyrionctl" "$STUB_LOG"
}

@test "mkv without a video stream (ffprobe available, audio-only) goes to lyrion" {
    export SECUBOX_FFPROBE_BIN="$BINDIR/ffprobe-audio"
    make_file "$TMP/dl/audiorip.mkv"
    queue_item "id-mkv-a" "AudioRip" "$TMP/dl/audiorip.mkv"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    grep -q "lyrionctl ingest $TMP/dl/audiorip.mkv" "$STUB_LOG"
    ! grep -q "peertubectl" "$STUB_LOG"
}

@test "mkv with no ffprobe available defaults to peertube (preserves existing video path)" {
    # SECUBOX_FFPROBE_BIN points at a nonexistent binary by default (helpers.bash).
    make_file "$TMP/dl/unknown.mkv"
    queue_item "id-mkv-noprobe" "Unknown" "$TMP/dl/unknown.mkv"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    grep -q "peertubectl upload $TMP/dl/unknown.mkv" "$STUB_LOG"
    ! grep -q "lyrionctl" "$STUB_LOG"
}

@test "video destination is declaratively overridable via ytsas.toml" {
    printf '[conserve]\nvideo = "none"\naudio = "lyrion"\n' > "$SECUBOX_YTSAS_TOML"
    make_file "$TMP/dl/movie.mp4"
    queue_item "id-cfgvideo" "Movie" "$TMP/dl/movie.mp4"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    ! grep -q "peertubectl" "$STUB_LOG"
    ! grep -q "lyrionctl" "$STUB_LOG"
    # "none" leaves it queued (an intentional operator opt-out), not errored.
    [ -f "$SECUBOX_YTSAS_DATA/.conserve-queue/id-cfgvideo.json" ]
}

@test "missing source file is a terminal error like before" {
    queue_item "id-missing" "Ghost" "$TMP/dl/does-not-exist.mp3"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    ! grep -q "peertubectl" "$STUB_LOG"
    ! grep -q "lyrionctl" "$STUB_LOG"
    [ ! -f "$SECUBOX_YTSAS_DATA/.conserve-queue/id-missing.json" ]
    [ "$(result_status id-missing)" = "error" ]
}
