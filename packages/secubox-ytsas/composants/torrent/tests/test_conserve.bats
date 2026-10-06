#!/usr/bin/env bats
# secubox-torrent-conserve routing tests (issue #967): audio (mp3/flac/…)
# must go to Lyrion, video keeps going to PeerTube, unclassifiable media
# never goes to either, and an absent partner tool leaves the item queued
# instead of losing it or misrouting it.

bats_require_minimum_version 1.5.0

load helpers

@test "empty queue: script exits cleanly, does nothing" {
    run "$CONSERVE"
    [ "$status" -eq 0 ]
}

@test "mp3 is routed to lyrion, never touches peertubectl" {
    make_file "$TMP/dl/song.mp3"
    queue_item "ih-mp3" "Song" "$TMP/dl/song.mp3"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    grep -q "lyrionctl ingest $TMP/dl/song.mp3" "$STUB_LOG"
    run ! grep -q "peertubectl" "$STUB_LOG"

    [ ! -f "$SECUBOX_TORRENT_DATA/.conserve-queue/ih-mp3.json" ]
    [ "$(result_status ih-mp3)" = "done" ]
}

@test "flac is routed to lyrion, never touches peertubectl" {
    make_file "$TMP/dl/album.flac"
    queue_item "ih-flac" "Album" "$TMP/dl/album.flac"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    grep -q "lyrionctl ingest $TMP/dl/album.flac" "$STUB_LOG"
    run ! grep -q "peertubectl" "$STUB_LOG"

    [ ! -f "$SECUBOX_TORRENT_DATA/.conserve-queue/ih-flac.json" ]
    [ "$(result_status ih-flac)" = "done" ]
}

@test "other common audio extensions (ogg/opus/m4a/wav) also route to lyrion" {
    for ext in ogg opus m4a wav; do
        make_file "$TMP/dl/track.$ext"
        queue_item "ih-$ext" "Track" "$TMP/dl/track.$ext"
    done

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    for ext in ogg opus m4a wav; do
        grep -q "lyrionctl ingest $TMP/dl/track.$ext" "$STUB_LOG"
    done
    run ! grep -q "peertubectl" "$STUB_LOG"
}

@test "mp4 video still goes to peertube, never touches lyrionctl" {
    make_file "$TMP/dl/movie.mp4"
    queue_item "ih-mp4" "Movie" "$TMP/dl/movie.mp4"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    grep -q "peertubectl upload $TMP/dl/movie.mp4" "$STUB_LOG"
    run ! grep -q "lyrionctl" "$STUB_LOG"

    [ ! -f "$SECUBOX_TORRENT_DATA/.conserve-queue/ih-mp4.json" ]
    [ "$(result_status ih-mp4)" = "done" ]
}

@test "unrecognised extension is not routed anywhere" {
    make_file "$TMP/dl/mystery.xyz"
    queue_item "ih-xyz" "Mystery" "$TMP/dl/mystery.xyz"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    run ! grep -q "peertubectl" "$STUB_LOG"
    run ! grep -q "lyrionctl" "$STUB_LOG"

    # Terminal error recorded and dequeued — re-running would never change
    # the verdict for a genuinely unrecognised extension.
    [ ! -f "$SECUBOX_TORRENT_DATA/.conserve-queue/ih-xyz.json" ]
    [ "$(result_status ih-xyz)" = "error" ]
}

@test "extensionless file is not routed anywhere" {
    make_file "$TMP/dl/noext"
    queue_item "ih-noext" "NoExt" "$TMP/dl/noext"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    run ! grep -q "peertubectl" "$STUB_LOG"
    run ! grep -q "lyrionctl" "$STUB_LOG"
    [ "$(result_status ih-noext)" = "error" ]
}

@test "lyrionctl absent: mp3 item stays queued, not lost, not diverted to peertube" {
    mv "$BINDIR/lyrionctl" "$TMP/lyrionctl.hidden"

    make_file "$TMP/dl/song.mp3"
    queue_item "ih-nolyr" "Song" "$TMP/dl/song.mp3"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    run ! grep -q "peertubectl" "$STUB_LOG"
    # Request untouched — no result written, nothing removed from the queue.
    [ -f "$SECUBOX_TORRENT_DATA/.conserve-queue/ih-nolyr.json" ]
    [ ! -f "$SECUBOX_TORRENT_DATA/.conserve-results/ih-nolyr.json" ]

    mv "$TMP/lyrionctl.hidden" "$BINDIR/lyrionctl"
}

@test "lyrionctl present but reports ok:false: mp3 item stays queued" {
    export STUB_LYRIONCTL_FAIL=1

    make_file "$TMP/dl/song.mp3"
    queue_item "ih-lyrfail" "Song" "$TMP/dl/song.mp3"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    grep -q "lyrionctl ingest $TMP/dl/song.mp3" "$STUB_LOG"
    run ! grep -q "peertubectl" "$STUB_LOG"
    [ -f "$SECUBOX_TORRENT_DATA/.conserve-queue/ih-lyrfail.json" ]
    [ ! -f "$SECUBOX_TORRENT_DATA/.conserve-results/ih-lyrfail.json" ]
}

@test "peertubectl absent: mp4 item stays queued (existing degrade behaviour preserved)" {
    mv "$BINDIR/peertubectl" "$TMP/peertubectl.hidden"

    make_file "$TMP/dl/movie.mp4"
    queue_item "ih-nopt" "Movie" "$TMP/dl/movie.mp4"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    [ -f "$SECUBOX_TORRENT_DATA/.conserve-queue/ih-nopt.json" ]
    [ ! -f "$SECUBOX_TORRENT_DATA/.conserve-results/ih-nopt.json" ]

    mv "$TMP/peertubectl.hidden" "$BINDIR/peertubectl"
}

@test "peertubectl absent does NOT block an mp3 in the same batch (audio routes independently)" {
    mv "$BINDIR/peertubectl" "$TMP/peertubectl.hidden"

    make_file "$TMP/dl/song.mp3"
    queue_item "ih-mixed" "Song" "$TMP/dl/song.mp3"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    grep -q "lyrionctl ingest $TMP/dl/song.mp3" "$STUB_LOG"
    [ ! -f "$SECUBOX_TORRENT_DATA/.conserve-queue/ih-mixed.json" ]
    [ "$(result_status ih-mixed)" = "done" ]

    mv "$TMP/peertubectl.hidden" "$BINDIR/peertubectl"
}

@test "mkv with a video stream (ffprobe available) goes to peertube" {
    export SECUBOX_FFPROBE_BIN="$BINDIR/ffprobe-video"
    make_file "$TMP/dl/clip.mkv"
    queue_item "ih-mkv-v" "Clip" "$TMP/dl/clip.mkv"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    grep -q "peertubectl upload $TMP/dl/clip.mkv" "$STUB_LOG"
    run ! grep -q "lyrionctl" "$STUB_LOG"
}

@test "mkv without a video stream (ffprobe available, audio-only) goes to lyrion" {
    export SECUBOX_FFPROBE_BIN="$BINDIR/ffprobe-audio"
    make_file "$TMP/dl/audiorip.mkv"
    queue_item "ih-mkv-a" "AudioRip" "$TMP/dl/audiorip.mkv"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    grep -q "lyrionctl ingest $TMP/dl/audiorip.mkv" "$STUB_LOG"
    run ! grep -q "peertubectl" "$STUB_LOG"
}

@test "mkv with no ffprobe available defaults to peertube (preserves existing video path)" {
    # SECUBOX_FFPROBE_BIN points at a nonexistent binary by default (helpers.bash).
    make_file "$TMP/dl/unknown.mkv"
    queue_item "ih-mkv-noprobe" "Unknown" "$TMP/dl/unknown.mkv"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    grep -q "peertubectl upload $TMP/dl/unknown.mkv" "$STUB_LOG"
    run ! grep -q "lyrionctl" "$STUB_LOG"
}

@test "video destination is declaratively overridable via torrent.toml" {
    printf '[conserve]\nvideo = "none"\naudio = "lyrion"\n' > "$SECUBOX_TORRENT_TOML"
    make_file "$TMP/dl/movie.mp4"
    queue_item "ih-cfgvideo" "Movie" "$TMP/dl/movie.mp4"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    run ! grep -q "peertubectl" "$STUB_LOG"
    run ! grep -q "lyrionctl" "$STUB_LOG"
    # "none" is an intentional, permanent operator opt-out — it terminally
    # skips (dequeues + records) rather than retrying forever, which would
    # otherwise grow the queue dir without bound.
    [ ! -f "$SECUBOX_TORRENT_DATA/.conserve-queue/ih-cfgvideo.json" ]
    [ "$(result_status ih-cfgvideo)" = "skipped" ]
}

@test "[conserve] section-awareness: a same-named key under another section does not leak in" {
    # video/audio would collide with a flat (non-section-aware) TOML reader
    # if this ever appeared above [conserve] in the file.
    printf '[decoy]\naudio = "peertube"\n\n[conserve]\naudio = "lyrion"\n' > "$SECUBOX_TORRENT_TOML"
    make_file "$TMP/dl/song.mp3"
    queue_item "ih-secaware" "Song" "$TMP/dl/song.mp3"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    grep -q "lyrionctl ingest $TMP/dl/song.mp3" "$STUB_LOG"
    run ! grep -q "peertubectl" "$STUB_LOG"
}

@test "missing source file is a terminal error like before" {
    queue_item "ih-missing" "Ghost" "$TMP/dl/does-not-exist.mp3"

    run "$CONSERVE"
    [ "$status" -eq 0 ]

    run ! grep -q "peertubectl" "$STUB_LOG"
    run ! grep -q "lyrionctl" "$STUB_LOG"
    [ ! -f "$SECUBOX_TORRENT_DATA/.conserve-queue/ih-missing.json" ]
    [ "$(result_status ih-missing)" = "error" ]
}
