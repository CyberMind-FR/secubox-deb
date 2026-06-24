// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: R4 media reverse-catcher (#736)
//
// In R4 / analyst mode every flow is MITM'd (media is no longer spliced), so the
// engine can SEE the real media URLs a page fetches — HLS/DASH manifests and
// direct audio/video responses. This records those URLs (NEVER the bodies) to an
// append-only JSONL discovery log that the mediaflow "Discovered Media" view
// reads and offers to CLONE (yt-dlp / ffmpeg). Consented R3/R4 demonstration on
// the operator's own traffic; the transparency banner already discloses the MITM.
//
// Pure standard library.
package main

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
)

// mediaCatchPath is the append-only JSONL discovery log (one record per line).
// /run is tmpfs — discovery is live/ephemeral; the durable artefact is the clone
// LIBRARY, which mediaflow owns. The four worker processes append concurrently;
// every record line is kept < PIPE_BUF (4096) so O_APPEND writes are atomic
// across processes (no interleaving / torn lines).
const mediaCatchPath = "/run/secubox/media-catch.jsonl"

// mediaCatchMaxSeen caps the per-worker dedup set (media chunk URLs are many);
// when full it is dropped and rebuilt so memory can't grow without bound.
const mediaCatchMaxSeen = 8192

type mediaRecord struct {
	TS      int64  `json:"ts"`
	Client  string `json:"client"`
	Host    string `json:"host"`
	URL     string `json:"url"`
	Referer string `json:"referer,omitempty"`
	Kind    string `json:"kind"` // manifest | video | audio
	Type    string `json:"ctype,omitempty"`
	Bytes   int64  `json:"bytes"`
}

type mediaCatcher struct {
	enabled bool
	mu      sync.Mutex
	seen    map[string]struct{}
	f       *os.File
}

func newMediaCatcher(enabled bool) *mediaCatcher {
	mc := &mediaCatcher{enabled: enabled, seen: make(map[string]struct{})}
	if enabled {
		if f, err := os.OpenFile(mediaCatchPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			mc.f = f
		}
	}
	return mc
}

// mediaKind classifies a response as cloneable media, or "" if it is not. It
// reads the URL path (manifest / known media extensions / googlevideo's
// videoplayback) and the Content-Type. HTML and non-media types return "".
func mediaKind(path, ctype string) string {
	p := strings.ToLower(path)
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	ct := strings.ToLower(ctype)
	switch {
	case strings.HasSuffix(p, ".m3u8"), strings.Contains(ct, "mpegurl"):
		return "manifest"
	case strings.HasSuffix(p, ".mpd"), strings.Contains(ct, "dash+xml"):
		return "manifest"
	case strings.Contains(p, "/videoplayback"): // youtube / googlevideo
		return "video"
	case strings.HasPrefix(ct, "video/"):
		return "video"
	case strings.HasPrefix(ct, "audio/"):
		return "audio"
	case strings.HasSuffix(p, ".mp4"), strings.HasSuffix(p, ".webm"), strings.HasSuffix(p, ".mkv"), strings.HasSuffix(p, ".mov"):
		return "video"
	case strings.HasSuffix(p, ".mp3"), strings.HasSuffix(p, ".m4a"), strings.HasSuffix(p, ".aac"), strings.HasSuffix(p, ".opus"), strings.HasSuffix(p, ".flac"):
		return "audio"
	}
	return ""
}

// dedupKey collapses a media URL to host + path WITHOUT the query, so the many
// byte-range / itag chunk requests for one stream record as a single line.
func dedupKey(host, path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return host + path
}

// record appends one media discovery record (deduped per worker). Best-effort:
// any error is swallowed (a media catcher must NEVER affect the proxied flow).
func (mc *mediaCatcher) record(client, host, url, path, referer, kind, ctype string, size int64) {
	if mc == nil || !mc.enabled || mc.f == nil {
		return
	}
	key := dedupKey(host, path)
	mc.mu.Lock()
	if _, ok := mc.seen[key]; ok {
		mc.mu.Unlock()
		return
	}
	if len(mc.seen) >= mediaCatchMaxSeen {
		mc.seen = make(map[string]struct{})
	}
	mc.seen[key] = struct{}{}
	f := mc.f
	mc.mu.Unlock()

	b, err := json.Marshal(mediaRecord{
		TS: time.Now().Unix(), Client: client, Host: host, URL: url,
		Referer: referer, Kind: kind, Type: ctype, Bytes: size,
	})
	if err != nil {
		return
	}
	b = append(b, '\n')
	if len(b) <= 4096 { // keep the append atomic across the 4 worker processes
		_, _ = f.Write(b)
	}
}
