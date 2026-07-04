// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: media buffer store tests (#812)
//
// Pure standard library.
package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// lastJSONL reads path and returns the last non-empty line parsed as a JSON
// object. Fails the test on any read/parse error (the file is expected to
// exist and contain at least one valid record by the time this is called).
func lastJSONL(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 0 || lines[len(lines)-1] == "" {
		t.Fatalf("no lines in %s", path)
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &m); err != nil {
		t.Fatalf("unmarshal last line of %s: %v", path, err)
	}
	return m
}

func TestMediaBufferIsMedia(t *testing.T) {
	b := NewMediaBuffer(t.TempDir(), true, 512<<20)
	cases := []struct {
		ctype, path string
		want        bool
	}{
		{"video/mp4", "/v.mp4", true},
		{"audio/mpeg", "/a.mp3", true},
		{"application/vnd.apple.mpegurl", "/index.m3u8", true},
		{"text/html", "/page", false},
		{"application/json", "/api", false},
	}
	for _, c := range cases {
		if got := b.IsMedia(c.ctype, c.path); got != c.want {
			t.Errorf("IsMedia(%q,%q)=%v want %v", c.ctype, c.path, got, c.want)
		}
	}
}

func TestMediaBufferCaptureAndMetatag(t *testing.T) {
	root := t.TempDir()
	b := NewMediaBuffer(root, true, 10) // 10-byte ceiling
	w := b.Capture("mac1", "cdn.example", "https://cdn.example/v.mp4", "/v.mp4", "video/mp4", "down", 4)
	if w == nil {
		t.Fatal("Capture returned nil for media")
	}
	n, _ := w.Write([]byte("0123456789ABCDEF")) // 16 > 10 → truncated
	_ = n
	w.Close(16)

	// object file exists under a session dir
	var objs, metas int
	filepath.WalkDir(root, func(p string, d fs.DirEntry, _ error) error {
		if d == nil || d.IsDir() {
			return nil
		}
		if strings.HasPrefix(d.Name(), "object-") {
			objs++
		}
		if d.Name() == "media-buffer.jsonl" {
			metas++
		}
		return nil
	})
	if objs != 1 || metas != 1 {
		t.Fatalf("objs=%d metas=%d want 1/1", objs, metas)
	}

	line := lastJSONL(t, filepath.Join(root, "media-buffer.jsonl"))
	if line["truncated"] != true {
		t.Error("expected truncated=true past ceiling")
	}
	if line["direction"] != "down" || line["mac_hash"] != "mac1" {
		t.Error("metatag fields wrong")
	}
	if line["kind"] == "" {
		t.Error("kind should be set")
	}
}

func TestMediaBufferNilAndDisabledSafe(t *testing.T) {
	var nilBuf *MediaBuffer
	if nilBuf.IsMedia("video/mp4", "/v.mp4") {
		t.Error("nil MediaBuffer.IsMedia should be false, never panic")
	}
	if w := nilBuf.Capture("mac1", "h", "https://h/v.mp4", "/v.mp4", "video/mp4", "down", 1); w != nil {
		t.Error("nil MediaBuffer.Capture should return nil")
	}

	disabled := NewMediaBuffer(t.TempDir(), false, 512<<20)
	if w := disabled.Capture("mac1", "h", "https://h/v.mp4", "/v.mp4", "video/mp4", "down", 1); w != nil {
		t.Error("disabled MediaBuffer.Capture should return nil")
	}

	var nilWriter *ObjectWriter
	n, err := nilWriter.Write([]byte("x"))
	if err != nil || n != 1 {
		t.Errorf("nil ObjectWriter.Write should be a no-op success, got n=%d err=%v", n, err)
	}
	nilWriter.Close(1) // must not panic
}

func TestMediaBufferNotMediaReturnsNil(t *testing.T) {
	b := NewMediaBuffer(t.TempDir(), true, 512<<20)
	if w := b.Capture("mac1", "h", "https://h/page", "/page", "text/html", "down", 100); w != nil {
		t.Error("Capture should return nil for non-media content")
	}
}
