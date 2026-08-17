// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: ad-block metrics aggregator tests (#662)
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecordAdBlockAggregatesGlobal(t *testing.T) {
	a := newAdStats()
	a.recordAdBlock("ads.example.com", "news.example", "")
	a.recordAdBlock("ads.example.com", "news.example", "")
	a.recordAdBlock("ads.example.com", "blog.example", "")

	if got := len(a.blocks); got != 2 {
		t.Fatalf("want 2 (adHost,site) keys, got %d", got)
	}
	c := a.blocks[adKey{"ads.example.com", "news.example"}]
	if c == nil || c.hits != 2 || c.bytes != 2*adEstBytesPerBlock {
		t.Fatalf("news.example counter wrong: %+v", c)
	}
	c = a.blocks[adKey{"ads.example.com", "blog.example"}]
	if c == nil || c.hits != 1 || c.bytes != adEstBytesPerBlock {
		t.Fatalf("blog.example counter wrong: %+v", c)
	}
}

func TestRecordAdBlockEmptyHostIgnored(t *testing.T) {
	a := newAdStats()
	a.recordAdBlock("", "site", "mac")
	if len(a.blocks) != 0 || len(a.clients) != 0 {
		t.Fatalf("empty adHost must be ignored: blocks=%d clients=%d", len(a.blocks), len(a.clients))
	}
}

func TestRecordAdBlockPerClientOnlyWhenMacSet(t *testing.T) {
	a := newAdStats()
	a.recordAdBlock("ads.example.com", "site", "")     // no mac → no client row
	a.recordAdBlock("ads.example.com", "site", "mac1") // mac → client row
	a.recordAdBlock("ads.example.com", "site", "mac1")

	if len(a.clients) != 1 {
		t.Fatalf("want 1 client key, got %d", len(a.clients))
	}
	c := a.clients[cliKey{"mac1", "ads.example.com"}]
	if c == nil || c.hits != 2 || c.bytes != 2*adEstBytesPerBlock {
		t.Fatalf("client counter wrong: %+v", c)
	}
	// Global counter accumulated all three hits regardless of mac.
	if g := a.blocks[adKey{"ads.example.com", "site"}]; g == nil || g.hits != 3 {
		t.Fatalf("global counter should be 3: %+v", g)
	}
}

func TestSnapshotClearsMaps(t *testing.T) {
	a := newAdStats()
	a.recordAdBlock("ads.example.com", "site", "mac1")
	p := a.snapshot()
	if len(p.Blocks) != 1 || len(p.Clients) != 1 {
		t.Fatalf("snapshot payload wrong: %d blocks %d clients", len(p.Blocks), len(p.Clients))
	}
	if len(a.blocks) != 0 || len(a.clients) != 0 {
		t.Fatalf("snapshot must clear the maps: blocks=%d clients=%d", len(a.blocks), len(a.clients))
	}
	// A second snapshot with nothing recorded is empty.
	if p2 := a.snapshot(); !p2.empty() {
		t.Fatalf("empty snapshot must report empty: %+v", p2)
	}
}

func TestSizeCapDropsNewKeysGracefully(t *testing.T) {
	a := newAdStats()
	// Fill past the cap with distinct keys.
	for i := 0; i < adMapCap+50; i++ {
		host := "ads" + itoa(i) + ".example.com"
		a.recordAdBlock(host, "site", "mac"+itoa(i))
	}
	if len(a.blocks) > adMapCap {
		t.Fatalf("blocks map exceeded cap: %d > %d", len(a.blocks), adMapCap)
	}
	if len(a.clients) > adMapCap {
		t.Fatalf("clients map exceeded cap: %d > %d", len(a.clients), adMapCap)
	}
	// An EXISTING key still accumulates even when the map is at cap.
	existing := "ads0.example.com"
	before := a.blocks[adKey{existing, "site"}].hits
	a.recordAdBlock(existing, "site", "mac0")
	after := a.blocks[adKey{existing, "site"}].hits
	if after != before+1 {
		t.Fatalf("existing key must keep accumulating at cap: %d -> %d", before, after)
	}
}

func TestFlushOncePayloadShapeMatchesContract(t *testing.T) {
	a := newAdStats()
	a.recordAdBlock("ads.example.com", "news.example", "mac1")

	var got adEventPayload
	var ct string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	a.flushOnce(srv.URL, nil, nil)

	if ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if len(got.Blocks) != 1 {
		t.Fatalf("blocks payload: %+v", got.Blocks)
	}
	b := got.Blocks[0]
	if b.AdHost != "ads.example.com" || b.Site != "news.example" || b.Hits != 1 || b.Bytes != adEstBytesPerBlock {
		t.Fatalf("block row shape wrong: %+v", b)
	}
	if len(got.Clients) != 1 {
		t.Fatalf("clients payload: %+v", got.Clients)
	}
	c := got.Clients[0]
	if c.MacHash != "mac1" || c.AdHost != "ads.example.com" || c.Hits != 1 || c.Bytes != adEstBytesPerBlock {
		t.Fatalf("client row shape wrong: %+v", c)
	}

	// flushOnce cleared the maps.
	if len(a.blocks) != 0 || len(a.clients) != 0 {
		t.Fatalf("flushOnce must clear maps")
	}
}

func TestFlushOnceEmptySkipsPost(t *testing.T) {
	a := newAdStats()
	posted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posted = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	a.flushOnce(srv.URL, nil, nil)
	if posted {
		t.Fatalf("flushOnce on empty aggregator must not POST")
	}
}

func TestFlushOnceSwallowsPortalError(t *testing.T) {
	a := newAdStats()
	a.recordAdBlock("ads.example.com", "site", "")
	// Unreachable portal → must not panic, must still clear the maps (snapshot
	// happens before the POST).
	a.flushOnce("http://127.0.0.1:1", nil, nil)
	if len(a.blocks) != 0 {
		t.Fatalf("flushOnce must clear maps even on POST failure")
	}
}

func TestRefererSite(t *testing.T) {
	cases := []struct{ ref, want string }{
		{"", ""},
		{"https://news.example.com/article/123", "example.com"},
		{"https://www.bbc.co.uk/news", "bbc.co.uk"},
		{"http://blog.example.com:8443/x", "example.com"},
		{"not a url ::::", ""},
	}
	for _, c := range cases {
		if got := refererSite(c.ref); got != c.want {
			t.Errorf("refererSite(%q) = %q, want %q", c.ref, got, c.want)
		}
	}
}

// itoa is a tiny stdlib-free int→string for the cap test keys (avoids importing
// strconv just for the test).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
