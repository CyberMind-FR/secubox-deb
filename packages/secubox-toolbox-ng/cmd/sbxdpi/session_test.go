// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"testing"
	"time"
)

func flow(src, dst, host, proto string, port int, bytes uint64) *dpiEvent {
	e := &dpiEvent{SrcIP: src, DstIP: dst, DstPort: port, DstBytes: bytes, FlowEventName: "end"}
	e.NDPI.Proto = proto
	e.NDPI.Hostname = host
	return e
}

// Corrélation L3 : des flux SORTANTS du même device et de la même famille
// d'usage, dans la fenêtre, forment UNE session — pas une liste de sockets.
func TestSessionCorrelation(t *testing.T) {
	e := newEnricher(writeRules(t, testRules), time.Second) // testRules : yt→streaming
	st := newSessionTracker(e)
	now := int64(1_000_000)

	// 3 flux YouTube du même poste dans la fenêtre → 1 session streaming.
	st.observe(flow("192.168.1.24", "1.2.3.4", "www.googlevideo.com", "TLS.YouTube", 443, 2<<20), now)
	st.observe(flow("192.168.1.24", "1.2.3.5", "rr5.googlevideo.com", "QUIC", 443, 5<<20), now+10)
	st.observe(flow("192.168.1.24", "1.2.3.6", "youtube.com", "TLS.YouTube", 443, 1<<20), now+30)
	// Un flux entrant (dst local) est ignoré (on suit le sortant).
	st.observe(flow("8.8.8.8", "192.168.1.24", "www.googlevideo.com", "TLS.YouTube", 443, 9<<20), now+40)
	// Un flux non classifié est ignoré.
	st.observe(flow("192.168.1.24", "9.9.9.9", "intranet.local", "TLS", 443, 1<<20), now+50)

	snap := st.snapshot(now + 60)
	if len(snap) != 1 {
		t.Fatalf("attendu 1 session, obtenu %d : %+v", len(snap), snap)
	}
	s := snap[0]
	if s.Device != "192.168.1.24" || s.Usage != "streaming" {
		t.Fatalf("session incorrecte : %+v", s)
	}
	if s.Flows != 3 || s.Bytes != (8<<20) {
		t.Errorf("agrégat session : flows=%d bytes=%d (attendu 3 / %d)", s.Flows, s.Bytes, 8<<20)
	}
	if len(s.Hosts) < 2 {
		t.Errorf("hôtes de session : %+v", s.Hosts)
	}
	if s.App != "YouTube" {
		t.Errorf("application de session : %q", s.App)
	}
}

// Hors fenêtre → deux sessions distinctes pour le même device+usage.
func TestSessionWindowSplit(t *testing.T) {
	e := newEnricher(writeRules(t, testRules), time.Second)
	st := newSessionTracker(e)
	now := int64(2_000_000)
	st.observe(flow("192.168.1.24", "1.2.3.4", "youtube.com", "TLS.YouTube", 443, 1<<20), now)
	st.observe(flow("192.168.1.24", "1.2.3.4", "youtube.com", "TLS.YouTube", 443, 1<<20), now+sessWindow+10)
	snap := st.snapshot(now + sessWindow + 20)
	if len(snap) != 2 {
		t.Fatalf("hors fenêtre → 2 sessions attendues, obtenu %d", len(snap))
	}
}
