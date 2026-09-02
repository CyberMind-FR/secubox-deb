// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import "testing"

// ev is a tiny helper to build a detected flow event with a hostname.
func ev(proto, cat, host, src, dst string, bytes uint64) *dpiEvent {
	e := &dpiEvent{SrcIP: src, DstIP: dst, DstBytes: bytes}
	e.NDPI.Proto = proto
	e.NDPI.Category = cat
	e.NDPI.Hostname = host
	return e
}

func hostsMap(s snapshot) map[string]counter {
	m := map[string]counter{}
	for _, k := range s.Hosts {
		m[k.Name] = counter{Flows: k.Flows, Bytes: k.Bytes}
	}
	return m
}

// L'agrégation SNI (#DPI-sémantique) : le hostname, lu mais jamais émis
// jusqu'ici, doit remonter dans snapshot.Hosts — normalisé, sans PII, additif.
func TestSNIAggregation(t *testing.T) {
	a := newAggregator()
	feed := func(e *dpiEvent) { a.recordFlow(e, false); a.recordBytes(e) }

	feed(ev("TLS.YouTube", "Media", "rr5.googlevideo.com", "10.0.0.2", "1.2.3.4", 1000))
	feed(ev("TLS.YouTube", "Media", "RR5.GoogleVideo.com", "10.0.0.2", "1.2.3.5", 500)) // casse → même clé
	feed(ev("QUIC.Google", "Web", "  www.google.com  ", "10.0.0.2", "1.2.3.6", 300))     // trim
	feed(ev("DNS", "Network", "", "10.0.0.2", "1.2.3.7", 200))                           // pas de SNI → non compté

	h := hostsMap(a.snapshot())

	if len(h) != 2 {
		t.Fatalf("attendu 2 hôtes distincts (googlevideo normalisé + google), obtenu %d : %v", len(h), h)
	}
	gv, ok := h["rr5.googlevideo.com"]
	if !ok {
		t.Fatalf("hôte googlevideo absent ou non normalisé : %v", h)
	}
	if gv.Flows != 2 || gv.Bytes != 1500 {
		t.Errorf("googlevideo : attendu flows=2 bytes=1500, obtenu flows=%d bytes=%d", gv.Flows, gv.Bytes)
	}
	if g, ok := h["www.google.com"]; !ok || g.Bytes != 300 {
		t.Errorf("google (trim) : attendu bytes=300, obtenu %v (present=%v)", g, ok)
	}
	if _, ok := h[""]; ok {
		t.Error("un flux sans hostname ne doit pas produire de clé vide dans hosts")
	}
}

// Non-régression : le snapshot reste un SURENSEMBLE — les dimensions lues par la
// cardlet existante (protocols/apps/categories/talkers/risks) sont toujours là.
func TestSnapshotStaysSuperset(t *testing.T) {
	a := newAggregator()
	e := ev("TLS.YouTube", "Media", "youtube.com", "10.0.0.2", "1.2.3.4", 42)
	a.recordFlow(e, false)
	a.recordBytes(e)

	s := a.snapshot()
	if len(s.Protocols) == 0 || s.Protocols[0].Name != "TLS" {
		t.Errorf("protocols manquant/incorrect : %v", s.Protocols)
	}
	if len(s.Apps) == 0 || s.Apps[0].Name != "TLS.YouTube" {
		t.Errorf("apps manquant/incorrect : %v", s.Apps)
	}
	if len(s.Categories) == 0 || s.Categories[0].Name != "Media" {
		t.Errorf("categories manquant/incorrect : %v", s.Categories)
	}
	if len(s.Talkers) == 0 {
		t.Error("talkers manquant")
	}
	if s.TotalFlows != 1 || s.TotalBytes != 42 {
		t.Errorf("totaux : attendu flows=1 bytes=42, obtenu flows=%d bytes=%d", s.TotalFlows, s.TotalBytes)
	}
}
