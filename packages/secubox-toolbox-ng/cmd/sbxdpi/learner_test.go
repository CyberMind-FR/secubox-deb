// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import "testing"

func TestRegistrable(t *testing.T) {
	cases := map[string]string{
		"rr5---sn.googlevideo.com": "googlevideo.com",
		"a.b.c.example.com":        "example.com",
		"www.bbc.co.uk":            "bbc.co.uk",
		"foo.com.au":               "foo.com.au",
		"localhost":                "localhost",
		"example.com":              "example.com",
	}
	for in, want := range cases {
		if got := registrable(in); got != want {
			t.Errorf("registrable(%q) = %q, attendu %q", in, got, want)
		}
	}
}

// Le learner regroupe les inconnus par domaine racine et propose une règle
// domain_suffix, triée par volume, avec confiance + evidence. Jamais promue.
func TestSuggestFromUnknown(t *testing.T) {
	unknown := []kv{
		{Name: "rr5---sn.googlevideo.com", Flows: 3, Bytes: 3 << 30},
		{Name: "rr6---sn.googlevideo.com", Flows: 2, Bytes: 1 << 30},
		{Name: "one.small.example.org", Flows: 1, Bytes: 1000},
	}
	sug := suggestFromUnknown(unknown)
	if len(sug) != 2 {
		t.Fatalf("attendu 2 domaines regroupés, obtenu %d : %+v", len(sug), sug)
	}
	top := sug[0]
	if top.Domain != "googlevideo.com" {
		t.Fatalf("top domaine attendu googlevideo.com, obtenu %q", top.Domain)
	}
	if top.Subdomains != 2 || top.Bytes != (4<<30) {
		t.Errorf("agrégat googlevideo : subs=%d bytes=%d", top.Subdomains, top.Bytes)
	}
	if top.Confidence <= 40 { // 2 sous-domaines + >1Gio → confiance forte
		t.Errorf("confiance trop faible : %d", top.Confidence)
	}
	// La règle proposée doit être un domain_suffix prêt à accepter, usage vide
	// (à compléter par l'humain) — jamais auto-promue.
	m, _ := top.ProposedRule["match"].(map[string]any)
	ds, _ := m["domain_suffix"].([]string)
	if len(ds) != 1 || ds[0] != "googlevideo.com" {
		t.Errorf("proposed_rule.match.domain_suffix incorrect : %+v", top.ProposedRule)
	}
	if u, _ := top.ProposedRule["usage"].(string); u != "" {
		t.Errorf("usage doit rester vide (revue humaine), obtenu %q", u)
	}
}

// L1-fin : JA4, ports et direction (out/in) remontent dans le snapshot, additif.
func TestL1FinSignals(t *testing.T) {
	a := newAggregator()
	e := &dpiEvent{SrcIP: "192.168.1.10", DstIP: "1.2.3.4", DstPort: 443, DstBytes: 500}
	e.NDPI.Proto = "TLS.YouTube"
	e.NDPI.JA4 = "t13d1516h2_abc"
	a.recordFlow(e, false)
	a.recordBytes(e)

	s := a.snapshot()
	if len(s.Fingerprints) == 0 || s.Fingerprints[0].Name != "t13d1516h2_abc" {
		t.Errorf("JA4 non propagé : %+v", s.Fingerprints)
	}
	if len(s.Ports) == 0 || s.Ports[0].Name != "443" {
		t.Errorf("port non propagé : %+v", s.Ports)
	}
	if s.OutBytes != 500 || s.InBytes != 0 {
		t.Errorf("direction : attendu out=500 in=0, obtenu out=%d in=%d", s.OutBytes, s.InBytes)
	}
}
