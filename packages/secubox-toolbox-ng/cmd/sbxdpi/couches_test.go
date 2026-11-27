// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func evFlux(nom string, id uint64, src, dst string, port int, proto string, risques ...string) *dpiEvent {
	ev := &dpiEvent{FlowEventName: nom, FlowID: id, SrcIP: src, DstIP: dst, DstPort: port, SrcBytes: 100, DstBytes: 50}
	ev.NDPI.Proto = proto
	if len(risques) > 0 {
		ev.NDPI.FlowRisk = map[string]struct {
			Risk     string `json:"risk"`
			Severity string `json:"severity"`
		}{}
		for i, r := range risques {
			ev.NDPI.FlowRisk[string(rune('a'+i))] = struct {
				Risk     string `json:"risk"`
				Severity string `json:"severity"`
			}{Risk: r, Severity: "High"}
		}
	}
	return ev
}

func TestCouchesAgregeParSourceExterne(t *testing.T) {
	c := newCouchesMenaces("", time.Hour)
	for i, ev := range []*dpiEvent{
		evFlux("new", 1, "203.0.113.7", "192.168.1.200", 22, ""),
		evFlux("detected", 1, "203.0.113.7", "192.168.1.200", 22, "SSH"),
		evFlux("end", 1, "203.0.113.7", "192.168.1.200", 22, "SSH", "Possible Exploit Attempt"),
		evFlux("new", 2, "203.0.113.7", "192.168.1.200", 23, ""),
		evFlux("not-detected", 2, "203.0.113.7", "192.168.1.200", 23, ""),
		evFlux("idle", 2, "203.0.113.7", "192.168.1.200", 23, "", "Probing Attempt"),
		evFlux("new", 3, "198.51.100.4", "192.168.1.200", 443, ""),
		evFlux("detected", 3, "198.51.100.4", "192.168.1.200", 443, "TLS.Google"),
	} {
		_ = i
		c.Observe(ev)
	}
	r := c.releve()
	if len(r.Sources) != 2 {
		t.Fatalf("2 sources attendues, %d", len(r.Sources))
	}
	s := r.Sources["203.0.113.7"]
	if s.Flux != 2 || s.Octets != 300 {
		t.Fatalf("flux/octets : %+v", s)
	}
	if got := strings.Join(servicesTries(s), ","); got != "SSH/22,Unknown/23" {
		t.Fatalf("services : %s", got)
	}
	if s.Risques["Possible Exploit Attempt"] != 1 || s.Risques["Probing Attempt"] != 1 {
		t.Fatalf("risques : %v", s.Risques)
	}
	if r.Sources["198.51.100.4"].Services["TLS/443"] != 1 {
		t.Fatalf("TLS/443 attendu : %v", r.Sources["198.51.100.4"].Services)
	}
}

func TestCouchesExclutLanEtSortant(t *testing.T) {
	c := newCouchesMenaces("", time.Hour)
	c.Observe(evFlux("new", 1, "192.168.1.50", "192.168.1.200", 22, "")) // LAN → box
	c.Observe(evFlux("new", 2, "192.168.42.10", "203.0.113.9", 443, "")) // sortant
	c.Observe(evFlux("new", 3, "100.64.1.2", "192.168.1.200", 22, ""))   // CGNAT
	c.Observe(evFlux("new", 4, "198.51.100.1", "203.0.113.9", 443, ""))  // transit
	c.Observe(evFlux("end", 2, "192.168.42.10", "203.0.113.9", 443, "TLS", "Malicious Fingerprint"))
	if n := len(c.releve().Sources); n != 0 {
		t.Fatalf("aucune source attendue, %d", n)
	}
}

func TestCouchesJA4RattacheParFlux(t *testing.T) {
	c := newCouchesMenaces("", time.Hour)
	// JA4 vu AVANT « new » (ordre possible sur le fil), puis un autre APRÈS.
	c.Empreinte(10, "t13d0410h1_aaaaaaaaaaaa_bbbbbbbbbbbb")
	c.Observe(evFlux("new", 10, "203.0.113.20", "192.168.1.200", 443, ""))
	c.Observe(evFlux("new", 11, "203.0.113.20", "192.168.1.200", 443, ""))
	c.Empreinte(11, "t13d0410h1_aaaaaaaaaaaa_bbbbbbbbbbbb")
	c.Empreinte(99, "t13d1516h2_cccccccccccc_dddddddddddd") // flux inconnu : en attente, jamais attribué
	s := c.releve().Sources["203.0.113.20"]
	if s.JA4["t13d0410h1_aaaaaaaaaaaa_bbbbbbbbbbbb"] != 2 || len(s.JA4) != 1 {
		t.Fatalf("JA4 : %v", s.JA4)
	}
	if c.ja4De("203.0.113.20") != "t13d0410h1_aaaaaaaaaaaa_bbbbbbbbbbbb" || c.ja4De("203.0.113.21") != "" {
		t.Fatal("ja4De")
	}
	var nul *couchesMenaces
	nul.Observe(evFlux("new", 1, "203.0.113.1", "192.168.1.200", 22, ""))
	nul.Empreinte(1, "x")
	if nul.ja4De("203.0.113.1") != "" {
		t.Fatal("nil-safe")
	}
}

func TestCouchesFenetreEtBornes(t *testing.T) {
	c := newCouchesMenaces("", time.Hour)
	base := time.Unix(1_800_000_000, 0)
	c.now = func() time.Time { return base }
	c.Observe(evFlux("new", 1, "203.0.113.30", "192.168.1.200", 22, ""))
	c.now = func() time.Time { return base.Add(2 * time.Hour) }
	if n := len(c.releve().Sources); n != 0 {
		t.Fatalf("source échue gardée : %d", n)
	}
	for p := 0; p < maxServicesParSrc+10; p++ {
		c.Observe(evFlux("detected", uint64(p), "203.0.113.31", "192.168.1.200", 1000+p, "SSH"))
	}
	if n := len(c.releve().Sources["203.0.113.31"].Services); n != maxServicesParSrc {
		t.Fatalf("services non bornés : %d", n)
	}
}

func TestCouchesDoubleTampon(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "couches.json")
	base := time.Unix(1_800_000_000, 0)
	c := newCouchesMenaces(chemin, time.Hour)
	c.debut = base
	c.now = func() time.Time { return base.Add(20 * time.Minute) }
	c.Observe(evFlux("new", 1, "203.0.113.40", "192.168.1.200", 22, ""))
	c.ecrire()
	lire := func() releveCouches {
		var r releveCouches
		buf, err := os.ReadFile(chemin)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(buf, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := lire(); !r.Complet || len(r.Sources) != 1 {
		t.Fatalf("relevé complet attendu : %+v", r)
	}
	// Redémarrage : relevé vide et en chauffe → ne remplace pas le complet.
	d := newCouchesMenaces(chemin, time.Hour)
	d.debut = base.Add(21 * time.Minute)
	d.now = func() time.Time { return base.Add(22 * time.Minute) }
	d.ecrire()
	if r := lire(); !r.Complet || len(r.Sources) != 1 {
		t.Fatalf("le relevé dégradé a écrasé le complet : %+v", r)
	}
	// Distributeur coupé : dégradé aussi.
	d.debut = base
	d.connecte = func() bool { return false }
	d.ecrire()
	if r := lire(); len(r.Sources) != 1 {
		t.Fatal("distributeur coupé : relevé écrasé")
	}
	// Complet trop ancien (> 2 fenêtres) : le dégradé passe.
	d.now = func() time.Time { return base.Add(5 * time.Hour) }
	d.ecrire()
	if r := lire(); r.Complet {
		t.Fatal("un complet périmé doit céder")
	}
	if _, err := os.Stat(chemin + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("fichier temporaire laissé")
	}
}

func TestCapteurPrendLeJA4DesCouches(t *testing.T) {
	c := newCouchesMenaces("", time.Hour)
	c.Observe(evFlux("new", 5, "203.0.113.50", "192.168.1.200", 443, ""))
	c.Empreinte(5, "t13d0410h1_aaaaaaaaaaaa_bbbbbbbbbbbb")
	em := &fauxEmetteur{}
	s := NewActorSensor(em, map[string]int{"Possible Exploit Attempt": 5})
	s.seuil = 5
	s.ja4De = c.ja4De
	s.Observe(evFlux("end", 5, "203.0.113.50", "192.168.1.200", 443, "TLS", "Possible Exploit Attempt"))
	if len(em.recus) != 1 || em.recus[0].TLSFingerprint != "t13d0410h1_aaaaaaaaaaaa_bbbbbbbbbbbb" {
		t.Fatalf("enveloppe sans JA4 : %+v", em.recus)
	}
}
