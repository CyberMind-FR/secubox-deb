// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// SBX TV Privacy lot 4 (#3374) : agrégat PAR ADRESSE CIBLE seulement (opt-in), borné, écrit atomiquement.

func cibles(t *testing.T, dir string, adresses ...string) string {
	t.Helper()
	p := filepath.Join(dir, "cibles.json")
	c := map[string]any{"version": 1, "appareils": []map[string]any{{"mac": "aa:bb:cc:00:00:01", "adresses": adresses}}}
	b, _ := json.Marshal(c)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAppareilsSeulementLesCibles(t *testing.T) {
	dir := t.TempDir()
	s := newSuiviAppareils(cibles(t, dir, "192.168.1.50", "2a01:e0a::1"), filepath.Join(dir, "out", "appareils.json"))
	s.proprietaire = uint32(os.Getuid())
	s.recharger()
	e := ev("TLS.Google", "Advertisement", "pagead2.googlesyndication.com", "192.168.1.50", "142.250.1.1", 0)
	e.DstPort, e.L4Proto, e.FlowEventName = 443, "tcp", "detected"
	s.observe(e, 1000)
	hors := ev("TLS.Google", "Web", "x.example", "192.168.1.99", "142.250.1.1", 0)
	hors.DstPort, hors.L4Proto = 443, "tcp"
	s.observe(hors, 1000)
	// sens retour : la cible est la DESTINATION
	r := ev("QUIC.YouTube", "Media", "", "142.250.9.9", "2a01:e0a::1", 0)
	r.SrcPort, r.L4Proto, r.FlowEventName, r.SrcBytes, r.DstBytes = 443, "udp", "end", 7000, 300
	s.observe(r, 1010)
	if err := s.ecrire(1020); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Version int `json:"version"`
		Genere  int64
		Flux    []map[string]any `json:"flux"`
	}
	b, err := os.ReadFile(filepath.Join(dir, "out", "appareils.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Version != 1 || len(out.Flux) != 2 {
		t.Fatalf("sortie inattendue : %s", b)
	}
	vus := map[string]map[string]any{}
	for _, f := range out.Flux {
		vus[f["local"].(string)] = f
	}
	if vus["192.168.1.50"]["hote"] != "pagead2.googlesyndication.com" || vus["192.168.1.50"]["distant"] != "" {
		t.Fatalf("flux avec nom : distant doit être vide, %v", vus["192.168.1.50"])
	}
	if vus["2a01:e0a::1"]["distant"] != "142.250.9.9" || vus["2a01:e0a::1"]["octets"].(float64) != 7300 || vus["2a01:e0a::1"]["port"].(float64) != 443 {
		t.Fatalf("flux sans nom : %v", vus["2a01:e0a::1"])
	}
	if _, ok := vus["192.168.1.99"]; ok {
		t.Fatal("une adresse hors cibles ne doit jamais être comptée par appareil")
	}
}

func TestAppareilsSansCiblesNeCompteRienEtNEcritRien(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "appareils.json")
	s := newSuiviAppareils(filepath.Join(dir, "absent.json"), out)
	s.proprietaire = uint32(os.Getuid())
	s.recharger()
	e := ev("TLS", "Web", "x.example", "192.168.1.50", "1.1.1.1", 0)
	s.observe(e, 1)
	if err := s.ecrire(2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("sans cibles, aucun fichier par appareil")
	}
}

func TestAppareilsBornesEtFenetre(t *testing.T) {
	dir := t.TempDir()
	s := newSuiviAppareils(cibles(t, dir, "192.168.1.50"), filepath.Join(dir, "a.json"))
	s.proprietaire = uint32(os.Getuid())
	s.recharger()
	for i := 0; i < maxClesParAdresse+50; i++ {
		e := ev("TLS", "Web", "", "192.168.1.50", "151.101."+itoa(i/250)+"."+itoa(i%250), 0)
		e.DstPort, e.L4Proto = 443, "tcp"
		s.observe(e, int64(1000+i))
	}
	if n := len(s.cles); n > maxClesParAdresse {
		t.Fatalf("plafond par adresse dépassé : %d", n)
	}
	s.observe(ev("TLS", "Web", "vieux.example", "192.168.1.50", "1.1.1.1", 0), 1)
	s.purger(1000 + 20*60)
	for k := range s.cles {
		if k.minute < (1000+20*60)/60-fenetreMinutes {
			t.Fatal("une minute hors fenêtre doit être purgée")
		}
	}
}

func itoa(i int) string {
	return string(rune('0'+i/100%10)) + string(rune('0'+i/10%10)) + string(rune('0'+i%10))
}

// Passe 2 (#3374) : S2 propriétaire root exigé, taille vérifiée avant lecture, m7 purge au rechargement.

func TestCiblesRefuseesSiPasRoot(t *testing.T) {
	dir := t.TempDir()
	s := newSuiviAppareils(cibles(t, dir, "192.168.1.50"), filepath.Join(dir, "a.json"))
	s.proprietaire = uint32(os.Getuid()) + 1 // le fichier n'appartient pas au propriétaire attendu
	s.recharger()
	if len(s.cibles) != 0 {
		t.Fatal("un fichier de cibles qui n'appartient pas à root doit être refusé")
	}
}

func TestCiblesTropGrossesRefuseesSansLecture(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cibles.json")
	if err := os.WriteFile(p, make([]byte, 2<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newSuiviAppareils(p, filepath.Join(dir, "a.json"))
	s.proprietaire = uint32(os.Getuid())
	if s.lirePlafonne(p) != nil {
		t.Fatal("un fichier de plus de 1 Mio ne doit pas être lu")
	}
}

func TestRetraitDeCiblePurgeSesCles(t *testing.T) {
	dir := t.TempDir()
	p := cibles(t, dir, "192.168.1.50", "192.168.1.51")
	s := newSuiviAppareils(p, filepath.Join(dir, "a.json"))
	s.proprietaire = uint32(os.Getuid())
	s.recharger()
	for _, ip := range []string{"192.168.1.50", "192.168.1.51"} {
		e := ev("TLS", "Web", "x.example", ip, "1.1.1.1", 0)
		e.L4Proto = "tcp"
		s.observe(e, 1000)
	}
	_ = os.Remove(p)
	s.recharger() // fichier disparu : plus de cibles, clés purgées, mtime oublié
	if len(s.cles) != 0 || !s.mtime.IsZero() {
		t.Fatal("cibles disparues : les clés doivent partir et le mtime être oublié")
	}
	cibles(t, dir, "192.168.1.50")
	s.recharger()
	e := ev("TLS", "Web", "x.example", "192.168.1.51", "1.1.1.1", 0)
	e.L4Proto = "tcp"
	s.observe(e, 1001)
	if len(s.cles) != 0 {
		t.Fatal("adresse retirée : plus comptée")
	}
}
