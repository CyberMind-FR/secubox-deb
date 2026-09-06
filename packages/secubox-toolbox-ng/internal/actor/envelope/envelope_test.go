// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package envelope

import (
	"errors"
	"strings"
	"testing"
)

func bon() Envelope {
	return Envelope{
		EventID:               NewEventID(),
		Timestamp:             1788000000, // 2026, dans les bornes
		Sensor:                SensorWAF,
		SrcIP:                 "203.0.113.7",
		SrcPort:               44321,
		DstService:            "nextcloud",
		Vhost:                 "nc.gk2.secubox.in",
		Transport:             "tls",
		Protocol:              "https",
		Action:                ActionObserve,
		RuleID:                "sqli-001",
		Severity:              60,
		PathShape:             "/index.php/apps/:id/files",
		UserAgentFamily:       "nuclei",
		TLSFingerprint:        "t13d1516h2_8daaf6152771_02713d6af862",
		BehaviorTags:          []string{"scan", "path-enum"},
		ASN:                   13335,
		GeoCountry:            "US",
		ReverseDNSClass:       RDNSCloud,
		RequestRateBucket:     RateBucket(42),
		SessionDurationBucket: DurationBucket(12),
		EvidenceRefs:          []string{"ev-1", "ev-2"},
	}
}

func TestValidate_OK(t *testing.T) {
	e := bon()
	if err := e.Validate(); err != nil {
		t.Fatalf("enveloppe valide rejetée : %v", err)
	}
	// IPv6 doit passer aussi.
	e.SrcIP = "2a01:e0a:dec:c4e0::1"
	if err := e.Validate(); err != nil {
		t.Fatalf("IPv6 rejetée : %v", err)
	}
}

func TestValidate_Rejette(t *testing.T) {
	cas := map[string]func(*Envelope){
		"sensor inconnu":    func(e *Envelope) { e.Sensor = "martien" },
		"sensor vide":       func(e *Envelope) { e.Sensor = "" },
		"ip invalide":       func(e *Envelope) { e.SrcIP = "999.1.2.3" },
		"ip vide":           func(e *Envelope) { e.SrcIP = "" },
		"port hors plage":   func(e *Envelope) { e.SrcPort = 70000 },
		"port négatif":      func(e *Envelope) { e.SrcPort = -1 },
		"ts trop ancien":    func(e *Envelope) { e.Timestamp = 100 },
		"ts trop futur":     func(e *Envelope) { e.Timestamp = maxValidUnix + 1 },
		"severity haute":    func(e *Envelope) { e.Severity = 101 },
		"severity négative": func(e *Envelope) { e.Severity = -1 },
		"rdns inconnue":     func(e *Envelope) { e.ReverseDNSClass = "nuage" },
		"geo non ISO2":      func(e *Envelope) { e.GeoCountry = "USA" },
		"champ géant":       func(e *Envelope) { e.Vhost = strings.Repeat("a", maxStr+1) },
		"path_shape géant":  func(e *Envelope) { e.PathShape = strings.Repeat("/x", maxPathShape) },
		"trop de tags":      func(e *Envelope) { e.BehaviorTags = make([]string, maxTags+1) },
		"tag géant":         func(e *Envelope) { e.BehaviorTags = []string{strings.Repeat("t", maxTag+1)} },
		"trop d'evidence":   func(e *Envelope) { e.EvidenceRefs = make([]string, maxEvidence+1) },
		"utf8 invalide":     func(e *Envelope) { e.RuleID = "rule-\xff\xfe" },
	}
	for nom, casse := range cas {
		e := bon()
		casse(&e)
		err := e.Validate()
		if err == nil {
			t.Errorf("%s : aurait dû être rejeté", nom)
			continue
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s : erreur %v n'enveloppe pas ErrInvalid", nom, err)
		}
	}
}

func TestHasher_SecretRotatable(t *testing.T) {
	if _, err := NewHasher([]byte("court")); err == nil {
		t.Fatal("un secret trop court aurait dû être refusé")
	}
	h1, err := NewHasher([]byte("secret-local-rotatable-0001"))
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := NewHasher([]byte("secret-local-rotatable-0002")) // secret ROTATÉ

	cred := "admin@nc.gk2.secubox.in"
	a := h1.Hash(cred)
	// Déterministe pour un même secret.
	if a != h1.Hash(cred) {
		t.Fatal("HMAC non déterministe pour le même secret")
	}
	// Jamais le credential en clair.
	if a == cred || strings.Contains(a, cred) {
		t.Fatal("le hash contient le credential en clair")
	}
	// La rotation du secret change le hash (invalide l'ancienne corrélation).
	if a == h2.Hash(cred) {
		t.Fatal("un secret différent devrait produire un hash différent")
	}
	// Un credential vide ne crée pas de faux pivot.
	if h1.Hash("") != "" {
		t.Fatal("un credential vide devrait rendre une chaîne vide")
	}
	// Longueur SHA-256 hex.
	if len(a) != 64 {
		t.Fatalf("longueur HMAC-SHA256 hex attendue 64, obtenu %d", len(a))
	}
}

func TestRateBucket(t *testing.T) {
	cas := []struct {
		v   float64
		att string
	}{{0, "none"}, {0.5, "lt1"}, {3, "1-6"}, {10, "6-30"}, {60, "30-120"}, {300, "120-600"}, {5000, "gt600"}}
	for _, c := range cas {
		if got := RateBucket(c.v); got != c.att {
			t.Errorf("RateBucket(%v) = %q, attendu %q", c.v, got, c.att)
		}
	}
}

func TestDurationBucket(t *testing.T) {
	cas := []struct {
		v   float64
		att string
	}{{0, "instant"}, {2, "lt5s"}, {30, "5-60s"}, {120, "1-10m"}, {1800, "10-60m"}, {7200, "gt1h"}}
	for _, c := range cas {
		if got := DurationBucket(c.v); got != c.att {
			t.Errorf("DurationBucket(%v) = %q, attendu %q", c.v, got, c.att)
		}
	}
}

func TestNewEventID_Unique(t *testing.T) {
	vus := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := NewEventID()
		if !strings.HasPrefix(id, "evt-") {
			t.Fatalf("préfixe attendu evt-, obtenu %q", id)
		}
		if vus[id] {
			t.Fatalf("collision d'event_id : %q", id)
		}
		vus[id] = true
	}
}
