// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testRules = `{
  "_meta": {"version": "t"},
  "rules": [
    {"id":"yt","application":"YouTube","usage":"streaming","content":"video","infra":"Google","infra_role":"cdn","confidence":92,
     "match":{"domain_suffix":["youtube.com","googlevideo.com"],"ndpi":["YouTube"]}},
    {"id":"cf","usage":"web","infra":"Cloudflare","infra_role":"cdn","confidence":55,
     "match":{"domain_suffix":["cloudflare.com"]}},
    {"id":"noop","usage":"never","confidence":99,"match":{}}
  ]
}`

func writeRules(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClassifyDomainAndNDPI(t *testing.T) {
	e := newEnricher(writeRules(t, testRules), time.Second)

	// domaine suffixe (sous-domaine profond)
	en := e.Classify("rr5---sn.googlevideo.com", "", "", 0)
	if en.Application != "YouTube" || en.Usage != "streaming" || en.Infra != "Google" {
		t.Fatalf("youtube par domaine : %+v", en)
	}
	if en.Confidence != 92 || len(en.Evidence) == 0 {
		t.Errorf("confiance/evidence : %+v", en)
	}

	// nDPI seul (pas de host connu) matche aussi la règle yt (OU dans le groupe)
	if en := e.Classify("inconnu.example", "YouTube", "TLS", 0); en.Application != "YouTube" {
		t.Errorf("match par nDPI attendu : %+v", en)
	}

	// hôte non couvert → unknown (confidence 0)
	if en := e.Classify("intranet.local", "", "", 0); en.Confidence != 0 {
		t.Errorf("attendu unknown, obtenu %+v", en)
	}

	// règle sans matcher ne s'applique jamais (garde-fou), malgré confidence 99
	if en := e.Classify("anything.at.all", "", "", 0); en.Usage == "never" {
		t.Error("une règle sans matcher ne doit JAMAIS s'appliquer")
	}
}

func TestUsageReportUnknownFirst(t *testing.T) {
	e := newEnricher(writeRules(t, testRules), time.Second)
	hosts := []kv{
		{Name: "www.googlevideo.com", Flows: 3, Bytes: 3000},
		{Name: "cdnjs.cloudflare.com", Flows: 1, Bytes: 1000},
		{Name: "mystery.example", Flows: 2, Bytes: 6000}, // non classifié
	}
	rep := e.report(hosts)

	if len(rep.Unknown) != 1 || rep.Unknown[0].Name != "mystery.example" {
		t.Fatalf("unknown-first : attendu [mystery.example], obtenu %+v", rep.Unknown)
	}
	// usages classés triés par octets desc ; streaming (3000) avant web (1000)
	if len(rep.Usages) != 2 || rep.Usages[0].Name != "streaming" {
		t.Fatalf("usages : %+v", rep.Usages)
	}
	if rep.Applications[0].Name != "YouTube" {
		t.Errorf("applications : %+v", rep.Applications)
	}
	// pct = part du volume TOTAL (unknown inclus) : streaming 3000/10000 = 30%
	if p := rep.Usages[0].Pct; p < 29.9 || p > 30.1 {
		t.Errorf("pct streaming attendu ~30, obtenu %.1f", p)
	}
}

func TestSeedRulesFileValid(t *testing.T) {
	// Le seed livré doit charger sans erreur et classer YouTube.
	e := newEnricher("../../debian/dpi/rules.json", time.Second)
	if en := e.Classify("a.b.googlevideo.com", "", "", 0); en.Application != "YouTube" {
		t.Fatalf("seed rules.json : YouTube non classé (%+v) — le fichier livré est-il valide ?", en)
	}
}
