// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
)

func robot(ip, famille string) *envelope.Envelope {
	return &envelope.Envelope{EventID: "e-" + ip, Timestamp: 1_800_000_000, Sensor: envelope.SensorWAF, SrcIP: ip, Vhost: "git.gk2.secubox.in",
		Protocol: "https", Action: envelope.ActionObserve, Severity: 40, UserAgentFamily: famille, BehaviorTags: []string{"robots"}}
}

func TestEstRobotConnu(t *testing.T) {
	ok := robot("1.2.3.4", "meta-externalagent")
	if f, v := estRobotConnu(ok); !v || f != "meta-externalagent" {
		t.Fatalf("robot annoncé non reconnu : %q %v", f, v)
	}
	mutations := map[string]func(*envelope.Envelope){
		"sévérité haute":        func(e *envelope.Envelope) { e.Severity = 75 },
		"règle déclenchée":      func(e *envelope.Envelope) { e.RuleID = "scan-003" },
		"bloqué":                func(e *envelope.Envelope) { e.Action = envelope.ActionBlock },
		"sans étiquette robots": func(e *envelope.Envelope) { e.BehaviorTags = nil },
		"étiquette en plus":     func(e *envelope.Envelope) { e.BehaviorTags = []string{"robots", "high_value_probe"} },
		"leurre":                func(e *envelope.Envelope) { e.BehaviorTags = []string{"robots", "leurre:marque-revenue"} },
		"famille vide":          func(e *envelope.Envelope) { e.UserAgentFamily = "" },
		"famille other":         func(e *envelope.Envelope) { e.UserAgentFamily = "other" },
		"navigateur générique":  func(e *envelope.Envelope) { e.UserAgentFamily = "browser-generic" },
		"famille hostile":       func(e *envelope.Envelope) { e.UserAgentFamily = "x\"; DROP" },
		"famille trop longue": func(e *envelope.Envelope) {
			e.UserAgentFamily = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		},
	}
	for nom, mut := range mutations {
		e := robot("1.2.3.4", "meta-externalagent")
		mut(e)
		if _, v := estRobotConnu(e); v {
			t.Errorf("%s : ne doit PAS être classé robot connu", nom)
		}
	}
}

func TestObserveRobotNeCreePasD_acteur(t *testing.T) {
	s := &Server{graph: graph.New(0), accum: map[string]*actorSignals{}}
	for i := 0; i < 50; i++ {
		id, _, _ := s.observe(robot("57.141.0."+itoa(i), "meta-externalagent"))
		if id != "" {
			t.Fatalf("un robot connu ne doit pas créer d'acteur, id=%q", id)
		}
	}
	if s.graph.Len() != 0 {
		t.Fatalf("graphe : %d acteurs, attendu 0", s.graph.Len())
	}
	snap := s.robots.Snapshot()
	if len(snap) != 1 || snap[0].Famille != "meta-externalagent" || snap[0].Hits != 50 || snap[0].IPs != 50 {
		t.Fatalf("registre des robots inattendu : %+v", snap)
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func TestUnVraiEvenementCreeToujoursUnActeur(t *testing.T) {
	s := &Server{graph: graph.New(0), accum: map[string]*actorSignals{}}
	e := robot("203.0.113.9", "nuclei")
	e.BehaviorTags, e.Severity, e.RuleID = []string{"lfi"}, 90, "lfi-001"
	id, _, _ := s.observe(e)
	if id == "" || s.graph.Len() != 1 || len(s.robots.Snapshot()) != 0 {
		t.Fatalf("un événement d'attaque doit créer un acteur et rester hors du registre des robots")
	}
}

func TestRegistreRobotsConcurrentEtBorne(t *testing.T) {
	r := &Robots{}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				r.Observe("googlebot", "10."+itoa(g)+".0."+itoa(i%250), 1_800_000_000+int64(i), "x.gk2.net")
			}
		}(g)
	}
	wg.Wait()
	s := r.Snapshot()
	if len(s) != 1 || s[0].Hits != 4000 || s[0].IPs != 8*250 {
		t.Fatalf("registre concurrent : %+v", s)
	}
	// la mémoire reste bornée : au-delà du plafond on compte les accès, plus les adresses
	b := &Robots{}
	for i := 0; i < robotsIPsMax+500; i++ {
		b.Observe("bytespider", "ip-"+itoa(i), 1, "v")
	}
	if got := b.Snapshot()[0]; got.IPs != robotsIPsMax || got.Hits != robotsIPsMax+500 {
		t.Fatalf("plafond non respecté : %+v", got)
	}
}

func TestRobotsNilSafe(t *testing.T) {
	var r *Robots
	r.Observe("x", "1.1.1.1", 1, "v")
	if r.Snapshot() != nil && len(r.Snapshot()) != 0 {
		t.Fatal("un registre nil rend une liste vide")
	}
}

func TestApercuIgnoreLesRobotsConnus(t *testing.T) {
	evs := []envelope.Envelope{*robot("57.141.0.1", "meta-externalagent"), *robot("57.141.0.2", "meta-externalagent")}
	evs[0].GeoCountry, evs[1].GeoCountry = "US", "US"
	vrai := *robot("203.0.113.9", "nuclei")
	vrai.BehaviorTags, vrai.Severity, vrai.RuleID, vrai.GeoCountry = []string{"lfi"}, 90, "lfi-001", "NL"
	evs = append(evs, vrai)
	out := apercu(evs, nil, 1_800_000_100)
	if len(out.TopPays) != 1 || out.TopPays[0].Code != "NL" {
		t.Errorf("top_pays doit ignorer les robots : %+v", out.TopPays)
	}
	if len(out.Recents) != 1 || out.Recents[0].Type != "lfi-001" {
		t.Errorf("recents doit ignorer les robots : %+v", out.Recents)
	}
	somme := 0
	for _, n := range out.Activite24h {
		somme += n
	}
	if somme != 1 {
		t.Errorf("activité 24 h : %d, attendu 1", somme)
	}
}

func TestRouteRobots(t *testing.T) {
	s := &Server{graph: graph.New(0), accum: map[string]*actorSignals{}}
	s.observe(robot("57.141.0.1", "meta-externalagent"))
	s.observe(robot("57.141.0.2", "meta-externalagent"))
	s.observe(robot("66.249.0.1", "googlebot"))
	for _, p := range prefixes {
		rec := httptest.NewRecorder()
		s.apiMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p+"/robots", nil))
		if rec.Code != 200 {
			t.Fatalf("%s/robots : %d", p, rec.Code)
		}
		var out []RobotFamille
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out) != 2 || out[0].Famille != "meta-externalagent" || out[0].Hits != 2 {
			t.Fatalf("%s/robots : %v %+v", p, err, out)
		}
		if body := rec.Body.String(); containsIPv4(body) {
			t.Errorf("la route robots ne doit exposer aucune adresse : %s", body)
		}
	}
}

func containsIPv4(s string) bool { return motifIPv4.MatchString(s) }
