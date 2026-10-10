// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
)

func ingere(t *testing.T, s *Server, e envelope.Envelope) string {
	t.Helper()
	if e.EventID == "" {
		e.EventID = envelope.NewEventID()
	}
	if err := s.store.Ingest(&e); err != nil {
		t.Fatal(err)
	}
	id, _, _ := s.observe(&e)
	return id
}

func appelle(s *Server, chemin string, complete bool) (*httptest.ResponseRecorder, map[string]any) {
	req := httptest.NewRequest(http.MethodGet, chemin, nil)
	if complete {
		req.Header.Set(enteteVue, valeurComplete)
	}
	rec := httptest.NewRecorder()
	s.apiMux().ServeHTTP(rec, req)
	var corps map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &corps)
	return rec, corps
}

func scenario(t *testing.T, s *Server) string {
	t.Helper()
	ip := "203.0.113.9"
	base := int64(1_800_000_000)
	var id string
	evs := []envelope.Envelope{
		{Timestamp: base, Sensor: "firewall", SrcIP: ip, RuleID: "fw.scan.vertical", Severity: 66, BehaviorTags: []string{"port_scan"}, Action: envelope.ActionBlock},
		{Timestamp: base + 60, Sensor: "waf", SrcIP: ip, DstService: "git.gk2", Severity: 55, BehaviorTags: []string{"scanners"}},
		{Timestamp: base + 120, Sensor: "waf", SrcIP: ip, DstService: "git.gk2", Severity: 85, BehaviorTags: []string{"sqli"}},
		{Timestamp: base + 130, Sensor: "dpi", SrcIP: ip, Severity: 80, RuleID: "dpi.risk.malicious_fingerprint"},
	}
	for _, e := range evs {
		id = ingere(t, s, e)
	}
	return id
}

func TestRisque_ExposeRisqueConfianceEtDecisionAvecFacteurs(t *testing.T) {
	s := serveur(t)
	id := scenario(t, s)
	rec, corps := appelle(s, "/actors/"+id+"/risk", true)
	if rec.Code != 200 {
		t.Fatalf("code %d : %s", rec.Code, rec.Body)
	}
	ev := corps["evaluation"].(map[string]any)
	risque, confiance := ev["risque"].(map[string]any), ev["confiance"].(map[string]any)
	if risque["valeur"].(float64) <= 0 || len(risque["facteurs"].([]any)) == 0 || len(confiance["facteurs"].([]any)) == 0 {
		t.Fatalf("risque et confiance séparés, chacun avec ses facteurs : %v", ev)
	}
	if ev["decision"].(map[string]any)["niveau"] == nil || corps["politique"] != "v2" {
		t.Fatalf("décision et version de politique attendues : %v", corps)
	}
}

func TestTimeline_OrdonneeAvecEtape(t *testing.T) {
	s := serveur(t)
	id := scenario(t, s)
	_, corps := appelle(s, "/actors/"+id+"/timeline", true)
	evs := corps["events"].([]any)
	if len(evs) != 4 || corps["total"].(float64) != 4 {
		t.Fatalf("4 événements attendus : %v", corps)
	}
	prec := 0.0
	for _, x := range evs {
		e := x.(map[string]any)
		if e["ts"].(float64) < prec || e["etape"] == "" {
			t.Fatalf("chronologie croissante avec étape : %v", e)
		}
		prec = e["ts"].(float64)
	}
	_, lim := appelle(s, "/actors/"+id+"/timeline?limit=2", true)
	if len(lim["events"].([]any)) != 2 {
		t.Fatalf("limit respectée : %v", lim)
	}
}

func TestGraphe_ViaApi(t *testing.T) {
	s := serveur(t)
	id := scenario(t, s)
	_, corps := appelle(s, "/actors/"+id+"/graph", true)
	if len(corps["noeuds"].([]any)) < 4 || len(corps["liens"].([]any)) < 3 {
		t.Fatalf("graphe attendu : %v", corps)
	}
}

func TestEvenements_FiltreParCapteurEtBorneLaLimite(t *testing.T) {
	s := serveur(t)
	scenario(t, s)
	_, tous := appelle(s, "/events", true)
	_, waf := appelle(s, "/events?sensor=waf", true)
	if len(tous["events"].([]any)) != 4 || len(waf["events"].([]any)) != 2 {
		t.Fatalf("filtre par capteur : %d / %d", len(tous["events"].([]any)), len(waf["events"].([]any)))
	}
	_, un := appelle(s, "/events?limit=1", true)
	if len(un["events"].([]any)) != 1 {
		t.Fatalf("limite : %v", un)
	}
	_, enorme := appelle(s, "/events?limit=999999", true)
	if enorme["limite"].(float64) > 1000 {
		t.Fatalf("limite plafonnée : %v", enorme["limite"])
	}
}

func TestVueReduite_NeSertAucuneDeCesRoutes(t *testing.T) {
	s := serveur(t)
	id := scenario(t, s)
	for _, chemin := range []string{"/actors/" + id + "/risk", "/actors/" + id + "/timeline", "/actors/" + id + "/graph", "/events"} {
		if rec, _ := appelle(s, chemin, false); rec.Code != http.StatusNotFound {
			t.Errorf("%s : la vue réduite (adresses, cibles) répond comme une route inexistante, obtenu %d", chemin, rec.Code)
		}
		if rec, _ := appelle(s, "/api/v1/actor"+chemin, true); rec.Code != http.StatusNotFound {
			t.Errorf("/api/v1/actor%s : l'arbre relayé est toujours réduit, obtenu %d", chemin, rec.Code)
		}
	}
}

func TestActeurInconnu_404(t *testing.T) {
	s := serveur(t)
	for _, c := range []string{"/actors/ACT-9999/risk", "/actors/ACT-9999/timeline", "/actors/ACT-9999/graph"} {
		if rec, _ := appelle(s, c, true); rec.Code != http.StatusNotFound {
			t.Errorf("%s : 404 attendu, obtenu %d", c, rec.Code)
		}
	}
}

func TestMuetsEnParametre_AbaissentLaConfianceSansToucherAuRisque(t *testing.T) {
	s := serveur(t)
	id := scenario(t, s)
	_, a := appelle(s, "/actors/"+id+"/risk", true)
	_, b := appelle(s, "/actors/"+id+"/risk?muets=dns,dpi", true)
	ra, rb := a["evaluation"].(map[string]any), b["evaluation"].(map[string]any)
	if rb["confiance"].(map[string]any)["valeur"].(float64) >= ra["confiance"].(map[string]any)["valeur"].(float64) ||
		rb["risque"].(map[string]any)["valeur"] != ra["risque"].(map[string]any)["valeur"] {
		t.Fatalf("confiance abaissée, risque inchangé : %v / %v", ra, rb)
	}
}
