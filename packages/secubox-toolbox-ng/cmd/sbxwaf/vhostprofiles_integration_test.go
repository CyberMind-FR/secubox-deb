// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// Phase G (#1080) — preuve d'INTÉGRATION : la suppression par vhost est bien
// câblée dans le chemin de détection (main.go, après MatchModes), pas seulement
// dans doitSupprimer. On pilote une vraie requête au travers de srv.handler().
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// buildScannerRulesFile écrit un waf-rules.json minimal : une catégorie
// `scanners` (block) qui matche un chemin de sonde, et une `sqli` (block) qui
// matche une injection. La sonde sert à démontrer la suppression ; l'injection
// à démontrer qu'elle n'est JAMAIS supprimée.
func buildScannerRulesFile(t *testing.T) string {
	t.Helper()
	doc := map[string]any{
		"categories": map[string]any{
			"scanners": map[string]any{
				"name": "Scanners", "severity": "high", "enabled": true,
				"patterns": []any{
					map[string]any{"id": "scanG", "pattern": `/probe-path`},
				},
			},
			"sqli": map[string]any{
				"name": "SQLi", "severity": "high", "enabled": true,
				"patterns": []any{
					map[string]any{"id": "sqli1", "pattern": `union\s+select`},
				},
			},
		},
	}
	f, err := os.CreateTemp(t.TempDir(), "waf-rules*.json")
	if err != nil {
		t.Fatalf("temp rules: %v", err)
	}
	if err := json.NewEncoder(f).Encode(doc); err != nil {
		t.Fatalf("encode: %v", err)
	}
	f.Close()
	return f.Name()
}

// profilG construit des profils : le vhost "profiled.example" fait tourner un
// service dont "/probe-path" est légitime ; scanners est supprimable.
func profilG(t *testing.T) *VhostProfiles {
	t.Helper()
	vp, err := chargerVhostProfilesDepuis([]byte(`{
	  "services": { "svc": { "legit_paths": ["^/probe-path"] } },
	  "vhosts": { "profiled.example": "svc" },
	  "suppress_categories": ["scanners"]
	}`))
	if err != nil {
		t.Fatalf("profils: %v", err)
	}
	return vp
}

func serveurG(t *testing.T, backendAddr string, vp *VhostProfiles) *Server {
	t.Helper()
	return &Server{
		routeLookup: func(host string) (string, int, bool) {
			h, p, err := splitHostPort(backendAddr)
			if err != nil {
				return "", 0, false
			}
			return h, p, true
		},
		rules:         LoadRules(buildScannerRulesFile(t)),
		vhostProfiles: vp,
	}
}

func TestPhaseG_SondeLegitimeDansSonServiceEstProxifiee(t *testing.T) {
	const corps = "backend ok"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, corps)
	}))
	defer backend.Close()

	srv := serveurG(t, backend.URL[len("http://"):], profilG(t))
	req := httptest.NewRequest(http.MethodGet, "http://profiled.example/probe-path", nil)
	req.Host = "profiled.example"
	req.RemoteAddr = "1.2.3.4:5555" // IP publique : pas de bypass de confiance
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("chemin légitime du service : attendu 200 (supprimé+proxifié), obtenu %d", rec.Code)
	}
	if body, _ := io.ReadAll(rec.Result().Body); string(body) != corps {
		t.Fatalf("le backend n'a pas été atteint : corps=%q", string(body))
	}
}

func TestPhaseG_MemeSondeHorsServiceEstBloquee(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ne devrait pas être atteint")
	}))
	defer backend.Close()

	srv := serveurG(t, backend.URL[len("http://"):], profilG(t))
	// Host NON profilé : la même sonde doit tirer normalement (Phase F).
	req := httptest.NewRequest(http.MethodGet, "http://autre.example/probe-path", nil)
	req.Host = "autre.example"
	req.RemoteAddr = "1.2.3.4:5555"
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("sonde hors de son service : attendu 403 (bloqué), obtenu %d", rec.Code)
	}
}

func TestPhaseG_InjectionJamaisSupprimeeMemeSurCheminLegitime(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ne devrait pas être atteint")
	}))
	defer backend.Close()

	srv := serveurG(t, backend.URL[len("http://"):], profilG(t))
	// Chemin légitime du service MAIS injection sqli en query : sqli n'est pas
	// dans suppress_categories → doit bloquer, la légitimité du chemin ne
	// protège jamais une injection.
	req := httptest.NewRequest(http.MethodGet,
		"http://profiled.example/probe-path?q=1+union+select+1,2", nil)
	req.Host = "profiled.example"
	req.RemoteAddr = "1.2.3.4:5555"
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("injection sur chemin légitime : attendu 403 (jamais supprimée), obtenu %d", rec.Code)
	}
}
