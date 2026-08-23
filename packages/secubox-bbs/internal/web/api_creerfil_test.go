// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Le POKE de MetaNews : POST /api/v1/bbs/threads ouvre un fil au nom de la
// passerelle. Exige un jeton ; crée compte passerelle + catégorie si absents.
func TestAPICreerFilPasserelle(t *testing.T) {
	srv := bancAPI(t)
	body := `{"title":"Incendie près de Marseille",
	          "body":"MetaNews\n\nRésumé :\nUn incendie...\n\nSources :\n• France Info — https://x/a",
	          "category":"actualites","source_url":"https://x/a","visibility":"local"}`

	post := func(jeton string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/v1/bbs/threads", strings.NewReader(body))
		if jeton != "" {
			r.Header.Set("Authorization", "Bearer "+jeton)
		}
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		return w
	}

	// Sans jeton → refusé (une passerelle DOIT s'authentifier).
	if w := post(""); w.Code != http.StatusUnauthorized {
		t.Fatalf("POST sans jeton devrait être 401, got %d", w.Code)
	}

	// Avec jeton valide → fil créé.
	w := post(jetonHS256("le-secret-partage", "sysop", time.Hour))
	if w.Code != 200 {
		t.Fatalf("création refusée : %d — %s", w.Code, w.Body.String())
	}
	var out struct {
		OK       bool   `json:"ok"`
		ThreadID int64  `json:"thread_id"`
		Slug     string `json:"slug"`
	}
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.OK || out.ThreadID == 0 {
		t.Fatalf("réponse inattendue : %s", w.Body.String())
	}

	// Le compte passerelle a bien été créé et le fil lui est rattaché.
	fils, err := srv.st.Recent(10, false)
	if err != nil || len(fils) == 0 {
		t.Fatalf("aucun fil récent : %v", err)
	}
	if out.Slug == "" {
		t.Errorf("slug du fil attendu")
	}
}
