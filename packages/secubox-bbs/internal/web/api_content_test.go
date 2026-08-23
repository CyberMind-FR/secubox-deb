// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// creerContenuTest ouvre un ContentObject via l'API elle-même (round-trip
// complet) et en rend l'id. La source est dérivée de t.Name() : deux tests
// qui appellent ce helper ne doivent jamais se percuter sur l'idempotence de
// la provenance originale (store.CreerContenu).
func creerContenuTest(t *testing.T, srv *Server) string {
	t.Helper()
	corps := fmt.Sprintf(
		`{"type":"video","title":"Test","provenance":[{"source_url":"https://example.com/%s","source_type":"web","original":true}]}`,
		t.Name())
	w, j := appelSysop(t, srv, "POST", "/api/v1/bbs/content", corps)
	if w.Code != http.StatusOK {
		t.Fatalf("creerContenuTest : HTTP %d — %s", w.Code, w.Body.String())
	}
	id, _ := j["id"].(string)
	if id == "" {
		t.Fatalf("creerContenuTest : id vide dans %v", j)
	}
	return id
}

// ── A5 : create / representation / event / topic / by-ref ─────────────────

func TestAPIContentExigeUnJeton(t *testing.T) {
	srv, _ := banc(t)
	srv.opt.JWTSecret = "le-secret-partage"
	r := httptest.NewRequest("POST", "/api/v1/bbs/content", strings.NewReader(`{"type":"video","title":"x"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("content sans jeton : code %d, attendu 401", w.Code)
	}
}

func TestAPIContentCreeEtResoutParRef(t *testing.T) {
	srv := bancAPI(t)
	corps := `{"type":"video","title":"Clip","provenance":[{"source_url":"https://youtu.be/X","source_type":"youtube","original":true}]}`
	w, j := appelSysop(t, srv, "POST", "/api/v1/bbs/content", corps)
	if w.Code != http.StatusOK {
		t.Fatalf("create HTTP %d — %s", w.Code, w.Body.String())
	}
	id, _ := j["id"].(string)
	if id == "" {
		t.Fatalf("id vide dans la reponse : %v", j)
	}

	w2, _ := appelSysop(t, srv, "POST", "/api/v1/bbs/content/"+id+"/representation",
		`{"kind":"radio","module":"secubox-radio","ref":"248","is_cache":true}`)
	if w2.Code != http.StatusOK {
		t.Fatalf("representation HTTP %d — %s", w2.Code, w2.Body.String())
	}

	w3, j3 := appelSysop(t, srv, "GET", "/api/v1/bbs/content/by-ref?module=secubox-radio&ref=248", "")
	if w3.Code != http.StatusOK {
		t.Fatalf("by-ref HTTP %d — %s", w3.Code, w3.Body.String())
	}
	if j3["id"] != id {
		t.Fatalf("by-ref id mismatch : obtenu %v, attendu %s", j3["id"], id)
	}
}

func TestAPIContentCreerEstIdempotentSurLaSourceOriginale(t *testing.T) {
	srv := bancAPI(t)
	corps := `{"type":"video","title":"Clip","provenance":[{"source_url":"https://youtu.be/IDEM","source_type":"youtube","original":true}]}`
	_, j1 := appelSysop(t, srv, "POST", "/api/v1/bbs/content", corps)
	_, j2 := appelSysop(t, srv, "POST", "/api/v1/bbs/content", corps)
	if j1["id"] != j2["id"] {
		t.Fatalf("deux creations sur la meme source originale : ids differents %v / %v", j1["id"], j2["id"])
	}
}

func TestAPIContentCreerRefuseSansProvenanceOriginale(t *testing.T) {
	srv := bancAPI(t)
	w, _ := appelSysop(t, srv, "POST", "/api/v1/bbs/content", `{"type":"video","title":"Sans origine"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("creation sans provenance originale : code %d, attendu 400", w.Code)
	}
}

func TestAPIContentEvenement(t *testing.T) {
	srv := bancAPI(t)
	id := creerContenuTest(t, srv)

	w, _ := appelSysop(t, srv, "POST", "/api/v1/bbs/content/"+id+"/event",
		`{"kind":"cache_hit","actor":"secubox-radio","payload":{"n":1}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("event HTTP %d — %s", w.Code, w.Body.String())
	}

	w2, j2 := appelSysop(t, srv, "GET", "/api/v1/bbs/content/"+id, "")
	if w2.Code != http.StatusOK {
		t.Fatalf("get HTTP %d — %s", w2.Code, w2.Body.String())
	}
	ev, _ := j2["events"].([]any)
	if len(ev) != 1 {
		t.Fatalf("events : %d, attendu 1 — %v", len(ev), j2)
	}
	premier, _ := ev[0].(map[string]any)
	if premier["kind"] != "cache_hit" {
		t.Fatalf("kind de l'event : %v, attendu cache_hit", premier["kind"])
	}
}

func TestAPIContentTopicOuvreEtRattacheLeFil(t *testing.T) {
	srv := bancAPI(t)
	id := creerContenuTest(t, srv)

	w, j := appelSysop(t, srv, "POST", "/api/v1/bbs/content/"+id+"/topic", "")
	if w.Code != http.StatusOK {
		t.Fatalf("topic HTTP %d — %s", w.Code, w.Body.String())
	}
	topicID, ok := j["bbs_topic_id"].(float64)
	if !ok || topicID == 0 {
		t.Fatalf("bbs_topic_id absent ou nul : %v", j)
	}

	// Idempotent : un second appel rend le MEME fil, n'en ouvre pas un second.
	w2, j2 := appelSysop(t, srv, "POST", "/api/v1/bbs/content/"+id+"/topic", "")
	if w2.Code != http.StatusOK || j2["bbs_topic_id"] != topicID {
		t.Fatalf("second appel /topic : code %d, bbs_topic_id %v (attendu %v)",
			w2.Code, j2["bbs_topic_id"], topicID)
	}

	w3, j3 := appelSysop(t, srv, "GET", "/api/v1/bbs/content/"+id, "")
	if w3.Code != http.StatusOK {
		t.Fatalf("get HTTP %d", w3.Code)
	}
	objet, _ := j3["objet"].(map[string]any)
	if objet["bbs_topic_id"] != topicID {
		t.Fatalf("bbs_topic_id sur l'objet : %v, attendu %v", objet["bbs_topic_id"], topicID)
	}
}

func TestAPIContentObtenirInconnuRend404(t *testing.T) {
	srv := bancAPI(t)
	w, _ := appelSysop(t, srv, "GET", "/api/v1/bbs/content/co_inconnu", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("contenu inconnu : code %d, attendu 404", w.Code)
	}
}

func TestAPIContentParRefInconnuRend404(t *testing.T) {
	srv := bancAPI(t)
	w, _ := appelSysop(t, srv, "GET", "/api/v1/bbs/content/by-ref?module=x&ref=y", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("by-ref inconnu : code %d, attendu 404", w.Code)
	}
}

// ── A6 : timeline (member-gated) ───────────────────────────────────────────

func TestAPITimelineGateEtRelecture(t *testing.T) {
	srv := bancAPI(t)
	id := creerContenuTest(t, srv)

	w, j := appelSysop(t, srv, "POST", "/api/v1/bbs/content/"+id+"/timeline",
		`{"author_id":0,"author":"anon","offset_ms":1000,"body":"x"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("anonyme doit etre refuse (400), code=%d — %s", w.Code, w.Body.String())
	}
	if j["erreur"] != "anonyme non persisté" {
		t.Fatalf("erreur attendue 'anonyme non persisté', obtenu %v", j["erreur"])
	}
	if _, present := j["error"]; present {
		t.Fatalf("la reponse ne doit porter que la clef 'erreur', pas 'error' : %v", j)
	}

	w2, _ := appelSysop(t, srv, "POST", "/api/v1/bbs/content/"+id+"/timeline",
		`{"author_id":7,"author":"Koda","offset_ms":64000,"body":"excellent"}`)
	if w2.Code != http.StatusOK {
		t.Fatalf("membre doit passer (200), code=%d — %s", w2.Code, w2.Body.String())
	}

	w3, j3 := appelSysop(t, srv, "GET", "/api/v1/bbs/content/"+id+"/timeline", "")
	if w3.Code != http.StatusOK {
		t.Fatalf("lecture timeline HTTP %d — %s", w3.Code, w3.Body.String())
	}
	comments, _ := j3["comments"].([]any)
	if n := len(comments); n != 1 {
		t.Fatalf("relecture timeline : %d commentaires, attendu 1 — %v", n, j3)
	}
	premier, _ := comments[0].(map[string]any)
	if premier["author"] != "Koda" || premier["offset_ms"] != float64(64000) {
		t.Fatalf("commentaire relu inattendu : %v", premier)
	}
}

func TestAPITimelineOrdonneeParOffset(t *testing.T) {
	srv := bancAPI(t)
	id := creerContenuTest(t, srv)

	appelSysop(t, srv, "POST", "/api/v1/bbs/content/"+id+"/timeline",
		`{"author_id":1,"author":"A","offset_ms":5000,"body":"second"}`)
	appelSysop(t, srv, "POST", "/api/v1/bbs/content/"+id+"/timeline",
		`{"author_id":2,"author":"B","offset_ms":1000,"body":"premier"}`)

	w, j := appelSysop(t, srv, "GET", "/api/v1/bbs/content/"+id+"/timeline", "")
	if w.Code != http.StatusOK {
		t.Fatalf("lecture timeline HTTP %d", w.Code)
	}
	comments, _ := j["comments"].([]any)
	if len(comments) != 2 {
		t.Fatalf("attendu 2 commentaires, obtenu %d", len(comments))
	}
	premier, _ := comments[0].(map[string]any)
	if premier["body"] != "premier" {
		t.Fatalf("l'ordre doit suivre offset_ms : premier commentaire = %v", premier)
	}
}

func TestAPITimelineContenuInconnuRend404(t *testing.T) {
	srv := bancAPI(t)
	w, _ := appelSysop(t, srv, "POST", "/api/v1/bbs/content/co_inconnu/timeline",
		`{"author_id":1,"author":"A","offset_ms":0,"body":"x"}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("timeline sur contenu inconnu : code %d, attendu 404", w.Code)
	}
}
