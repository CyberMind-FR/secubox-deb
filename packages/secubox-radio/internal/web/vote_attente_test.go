package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// LES AUDITEURS DOIVENT POUVOIR VOTER LES TITRES EN ATTENTE. Le backend sait
// déjà compter un cœur sur une proposition (`POST /propositions/<id>/coeur`),
// mais la page publique ne montrait que la file validée : impossible de
// soutenir un titre proposé (#1131g). L'accueil DOIT exposer une section
// « en attente », et le script la peupler avec un bouton de vote.
func TestAccueilExposeLesTitresEnAttente(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Serveur{}).accueil(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("accueil = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `id="attente"`) {
		t.Fatal("la page publique n'expose pas la section des titres en attente")
	}
}

func TestLeScriptCableLeVoteEnAttente(t *testing.T) {
	src, err := statique.ReadFile("static/radio.js")
	if err != nil {
		t.Fatalf("lecture du script : %v", err)
	}
	js := string(src)
	// Il lit la file des propositions ET vote sur l'une d'elles.
	if !strings.Contains(js, "/api/v1/radio/propositions'") && !strings.Contains(js, "/api/v1/radio/propositions ") {
		t.Error("le script ne lit pas la file des propositions")
	}
	if !strings.Contains(js, "/propositions/") || !strings.Contains(js, "/coeur") {
		t.Error("le script ne câble pas le vote sur une proposition")
	}
}
