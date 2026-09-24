// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package billets

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// CE QUE CES TESTS GARDENT (#1358).
//
// Le pont etait en ECRITURE SEULE : chaque publication faisait un POST, quelle
// que soit l'histoire du fil. Corriger un titre et republier creait donc un
// billet de plus — et `MarkPublished`, qui fait un INSERT OR REPLACE, faisait
// oublier le precedent au BBS : il restait en ligne sans que plus rien ne
// puisse le retirer.
//
// Mesure au moment du correctif, sur la board : 276 billets dont 43 EN TROP,
// certains fils en TROIS exemplaires, avec `updated_at == created_at` sur les
// trois — aucun n'avait jamais ete mis a jour.

func filValide(id string) Fil {
	return Fil{
		Titre: "Un fil", Public: true, Session: "s", BilletID: id,
		Messages: []Message{{Auteur: "gk2", Corps: "bonjour", Public: true}},
	}
}

func TestSansIdentifiantOnCree(t *testing.T) {
	var methode, chemin string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methode, chemin = r.Method, r.URL.Path
		w.Write([]byte(`{"success":true,"id":"neuf","url":"/b/neuf"}`))
	}))
	defer srv.Close()

	c := &Client{Base: srv.URL, HTTP: srv.Client()}
	if _, err := c.Publier(filValide("")); err != nil {
		t.Fatalf("publication refusee : %v", err)
	}
	if methode != "POST" {
		t.Errorf("methode %q, attendu POST : un fil jamais publie se cree", methode)
	}
	if chemin != "/admin/api/billets" {
		t.Errorf("chemin %q", chemin)
	}
}

// LE TEST QUI COMPTE : republier ne doit JAMAIS creer un second billet.
func TestAvecIdentifiantOnMetAJour(t *testing.T) {
	var methode, chemin string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methode, chemin = r.Method, r.URL.Path
		w.Write([]byte(`{"success":true,"id":"ancien","url":"/b/ancien"}`))
	}))
	defer srv.Close()

	c := &Client{Base: srv.URL, HTTP: srv.Client()}
	if _, err := c.Publier(filValide("ancien")); err != nil {
		t.Fatalf("republication refusee : %v", err)
	}
	if methode != "PUT" {
		t.Fatalf("methode %q : un fil DEJA publie doit etre mis a jour, pas "+
			"recree — c'est exactement ce qui produisait des triplons", methode)
	}
	if chemin != "/admin/api/billets/ancien" {
		t.Errorf("chemin %q, attendu /admin/api/billets/ancien", chemin)
	}
}

func TestUnIdentifiantExotiqueEstEchappe(t *testing.T) {
	// Il vient de notre base, mais il transite par une URL : le laisser brut
	// ferait d'un caractere reserve une route differente, et l'on mettrait a
	// jour un billet qui n'est pas le bon — ou aucun, en silence.
	var chemin string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chemin = r.URL.EscapedPath()
		w.Write([]byte(`{"success":true,"id":"x","url":"/b/x"}`))
	}))
	defer srv.Close()

	c := &Client{Base: srv.URL, HTTP: srv.Client()}
	if _, err := c.Publier(filValide("a/b c")); err != nil {
		t.Fatalf("republication refusee : %v", err)
	}
	if strings.Contains(chemin, " ") {
		t.Errorf("identifiant non echappe dans %q", chemin)
	}
}

// ── La depublication ────────────────────────────────────────────────────────

func TestRetireSupprimeChezBillets(t *testing.T) {
	var methode, chemin, cookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methode, chemin = r.Method, r.URL.Path
		cookie = r.Header.Get("Cookie")
		w.Write([]byte(`{"success":true,"deleted":true}`))
	}))
	defer srv.Close()

	c := &Client{Base: srv.URL, HTTP: srv.Client()}
	if err := c.Retire("abc", "jeton"); err != nil {
		t.Fatalf("retrait refuse : %v", err)
	}
	if methode != "DELETE" || chemin != "/admin/api/billets/abc" {
		t.Errorf("%s %s", methode, chemin)
	}
	if !strings.Contains(cookie, "jeton") {
		t.Error("la session de l'operateur n'a pas ete relayee : le BBS n'a pas " +
			"d'identite propre chez billets, il transmet celle qu'on lui presente")
	}
}

func TestUnBilletDejaPartiEstUnSucces(t *testing.T) {
	// Exiger qu'il existe encore bloquerait la depublication d'un fil dont le
	// billet a deja ete supprime depuis l'administration de billets — c'est-a-
	// dire l'etat qu'on cherche justement a atteindre.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"billet not found"}`, http.StatusNotFound)
	}))
	defer srv.Close()

	c := &Client{Base: srv.URL, HTTP: srv.Client()}
	if err := c.Retire("disparu", "jeton"); err != nil {
		t.Errorf("un 404 doit valoir succes, on a eu : %v", err)
	}
}

func TestUnRefusDeBilletsRemonte(t *testing.T) {
	// L'echec doit REMONTER : c'est lui qui empeche le BBS d'oublier le lien.
	// Oublier apres un echec laisserait un billet orphelin, en ligne et
	// introuvable — precisement le defaut qu'on corrige.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"nope"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := &Client{Base: srv.URL, HTTP: srv.Client()}
	if err := c.Retire("abc", "jeton"); err == nil {
		t.Error("un refus de billets doit remonter")
	}
}

func TestRetirerSansSessionEstRefuse(t *testing.T) {
	var appele bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appele = true
	}))
	defer srv.Close()

	c := &Client{Base: srv.URL, HTTP: srv.Client()}
	if err := c.Retire("abc", ""); err == nil {
		t.Error("sans session, le retrait doit etre refuse")
	}
	if appele {
		t.Error("une requete est partie sans session")
	}
}
