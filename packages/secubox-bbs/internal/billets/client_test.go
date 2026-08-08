package billets

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUnFilLocalNEstJamaisPublie(t *testing.T) {
	// LA garde de ce paquet. Publier, c'est mettre sur internet ; le faire
	// depuis un fil local serait irrattrapable — c'est lu, indexe, archive.
	var appele bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appele = true
		w.Write([]byte(`{"success":true,"id":"x","url":"/b/x"}`))
	}))
	defer srv.Close()

	c := &Client{Base: srv.URL, Secret: "un-secret", HTTP: srv.Client()}
	_, err := c.Publier(Fil{Titre: "Fil prive", Public: false,
		Messages: []Message{{Auteur: "gk2", Corps: "…", Public: true}}})
	if err == nil {
		t.Error("un fil local a ete publie")
	}
	if appele {
		t.Error("une requete a ete envoyee a billets pour un fil local")
	}
}

func TestSeulsLesMessagesPublicsSontEnvoyes(t *testing.T) {
	var recu string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		recu = string(b)
		w.Write([]byte(`{"success":true,"id":"abc","url":"/b/abc"}`))
	}))
	defer srv.Close()

	c := &Client{Base: srv.URL, Secret: "un-secret", HTTP: srv.Client()}
	res, err := c.Publier(Fil{Titre: "Fil public", Public: true, Messages: []Message{
		{Auteur: "gk2", Corps: "ceci est public", Public: true},
		{Auteur: "thomas", Corps: "ADRESSE DE LA GRANGE", Public: false},
		{Auteur: "marie", Corps: "ceci aussi est public", Public: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(recu, "ADRESSE DE LA GRANGE") {
		t.Error("un message local a ete transmis a billets")
	}
	if !strings.Contains(recu, "ceci est public") {
		t.Error("un message public n'a pas ete transmis")
	}
	if res.Pris != 2 || res.Retenus != 1 {
		t.Errorf("comptes errones : %d pris, %d retenus", res.Pris, res.Retenus)
	}
}

func TestSansSecretRienNEstPublie(t *testing.T) {
	// « Ne jamais signer avec une valeur par defaut » est la regle du core.
	// Un jeton signe avec un secret vide serait accepte par tout service qui
	// ferait la meme erreur.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("une requete a ete envoyee sans secret configure")
	}))
	defer srv.Close()
	c := &Client{Base: srv.URL, Secret: "", HTTP: srv.Client()}
	if _, err := c.Publier(Fil{Titre: "T", Public: true,
		Messages: []Message{{Auteur: "a", Corps: "b", Public: true}}}); err == nil {
		t.Error("publication acceptee sans secret de signature")
	}
}

func TestLeJetonEstSigneEtBrefEtPorteLeRole(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.Write([]byte(`{"success":true,"id":"x","url":"/b/x"}`))
	}))
	defer srv.Close()

	c := &Client{Base: srv.URL, Secret: "un-secret", HTTP: srv.Client()}
	c.Publier(Fil{Titre: "T", Public: true, Messages: []Message{{Auteur: "a", Corps: "b", Public: true}}})

	if !strings.HasPrefix(auth, "Bearer ") {
		t.Fatalf("en-tete d'autorisation inattendu : %q", auth)
	}
	corps, err := charge(strings.TrimPrefix(auth, "Bearer "))
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	json.Unmarshal(corps, &p)
	exp, _ := p["exp"].(float64)
	iat, _ := p["iat"].(float64)
	if exp-iat > 120 {
		t.Errorf("jeton valable %.0f s — trop long pour un appel unique", exp-iat)
	}
	if p["role"] != "sysop" {
		t.Errorf("role du jeton : %v", p["role"])
	}
}

func TestUnEchecDeBilletsNEstPasSilencieux(t *testing.T) {
	// Si billets refuse, le BBS ne doit PAS enregistrer que le fil est publie :
	// il afficherait un lien vers une page inexistante.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`{"detail":"base indisponible"}`))
	}))
	defer srv.Close()
	c := &Client{Base: srv.URL, Secret: "s", HTTP: srv.Client()}
	if _, err := c.Publier(Fil{Titre: "T", Public: true,
		Messages: []Message{{Auteur: "a", Corps: "b", Public: true}}}); err == nil {
		t.Error("un echec de billets est passe pour un succes")
	}
}
