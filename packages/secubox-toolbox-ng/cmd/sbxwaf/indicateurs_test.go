// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Tests de la passe de correction finale de #3273 (I1) : le coût ajouté sur
// chaque requête de chaque vhost. Les indicateurs des règles sont calculés au
// chargement ; le verdict PHP d'un hôte est mémorisé dans une table bornée.
package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// I1 : un vhost non PHP ne déclenche, requête après requête, ni parcours des
// catégories ni regex php_hotes. Seule la première requête d'un hôte évalue
// les motifs ; le verdict est ensuite lu dans la table.
func TestVhostNonPHPNiRegexNiParcours(t *testing.T) {
	b := nouveauBancMultipart(t, nil)
	vp, err := chargerVhostProfilesDepuis([]byte(`{
		"services": {"nextcloud": {"legit_paths": []}},
		"vhosts": {"nc.example": "nextcloud"},
		"php_services": ["nextcloud"],
		"php_hotes": ["^webmail\\.", "^cloud\\."]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	b.s.vhostProfiles = vp
	envoyer := func(hote string) {
		req := httptest.NewRequest(http.MethodGet, "http://"+hote+"/", nil)
		req.Host = hote
		req.RemoteAddr = ipPublique + ":40000"
		rec := httptest.NewRecorder()
		b.s.handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s : statut %d, attendu 200", hote, rec.Code)
		}
	}
	envoyer("vitrine.example") // premier passage : verdict calculé une fois
	parcours, motifs := parcoursRegles.Load(), motifsPHPEvalues.Load()
	for i := 0; i < 5; i++ {
		envoyer("vitrine.example")
		envoyer("VITRINE.example:443") // même hôte normalisé
	}
	if n := parcoursRegles.Load() - parcours; n != 0 {
		t.Errorf("catégories parcourues %d fois pour un vhost non PHP, attendu 0", n)
	}
	if n := motifsPHPEvalues.Load() - motifs; n != 0 {
		t.Errorf("motifs php_hotes évalués %d fois pour un hôte déjà vu, attendu 0", n)
	}
}

// I1 : la table des verdicts est bornée. Au-delà de servicePHPMemoMax hôtes
// distincts (en-têtes Host forgés), rien n'est plus mémorisé : le verdict
// reste juste, la table ne grossit plus.
func TestServicePHPMemoBornee(t *testing.T) {
	vp, err := chargerVhostProfilesDepuis([]byte(`{
		"services": {"nextcloud": {"legit_paths": []}},
		"vhosts": {"nc.example": "nextcloud"},
		"php_services": ["nextcloud"],
		"php_hotes": ["^webmail\\."]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < servicePHPMemoMax+100; i++ {
		if _, php := vp.servicePHP(fmt.Sprintf("forge%d.example", i)); php {
			t.Fatalf("forge%d.example tenu pour PHP", i)
		}
	}
	if n := vp.tailleMemoPHP(); n != servicePHPMemoMax {
		t.Errorf("table des verdicts : %d entrées, attendu %d (bornée)", n, servicePHPMemoMax)
	}
	// Table pleine : un hôte neuf est encore jugé juste, sans être retenu.
	if sv, php := vp.servicePHP("webmail.neuf"); sv != "" || !php {
		t.Errorf("webmail.neuf = (%q, %v), attendu (\"\", true)", sv, php)
	}
	if sv, php := vp.servicePHP("NC.example:443"); sv != "nextcloud" || !php {
		t.Errorf("nc.example = (%q, %v), attendu (nextcloud, true)", sv, php)
	}
	// Un rechargement des profils repart d'une table vide.
	vp2, _ := chargerVhostProfilesDepuis([]byte(`{"services": {}, "vhosts": {}}`))
	if n := vp2.tailleMemoPHP(); n != 0 {
		t.Errorf("profils rechargés : %d entrées, attendu 0", n)
	}
}

// I1, M3, M4 : les indicateurs sont calculés UNE fois, au chargement des
// règles ; les lire ne parcourt plus les catégories.
func TestIndicateursCalculesAuChargement(t *testing.T) {
	r := LoadRules(ecrisRegles(t, `{"categories": {
	  "php_requete": {"mode": "detect", "structural": [
	    {"id": "php-002", "check": "xml_dtd_prologue"},
	    {"id": "php-003", "check": "cookie_prefixe_normalise"}]},
	  "roundcube": {"mode": "detect", "structural": [
	    {"id": "rc-001", "check": "rc_from_invalide"}]},
	  "inactive": {"mode": "detect", "enabled": false, "structural": [
	    {"id": "nc-005", "check": "nc_put_non_raster"}]}
	}}`))
	avant := parcoursRegles.Load()
	for i := 0; i < 10; i++ {
		ind := r.indicateurs()
		if !ind.structurelles || !ind.litRequete {
			t.Fatalf("indicateurs %+v : structurelles et litRequete attendus", ind)
		}
		if !ind.aControle("cookie_prefixe_normalise") || ind.aControle("sonde_php_cgi") {
			t.Errorf("aControle : cookie attendu, sonde_php_cgi non chargée")
		}
		if !ind.litCorps(corpsXML) || ind.litCorps(corpsDebut) || ind.litCorps(corpsUrlencoded) {
			t.Errorf("corps lus %b : XML seulement attendu parmi XML/début/urlencoded", ind.corps)
		}
		if ind.litCorps(corpsMultipart) {
			t.Errorf("multipart tenu pour lu : aucun contrôle multipart chargé")
		}
	}
	if n := parcoursRegles.Load() - avant; n != 0 {
		t.Errorf("catégories parcourues %d fois après le chargement, attendu 0", n)
	}
	var nilRules *Rules
	if ind := nilRules.indicateurs(); ind.structurelles || ind.litRequete || ind.corps != 0 {
		t.Errorf("règles nil : %+v, attendu tout faux", ind)
	}
}

// indicateursTous : tous les genres de corps lus (tests unitaires de
// corpsACapturer, qui ne chargent pas de règles).
var indicateursTous = &indicateursPHP{structurelles: true, litRequete: true, corps: 0xFF}

// M4 : une catégorie désactivée ne fait plus capturer le corps qu'elle seule
// lit. php_requete désactivée : un PROPFIND n'est pas capturé ; nc_put_non_raster
// absente : pas de début de PUT ; aucun contrôle urlencoded actif : pas de
// capture urlencoded (ni jeton). Le multipart, lu par php2shell, reste capturé.
func TestCorpsACapturerSuitLesControlesActifs(t *testing.T) {
	regles := LoadRules(ecrisRegles(t, `{"categories": {
	  "php2shell": {"mode": "detect", "structural": [
	    {"id": "php2shell-001", "check": "upload_progress_fichiers", "params": {"fichiers_apres_min": 2}}]},
	  "php_requete": {"mode": "detect", "enabled": false, "structural": [
	    {"id": "php-002", "check": "xml_dtd_prologue"}]},
	  "nextcloud": {"mode": "detect", "enabled": false, "structural": [
	    {"id": "nc-005", "check": "nc_put_non_raster"}]},
	  "roundcube": {"mode": "detect", "enabled": false, "structural": [
	    {"id": "rc-003", "check": "rc_crlf_envoi"}]}
	}}`))
	ind := regles.indicateurs()
	s := &Server{}
	cas := []struct {
		nom, methode, chemin, ct string
		genre                    genreCorps
	}{
		{"PROPFIND", "PROPFIND", "/remote.php/dav/files/alice/", "application/xml", corpsAucun},
		{"PUT raster", http.MethodPut, "/remote.php/dav/files/alice/a.png", "image/png", corpsAucun},
		{"urlencoded", http.MethodPost, "/index.php", "application/x-www-form-urlencoded", corpsAucun},
		{"multipart", http.MethodPost, "/upload", ctTest, corpsMultipart},
	}
	for _, c := range cas {
		r := httptest.NewRequest(c.methode, "http://nc.example"+c.chemin, strings.NewReader("<?xml version=\"1.0\"?><!DOCTYPE x>"))
		r.Header.Set("Content-Type", c.ct)
		e := s.nouvelleEntreePHP(r, "nextcloud")
		if g, _, _ := s.corpsACapturer(r, e, ind); g != c.genre {
			t.Errorf("%s : genre %v, attendu %v", c.nom, g, c.genre)
		}
	}
}

// M3 : les signaux (compteurs du multipart, variables, from_bang) ne sont
// construits que pour une ligne : une détection, ou un multipart dont le
// statut n'est pas « analyse ». Un envoi ordinaire n'en paie pas le coût.
func TestSignauxConstruitsPourUneLigneSeulement(t *testing.T) {
	n := new(atomic.Int64)
	orig := signauxEntreePHP
	signauxEntreePHP = func(e *EntreePHP) map[string]int { n.Add(1); return orig(e) }
	t.Cleanup(func() { signauxEntreePHP = orig })
	b := nouveauBancMultipart(t, nil)
	ordinaire := fabriquerMultipart("BND", []partieTest{
		{nom: "titre", contenu: "vacances"},
		{nom: "f1", filename: "photo.jpg", fichier: true, contenu: "y"},
	}, false)
	b.envoyer("nc.example", "/upload", ipPublique, ctTest, bytes.NewReader(ordinaire))
	b.verifierRecu(t, ordinaire)
	if ls := b.lignes(t); len(ls) != 0 {
		t.Fatalf("aucune ligne attendue, eu %v", ls)
	}
	if v := n.Load(); v != 0 {
		t.Errorf("signaux construits %d fois sans ligne, attendu 0", v)
	}
	b.envoyer("nc.example", "/upload", ipPublique, ctTest, bytes.NewReader(corpsExploit()))
	if d := lignesDe(b.lignes(t), "php2shell"); len(d) != 1 {
		t.Fatalf("une détection php2shell attendue, eu %v", b.lignes(t))
	}
	if v := n.Load(); v != 1 {
		t.Errorf("signaux construits %d fois pour une détection, attendu 1", v)
	}
}
