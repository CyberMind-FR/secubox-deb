// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// #1066 phase A — la vitrine des billets doit montrer le CONTENU REEL du
// module billets, pas seulement les fils publies depuis le BBS.
package web

import (
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// serveurBillets ouvre un serveur HTTP sur une socket unix, pour imiter le
// module billets tel que le BBS lui parle en production (jamais un port TCP,
// voir internal/billets/client.go). Ferme automatiquement a la fin du test.
func serveurBillets(t *testing.T, corps string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "billets.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(corps))
		})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func TestVitrineBilletsSansSocketRendUnePanneDite(t *testing.T) {
	// module billets non configure (Options.BilletsSocket vide) : la page ne
	// doit pas pretendre qu'il n'y a « aucun billet », elle doit dire que le
	// module n'est pas raccorde.
	srv, _ := banc(t)
	bs, panne := srv.vitrineBillets()
	if bs != nil {
		t.Errorf("Billets = %v, veut nil", bs)
	}
	if panne == "" {
		t.Fatal("aucune panne rendue alors que BilletsSocket est vide")
	}
	if strings.Contains(panne, "aucun") {
		t.Errorf("la panne %q se lit comme un vide normal, pas comme une panne", panne)
	}
}

func TestVitrineBilletsFluxInjoignableRendUnePanneDite(t *testing.T) {
	// La socket est configuree mais AUCUN service n'ecoute derriere : c'est
	// le cas « billets.gk2 est en panne ». Le gestionnaire ne doit pas
	// planter, et ne doit pas afficher une liste vide comme si de rien
	// n'etait.
	root := t.TempDir()
	s, err := store.Open(filepath.Join(root, "bbs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	srv, err := New(s, nil, Options{Titre: "Banc", Secrets: filepath.Join(root, "secrets"),
		BilletsSocket: filepath.Join(root, "absente.sock")})
	if err != nil {
		t.Fatal(err)
	}

	bs, panne := srv.vitrineBillets()
	if bs != nil {
		t.Errorf("Billets = %v, veut nil", bs)
	}
	if panne == "" {
		t.Fatal("aucune panne rendue alors que le flux est injoignable")
	}
}

func TestVitrineBilletsListeLeFluxEtCroiseLeFilOrigine(t *testing.T) {
	// Deux billets dans le flux : l'un a ete publie depuis un fil du BBS
	// (billet_id enregistre par MarkPublished), l'autre a ete ecrit
	// directement chez billets. La vitrine doit distinguer les deux SANS
	// perdre le second — c'est precisement ce que cartesBillets ratait.
	sock := serveurBillets(t, `{"items":[
		{"id":"depuis-bbs","title":"Un fil devenu billet","url":"/b/un-fil-devenu-billet",
		 "summary":"resume ignore au profit du contenu","content_html":"<p>Corps <b>reel</b> du billet, ecrit en plusieurs phrases pour verifier l'extrait.</p>",
		 "date_published":"2026-08-01T10:00:00Z"},
		{"id":"ecrit-chez-billets","title":"Ecrit directement chez billets","url":"/b/ecrit-directement",
		 "summary":"","content_html":"<p>Jamais passe par un fil du BBS.</p>",
		 "date_published":"2026-08-02T10:00:00Z"}
	]}`)

	root := t.TempDir()
	s, err := store.Open(filepath.Join(root, "bbs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	uid, err := s.CreateUser("gk2", "Gandalf", store.RoleSysop)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := s.CreateCategory("atelier", "Atelier", "")
	if err != nil {
		t.Fatal(err)
	}
	fil, err := s.NewThread(cat, uid, "Un fil devenu billet", "corps", store.VisPublic)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkPublished(fil, "depuis-bbs", "/b/un-fil-devenu-billet", 3, 1); err != nil {
		t.Fatal(err)
	}

	srv, err := New(s, nil, Options{Titre: "Banc", Secrets: filepath.Join(root, "secrets"),
		BilletsSocket: sock, BilletsBase: "https://billets.gk2.secubox.in"})
	if err != nil {
		t.Fatal(err)
	}

	bs, panne := srv.vitrineBillets()
	if panne != "" {
		t.Fatalf("panne inattendue : %s", panne)
	}
	if len(bs) != 2 {
		t.Fatalf("len(Billets) = %d, veut 2 — un billet ecrit hors BBS a disparu", len(bs))
	}

	var depuisFil, horsBBS *billetVue
	for i := range bs {
		switch bs[i].Titre {
		case "Un fil devenu billet":
			depuisFil = &bs[i]
		case "Ecrit directement chez billets":
			horsBBS = &bs[i]
		}
	}
	if depuisFil == nil || horsBBS == nil {
		t.Fatalf("titres inattendus : %+v", bs)
	}

	if !depuisFil.DepuisFil || depuisFil.ThreadID != fil {
		t.Errorf("croisement manque : DepuisFil=%v ThreadID=%d, veut true et %d",
			depuisFil.DepuisFil, depuisFil.ThreadID, fil)
	}
	if depuisFil.Lien != "https://billets.gk2.secubox.in/b/un-fil-devenu-billet" {
		t.Errorf("Lien = %q, l'adresse relative n'a pas ete resolue via BilletsBase", depuisFil.Lien)
	}
	if !strings.Contains(depuisFil.Resume, "Corps") {
		t.Errorf("Resume = %q, veut le contenu reel plutot que le resume", depuisFil.Resume)
	}

	// LE BILLET ECRIT HORS BBS EST LA RAISON D'ETRE DE CETTE PHASE : c'est
	// exactement celui que cartesBillets ne montrait jamais.
	if horsBBS.DepuisFil {
		t.Error("un billet ecrit directement chez billets est faussement marque DepuisFil")
	}
	if horsBBS.Lien != "https://billets.gk2.secubox.in/b/ecrit-directement" {
		t.Errorf("Lien = %q", horsBBS.Lien)
	}
}

func TestExtraitCoupeSurUneFrontiereDeMot(t *testing.T) {
	long := strings.Repeat("mot ", 100) // 400 caracteres
	e := extrait(long, 20)
	if strings.HasSuffix(e, "mo…") || strings.HasSuffix(e, "m…") {
		t.Errorf("extrait a coupe en plein mot : %q", e)
	}
	if !strings.HasSuffix(e, "…") {
		t.Errorf("extrait tronque devrait se terminer par … : %q", e)
	}
	court := "texte court"
	if extrait(court, 300) != court {
		t.Errorf("extrait a modifie un texte plus court que la borne : %q", extrait(court, 300))
	}
}
