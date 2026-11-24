// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"testing"
)

// Les fiches par source vivent 48 h, une campagne dure des jours : une adresse
// dont la fiche est partie n'a PAS de classe connue, elle n'est pas « inconnu ».
// Les parts se calculent sur les seules adresses qui ont une fiche (#3919).

// oublier retire les fiches des adresses pour lesquelles garder rend false.
func oublier(s *Server, garder func(ip string) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ip := range s.sources {
		if !garder(ip) {
			delete(s.sources, ip)
		}
	}
	return len(s.sources)
}

func TestPartsSurLesSeulesFiches(t *testing.T) {
	s := serveurRotation(t)
	// 60 sources dont 50 proxy_loue : on oublie 10 fiches proxy_loue / US.
	i := 0
	if n := oublier(s, func(ip string) bool {
		f := s.sources[ip]
		if i < 10 && f.asn == 212238 && string(f.pays[:]) == "US" {
			i++
			return false
		}
		return true
	}); n != 50 {
		t.Fatalf("précondition : %d fiches, attendu 50", n)
	}
	cs := s.campagnes()
	if len(cs) != 1 {
		t.Fatalf("attendu 1 campagne, obtenu %d", len(cs))
	}
	c := cs[0]
	if c.Sources != 60 {
		t.Errorf("sources = %d, attendu 60 (toutes les adresses de la campagne)", c.Sources)
	}
	if c.Classes["proxy_loue"] != 80 || c.Classes["inconnu"] != 20 {
		t.Errorf("classes = %v, attendu proxy_loue 80 / inconnu 20 (40 et 10 sur 50 fiches)", c.Classes)
	}
	if len(c.PaysTop) != 2 || c.PaysTop[0] != (PaysPart{Code: "US", Part: 60}) ||
		c.PaysTop[1] != (PaysPart{Code: "GB", Part: 40}) {
		t.Errorf("pays_top = %+v, attendu US 60 / GB 40", c.PaysTop)
	}
	if c.Une == nil || *c.Une != 100 || c.Le3 == nil || *c.Le3 != 100 {
		t.Errorf("une/le3 = %v/%v, attendu 100/100", c.Une, c.Le3)
	}
	if !c.Rotation {
		t.Error("rotation attendue : 50 fiches, toutes à une tentative")
	}
}

// TestRotationExigeCinquanteFiches : 60 adresses dont 49 fiches → le détecteur
// n'a pas assez d'adresses mesurées, même à 100 %.
func TestRotationExigeCinquanteFiches(t *testing.T) {
	s := serveurRotation(t)
	i := 0
	if n := oublier(s, func(string) bool { i++; return i > 11 }); n != 49 {
		t.Fatalf("précondition : %d fiches, attendu 49", n)
	}
	c := s.campagnes()[0]
	if c.Sources != 60 || c.Le3 == nil || *c.Le3 != 100 {
		t.Fatalf("sources = %d, le3 = %v, attendu 60 et 100", c.Sources, c.Le3)
	}
	if c.Rotation {
		t.Error("rotation vraie sur 49 fiches, 50 exigées")
	}
}

// TestAucuneFiche : rien n'est mesuré → les parts sont ABSENTES (jamais 0 ni
// « inconnu 100 % »), dans les deux vues ; la campagne reste listée.
func TestAucuneFiche(t *testing.T) {
	s := serveurRotation(t)
	oublier(s, func(string) bool { return false })
	for _, vue := range []*string{complete, nil} {
		w := appel(t, s, "GET", "/campaigns", vue, "")
		var out []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if len(out) != 1 {
			t.Fatalf("attendu 1 campagne, obtenu %d", len(out))
		}
		for _, k := range []string{"classes", "pays_top", "une", "le3"} {
			if v, ok := out[0][k]; ok {
				t.Errorf("%s = %v présent sans aucune fiche", k, v)
			}
		}
		if out[0]["rotation"] != false {
			t.Errorf("rotation = %v, attendu false", out[0]["rotation"])
		}
		if out[0]["sources"] != float64(60) {
			t.Errorf("sources = %v, attendu 60", out[0]["sources"])
		}
		// La page Actor choisit la carte sur « famille » : elle reste présente.
		if out[0]["famille"] != "autre" {
			t.Errorf("famille = %v, attendu autre", out[0]["famille"])
		}
	}
}

// TestPartsNullesPresentes : une part mesurée à 0 n'est pas une part absente.
func TestPartsNullesPresentes(t *testing.T) {
	s := serveurRotation(t)
	s.mu.Lock()
	for _, f := range s.sources {
		f.evts = 9
		f.pays = [2]byte{}
	}
	s.mu.Unlock()
	w := appel(t, s, "GET", "/campaigns", complete, "")
	var out []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out[0]["une"] != float64(0) || out[0]["le3"] != float64(0) || out[0]["rotation"] != false {
		t.Errorf("une/le3/rotation = %v/%v/%v, attendu 0/0/false", out[0]["une"], out[0]["le3"], out[0]["rotation"])
	}
}
