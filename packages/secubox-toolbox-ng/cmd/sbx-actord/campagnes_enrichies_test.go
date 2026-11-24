// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reseau"
)

// annuaireEssai : catalogue minimal (212238 = proxy loué), sans base mmdb.
func annuaireEssai(t testing.TB) *reseau.Annuaire {
	t.Helper()
	cat := filepath.Join(t.TempDir(), "classes.toml")
	if err := os.WriteFile(cat, []byte("[classes]\nproxy_loue = [212238]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := reseau.Ouvrir("", cat)
	t.Cleanup(a.Close)
	return a
}

// serveurRotation : 60 sources distinctes (plage de documentation), un
// événement chacune, 50 sur l'ASN 212238, pays US×40 / GB×20, catégorie
// aspirateur_ua, toutes sur forge.exemple.test.
func serveurRotation(t *testing.T) *Server {
	t.Helper()
	s := serveur(t)
	s.annuaire = annuaireEssai(t)
	now := time.Now().Unix()
	for i := 0; i < 60; i++ {
		e := &envelope.Envelope{
			EventID: envelope.NewEventID(), Timestamp: now - int64(i),
			Sensor: envelope.SensorWAF, SrcIP: fmt.Sprintf("203.0.113.%d", i+1),
			DstService: "forge.exemple.test", Vhost: "forge.exemple.test",
			Action: envelope.ActionObserve, Severity: 40,
			PathShape: "/depot/{id}", UserAgentFamily: "aspirateur",
			BehaviorTags: []string{"aspirateur_ua"},
		}
		if i < 50 {
			e.ASN = 212238
		}
		if i < 40 {
			e.GeoCountry = "US"
		} else {
			e.GeoCountry = "GB"
		}
		if err := e.Validate(); err != nil {
			t.Fatalf("enveloppe d'essai invalide : %v", err)
		}
		s.correlate(e)
	}
	return s
}

func TestCampagneEnrichie(t *testing.T) {
	s := serveurRotation(t)
	w := appel(t, s, "GET", "/campaigns", complete, "")
	if w.Code != 200 {
		t.Fatalf("code %d", w.Code)
	}
	var out []struct {
		Sources    int            `json:"sources"`
		Famille    string         `json:"famille"`
		CiblesNoms []string       `json:"cibles_noms"`
		Classes    map[string]int `json:"classes"`
		PaysTop    []PaysPart     `json:"pays_top"`
		Une        int            `json:"une"`
		Le3        int            `json:"le3"`
		Rotation   bool           `json:"rotation"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("attendu 1 campagne, obtenu %d : %s", len(out), w.Body.String())
	}
	c := out[0]
	if c.Sources != 60 {
		t.Errorf("sources = %d, attendu 60", c.Sources)
	}
	if c.Famille != "collecte" {
		t.Errorf("famille = %q, attendu collecte", c.Famille)
	}
	if len(c.CiblesNoms) != 1 || c.CiblesNoms[0] != "forge.exemple.test" {
		t.Errorf("cibles_noms = %v", c.CiblesNoms)
	}
	if c.Classes["proxy_loue"] != 83 || c.Classes["inconnu"] != 17 {
		t.Errorf("classes = %v, attendu proxy_loue 83 / inconnu 17", c.Classes)
	}
	if len(c.PaysTop) != 2 || c.PaysTop[0] != (PaysPart{Code: "US", Part: 67}) ||
		c.PaysTop[1] != (PaysPart{Code: "GB", Part: 33}) {
		t.Errorf("pays_top = %+v", c.PaysTop)
	}
	if c.Une != 100 || c.Le3 != 100 {
		t.Errorf("une = %d, le3 = %d, attendu 100/100", c.Une, c.Le3)
	}
	if !c.Rotation {
		t.Error("rotation attendue (le3 >= 80 et sources >= 50)")
	}
}

func TestVueReduiteSansCiblesNoms(t *testing.T) {
	s := serveurRotation(t)
	for _, p := range prefixes {
		w := appel(t, s, "GET", p+"/campaigns", nil, "")
		var out []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if len(out) != 1 {
			t.Fatalf("%s : attendu 1 campagne, obtenu %d", p, len(out))
		}
		if _, ok := out[0]["cibles_noms"]; ok {
			t.Errorf("%s : cibles_noms présent dans la vue réduite", p)
		}
		for _, k := range []string{"famille", "classes", "pays_top", "une", "le3", "rotation"} {
			if _, ok := out[0][k]; !ok {
				t.Errorf("%s : clé %q absente de la vue réduite", p, k)
			}
		}
		sansDonneeInterne(t, p+"/campaigns", w.Body.Bytes())
	}
}

// TestRotationSeuils : peu de sources, ou des sources insistantes, ne sont
// pas une rotation ; un compte visé est masqué dans cibles_noms.
func TestRotationSeuils(t *testing.T) {
	s := serveur(t)
	s.annuaire = annuaireEssai(t)
	now := time.Now().Unix()
	for i := 0; i < 10; i++ {
		for j := 0; j < 5; j++ { // 5 événements par source : ni « une », ni « le3 »
			e := &envelope.Envelope{
				EventID: envelope.NewEventID(), Timestamp: now - int64(i*10+j),
				Sensor: envelope.SensorAuthWatch, SrcIP: fmt.Sprintf("198.51.100.%d", i+1),
				DstService: "compte.essai@exemple.test", RuleID: "auth_smtp_bruteforce",
				BehaviorTags: []string{"auth_smtp_bruteforce"}, Severity: 50,
			}
			s.correlate(e)
		}
	}
	cs := s.campagnes()
	if len(cs) != 1 {
		t.Fatalf("attendu 1 campagne, obtenu %d", len(cs))
	}
	c := cs[0]
	if c.Rotation || c.Une != 0 || c.Le3 != 0 {
		t.Errorf("rotation=%v une=%d le3=%d, attendu false/0/0", c.Rotation, c.Une, c.Le3)
	}
	if c.Famille != "messagerie" {
		t.Errorf("famille = %q, attendu messagerie", c.Famille)
	}
	if len(c.CiblesNoms) != 1 || c.CiblesNoms[0] != "com…" {
		t.Errorf("cibles_noms = %v, attendu [com…]", c.CiblesNoms)
	}
	if c.Classes["inconnu"] != 100 || len(c.PaysTop) != 0 {
		t.Errorf("classes = %v, pays_top = %v", c.Classes, c.PaysTop)
	}
}

// serveurGrand : une campagne de nbActeurs acteurs distincts (une adresse,
// une empreinte TLS chacun), sources à l'échelle de la plus grosse campagne
// vue sur gk2 (≈ 5 sources par acteur).
func serveurGrand(t testing.TB, nbActeurs int) *Server {
	t.Helper()
	// observe ne touche pas au magasin : un serveur sans store suffit.
	s := &Server{shadow: true, graph: graph.New(0), accum: map[string]*actorSignals{}}
	s.annuaire = annuaireEssai(t)
	now := time.Now().Unix()
	for i := 0; i < nbActeurs; i++ {
		for k := 0; k < 5; k++ {
			e := &envelope.Envelope{
				EventID: envelope.NewEventID(), Timestamp: now - int64(i),
				Sensor: envelope.SensorWAF, SrcIP: fmt.Sprintf("2001:db8:%x::%x", i, k+1),
				DstService: "forge.exemple.test", BehaviorTags: []string{"scanners"},
				TLSFingerprint: fmt.Sprintf("t13d%06d", i), UserAgentFamily: fmt.Sprintf("outil-%d", i),
				PathShape: fmt.Sprintf("/p%d", i), CredentialTokenHash: fmt.Sprintf("h%d", i),
				ASN: uint32(64496 + i%3), GeoCountry: []string{"US", "GB", "DE", "FR"}[i%4],
				Severity: 40,
			}
			s.observe(e)
		}
	}
	return s
}

// TestEnrichissementRapide : l'enrichissement d'une campagne de 1 000 acteurs
// ne relit pas le magasin et tient sous 50 ms.
func TestEnrichissementRapide(t *testing.T) {
	s := serveurGrand(t, 1000)
	debut := time.Now()
	cs := s.campagnes()
	duree := time.Since(debut)
	if len(cs) != 1 || cs[0].NbActeurs < 1000 {
		n := 0
		if len(cs) > 0 {
			n = cs[0].NbActeurs
		}
		t.Fatalf("précondition : 1 campagne de 1 000 acteurs attendue, %d campagne(s), %d acteurs", len(cs), n)
	}
	if duree > 50*time.Millisecond {
		t.Errorf("campagnes() en %s pour %d acteurs / %d sources, attendu < 50 ms", duree, cs[0].NbActeurs, cs[0].Sources)
	}
}

func BenchmarkCampagnesEnrichies(b *testing.B) {
	s := serveurGrand(b, 1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.campagnes()
	}
}
