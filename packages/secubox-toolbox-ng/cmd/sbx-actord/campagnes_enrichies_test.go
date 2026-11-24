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
	"runtime"
	"strings"
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
	if c.Rotation || c.Une == nil || *c.Une != 0 || c.Le3 == nil || *c.Le3 != 0 {
		t.Errorf("rotation=%v une=%v le3=%v, attendu false/0/0", c.Rotation, c.Une, c.Le3)
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

// TestCompteAuthwatchMasque : une cible d'authwatch est un compte par son
// origine, même sans « @ » : « root » sort masqué par reseau.MasquerCompte
// (« roo… » : plus de 3 caractères, les 3 premiers restent).
func TestCompteAuthwatchMasque(t *testing.T) {
	s := serveur(t)
	s.annuaire = annuaireEssai(t)
	now := time.Now().Unix()
	for i := 0; i < 2; i++ {
		s.correlate(&envelope.Envelope{
			EventID: envelope.NewEventID(), Timestamp: now - int64(i),
			Sensor: envelope.SensorAuthWatch, SrcIP: fmt.Sprintf("198.51.100.%d", i+1),
			DstService: "root", RuleID: "auth_ssh_bruteforce", Severity: 50,
		})
	}
	cs := s.campagnes()
	if len(cs) != 1 {
		t.Fatalf("attendu 1 campagne, obtenu %d", len(cs))
	}
	if got := cs[0].CiblesNoms; len(got) != 1 || got[0] != reseau.MasquerCompte("root") || got[0] == "root" {
		t.Errorf("cibles_noms = %v, attendu [%s]", got, reseau.MasquerCompte("root"))
	}
	for _, f := range s.sources {
		if f.cible == "root" {
			t.Error("la fiche garde le compte en clair")
		}
	}
	if cs[0].Famille != "acces_distant" {
		t.Errorf("famille = %q, attendu acces_distant", cs[0].Famille)
	}
}

func evtSource(ip string, ts int64, cible string) *envelope.Envelope {
	return &envelope.Envelope{
		EventID: "e", Timestamp: ts, Sensor: envelope.SensorWAF, SrcIP: ip,
		DstService: cible, ASN: 64496, GeoCountry: "US", BehaviorTags: []string{"scanners"},
	}
}

// TestPlafondSourcesEviction : plein, le registre évince les fiches les plus
// anciennes (par dernier), jamais la nouvelle, et ne dépasse pas le plafond.
func TestPlafondSourcesEviction(t *testing.T) {
	s := &Server{sourcesMax: 100}
	now := time.Now().Unix()
	for i := 0; i < 100; i++ { // la fiche i a dernier = now-1000+i : 0 est la plus ancienne
		s.noterSource(evtSource(fmt.Sprintf("203.0.113.%d", i), now-1000+int64(i), "forge.exemple.test"))
	}
	if len(s.sources) != 100 {
		t.Fatalf("précondition : %d fiches", len(s.sources))
	}
	s.noterSource(evtSource("198.51.100.1", now, "forge.exemple.test"))
	if len(s.sources) > 100 {
		t.Fatalf("%d fiches, plafond 100 dépassé", len(s.sources))
	}
	if s.sources["198.51.100.1"] == nil {
		t.Error("la nouvelle adresse doit être retenue")
	}
	for i := 0; i < 10; i++ { // 10 % du plafond évincés : les 10 plus anciennes
		if s.sources[fmt.Sprintf("203.0.113.%d", i)] != nil {
			t.Errorf("203.0.113.%d (ancienne) aurait dû être évincée", i)
		}
	}
	if s.sources["203.0.113.10"] == nil || s.sources["203.0.113.99"] == nil {
		t.Error("les fiches récentes doivent rester")
	}
	// Une adresse connue ne déclenche aucune éviction.
	avant := len(s.sources)
	s.noterSource(evtSource("203.0.113.50", now, "forge.exemple.test"))
	if len(s.sources) != avant {
		t.Error("une adresse déjà connue ne doit rien évincer")
	}
}

// TestRetentionSources : une fiche muette depuis plus de 48 h est oubliée ; un
// événement plus vieux que 48 h (rejeu) n'en crée pas.
func TestRetentionSources(t *testing.T) {
	s := &Server{}
	now := time.Now().Unix()
	s.noterSource(evtSource("203.0.113.1", now-49*3600, "forge.exemple.test"))
	if len(s.sources) != 0 {
		t.Error("un événement hors rétention ne doit pas créer de fiche")
	}
	s.noterSource(evtSource("203.0.113.2", now-47*3600, "forge.exemple.test"))
	s.noterSource(evtSource("203.0.113.3", now, "forge.exemple.test"))
	defer func(o func() int64) { maintenant = o }(maintenant)
	maintenant = func() int64 { return now + 2*3600 }
	s.purgerSources()
	if s.sources["203.0.113.2"] != nil || s.sources["203.0.113.3"] == nil {
		t.Errorf("purge 48 h incorrecte : %v", s.sources)
	}
}

// TestOctetsParFiche : coût mémoire d'une fiche à une cible (clé d'adresse,
// entrée de map et chaîne de cible comprises), mesuré sur 100 000 fiches.
func TestOctetsParFiche(t *testing.T) {
	const n = 100000
	s := &Server{}
	now := time.Now().Unix()
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	for i := 0; i < n; i++ {
		// Chaînes neuves, comme celles d'une enveloppe décodée ; l'enveloppe
		// devient ordure, seul ce que la fiche retient reste compté.
		s.noterSource(evtSource(fmt.Sprintf("2001:db8::%x:%x", i>>16, i&0xffff), now, strings.Clone("forge.exemple.test")))
	}
	runtime.GC()
	runtime.ReadMemStats(&m1)
	par := float64(m1.HeapAlloc-m0.HeapAlloc) / n
	t.Logf("%.0f octets par fiche (%d fiches)", par, len(s.sources))
	if par > 200 {
		t.Errorf("%.0f octets par fiche, attendu ≤ 200", par)
	}
	runtime.KeepAlive(s)
}
