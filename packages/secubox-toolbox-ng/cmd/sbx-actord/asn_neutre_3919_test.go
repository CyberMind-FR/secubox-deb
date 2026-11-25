// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
)

// L'ASN posé dans l'enveloppe depuis #3919 sert les VUES, jamais la décision :
// deux flux qui ne diffèrent que par lui donnent le même graphe, les mêmes
// scores, les mêmes mesures et les mêmes propositions de ban, en direct comme au
// rejeu des événements déjà en base.

// fluxAvecASN : deux vagues d'adresses tournantes qui partagent peu d'axes (le
// cas où +5 d'ASN fait basculer un rattachement et un 3e signal concordant la
// confiance), répétées pour accumuler des scores. asn=false : le même, sans ASN.
func fluxAvecASN(now int64, asn bool) []*envelope.Envelope {
	var out []*envelope.Envelope
	for i := 0; i < 40; i++ {
		e := &envelope.Envelope{
			EventID: fmt.Sprintf("evt-%03d", i), Timestamp: now - 4000 + int64(i*90),
			Sensor: envelope.SensorWAF, SrcIP: fmt.Sprintf("203.0.113.%d", i%8+1),
			DstService: []string{"a.exemple.test", "b.exemple.test", "c.exemple.test"}[i%3],
			Action:     envelope.ActionBlock, Severity: 80 + i%15,
			PathShape: fmt.Sprintf("/p%d", i%5), UserAgentFamily: []string{"python-requests", "curl", ""}[i%3],
			GeoCountry: []string{"US", "GB"}[i%2], BehaviorTags: []string{"sqli", "high_value_probe", "k3"},
		}
		if i%4 == 0 {
			e.UserAgentFamily, e.PathShape = "", ""
		}
		if i%5 == 0 { // second capteur : sans lui, aucune mesure forte
			e.Sensor, e.RuleID, e.DstService = envelope.SensorDPI, "dpi.risk.malicious_fingerprint", ""
		}
		if asn {
			e.ASN = uint32(64496 + i%2)
		}
		out = append(out, e)
	}
	return out
}

type decision struct {
	Acteurs      string
	Campagnes    string
	Mesures      string
	Propositions string
	Confiances   []int
}

func decisionDe(t *testing.T, s *Server, now int64) decision {
	t.Helper()
	j := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	m, err := s.recalculerMesures(now)
	if err != nil {
		t.Fatal(err)
	}
	d := decision{Mesures: j(m), Propositions: j(s.propositions()), Acteurs: j(s.graph.Actors())}
	for _, a := range s.graph.Actors() {
		d.Confiances = append(d.Confiances, a.Vector.Confidence)
	}
	type lien struct {
		Sig     string
		Acteurs []string
		P, C    int
	}
	var ls []lien
	for _, c := range s.campagnes() {
		ls = append(ls, lien{c.Signature, c.Acteurs, c.Priorite, c.Continuite})
	}
	d.Campagnes = j(ls)
	return d
}

func TestASNNeChangeAucuneDecision(t *testing.T) {
	now := time.Now().Unix()
	var ref, avec [2]decision // [direct, rejeu]
	for k, asn := range []bool{false, true} {
		s := serveur(t)
		for _, e := range fluxAvecASN(now, asn) {
			if err := e.Validate(); err != nil {
				t.Fatal(err)
			}
			if err := s.store.Ingest(e); err != nil {
				t.Fatal(err)
			}
			s.correlate(e)
		}
		direct := decisionDe(t, s, now)
		// Redémarrage : le graphe est reconstruit depuis les événements STOCKÉS,
		// qui portent l'ASN.
		r := serveur(t)
		r.store = s.store
		r.rebuild()
		rejeu := decisionDe(t, r, now)
		if k == 0 {
			ref = [2]decision{direct, rejeu}
		} else {
			avec = [2]decision{direct, rejeu}
		}
	}
	if len(ref[0].Confiances) == 0 || ref[0].Mesures == "null" {
		t.Fatalf("précondition : %d acteurs, mesures %s", len(ref[0].Confiances), ref[0].Mesures)
	}
	for i, nom := range []string{"direct", "rejeu"} {
		if !reflect.DeepEqual(ref[i], avec[i]) {
			t.Errorf("%s : l'ASN change la décision\nsans %+v\navec %+v", nom, ref[i], avec[i])
		}
	}
}

// TestASNSertToujoursLesVues : la classe de réseau vient des fiches par source.
func TestASNSertToujoursLesVues(t *testing.T) {
	s := serveurRotation(t)
	if c := s.campagnes()[0]; c.Classes["proxy_loue"] != 83 {
		t.Errorf("classes = %v", c.Classes)
	}
	for _, a := range s.graph.Actors() {
		if len(a.ASNs) != 0 {
			t.Errorf("ASN dans le graphe de corrélation : %v", a.ASNs)
		}
	}
}
