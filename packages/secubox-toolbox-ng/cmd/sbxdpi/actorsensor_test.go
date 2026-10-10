// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
)

type fauxEmetteur struct{ recus []*envelope.Envelope }

func (f *fauxEmetteur) Emit(e *envelope.Envelope) bool { f.recus = append(f.recus, e); return true }

func evRisque(src string, flow uint64, port int, risques ...string) *dpiEvent {
	ev := &dpiEvent{FlowEventName: "detected", FlowID: flow, L4Proto: "tcp", SrcIP: src, DstIP: "192.168.1.200", SrcPort: 40000, DstPort: port}
	ev.NDPI.Proto = "TLS.Unknown"
	ev.NDPI.JA4 = "t13d1516h2_8daaf6152771_b186095e22b6"
	ev.NDPI.FlowRisk = map[string]struct {
		Risk     string `json:"risk"`
		Severity string `json:"severity"`
	}{}
	for i, r := range risques {
		ev.NDPI.FlowRisk[fmt.Sprint(i)] = struct {
			Risk     string `json:"risk"`
			Severity string `json:"severity"`
		}{Risk: r, Severity: "High"}
	}
	return ev
}

func capteur(fe *fauxEmetteur) *ActorSensor {
	s := NewActorSensor(fe, parseRisquesCapteur(""))
	t := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return t }
	return s
}

func TestRisquesParDefautEtSurcharge(t *testing.T) {
	d := parseRisquesCapteur("")
	if d["Malicious Fingerprint"] != 3 || d["Probing Attempt"] != 1 || d["Known Proto on Non Std Port"] != 0 {
		t.Fatalf("défauts inattendus : %v", d)
	}
	m := parseRisquesCapteur("Probing Attempt=4, Foo Bar=2, mauvais, X=abc")
	if m["Probing Attempt"] != 4 || m["Foo Bar"] != 2 || len(m) != 2 {
		t.Fatalf("surcharge attendue sans entrées invalides : %v", m)
	}
}

func TestPasDeSignalSousLeSeuil(t *testing.T) {
	fe := &fauxEmetteur{}
	s := capteur(fe)
	for i := 0; i < 5; i++ {
		s.Observe(evRisque("203.0.113.9", uint64(i), 443, "Probing Attempt")) // score 5 < 6
	}
	if len(fe.recus) != 0 {
		t.Fatalf("aucune enveloppe sous le seuil : %d", len(fe.recus))
	}
}

func TestEnveloppeAuSeuilDepuisUneAdressePublique(t *testing.T) {
	fe := &fauxEmetteur{}
	s := capteur(fe)
	s.Observe(evRisque("93.184.216.34", 1, 443, "Malicious Fingerprint"))
	s.Observe(evRisque("93.184.216.34", 2, 8443, "Malicious Fingerprint", "HTTP Susp User-Agent"))
	if len(fe.recus) != 1 {
		t.Fatalf("une enveloppe attendue, obtenu %d", len(fe.recus))
	}
	e := fe.recus[0]
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	if e.Sensor != envelope.SensorDPI || e.SrcIP != "93.184.216.34" || e.Action != envelope.ActionObserve || e.Protocol != "tls" || e.Transport != "tcp" {
		t.Fatalf("enveloppe inattendue : %+v", e)
	}
	if !strings.HasPrefix(e.RuleID, "dpi.risk.malicious") || e.DstService != "ports:2" || e.TLSFingerprint == "" || e.Severity < 35 || e.Severity > 100 {
		t.Fatalf("règle, ports, JA4 et gravité attendus : %+v", e)
	}
	if !strings.Contains(strings.Join(e.BehaviorTags, ","), "dpi_risk") {
		t.Fatalf("étiquette dpi_risk attendue : %v", e.BehaviorTags)
	}
}

func TestUnMemeFluxNeCompteQuUneFois(t *testing.T) {
	fe := &fauxEmetteur{}
	s := capteur(fe)
	for i := 0; i < 10; i++ { // détecté, mis à jour, terminé : le même flux
		s.Observe(evRisque("93.184.216.34", 7, 443, "Malicious Fingerprint"))
	}
	if len(fe.recus) != 0 {
		t.Fatalf("un seul flux (score 3) ne passe pas le seuil de 6 : %d", len(fe.recus))
	}
}

func TestJamaisUneAdressePriveeLocaleOuLaBoxElleMeme(t *testing.T) {
	fe := &fauxEmetteur{}
	s := capteur(fe)
	for _, ip := range []string{"192.168.1.60", "10.100.0.5", "127.0.0.1", "fe80::1", "169.254.1.1", "100.64.0.9"} {
		for i := 0; i < 5; i++ {
			s.Observe(evRisque(ip, uint64(i), 443, "Malicious Fingerprint"))
		}
	}
	if len(fe.recus) != 0 {
		t.Fatalf("aucune adresse non publique ne peut être un acteur DPI : %d", len(fe.recus))
	}
}

func TestRisquesBanalsNeComptentPas(t *testing.T) {
	fe := &fauxEmetteur{}
	s := capteur(fe)
	for i := 0; i < 200; i++ {
		s.Observe(evRisque("93.184.216.34", uint64(i), 443, "Known Proto on Non Std Port", "Error Code", "Susp Entropy"))
	}
	if len(fe.recus) != 0 {
		t.Fatalf("les risques banals (bruit) ne font aucun signal : %d", len(fe.recus))
	}
}

func TestPasDeRepetitionSaufAggravation(t *testing.T) {
	fe := &fauxEmetteur{}
	s := capteur(fe)
	for i := 0; i < 6; i++ {
		s.Observe(evRisque("93.184.216.34", uint64(i), 443, "Probing Attempt"))
	}
	n := len(fe.recus)
	s.Observe(evRisque("93.184.216.34", 100, 443, "Probing Attempt"))
	if n != 1 || len(fe.recus) != 1 {
		t.Fatalf("une enveloppe puis pas de répétition : %d puis %d", n, len(fe.recus))
	}
	for i := 200; i < 212; i++ { // le score double : on ré-émet
		s.Observe(evRisque("93.184.216.34", uint64(i), 443, "Probing Attempt"))
	}
	if len(fe.recus) != 2 {
		t.Fatalf("une aggravation (×2) se ré-émet : %d", len(fe.recus))
	}
}

func TestLaFenetreSeRenouvelle(t *testing.T) {
	fe := &fauxEmetteur{}
	s := capteur(fe)
	t0 := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return t0 }
	for i := 0; i < 3; i++ {
		s.Observe(evRisque("93.184.216.34", uint64(i), 443, "Probing Attempt"))
	}
	s.now = func() time.Time { return t0.Add(11 * time.Minute) } // hors fenêtre : le compte repart de zéro
	for i := 10; i < 13; i++ {
		s.Observe(evRisque("93.184.216.34", uint64(i), 443, "Probing Attempt"))
	}
	if len(fe.recus) != 0 {
		t.Fatalf("3 + 3 flux séparés de 11 min ne s'additionnent pas : %d", len(fe.recus))
	}
}

func TestMemoireBornee(t *testing.T) {
	fe := &fauxEmetteur{}
	s := capteur(fe)
	for i := 0; i < 20000; i++ {
		s.Observe(evRisque(fmt.Sprintf("8.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255), uint64(i), 443, "Probing Attempt"))
	}
	if s.suivies() > maxSourcesCapteur {
		t.Fatalf("sources suivies plafonnées : %d", s.suivies())
	}
}

func TestSansEmetteurNeFaitRien(t *testing.T) {
	s := NewActorSensor(nil, parseRisquesCapteur(""))
	s.Observe(evRisque("93.184.216.34", 1, 443, "Malicious Fingerprint", "Possible Exploit Attempt")) // ne panique pas
}

func TestUnRisqueReduitAuSilenceParLOperateurNeCompteJamais(t *testing.T) {
	fe := &fauxEmetteur{}
	s := capteur(fe)
	s.muet = func(r string) bool { return r == "Malicious Fingerprint" }
	for i := 0; i < 10; i++ {
		s.Observe(evRisque("93.184.216.34", uint64(i), 443, "Malicious Fingerprint"))
	}
	if len(fe.recus) != 0 {
		t.Fatalf("un risque muet ne produit aucun signal : %d", len(fe.recus))
	}
}
