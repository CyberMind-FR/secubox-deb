// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
)

// jsonEnsemble fabrique la sortie de `nft -j list set` (forme réelle, relevée sous nft 1.0.9).
func jsonEnsemble(timeout int, elems ...string) []byte {
	var e []string
	for _, x := range elems { // « ip:port:expire »
		p := strings.Split(x, "|")
		e = append(e, fmt.Sprintf(`{"elem":{"val":{"concat":["%s",%s]},"expires":%s}}`, p[0], p[1], p[2]))
	}
	return []byte(fmt.Sprintf(`{"nftables":[{"metainfo":{"version":"1.0.9"}},{"set":{"name":"s","timeout":%d,"elem":[%s]}}]}`, timeout, strings.Join(e, ",")))
}

func TestParseEnsembleScan_AgeEtPort(t *testing.T) {
	el, err := parseEnsembleScan(jsonEnsemble(600, "203.0.113.9|22|599", "203.0.113.9|3389|100", "2001:db8::5|443|10"))
	if err != nil || len(el) != 3 {
		t.Fatalf("3 éléments attendus : %v %v", el, err)
	}
	if el[0].IP != "203.0.113.9" || el[0].Port != 22 || el[0].Age != 1 || el[1].Age != 500 {
		t.Fatalf("âge = timeout − expiration : %+v", el)
	}
}

func TestParseEnsembleScan_VideOuInvalide(t *testing.T) {
	if el, err := parseEnsembleScan([]byte(`{"nftables":[{"set":{"name":"s","timeout":600}}]}`)); err != nil || len(el) != 0 {
		t.Fatalf("ensemble vide = aucun élément, obtenu %v %v", el, err)
	}
	if _, err := parseEnsembleScan([]byte(`pas du json`)); err == nil {
		t.Fatal("une sortie illisible est une erreur, pas un silence")
	}
}

func elems(ip string, ports ...int) []scanElem {
	var o []scanElem
	for _, p := range ports {
		o = append(o, scanElem{IP: ip, Port: p, Age: 30})
	}
	return o
}

func TestAnalyserScans_SeuilEtDistinction(t *testing.T) {
	var tous []scanElem
	tous = append(tous, elems("203.0.113.9", 21, 22, 23, 25, 80, 443, 3306, 3389)...) // 8 ports : un balayage
	tous = append(tous, elems("203.0.113.10", 22, 22, 22)...)                         // un seul port, répété : pas un balayage
	tous = append(tous, elems("203.0.113.11", 80, 443)...)                            // deux ports : un client ordinaire
	ev := analyserScans(tous, 8, nil)
	if len(ev) != 1 || ev[0].IP != "203.0.113.9" || ev[0].Ports != 8 {
		t.Fatalf("un seul balayage attendu : %+v", ev)
	}
}

func TestAnalyserScans_JamaisPriveProtegeeOuLocale(t *testing.T) {
	var tous []scanElem
	for _, ip := range []string{"192.168.1.50", "10.100.0.5", "127.0.0.1", "203.0.113.200", "fe80::1"} {
		tous = append(tous, elems(ip, 1, 2, 3, 4, 5, 6, 7, 8, 9)...)
	}
	ev := analyserScans(tous, 8, parseCIDRs("203.0.113.200/32"))
	if len(ev) != 0 {
		t.Fatalf("aucune adresse privée, locale ou protégée ne peut être un balayage : %+v", ev)
	}
}

type fauxEmetteurScan struct{ recus []*envelope.Envelope }

func (f *fauxEmetteurScan) Emit(e *envelope.Envelope) bool { f.recus = append(f.recus, e); return true }

func capteurTest(sortie []byte, fe *fauxEmetteurScan) *ScanSensor {
	s := NewScanSensor(func(_ context.Context, args ...string) ([]byte, error) { return sortie, nil }, fe)
	s.seuil = 8
	s.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	return s
}

func neuf(ip string) []string {
	var o []string
	for p := 1; p <= 9; p++ {
		o = append(o, fmt.Sprintf("%s|%d|580", ip, 1000+p))
	}
	return o
}

func TestScanSensor_EmetUneEnveloppeValideParBalayage(t *testing.T) {
	fe := &fauxEmetteurScan{}
	c := capteurTest(jsonEnsemble(600, neuf("203.0.113.9")...), fe)
	c.Tick()
	if len(fe.recus) != 1 {
		t.Fatalf("une enveloppe attendue, obtenu %d", len(fe.recus))
	}
	e := fe.recus[0]
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	if e.Sensor != envelope.SensorFirewall || e.SrcIP != "203.0.113.9" || e.Action != envelope.ActionBlock || e.RuleID != "fw.scan.vertical" || e.Severity < 30 || e.Severity > 100 {
		t.Fatalf("enveloppe inattendue : %+v", e)
	}
	if !strings.Contains(strings.Join(e.BehaviorTags, ","), "port_scan") || e.DstService != "ports:9" {
		t.Fatalf("étiquette de balayage et nombre de ports attendus : %+v", e)
	}
}

func TestScanSensor_PasDeRepetitionSaufCroissance(t *testing.T) {
	fe := &fauxEmetteurScan{}
	c := capteurTest(jsonEnsemble(600, neuf("203.0.113.9")...), fe)
	c.Tick()
	c.Tick()
	if len(fe.recus) != 1 {
		t.Fatalf("le même balayage ne se ré-émet pas : %d", len(fe.recus))
	}
	var plus []string
	for p := 1; p <= 40; p++ {
		plus = append(plus, fmt.Sprintf("203.0.113.9|%d|500", 2000+p))
	}
	c.runner = func(_ context.Context, _ ...string) ([]byte, error) { return jsonEnsemble(600, plus...), nil }
	c.Tick()
	if len(fe.recus) != 2 {
		t.Fatalf("un balayage qui s'étend se ré-émet : %d", len(fe.recus))
	}
}

func TestScanSensor_PanneDeNftNeCassePas(t *testing.T) {
	fe := &fauxEmetteurScan{}
	c := NewScanSensor(func(_ context.Context, _ ...string) ([]byte, error) {
		return []byte("Error: No such file or directory"), fmt.Errorf("nft: exit 1")
	}, fe)
	c.Tick() // ne panique pas, n'émet rien
	if len(fe.recus) != 0 || c.Erreurs() == 0 {
		t.Fatalf("une panne se compte et ne produit aucun événement : %d %d", len(fe.recus), c.Erreurs())
	}
}
