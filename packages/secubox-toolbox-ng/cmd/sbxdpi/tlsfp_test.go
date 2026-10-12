// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// ClientHello TLS 1.3 de référence (GREASE, SNI, groupes, formats, algorithmes
// de signature, ALPN h2, versions). Les valeurs attendues sortent d'un calcul
// Python indépendant de ce code, selon les spécifications JA3 et JA4 (FoxIO).
const helloHex = "160301007c01000078030300000000000000000000000000000000000000000000000000000000000000000000080a0a13011302c02b010000472a2a000000000011000f00000c6578656d706c652e74657374000a00060004001d0017000b00020100000d0006000404030804001000050003026832002b0007060a0a03040303"

const (
	attenduJA3 = "11138d9933242c3a03b6aad35a296476"
	attenduJA4 = "t13d0306h2_5559582ccdc4_fb71836bce29"
)

func hello(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(helloHex)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestClientHelloJA3JA4(t *testing.T) {
	e, ok, inc := lireClientHello(hello(t))
	if !ok || inc {
		t.Fatalf("ClientHello non lu (ok=%v incomplet=%v)", ok, inc)
	}
	if e.JA3 != attenduJA3 {
		t.Errorf("JA3 = %s, attendu %s", e.JA3, attenduJA3)
	}
	if e.JA4 != attenduJA4 {
		t.Errorf("JA4 = %s, attendu %s", e.JA4, attenduJA4)
	}
}

func TestClientHelloTronque(t *testing.T) {
	h := hello(t)
	if _, ok, inc := lireClientHello(h[:60]); ok || !inc {
		t.Errorf("un hello coupé doit être « incomplet » (ok=%v inc=%v)", ok, inc)
	}
}

func TestPasUnClientHello(t *testing.T) {
	for _, p := range [][]byte{nil, {0x16}, []byte("GET / HTTP/1.1\r\n\r\n"), {0x17, 3, 3, 0, 5, 1, 2, 3, 4, 5, 6}} {
		if _, ok, inc := lireClientHello(p); ok || inc {
			t.Errorf("%x ne doit pas être lu comme un ClientHello", p)
		}
	}
}

func TestRecollageSurDeuxSegments(t *testing.T) {
	h := hello(t)
	r := newRecolleur()
	if _, ok := r.Observe(7, h[:70]); ok {
		t.Fatal("le premier segment seul ne suffit pas")
	}
	e, ok := r.Observe(7, h[70:])
	if !ok || e.JA4 != attenduJA4 {
		t.Fatalf("recollage : ok=%v ja4=%s", ok, e.JA4)
	}
	// une seule empreinte par flux, même si le hello est retransmis
	if _, ok := r.Observe(7, h); ok {
		t.Error("une retransmission ne doit pas être recomptée")
	}
}

// trame fabrique une trame Ethernet / IPv4 / TCP portant la charge.
func trame(charge []byte) []byte {
	eth := make([]byte, 14)
	eth[12], eth[13] = 0x08, 0x00
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = 6
	tcp := make([]byte, 20)
	tcp[12] = 5 << 4
	return append(append(append(eth, ip...), tcp...), charge...)
}

func TestEvenementPaquetAlimenteLesCompteurs(t *testing.T) {
	agg := newAggregator()
	ev := &dpiEvent{PacketEventName: "packet-flow", FlowID: 42, PktL3Offset: 14, PktType: 0x0800,
		Pkt: base64.StdEncoding.EncodeToString(trame(hello(t)))}
	ingest(agg, nil, nil, ev)
	ingest(agg, nil, nil, ev) // même flux : compté une fois
	s := agg.snapshot()
	if len(s.Fingerprints) != 1 || s.Fingerprints[0].Name != attenduJA4 || s.Fingerprints[0].Flows != 1 {
		t.Errorf("JA4 agrégé = %+v", s.Fingerprints)
	}
	if len(s.FingerprintsJA3) != 1 || s.FingerprintsJA3[0].Name != attenduJA3 {
		t.Errorf("JA3 agrégé = %+v", s.FingerprintsJA3)
	}
}

func TestSNIEtMetaParEmpreinte(t *testing.T) {
	e, _, _ := lireClientHello(hello(t))
	if e.SNI != "exemple.test" {
		t.Errorf("SNI = %q", e.SNI)
	}
	agg := newAggregator()
	ev := &dpiEvent{PacketEventName: "packet-flow", FlowID: 1, PktL3Offset: 14, PktType: 0x0800,
		Pkt: base64.StdEncoding.EncodeToString(trame(hello(t)))}
	ingest(agg, nil, nil, ev)
	ev.FlowID = 2
	ingest(agg, nil, nil, ev)
	m, ok := agg.snapshot().FingerprintMeta[attenduJA4]
	if !ok || m.First == 0 || m.Last < m.First {
		t.Fatalf("meta JA4 = %+v (ok=%v)", m, ok)
	}
	if len(m.SNI) != 1 || m.SNI[0].Name != "exemple.test" || m.SNI[0].Flows != 2 {
		t.Errorf("SNI agrégés = %+v", m.SNI)
	}
	if _, ok := agg.snapshot().FingerprintMeta[attenduJA3]; !ok {
		t.Error("meta JA3 absente")
	}
}

func TestSNIDouteuxEcarte(t *testing.T) {
	for _, d := range [][]byte{
		{0, 5, 0, 0, 2, 'a', '<'},  // caractère interdit
		{0, 3, 0, 0, 0},            // nom vide
		{0, 5, 1, 0, 2, 'a', 'b'},  // type de nom inconnu
		{0, 9, 0, 0, 90, 'a', 'b'}, // longueur annoncée trop grande
	} {
		if s := lireSNI(d); s != "" {
			t.Errorf("SNI douteux accepté : %q", s)
		}
	}
	if s := lireSNI([]byte{0, 5, 0, 0, 2, 'A', 'b'}); s != "ab" {
		t.Errorf("SNI normalisé = %q", s)
	}
}
