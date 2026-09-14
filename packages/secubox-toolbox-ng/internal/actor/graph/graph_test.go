// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package graph

import (
	"fmt"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/similarity"
)

// Deux sources différentes qui partagent la même grammaire d'attaque (credential
// réutilisé + même chemins + même TLS) doivent être regroupées en UN acteur,
// malgré des IP différentes (RFC-0013 §10 : un changement d'IP ne casse pas une
// campagne si 3+ signaux indépendants restent stables).
func TestClustering_IPDifferenteMemeCampagne(t *testing.T) {
	g := New(DefaultThreshold)
	o1 := Obs{Sig: similarity.Signature{CredentialHash: "c", PathSig: "p", TLSFingerprint: "t",
		IP: "1.1.1.1", ASN: 100, Country: "US", SeenAt: 1000}, Severity: 60, Target: "ssh", Timestamp: 1000}
	o2 := Obs{Sig: similarity.Signature{CredentialHash: "c", PathSig: "p", TLSFingerprint: "t",
		IP: "2.2.2.2", ASN: 100, Country: "US", SeenAt: 1100}, Severity: 40, Target: "mail", Timestamp: 1100}

	a1 := g.Observe(o1)
	a2 := g.Observe(o2)
	if a1.ID != a2.ID {
		t.Fatalf("les deux observations auraient dû être le même acteur (%s vs %s)", a1.ID, a2.ID)
	}
	if g.Len() != 1 {
		t.Fatalf("attendu 1 acteur, obtenu %d", g.Len())
	}
	if a2.Events != 2 {
		t.Errorf("Events = %d, attendu 2", a2.Events)
	}
	if len(a2.IPs) != 2 {
		t.Errorf("2 IP distinctes attendues, obtenu %v", a2.IPs)
	}
	if len(a2.Targets) != 2 {
		t.Errorf("2 cibles attendues, obtenu %v", a2.Targets)
	}
	// continuité = credential 30 + path 18 + tls 12 + asn 5 + pays 1 = 66
	if a2.Vector.Continuity != 66 {
		t.Errorf("continuité = %d, attendu 66", a2.Vector.Continuity)
	}
	if a2.Vector.Severity != 60 {
		t.Errorf("gravité (max) = %d, attendu 60", a2.Vector.Severity)
	}
	if a2.Vector.Confidence < 60 {
		t.Errorf("confiance faible (%d) malgré 5 signaux concordants", a2.Vector.Confidence)
	}
}

// Une observation sans aucun signal commun crée un NOUVEL acteur (pas de
// sur-regroupement).
func TestClustering_NonRelie(t *testing.T) {
	g := New(DefaultThreshold)
	g.Observe(Obs{Sig: similarity.Signature{CredentialHash: "c", PathSig: "p", TLSFingerprint: "t", IP: "1.1.1.1", SeenAt: 1000}, Timestamp: 1000})
	g.Observe(Obs{Sig: similarity.Signature{CredentialHash: "z", PathSig: "q", TLSFingerprint: "u", IP: "9.9.9.9", ASN: 999, Country: "CN", SeenAt: 2000}, Timestamp: 2000})
	if g.Len() != 2 {
		t.Fatalf("attendu 2 acteurs distincts, obtenu %d", g.Len())
	}
}

func TestSetScoresEtPriorite(t *testing.T) {
	g := New(DefaultThreshold)
	a := g.Observe(Obs{Sig: similarity.Signature{IP: "1.1.1.1", SeenAt: 1}, Severity: 80, Timestamp: 1})
	g.SetScores(a.ID, 70, 60, 90, 40)
	if a.Vector.Knowledge != 70 || a.Vector.Intent != 60 || a.Vector.Automation != 90 || a.Vector.Persistence != 40 {
		t.Fatalf("axes injectés incohérents : %+v", a.Vector)
	}
	// Priority(v) = 0.25*sev + 0.20*know + 0.20*intent + 0.15*cont + 0.10*persist + 0.10*conf
	want := Priority(a.Vector)
	if a.Priority != want {
		t.Errorf("priorité non recalculée : %d != %d", a.Priority, want)
	}
	// L'automation ne pèse PAS dans la priorité (RFC-0008).
	before := a.Priority
	g.SetScores(a.ID, 70, 60, 10, 40) // automation 90 -> 10
	if a.Priority != before {
		t.Errorf("l'automation ne devrait pas changer la priorité : %d != %d", a.Priority, before)
	}
}

func TestActorsTriParPriorite(t *testing.T) {
	g := New(DefaultThreshold)
	lo := g.Observe(Obs{Sig: similarity.Signature{IP: "1.1.1.1", SeenAt: 1}, Severity: 10, Timestamp: 1})
	hi := g.Observe(Obs{Sig: similarity.Signature{IP: "2.2.2.2", SeenAt: 2}, Severity: 95, Timestamp: 2})
	_ = lo
	list := g.Actors()
	if len(list) != 2 || list[0].ID != hi.ID {
		t.Errorf("le plus prioritaire devrait être en tête : %v", list)
	}
}

// ── Agregation reelle et cout (2026-09-14) ──────────────────────────────────

func TestObserve_AgregeAvecLesSeulsCapteursDuWAF(t *testing.T) {
	// Ce que la box emet vraiment : chemin, outil, IP. Rien d'autre.
	g := New(DefaultThreshold)
	sig := func(ip string) similarity.Signature {
		return similarity.Signature{PathSig: "wp-login", UAFamily: "nuclei", IP: ip, SeenAt: 1000}
	}
	a1 := g.Observe(Obs{Sig: sig("1.2.3.4"), Timestamp: 1000})
	a2 := g.Observe(Obs{Sig: sig("5.6.7.8"), Timestamp: 1001}) // MEME profil, AUTRE IP
	if a1.ID != a2.ID {
		t.Fatalf("deux observations du meme profil ont cree %s et %s : aucune agregation", a1.ID, a2.ID)
	}
	if g.Len() != 1 {
		t.Fatalf("%d acteurs pour un seul profil", g.Len())
	}
}

func TestObserve_NeFusionnePasDeuxProfilsEtrangers(t *testing.T) {
	g := New(DefaultThreshold)
	a := g.Observe(Obs{Sig: similarity.Signature{PathSig: "wp-login", UAFamily: "nuclei", IP: "1.1.1.1", SeenAt: 1000}, Timestamp: 1000})
	b := g.Observe(Obs{Sig: similarity.Signature{PathSig: "api-graphql", UAFamily: "curl", IP: "2.2.2.2", SeenAt: 1000}, Timestamp: 1001})
	if a.ID == b.ID {
		t.Fatal("deux profils sans rien en commun ont ete fusionnes")
	}
}

func TestObserve_NeBalaiePlusTousLesActeurs(t *testing.T) {
	// L'index doit rendre le cout independant du nombre d'acteurs etrangers :
	// mille acteurs sans aucune valeur commune ne doivent pas etre compares.
	g := New(DefaultThreshold)
	for i := 0; i < 1000; i++ {
		g.Observe(Obs{Sig: similarity.Signature{
			PathSig: fmt.Sprintf("p%d", i), UAFamily: fmt.Sprintf("ua%d", i),
			IP: fmt.Sprintf("10.0.%d.%d", i/256, i%256), SeenAt: 1000}, Timestamp: 1000})
	}
	if n := len(g.candidats(similarity.Signature{PathSig: "inconnu", UAFamily: "inconnu", IP: "9.9.9.9"})); n != 0 {
		t.Fatalf("%d candidats pour une signature sans rien en commun : l'index ne filtre pas", n)
	}
}
