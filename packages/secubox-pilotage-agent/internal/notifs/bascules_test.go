// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package notifs

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func etatLocal(liees bool, sup *Support, cs ...Consentement) EtatLocal {
	return EtatLocal{MainsLiees: liees, Consentements: cs, Support: sup}
}

func resume(ev []Evenement) [][3]string {
	var r [][3]string
	for _, e := range ev {
		r = append(r, [3]string{e.Type, e.ID, e.Etat + e.Decision})
	}
	return r
}

// TestBasculesPremierEtatRenotifie (I1, R-L2-33 b) : au premier état lu après le démarrage de l'agent, l'état des
// mains liées et la session de support en cours (avec sa fin) sont notifiés : un agent qui redémarre pendant une
// session ouverte la renotifie. Les consentements et une session terminée ne le sont pas.
func TestBasculesPremierEtatRenotifie(t *testing.T) {
	b := NouvellesBascules(func() time.Time { return time.Unix(1_800_000_000, 0) })
	ev := b.Observer(etatLocal(true, &Support{ID: "s-01", Etat: "ouvert", Fin: 1_800_001_800}, Consentement{"0123456789abcdef", "accepte"}))
	want := [][3]string{{TypeMainsLiees, "", "on"}, {TypeSupport, "s-01", "ouvert"}}
	if got := resume(ev); !reflect.DeepEqual(got, want) {
		t.Fatalf("premier état : %v, attendu %v", got, want)
	}
	if ev[1].Fin != "2027-01-15T08:30:00Z" {
		t.Fatalf("fin %q", ev[1].Fin)
	}
	for _, sup := range []*Support{nil, {ID: "s-01", Etat: "ferme"}, {ID: "s-01", Etat: "expire"}} {
		b := NouvellesBascules(nil)
		if got := resume(b.Observer(etatLocal(false, sup))); !reflect.DeepEqual(got, [][3]string{{TypeMainsLiees, "", "off"}}) {
			t.Fatalf("support %+v : %v", sup, got)
		}
	}
	b = NouvellesBascules(nil)
	if got := resume(b.Observer(etatLocal(false, &Support{ID: "s-02", Etat: "en_attente"}))); len(got) != 2 || got[1][2] != "en_attente" {
		t.Fatalf("demande en attente : %v", got)
	}
}

// TestBasculesSectionsIllisibles (M2) : HandsTied part même quand consentements et support sont illisibles ; une
// section illisible ne produit rien et garde la mémoire précédente (pas de fausse décision à son retour).
func TestBasculesSectionsIllisibles(t *testing.T) {
	b := NouvellesBascules(nil)
	c1 := "0123456789abcdef"
	b.Observer(etatLocal(false, &Support{ID: "s-01", Etat: "ouvert", Fin: 9}, Consentement{c1, "accepte"}))
	ev := b.Observer(EtatLocal{MainsLiees: true, ConsentementsIllisibles: true, SupportIllisible: true})
	if got := resume(ev); !reflect.DeepEqual(got, [][3]string{{TypeMainsLiees, "", "on"}}) {
		t.Fatalf("événements %v", got)
	}
	if ev := b.Observer(etatLocal(true, &Support{ID: "s-01", Etat: "ouvert", Fin: 9}, Consentement{c1, "accepte"})); len(ev) != 0 {
		t.Fatalf("retour à l'identique : %+v", ev)
	}
}

// TestBasculesNotifiees : mains liées {etat}, décision d'un consentement {id, decision}, support {id, etat} ; une fois
// chacune, horodatées.
func TestBasculesNotifiees(t *testing.T) {
	b := NouvellesBascules(func() time.Time { return time.Unix(1_800_000_000, 0) })
	c1, c2 := "0123456789abcdef", "fedcba9876543210"
	b.Observer(etatLocal(false, nil, Consentement{c1, "en_attente"}))
	ev := b.Observer(etatLocal(true, &Support{ID: "s-01", Etat: "en_attente"}, Consentement{c1, "accepte"}, Consentement{c2, "refuse"}))
	want := [][3]string{
		{TypeMainsLiees, "", "on"},
		{TypeConsentement, c1, "accepte"},
		{TypeConsentement, c2, "refuse"}, // créé et décidé entre deux lectures : notifié aussi
		{TypeSupport, "s-01", "en_attente"},
	}
	if got := resume(ev); !reflect.DeepEqual(got, want) {
		t.Fatalf("événements %v, attendu %v", got, want)
	}
	if ev[0].Instant != 1_800_000_000 {
		t.Errorf("horodatage %d", ev[0].Instant)
	}
	// rien de neuf : rien ; utilisé n'est pas une décision ; puis expiration, ouverture, fermeture, mains déliées
	if ev := b.Observer(etatLocal(true, &Support{ID: "s-01", Etat: "en_attente"}, Consentement{c1, "accepte"}, Consentement{c2, "refuse"})); len(ev) != 0 {
		t.Fatalf("état inchangé : %+v", ev)
	}
	ev = b.Observer(etatLocal(true, &Support{ID: "s-01", Etat: "ouvert", Fin: 1_800_002_700}, Consentement{c1, "utilise"}, Consentement{c2, "refuse"}))
	if got := resume(ev); !reflect.DeepEqual(got, [][3]string{{TypeSupport, "s-01", "ouvert"}}) {
		t.Fatalf("événements %v", got)
	}
	// I1 (R-L2-33 a) : l'ouverture porte la fin (RFC 3339) : le maître expire la session lui-même
	if ev[0].Fin != "2027-01-15T08:45:00Z" {
		t.Fatalf("fin %q", ev[0].Fin)
	}
	c3 := "00000000000000aa"
	b.Observer(etatLocal(true, &Support{ID: "s-01", Etat: "ouvert", Fin: 1_800_002_700}, Consentement{c3, "en_attente"}))
	ev = b.Observer(etatLocal(false, &Support{ID: "s-01", Etat: "expire"}, Consentement{c3, "expire"}))
	want = [][3]string{{TypeMainsLiees, "", "off"}, {TypeConsentement, c3, "expire"}, {TypeSupport, "s-01", "expire"}}
	if got := resume(ev); !reflect.DeepEqual(got, want) {
		t.Fatalf("événements %v, attendu %v", got, want)
	}
	// un consentement annulé par les mains liées est notifié ; un support disparu ne l'est pas (rien à dire)
	c4 := "00000000000000bb"
	b.Observer(etatLocal(false, nil, Consentement{c4, "en_attente"}))
	ev = b.Observer(etatLocal(true, nil, Consentement{c4, "annule"}))
	want = [][3]string{{TypeMainsLiees, "", "on"}, {TypeConsentement, c4, "annule"}}
	if got := resume(ev); !reflect.DeepEqual(got, want) {
		t.Fatalf("événements %v, attendu %v", got, want)
	}
}

// TestBasculesFormeJSON : corps attendus par le maître — HandsTied {etat}, Consent {id, decision}, Support {id, etat}.
func TestBasculesFormeJSON(t *testing.T) {
	for _, c := range []struct {
		e    Evenement
		want string
	}{
		{Evenement{Type: TypeMainsLiees, Etat: "off", Instant: 7}, `{"type":"X_SECUBOX_HandsTied","ts":7,"etat":"off"}`},
		{Evenement{Type: TypeConsentement, ID: "0123456789abcdef", Decision: "refuse", Instant: 7},
			`{"type":"X_SECUBOX_Consent","ts":7,"id":"0123456789abcdef","decision":"refuse"}`},
		{Evenement{Type: TypeSupport, ID: "s-01", Etat: "ouvert", Fin: "2027-01-15T08:30:00Z", Instant: 7},
			`{"type":"X_SECUBOX_Support","ts":7,"id":"s-01","etat":"ouvert","fin":"2027-01-15T08:30:00Z"}`},
	} {
		b, err := json.Marshal(c.e)
		if err != nil || string(b) != c.want {
			t.Errorf("%s, attendu %s (%v)", b, c.want, err)
		}
	}
}
