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

// TestBasculesPremierEtatSansNotification : le premier état lu sert de référence (le maître lit l'état par Get).
func TestBasculesPremierEtatSansNotification(t *testing.T) {
	b := NouvellesBascules(func() time.Time { return time.Unix(1_800_000_000, 0) })
	if ev := b.Observer(etatLocal(true, &Support{ID: "s-01", Etat: "ouvert"}, Consentement{"0123456789abcdef", "accepte"})); len(ev) != 0 {
		t.Fatalf("premier état : %+v", ev)
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
	ev = b.Observer(etatLocal(true, &Support{ID: "s-01", Etat: "ouvert"}, Consentement{c1, "utilise"}, Consentement{c2, "refuse"}))
	if got := resume(ev); !reflect.DeepEqual(got, [][3]string{{TypeSupport, "s-01", "ouvert"}}) {
		t.Fatalf("événements %v", got)
	}
	c3 := "00000000000000aa"
	b.Observer(etatLocal(true, &Support{ID: "s-01", Etat: "ouvert"}, Consentement{c3, "en_attente"}))
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
		{Evenement{Type: TypeSupport, ID: "s-01", Etat: "ouvert", Instant: 7}, `{"type":"X_SECUBOX_Support","ts":7,"id":"s-01","etat":"ouvert"}`},
	} {
		b, err := json.Marshal(c.e)
		if err != nil || string(b) != c.want {
			t.Errorf("%s, attendu %s (%v)", b, c.want, err)
		}
	}
}
