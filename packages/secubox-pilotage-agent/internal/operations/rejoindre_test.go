// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package operations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/notifs"
)

// codeMaillage fabrique un vrai code sbxmesh1 (format de secubox-p2p api/automesh.encoder).
func codeMaillage(jeton string) string {
	charge := strings.TrimRight(base64.URLEncoding.EncodeToString(
		[]byte(fmt.Sprintf(`{"a":"192.168.1.1","t":"%s"}`, jeton))), "=")
	somme := sha256.Sum256([]byte(charge))
	return "sbxmesh1." + charge + "." + hex.EncodeToString(somme[:])[:4]
}

// fauxCtlEntree remplace `sudo` pour les verbes qui lisent l'entrée standard : argv et entrée notés à part.
type fauxCtlEntree struct {
	mu       sync.Mutex
	appels   [][]string
	entrees  [][]byte
	repondre func(args []string) ([]byte, error)
}

func (f *fauxCtlEntree) lancer(_ context.Context, entree []byte, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.appels = append(f.appels, append([]string(nil), args...))
	f.entrees = append(f.entrees, append([]byte(nil), entree...))
	r := f.repondre
	f.mu.Unlock()
	if r == nil {
		return []byte(`{"ok": true, "job": "0123456789abcdef"}` + "\n"), nil
	}
	return r(args)
}

// TestRejoindreCodeParEntreeStandard (R-L2-2) : Device.X_SECUBOX_Maillage.Rejoindre() {"code"} devient
// `sudo -n secubox-pilotagectl [--acteur …] maillage-rejoindre`, le code sur l'entrée standard, jamais dans l'argv.
func TestRejoindreCodeParEntreeStandard(t *testing.T) {
	ctl, ent := &fauxCtl{}, &fauxCtlEntree{}
	e := Nouveau(Config{Ctl: ctl.lancer, CtlEntree: ent.lancer,
		Systemctl: func(context.Context, ...string) ([]byte, error) { return []byte("active\n"), nil },
		Pas:       time.Hour})
	code := codeMaillage(strings.Repeat("ab", 32))
	r := e.Operer(context.Background(), CmdRejoindre, map[string]any{"code": code}, "gk2admin")
	if r.Etat != Accepte || r.Job != "0123456789abcdef" {
		t.Fatalf("acceptée attendue, reçu %+v", r)
	}
	if len(ent.appels) != 1 || strings.Join(ent.appels[0], " ") != "-n /usr/sbin/secubox-pilotagectl --acteur gk2admin maillage-rejoindre" {
		t.Fatalf("argv inattendu : %v", ent.appels)
	}
	if string(ent.entrees[0]) != code+"\n" {
		t.Fatalf("le code doit passer par l'entrée standard, reçu %q", ent.entrees[0])
	}
	if ctl.nb() != 0 {
		t.Fatalf("la demande ne passe pas par le lanceur sans entrée (%d appels)", ctl.nb())
	}
	// Sans lanceur à entrée standard : refus net, jamais l'argv en repli.
	sans := Nouveau(Config{Ctl: ctl.lancer, Systemctl: func(context.Context, ...string) ([]byte, error) { return nil, nil }})
	if r := sans.Operer(context.Background(), CmdRejoindre, map[string]any{"code": code}, ""); r.Etat != Refuse {
		t.Fatalf("refus attendu sans CtlEntree, reçu %+v", r)
	}
	if ctl.nb() != 0 {
		t.Fatalf("le code ne part jamais par l'argv")
	}
}

func TestRejoindreCodeInvalideRefuse(t *testing.T) {
	ent := &fauxCtlEntree{}
	e := Nouveau(Config{Ctl: (&fauxCtl{}).lancer, CtlEntree: ent.lancer,
		Systemctl: func(context.Context, ...string) ([]byte, error) { return nil, nil }})
	bon := codeMaillage(strings.Repeat("cd", 32))
	for _, args := range []map[string]any{nil, {}, {"code": 3.0}, {"code": ""}, {"code": "1234"},
		{"code": bon + "x"}, {"code": bon[:len(bon)-4] + "0000"}, {"code": " " + bon},
		{"code": "sbxmesh1." + strings.Repeat("a", 700) + ".abcd"}, {"code": bon, "nom": "gk5"}} {
		r := e.Operer(context.Background(), CmdRejoindre, args, "")
		if r.Etat != Refuse || r.Raison == "" || strings.Contains(r.Raison, "sbxmesh1") {
			t.Errorf("%v : refus sans recopie attendu, reçu %+v", args, r)
		}
	}
	if len(ent.appels) != 0 {
		t.Fatalf("le ctl ne doit pas être appelé (%d appels)", len(ent.appels))
	}
}

// TestCodeJamaisJournalise (R-L2-2) : le code n'apparaît ni dans l'argv d'un appel (sudo, systemctl), ni dans le
// journal de l'agent, ni dans les notifications (progression, fin), ni dans la réponse au maître — quel que soit
// le chemin (acceptée et suivie jusqu'à sa fin, refusée par le ctl, ctl en erreur, réponse incohérente).
func TestCodeJamaisJournalise(t *testing.T) {
	jeton := strings.Repeat("f00dcafe", 8)
	code := codeMaillage(jeton)
	var journal bytes.Buffer
	ancien := log.Writer()
	log.SetOutput(&journal)
	defer log.SetOutput(ancien)

	var mu sync.Mutex
	var traces []string
	noter := func(s string) {
		mu.Lock()
		traces = append(traces, s)
		mu.Unlock()
	}
	reponses := []func() ([]byte, error){
		func() ([]byte, error) { return []byte(`{"ok": true, "job": "0123456789abcdef"}`), nil },
		func() ([]byte, error) { return []byte(`{"ok": false, "refus": "box cliente : hors maillage"}`), nil },
		func() ([]byte, error) { return nil, errors.New("sudo : code 1") },
		func() ([]byte, error) { return []byte(`pas du json`), nil },
	}
	n := 0
	ent := &fauxCtlEntree{repondre: func(args []string) ([]byte, error) {
		noter(strings.Join(args, " "))
		r := reponses[n%len(reponses)]
		n++
		return r()
	}}
	ctl := &fauxCtl{repondre: func(args []string) ([]byte, error) {
		noter(strings.Join(args, " "))
		return []byte(`{"ok": true, "job": "0123456789abcdef", "etat": "termine", "resultat": "echec", "rc": 1}`), nil
	}}
	boite := NouvelleBoite(0)
	e := Nouveau(Config{Ctl: ctl.lancer, CtlEntree: ent.lancer, Resultats: boite, Pas: time.Millisecond,
		Systemctl: func(_ context.Context, args ...string) ([]byte, error) {
			noter(strings.Join(args, " "))
			return []byte("inactive\ninactive\n"), nil
		},
		Progression: func(ev notifs.Evenement) { noter(fmt.Sprintf("%+v", ev)) }})
	ctx, annule := context.WithCancel(context.Background())
	for range reponses {
		r := e.Operer(ctx, CmdRejoindre, map[string]any{"code": code}, "gk2admin")
		noter(fmt.Sprintf("%+v", r))
	}
	// L'opération acceptée est suivie jusqu'à sa fin (X_SECUBOX_OperationDone dans la boîte).
	limite := time.Now().Add(5 * time.Second)
	for boite.Taille() == 0 && time.Now().Before(limite) {
		time.Sleep(5 * time.Millisecond)
	}
	annule()
	e.Attendre()
	fins, _ := boite.Prendre(10)
	if len(fins) != 1 || fins[0].Resume != "maillage-rejoindre : échec (code 1)" {
		t.Fatalf("une fin attendue, reçu %+v", fins)
	}
	for _, f := range fins {
		noter(fmt.Sprintf("%+v", f))
	}
	tout := journal.String() + strings.Join(traces, "\n")
	for _, morceau := range []string{code, jeton, strings.Split(code, ".")[1][:24]} {
		if strings.Contains(tout, morceau) {
			t.Fatalf("le code fuit : %q dans\n%s", morceau, tout)
		}
	}
	if !strings.Contains(tout, "maillage-rejoindre") {
		t.Fatalf("les traces doivent bien couvrir les appels du ctl :\n%s", tout)
	}
}
