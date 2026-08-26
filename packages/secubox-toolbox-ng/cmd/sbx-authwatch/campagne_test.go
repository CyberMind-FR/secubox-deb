// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"testing"
	"time"
)

// Le cas mesure sur gk2 : des centaines de sources, chacune une seule fois,
// toutes contre le meme compte. Le compteur par IP ne verrait rien ; la
// campagne, elle, doit se declarer.
func TestCampagneSeDeclareSurSourcesDistinctes(t *testing.T) {
	c := NewCampagnes(time.Hour, 5)
	t0 := time.Unix(1_700_000_000, 0)
	ips := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"}
	for _, ip := range ips {
		if _, camp := c.Note("gerald@gk2.net", ip, t0); camp {
			t.Fatalf("campagne declaree trop tot (a %s)", ip)
		}
	}
	sources, camp := c.Note("gerald@gk2.net", "203.0.113.5", t0)
	if !camp || sources != 5 {
		t.Fatalf("cinquieme source : campagne=%v sources=%d, attendu true/5", camp, sources)
	}
}

// La meme source qui insiste ne fabrique pas une campagne : ce qu'on reconnait
// ici, c'est une action COLLECTIVE, pas de l'acharnement individuel.
func TestUneSeuleSourceNeFaitPasCampagne(t *testing.T) {
	c := NewCampagnes(time.Hour, 3)
	t0 := time.Unix(1_700_000_000, 0)
	for i := 0; i < 20; i++ {
		if _, camp := c.Note("gege", "203.0.113.9", t0.Add(time.Duration(i)*time.Second)); camp {
			t.Fatal("une source unique ne doit pas etablir une campagne")
		}
	}
}

func TestCiblesIndependantes(t *testing.T) {
	c := NewCampagnes(time.Hour, 3)
	t0 := time.Unix(1_700_000_000, 0)
	c.Note("gerald", "1.1.1.1", t0)
	c.Note("gerald", "2.2.2.2", t0)
	c.Note("gerard", "3.3.3.3", t0)
	if _, camp := c.Note("gerard", "4.4.4.4", t0); camp {
		t.Fatal("les sources d'une cible ne doivent pas compter pour une autre")
	}
	if _, camp := c.Note("gerald", "5.5.5.5", t0); !camp {
		t.Fatal("gerald a bien trois sources distinctes")
	}
}

func TestCampagneOublieHorsFenetre(t *testing.T) {
	c := NewCampagnes(time.Minute, 3)
	t0 := time.Unix(1_700_000_000, 0)
	c.Note("gege", "1.1.1.1", t0)
	c.Note("gege", "2.2.2.2", t0)
	// Deux minutes plus tard, les deux premieres sont sorties de la fenetre.
	sources, camp := c.Note("gege", "3.3.3.3", t0.Add(2*time.Minute))
	if camp || sources != 1 {
		t.Fatalf("hors fenetre : campagne=%v sources=%d, attendu false/1", camp, sources)
	}
}

func TestCibleVideIgnoree(t *testing.T) {
	c := NewCampagnes(time.Hour, 1)
	if _, camp := c.Note("", "1.1.1.1", time.Now()); camp {
		t.Fatal("une ligne sans compte vise ne doit rien declencher")
	}
}

// Bout en bout : une campagne distribuee doit bannir des la PREMIERE tentative
// de chaque nouvelle source, la ou le compteur par IP resterait muet.
func TestCampagneBannitDesLaPremiereTentative(t *testing.T) {
	b, fx := banneurTest(t)
	j, _ := journalTest(t)
	lb, _ := NewListeBlanche("")
	camp := NewCampagnes(time.Hour, 3)

	ctx, annule := context.WithCancel(context.Background())
	signaux := make(chan Signal, 16)
	// Seuil du compteur volontairement inatteignable : seule la campagne peut
	// declencher, ce qui prouve que c'est bien elle qui agit.
	go traite(ctx, signaux, NewCompteur(time.Hour, 999, time.Hour), camp, nil, b, j, lb, false)

	for _, ip := range []string{"203.0.113.11", "203.0.113.12", "203.0.113.13", "203.0.113.14"} {
		signaux <- Signal{IP: ip, Service: "smtp", Categorie: "auth_smtp:sasl_failed",
			Severite: "high", Detail: "SASL refusee", Cible: "gerald@gk2.net"}
		time.Sleep(30 * time.Millisecond)
	}
	time.Sleep(80 * time.Millisecond)
	annule()

	// Les deux premieres etablissent la campagne, les suivantes sont bannies.
	if len(fx.bannies) < 2 {
		t.Fatalf("la campagne aurait du bannir les sources tardives, obtenu %v", fx.bannies)
	}
	if fx.bannies[0] != "203.0.113.13" {
		t.Errorf("le bannissement doit commencer a la source qui etablit le seuil, obtenu %v", fx.bannies)
	}
}

func TestCiblesExtraitesDesLignesReelles(t *testing.T) {
	cas := map[string]string{
		"postfix/submission/smtpd[9784]: warning: unknown[122.187.229.218]: SASL LOGIN authentication failed: (reason unavailable), sasl_username=gerald@gk2.net": "gerald@gk2.net",
		"dovecot[37002]: imap-login: Disconnected: Connection closed (auth failed, 2 attempts in 8 secs): user=<gk2>, method=PLAIN, rip=91.204.14.9":              "gk2",
		"sshd[1234]: Invalid user admin from 45.83.64.1 port 51234":                                                                                              "admin",
	}
	for ligne, attendu := range cas {
		sig, ok := Reconnaitre(ligne)
		if !ok {
			t.Errorf("ligne non reconnue : %.60s", ligne)
			continue
		}
		if sig.Cible != attendu {
			t.Errorf("cible %q, attendu %q (ligne %.50s)", sig.Cible, attendu, ligne)
		}
	}
}
