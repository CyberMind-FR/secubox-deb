// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package gateway

import (
	"errors"
	"testing"
)

// connecteur feint qui reconnaît certaines URL et rend un contenu marqué.
type connFeint struct {
	Base
	nom     string
	motifs  []string
	rendu   string // titre rendu par Resoudre, pour vérifier le routage
	echoue  bool
	resolus int
}

func (c *connFeint) Manifeste() Manifeste {
	return Manifeste{Nom: c.nom, Version: "1.0",
		Capacites: []string{CapResoudre, CapTirer}, AuthKind: AuthAucune,
		MotifsURL: c.motifs}
}
func (c *connFeint) Resoudre(u string) (Contenu, error) {
	c.resolus++
	if c.echoue {
		return Contenu{}, errors.New("panne du connecteur")
	}
	return Contenu{Genre: GenreVideo, Titre: c.rendu, SourceURL: u,
		Connecteur: c.nom, Propriete: ProprieteTiers, NoeudOrigine: "gk2"}, nil
}
func (c *connFeint) RecupererMedias(Contenu) ([]Media, error) { return nil, nil }
func (c *connFeint) Tirer(int64) ([]Contenu, error)           { return nil, nil }
func (c *connFeint) Sante() Sante                             { return Sante{Etat: EtatSain} }

func registreDe(t *testing.T, cs ...*connFeint) *Registre {
	t.Helper()
	r := NouveauRegistre()
	for _, c := range cs {
		c.Base.Sortie = nil
		if err := r.Enregistrer(c); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

// ── routage ──────────────────────────────────────────────────────────────

func TestUneURLVaAuConnecteurQuiLaReconnait(t *testing.T) {
	yt := &connFeint{nom: "youtube", rendu: "une vidéo",
		motifs: []string{`(?i)youtube\.com/watch`}}
	r := registreDe(t, yt)
	c, err := NouveauResolveur(r, "gk2").Resoudre("https://www.youtube.com/watch?v=abc")
	if err != nil {
		t.Fatal(err)
	}
	if c.Connecteur != "youtube" || c.Titre != "une vidéo" {
		t.Fatalf("mauvais routage : %+v", c)
	}
	if yt.resolus != 1 {
		t.Fatalf("le connecteur a été sollicité %d fois", yt.resolus)
	}
}

func TestChaqueConnecteurNeRecoitQueCeQuiLeConcerne(t *testing.T) {
	yt := &connFeint{nom: "youtube", rendu: "vidéo", motifs: []string{`(?i)youtube\.com`}}
	rss := &connFeint{nom: "rss", rendu: "article", motifs: []string{`(?i)/feed/?`}}
	res := NouveauResolveur(registreDe(t, yt, rss), "gk2")

	c, _ := res.Resoudre("https://exemple.org/feed/")
	if c.Connecteur != "rss" {
		t.Fatalf("un flux est allé à %q", c.Connecteur)
	}
	if yt.resolus != 0 {
		t.Fatal("youtube a été sollicité pour un flux")
	}
}

func TestUneURLInconnueDonneUneCarteLienGenerique(t *testing.T) {
	// L'inconnu ne doit jamais échouer : on rend une carte « lien » minimale,
	// sans réseau, plutôt que de refuser. L'utilisateur colle, quelque chose
	// apparaît.
	res := NouveauResolveur(registreDe(t), "gk2")
	c, err := res.Resoudre("https://un-site-quelconque.example/page/42")
	if err != nil {
		t.Fatal(err)
	}
	if c.Genre != GenreLien {
		t.Fatalf("carte inconnue de genre %q, attendu lien", c.Genre)
	}
	if c.Connecteur != "generique" {
		t.Fatalf("connecteur %q, attendu generique", c.Connecteur)
	}
	if err := c.Valider(); err != nil {
		t.Fatalf("carte générique invalide : %v", err)
	}
}

func TestLaCarteGeneriquePorteLHoteEtResteTierce(t *testing.T) {
	// Sans connaître la source, on ne présume rien : c'est du tiers, et le
	// titre à défaut est l'hôte, repère lisible.
	c, _ := NouveauResolveur(registreDe(t), "gk2").
		Resoudre("https://blog.example.org/2026/note")
	if c.Propriete != ProprieteTiers {
		t.Fatalf("carte générique de propriété %q, attendu tiers", c.Propriete)
	}
	if c.Titre != "blog.example.org" {
		t.Fatalf("titre générique = %q, attendu l'hôte", c.Titre)
	}
	if c.SourceURL != "https://blog.example.org/2026/note" {
		t.Fatal("l'adresse d'origine doit toujours être conservée")
	}
}

// ── robustesse ───────────────────────────────────────────────────────────

func TestLeResolveurRefuseUneAdresseVide(t *testing.T) {
	if _, err := NouveauResolveur(registreDe(t), "gk2").Resoudre("  "); err == nil {
		t.Fatal("adresse vide acceptée")
	}
}

func TestLeResolveurRefuseLesAdressesNonHttp(t *testing.T) {
	// Même règle qu'ailleurs : pas de file://, pas de javascript:.
	for _, u := range []string{"file:///etc/passwd", "javascript:alert(1)", "ftp://x/y"} {
		if _, err := NouveauResolveur(registreDe(t), "gk2").Resoudre(u); err == nil {
			t.Fatalf("adresse acceptée : %s", u)
		}
	}
}

func TestUnConnecteurQuiEchoueNeRetombePasEnGenerique(t *testing.T) {
	// Si le bon connecteur est trouvé mais qu'il échoue, on remonte SON erreur.
	// Retomber sur la carte générique masquerait le vrai problème (cookies
	// périmés, plateforme en panne) derrière une carte creuse.
	yt := &connFeint{nom: "youtube", echoue: true, motifs: []string{`(?i)youtube\.com`}}
	_, err := NouveauResolveur(registreDe(t, yt), "gk2").
		Resoudre("https://youtube.com/watch?v=x")
	if err == nil {
		t.Fatal("l'échec du connecteur a été masqué par une carte générique")
	}
}

func TestUnMotifIllisibleDansUnManifesteNeCassePasLeResolveur(t *testing.T) {
	// Un manifeste au motif cassé est refusé à l'enregistrement (T4) ; le
	// résolveur n'a donc jamais à composer avec. On le vérifie : l'inscription
	// échoue, le résolveur reste sain avec les connecteurs valides.
	r := NouveauRegistre()
	if err := r.Enregistrer(&connFeint{nom: "cassé", motifs: []string{"^("}}); err == nil {
		t.Fatal("un motif illisible est entré au registre")
	}
	c, err := NouveauResolveur(r, "gk2").Resoudre("https://x.example/y")
	if err != nil || c.Connecteur != "generique" {
		t.Fatalf("le résolveur devrait rendre une carte générique : %+v (%v)", c, err)
	}
}

func TestLePremierConnecteurParOrdreDeNomTranche(t *testing.T) {
	// Deux connecteurs qui reconnaissent la même URL : on choisit par ordre de
	// nom, pour que le routage soit reproductible et non dépendant de la carte.
	a := &connFeint{nom: "alpha", rendu: "A", motifs: []string{`(?i)exemple\.org`}}
	z := &connFeint{nom: "zeta", rendu: "Z", motifs: []string{`(?i)exemple\.org`}}
	c, _ := NouveauResolveur(registreDe(t, z, a), "gk2").Resoudre("https://exemple.org/x")
	if c.Connecteur != "alpha" {
		t.Fatalf("routage non déterministe : %q", c.Connecteur)
	}
}
