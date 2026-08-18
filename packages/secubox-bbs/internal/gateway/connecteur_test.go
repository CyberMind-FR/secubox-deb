// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package gateway

import (
	"errors"
	"testing"
)

// faux connecteur minimal, qui embarque Base comme tout connecteur reel.
type fauxConnecteur struct {
	Base
	publie  int
	manifTV Manifeste
}

func (f *fauxConnecteur) Manifeste() Manifeste { return f.manifTV }
func (f *fauxConnecteur) Resoudre(u string) (Contenu, error) {
	return Contenu{Genre: GenreLien, SourceURL: u, Connecteur: f.manifTV.Nom,
		Propriete: ProprieteTiers, NoeudOrigine: "gk2"}, nil
}
func (f *fauxConnecteur) Tirer(depuis int64) ([]Contenu, error) { return nil, nil }
func (f *fauxConnecteur) RecupererMedias(c Contenu) ([]Media, error) {
	return nil, nil
}
func (f *fauxConnecteur) Sante() Sante { return Sante{Etat: EtatSain} }

// PublierAutorise n'est appele qu'apres le controle de propriete.
func (f *fauxConnecteur) PublierAutorise(c Contenu) (Replique, error) {
	f.publie++
	return Replique{Cible: f.manifTV.Nom, Mode: ModePousse}, nil
}

func neuf(nom string) *fauxConnecteur {
	f := &fauxConnecteur{manifTV: Manifeste{
		Nom: nom, Version: "1.0",
		Capacites: []string{CapResoudre, CapTirer, CapPousser, CapAuth},
		// Un connecteur qui publie chez un tiers s'y authentifie : le montage
		// doit etre coherent, sinon c'est lui qui est faux, pas la regle.
		AuthKind:  AuthJeton,
		MotifsURL: []string{`^https://exemple\.org/`},
	}}
	f.Base.Sortie = f
	return f
}

// ── garde de propriete ───────────────────────────────────────────────────

func TestUnContenuTiersNeSePublieJamais(t *testing.T) {
	// C'est LA regle du module : on ne republie pas le travail d'autrui. Elle
	// vit dans Base, pas dans chaque connecteur, pour qu'aucun ne l'oublie.
	f := neuf("faux")
	c := Contenu{Genre: GenreTexte, SourceURL: "https://exemple.org/a",
		Connecteur: "faux", Propriete: ProprieteTiers, NoeudOrigine: "gk2"}
	_, err := f.Publier(c)
	if !errors.Is(err, ErrProprieteTiers) {
		t.Fatalf("publication d'un contenu tiers acceptee (err=%v)", err)
	}
	if f.publie != 0 {
		t.Fatal("le connecteur a ete sollicite malgre le refus")
	}
}

func TestUnContenuPropreSePublie(t *testing.T) {
	f := neuf("faux")
	c := Contenu{Genre: GenreTexte, SourceURL: "https://exemple.org/a",
		Connecteur: "faux", Propriete: ProprieteSoi, NoeudOrigine: "gk2"}
	r, err := f.Publier(c)
	if err != nil {
		t.Fatal(err)
	}
	if f.publie != 1 {
		t.Fatalf("le connecteur a ete sollicite %d fois", f.publie)
	}
	if r.Mode != ModePousse {
		t.Fatalf("mode de replique inattendu : %q", r.Mode)
	}
}

func TestUneProprieteNonDeclareeVautRefus(t *testing.T) {
	// Le silence ne vaut pas autorisation.
	f := neuf("faux")
	c := Contenu{Genre: GenreTexte, SourceURL: "https://exemple.org/a",
		Connecteur: "faux", NoeudOrigine: "gk2"}
	if _, err := f.Publier(c); err == nil {
		t.Fatal("propriete absente traitee comme une autorisation")
	}
}

func TestUnConnecteurSansSortieRefusePoliment(t *testing.T) {
	f := &fauxConnecteur{manifTV: Manifeste{Nom: "lecture-seule", Version: "1.0",
		Capacites: []string{CapResoudre}, AuthKind: AuthAucune}}
	c := Contenu{Genre: GenreTexte, SourceURL: "https://exemple.org/a",
		Connecteur: "lecture-seule", Propriete: ProprieteSoi, NoeudOrigine: "gk2"}
	_, err := f.Publier(c)
	if !errors.Is(err, ErrPasDePublication) {
		t.Fatalf("erreur attendue ErrPasDePublication, obtenu %v", err)
	}
}

// ── manifeste ────────────────────────────────────────────────────────────

func TestUnManifesteSansNomEstRefuse(t *testing.T) {
	m := Manifeste{Version: "1.0", AuthKind: AuthAucune}
	if err := m.Valider(); err == nil {
		t.Fatal("manifeste sans nom accepte")
	}
}

func TestUneCapaciteInconnueEstRefusee(t *testing.T) {
	m := Manifeste{Nom: "x", Version: "1.0", AuthKind: AuthAucune,
		Capacites: []string{"telepathie"}}
	if err := m.Valider(); err == nil {
		t.Fatal("capacite hors vocabulaire acceptee")
	}
}

func TestUnMotifDURLIllisibleEstRefuse(t *testing.T) {
	// Un motif casse ferait echouer le resolveur a l'execution, loin de sa
	// cause : on le refuse au chargement.
	m := Manifeste{Nom: "x", Version: "1.0", AuthKind: AuthAucune,
		MotifsURL: []string{"^https://("}}
	if err := m.Valider(); err == nil {
		t.Fatal("motif d'URL invalide accepte")
	}
}

func TestUnManifesteQuiPousseSansCapaciteEstRefuse(t *testing.T) {
	// Coherence : declarer AuthAucune et pretendre pousser sur une plateforme
	// est une contradiction qu'il vaut mieux voir au chargement.
	m := Manifeste{Nom: "x", Version: "1.0", AuthKind: AuthAucune,
		Capacites: []string{CapPousser}}
	if err := m.Valider(); err == nil {
		t.Fatal("publication sans authentification acceptee")
	}
}

func TestUnManifesteValidePasse(t *testing.T) {
	if err := neuf("faux").Manifeste().Valider(); err != nil {
		t.Fatalf("manifeste valide refuse : %v", err)
	}
}

func TestLeManifesteDitCeQuIlSaitFaire(t *testing.T) {
	m := neuf("faux").Manifeste()
	if !m.SaitFaire(CapTirer) || m.SaitFaire("telepathie") {
		t.Fatal("SaitFaire repond a cote")
	}
}

// ── registre ─────────────────────────────────────────────────────────────

func TestUnConnecteurEnregistreSeRetrouve(t *testing.T) {
	r := NouveauRegistre()
	f := neuf("exemple")
	if err := r.Enregistrer(f); err != nil {
		t.Fatal(err)
	}
	got, err := r.Ouvrir("exemple")
	if err != nil {
		t.Fatal(err)
	}
	if got.Manifeste().Nom != "exemple" {
		t.Fatalf("mauvais connecteur : %q", got.Manifeste().Nom)
	}
}

func TestUnConnecteurInconnuDonneUneErreurClaire(t *testing.T) {
	r := NouveauRegistre()
	_, err := r.Ouvrir("fantome")
	if !errors.Is(err, ErrConnecteurInconnu) {
		t.Fatalf("erreur attendue ErrConnecteurInconnu, obtenu %v", err)
	}
}

func TestUnDoublonDeNomEstRefuse(t *testing.T) {
	// Deux connecteurs du meme nom rendraient le resolveur imprevisible.
	r := NouveauRegistre()
	if err := r.Enregistrer(neuf("exemple")); err != nil {
		t.Fatal(err)
	}
	if err := r.Enregistrer(neuf("exemple")); err == nil {
		t.Fatal("doublon de nom accepte")
	}
}

func TestUnManifesteInvalideNEntrePasAuRegistre(t *testing.T) {
	r := NouveauRegistre()
	f := neuf("exemple")
	f.manifTV.Capacites = []string{"telepathie"}
	if err := r.Enregistrer(f); err == nil {
		t.Fatal("connecteur au manifeste invalide accepte")
	}
}

func TestLeRegistreSeListeParOrdreStable(t *testing.T) {
	r := NouveauRegistre()
	for _, n := range []string{"zeta", "alpha", "mu"} {
		if err := r.Enregistrer(neuf(n)); err != nil {
			t.Fatal(err)
		}
	}
	noms := r.Noms()
	if len(noms) != 3 || noms[0] != "alpha" || noms[2] != "zeta" {
		t.Fatalf("ordre instable : %v", noms)
	}
}

// ── sante ────────────────────────────────────────────────────────────────

func TestUnConnecteurDegradeResteInterrogeable(t *testing.T) {
	// Une plateforme qui change ses regles ne doit pas faire perdre ce qui est
	// deja entre : le connecteur passe degrade, les contenus restent.
	s := Sante{Etat: EtatDegrade, Motif: "jeton expire"}
	if s.Utilisable() {
		t.Fatal("un connecteur degrade est declare utilisable")
	}
	if s.Motif == "" {
		t.Fatal("un etat degrade sans motif n'aide personne")
	}
}
