// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package gateway

import "testing"

func contenu(modif ...func(*Contenu)) Contenu {
	c := Contenu{
		Genre:        GenreTexte,
		Titre:        "Un titre",
		Corps:        "Le corps du message.",
		Auteur:       "@gandalf@mastodon.example",
		SourceURL:    "https://mastodon.example/@gandalf/123",
		Connecteur:   "mastodon",
		RefNative:    "123",
		Propriete:    ProprieteSoi,
		NoeudOrigine: "gk2",
	}
	for _, m := range modif {
		m(&c)
	}
	return c
}

// ── empreinte ────────────────────────────────────────────────────────────

func TestLEmpreinteEstDeterministe(t *testing.T) {
	if Empreinte(contenu()) != Empreinte(contenu()) {
		t.Fatal("deux calculs sur le meme contenu donnent des empreintes differentes")
	}
}

func TestUneMemeSourceImporteeDeuxFoisDonneLaMemeEmpreinte(t *testing.T) {
	// Deux imports separes : dates de collecte et metadonnees different, mais
	// c'est le MEME contenu. Sans cela le BBS afficherait deux fois la meme
	// chose a chaque passage du collecteur.
	a := contenu(func(c *Contenu) { c.Metadonnees = map[string]string{"vu": "lundi"} })
	b := contenu(func(c *Contenu) {
		c.Metadonnees = map[string]string{"vu": "mardi", "extra": "1"}
		c.PublieLe = 1600000000
	})
	if Empreinte(a) != Empreinte(b) {
		t.Fatal("le meme contenu revu plus tard produit un doublon")
	}
}

func TestLURLEstNormaliseePourLEmpreinte(t *testing.T) {
	// Suivi publicitaire, ancre, casse de l'hote et barre finale ne changent
	// pas l'identite d'un contenu : ils changent l'adresse, pas l'oeuvre.
	for _, variante := range []string{
		"https://MASTODON.example/@gandalf/123",
		"https://mastodon.example/@gandalf/123/",
		"https://mastodon.example/@gandalf/123?utm_source=newsletter",
		"https://mastodon.example/@gandalf/123#en-haut",
		"https://mastodon.example/@gandalf/123/?fbclid=xyz&utm_medium=x#bas",
	} {
		a := contenu()
		b := contenu(func(c *Contenu) { c.SourceURL = variante })
		if Empreinte(a) != Empreinte(b) {
			t.Fatalf("variante d'adresse traitee comme un autre contenu : %s", variante)
		}
	}
}

func TestUnParametreSignifiantEstConserve(t *testing.T) {
	// On retire le pistage, pas la pagination : « ?page=2 » designe une autre
	// page, donc un autre contenu.
	a := contenu(func(c *Contenu) { c.SourceURL = "https://exemple.org/fil?page=1" })
	b := contenu(func(c *Contenu) { c.SourceURL = "https://exemple.org/fil?page=2" })
	if Empreinte(a) == Empreinte(b) {
		t.Fatal("deux pages distinctes confondues")
	}
}

func TestLeTexteEstNormalisePourLEmpreinte(t *testing.T) {
	a := contenu()
	b := contenu(func(c *Contenu) { c.Corps = "  Le corps   du message.\r\n " })
	if Empreinte(a) != Empreinte(b) {
		t.Fatal("un espacement different suffit a creer un doublon")
	}
}

func TestUnCorpsDifferentDonneUneEmpreinteDifferente(t *testing.T) {
	a := contenu()
	b := contenu(func(c *Contenu) { c.Corps = "Tout autre chose." })
	if Empreinte(a) == Empreinte(b) {
		t.Fatal("deux contenus distincts partagent une empreinte")
	}
}

func TestLeConnecteurEntreDansLEmpreinte(t *testing.T) {
	// La meme adresse vue par deux connecteurs reste deux objets : le contexte
	// d'acquisition fait partie de l'identite.
	a := contenu()
	b := contenu(func(c *Contenu) { c.Connecteur = "rss" })
	if Empreinte(a) == Empreinte(b) {
		t.Fatal("le connecteur n'entre pas dans l'empreinte")
	}
}

func TestLesMediasEntrentDansLEmpreinte(t *testing.T) {
	a := contenu()
	b := contenu(func(c *Contenu) {
		c.Medias = []Media{{Chemin: "ab/x/img.jpg", Mime: "image/jpeg", Taille: 10, Somme: "a1"}}
	})
	if Empreinte(a) == Empreinte(b) {
		t.Fatal("l'ajout d'un media ne change pas l'empreinte")
	}
}

func TestLOrdreDesMediasEstSansEffet(t *testing.T) {
	m1 := Media{Chemin: "a/1.jpg", Mime: "image/jpeg", Taille: 1, Somme: "11"}
	m2 := Media{Chemin: "a/2.jpg", Mime: "image/jpeg", Taille: 2, Somme: "22"}
	a := contenu(func(c *Contenu) { c.Medias = []Media{m1, m2} })
	b := contenu(func(c *Contenu) { c.Medias = []Media{m2, m1} })
	if Empreinte(a) != Empreinte(b) {
		t.Fatal("l'ordre de collecte des medias change l'identite du contenu")
	}
}

func TestLEmpreinteEstDuBlake2bHexadecimal(t *testing.T) {
	e := Empreinte(contenu())
	if len(e) != 64 {
		t.Fatalf("longueur inattendue : %d", len(e))
	}
	for _, r := range e {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Fatalf("caractere non hexadecimal : %q", r)
		}
	}
}

func TestLaFormeCanoniqueEstStable(t *testing.T) {
	if FormeCanonique(contenu()) != FormeCanonique(contenu()) {
		t.Fatal("la forme canonique varie d'un appel a l'autre")
	}
}

// ── validation ───────────────────────────────────────────────────────────

func TestUnContenuSansProprieteEstRefuse(t *testing.T) {
	// Ce champ decide si un contenu peut etre republie. Il ne doit JAMAIS
	// avoir de valeur par defaut, sous peine de republier du tiers par erreur.
	c := contenu(func(c *Contenu) { c.Propriete = "" })
	if err := c.Valider(); err == nil {
		t.Fatal("un contenu sans propriete declaree est accepte")
	}
}

func TestUneProprieteInconnueEstRefusee(t *testing.T) {
	c := contenu(func(c *Contenu) { c.Propriete = "peut-etre" })
	if err := c.Valider(); err == nil {
		t.Fatal("propriete inconnue acceptee")
	}
}

func TestUnGenreInconnuEstRefuse(t *testing.T) {
	c := contenu(func(c *Contenu) { c.Genre = "hologramme" })
	if err := c.Valider(); err == nil {
		t.Fatal("genre inconnu accepte")
	}
}

func TestUneRetentionInconnueEstRefusee(t *testing.T) {
	c := contenu(func(c *Contenu) { c.Retention = "eternel" })
	if err := c.Valider(); err == nil {
		t.Fatal("retention inconnue acceptee")
	}
}

func TestLaRetentionParDefautEstLeCache(t *testing.T) {
	c := contenu()
	if err := c.Valider(); err != nil {
		t.Fatalf("contenu valide refuse : %v", err)
	}
	if c.Retention != RetentionCache {
		t.Fatalf("retention par defaut = %q, attendu %q", c.Retention, RetentionCache)
	}
}

func TestUneSourceSansAdresseEstRefusee(t *testing.T) {
	c := contenu(func(c *Contenu) { c.SourceURL = "" })
	if err := c.Valider(); err == nil {
		t.Fatal("contenu sans adresse source accepte")
	}
}

func TestUneAdresseNonHttpEstRefusee(t *testing.T) {
	// Un connecteur compromis ne doit pas pouvoir faire lire un fichier local.
	for _, u := range []string{"file:///etc/passwd", "ftp://x.example/a", "javascript:alert(1)"} {
		c := contenu(func(c *Contenu) { c.SourceURL = u })
		if err := c.Valider(); err == nil {
			t.Fatalf("adresse acceptee alors qu'elle devrait etre refusee : %s", u)
		}
	}
}

func TestValiderRenseigneLEmpreinte(t *testing.T) {
	c := contenu()
	if err := c.Valider(); err != nil {
		t.Fatalf("contenu valide refuse : %v", err)
	}
	if c.Empreinte != Empreinte(c) {
		t.Fatal("l'empreinte n'est pas posee par la validation")
	}
}
