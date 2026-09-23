// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package store

import (
	"strings"
	"testing"
	"time"
)

// LE PRÉ-FILTRE DOIT ÊTRE UN SUR-ENSEMBLE, ET RIEN D'AUTRE.
//
// `ArticlesSuspectsDeGabarit` déblaie en SQL pour ne pas relire 41 000 lignes,
// et laisse Go trancher. Tout le danger est là : si un `LIKE` ratait une forme
// que `linker.PorteUnGabarit` reconnaît, la réparation sauterait l'article SANS
// RIEN DIRE — un titre resterait illisible et personne ne saurait pourquoi.
//
// Ce test verrouille donc le contrat côté SQL : toute forme de gabarit doit
// ressortir. Qu'il ramène aussi des innocents est normal et voulu — Go les
// écarte ensuite.
func TestLePreFiltreNeRateAucuneFormeDeGabarit(t *testing.T) {
	s := ouvrir(t)
	src, err := s.AddSource(Source{Slug: "d", Name: "Dauphiné", URL: "https://x/rss", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	maintenant := time.Now().Unix()

	gabarits := []string{
		"Vidéo. $content.TitleNoTags", // le cas réel
		"${titre}",
		"{{ article.title }}",
		"<%= post.title %>",
	}
	// Des titres innocents : le pré-filtre peut les ramener (c'est son droit),
	// mais leur présence ici documente qu'ils passent par le même chemin.
	innocents := []string{
		"TikTok to pay $400m to US",
		"A$AP Rocky visite une villa",
		"La météo pour ce mercredi",
	}
	for i, titre := range append(append([]string{}, gabarits...), innocents...) {
		if _, _, err := s.UpsertArticle(Article{
			SourceID: src, Ref: string(rune('a' + i)), Title: titre,
			Summary:     "Un résumé suffisamment long pour tenir lieu de titre.",
			PublishedAt: maintenant,
		}); err != nil {
			t.Fatal(err)
		}
	}

	arts, err := s.ArticlesSuspectsDeGabarit(maintenant - 3600)
	if err != nil {
		t.Fatal(err)
	}
	vus := map[string]bool{}
	for _, a := range arts {
		vus[a.Title] = true
	}
	for _, g := range gabarits {
		if !vus[g] {
			t.Errorf("forme de gabarit ratée par le pré-filtre SQL : %q\n"+
				"→ l'article ne serait jamais réparé, et en silence", g)
		}
	}
}

// La fenêtre borne bien la passe : on ne réécrit pas les archives.
func TestLePreFiltreSArreteALaFenetre(t *testing.T) {
	s := ouvrir(t)
	src, _ := s.AddSource(Source{Slug: "d", Name: "D", URL: "https://x/rss", Enabled: true})
	maintenant := time.Now().Unix()
	_, _, _ = s.UpsertArticle(Article{SourceID: src, Ref: "vieux",
		Title: "Vidéo. $content.TitleNoTags", PublishedAt: maintenant - 90*24*3600})
	_, _, _ = s.UpsertArticle(Article{SourceID: src, Ref: "recent",
		Title: "Savoie. $content.TitleNoTags", PublishedAt: maintenant})

	arts, err := s.ArticlesSuspectsDeGabarit(maintenant - 30*24*3600)
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 1 || !strings.HasPrefix(arts[0].Title, "Savoie") {
		t.Fatalf("veut le seul article récent, a %d : %+v", len(arts), arts)
	}
}

// ── LES SUJETS FANTÔMES ────────────────────────────────────────────────────
// Reclasser détache les articles mal rattachés ; un sujet qui perd le dernier
// RESTE, avec son titre d'alors, et n'est plus recomposable — mais reste
// listé. C'est par deux d'entre eux que le défaut s'est vu : ils affichaient
// encore « $content.TitleNoTags » alors que tous les articles étaient réparés.

func TestUnSujetSansArticleEstRetire(t *testing.T) {
	s := ouvrir(t)
	maintenant := time.Now().Unix()
	vieux := maintenant - 7200
	if err := s.CreerSujet(Topic{ID: "fantome", Title: "Vidéo. $content.TitleNoTags",
		UpdatedAt: vieux}); err != nil {
		t.Fatal(err)
	}
	if err := s.AjouterEvenement("fantome", vieux, "resume", ""); err != nil {
		t.Fatal(err)
	}
	n, err := s.PurgerSujetsVides(maintenant - 3600)
	if err != nil || n != 1 {
		t.Fatalf("purge = %d, %v ; veut 1", n, err)
	}
	if _, err := s.SujetParID("fantome"); err == nil {
		t.Error("le sujet fantôme est toujours là")
	}
	// Ses événements partent avec lui : sans quoi ils s'accumuleraient en
	// désignant un sujet qui n'existe plus.
	lignes, _ := s.Timeline("fantome")
	if len(lignes) != 0 {
		t.Errorf("%d événement(s) orphelin(s) subsistent", len(lignes))
	}
}

func TestUnSujetQUI_NAIT_NEstPasPurge(t *testing.T) {
	// `Regrouper` crée le sujet PUIS lui rattache l'article : entre les deux
	// il est légitimement vide, et le sondage tourne EN MÊME TEMPS que la
	// passe. Sans marge d'âge, on supprimerait un sujet en train de naître.
	s := ouvrir(t)
	maintenant := time.Now().Unix()
	if err := s.CreerSujet(Topic{ID: "tout-neuf", Title: "À peine né",
		UpdatedAt: maintenant}); err != nil {
		t.Fatal(err)
	}
	n, err := s.PurgerSujetsVides(maintenant - 3600)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("un sujet qui naît a été purgé (%d)", n)
	}
	if _, err := s.SujetParID("tout-neuf"); err != nil {
		t.Errorf("le sujet neuf a disparu : %v", err)
	}
}

func TestUnSujetHABITE_NEstJamaisPurge(t *testing.T) {
	s := ouvrir(t)
	maintenant := time.Now().Unix()
	vieux := maintenant - 7200
	src, _ := s.AddSource(Source{Slug: "d", Name: "D", URL: "https://x/rss", Enabled: true})
	if err := s.CreerSujet(Topic{ID: "habite", Title: "Un vrai sujet", UpdatedAt: vieux}); err != nil {
		t.Fatal(err)
	}
	id, _, err := s.UpsertArticle(Article{SourceID: src, Ref: "a1", Title: "Titre",
		PublishedAt: vieux})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetArticleSujet(id, "habite"); err != nil {
		t.Fatal(err)
	}
	n, err := s.PurgerSujetsVides(maintenant - 3600)
	if err != nil || n != 0 {
		t.Fatalf("purge = %d, %v ; un sujet habité ne doit JAMAIS partir", n, err)
	}
}
