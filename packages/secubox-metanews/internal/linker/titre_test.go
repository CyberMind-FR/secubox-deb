// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package linker

import "testing"

// LES VRAIS TITRES D'ABORD. Un premier filtre sur le seul caractère `$` en
// attrapait une centaine pour soixante-dix-neuf vrais cas : les prix en
// dollars sont partout dans un flux d'actualité, et deux noms propres portent
// le signe. Ce test est celui qui doit tenir : abîmer un titre juste est plus
// grave que laisser passer un gabarit.
func TestUnVraiTitreNestJamaisTouche(t *testing.T) {
	intacts := []string{
		"TikTok to pay $400m to US in one of largest child privacy settlements",
		"Trump says every adult American would get $5,000 if Republicans win",
		"A$AP Rocky, le rappeur qui s’affranchit des injonctions viriles",
		"LAPSUS$ réapparaît autour d’une attaque contre Courir",
		"Vosges. Rihanna et A$AP Rocky visitent une villa",
		"Le coût de la vie a augmenté de 3.5 % cette année",
		"La météo pour ce mercredi 23 septembre 2026",
		"",
	}
	for _, in := range intacts {
		if got := TitreLisible(in, "Un résumé quelconque et assez long pour servir."); got != in {
			t.Errorf("titre abîmé :\n  avant %q\n  après %q", in, got)
		}
		if PorteUnGabarit(in) {
			t.Errorf("faux positif de gabarit : %q", in)
		}
	}
}

func TestLeGabaritCedeLaPlaceAuResume(t *testing.T) {
	cas := []struct {
		titre, corps, veut string
	}{
		{ // le cas réel du Dauphiné, chapeau compris
			"Vidéo. $content.TitleNoTags",
			"Qui est Elif Eralp, la tête de liste de gauche qui a remporté " +
				"l'élection de maire de Berlin dimanche 20 septembre ? Elle " +
				"siège depuis 2021.",
			"Vidéo. Qui est Elif Eralp, la tête de liste de gauche qui a " +
				"remporté l'élection de maire de Berlin dimanche 20 septembre ?",
		},
		{ // chapeau sans ponctuation : on en pose une
			"Savoie $content.TitleNoTags",
			"Le procès se poursuit devant le tribunal correctionnel de Chambéry.",
			"Savoie. Le procès se poursuit devant le tribunal correctionnel de Chambéry.",
		},
		{ // pas de chapeau : le résumé seul
			"{{ article.title }}",
			"Va-t-on passer de classes surbondées à des cours vides ? Certains s'en inquiètent.",
			"Va-t-on passer de classes surbondées à des cours vides ?",
		},
		{ // autres moteurs de gabarit
			"${titre}", "Une dépêche parfaitement ordinaire et suffisamment longue.",
			"Une dépêche parfaitement ordinaire et suffisamment longue.",
		},
	}
	for _, c := range cas {
		if got := TitreLisible(c.titre, c.corps); got != c.veut {
			t.Errorf("TitreLisible(%q)\n  veut %q\n  a    %q", c.titre, c.veut, got)
		}
	}
}

// SANS CORPS, ON NE FABRIQUE RIEN. Un gabarit affiché reste préférable à une
// dépêche sans titre : on ne saurait plus ni la désigner ni la retrouver.
func TestSansQuoiReparerOnNAbimeRien(t *testing.T) {
	if got := TitreLisible("$content.TitleNoTags", ""); got != "$content.TitleNoTags" {
		t.Errorf("veut le titre d'origine, a %q", got)
	}
	if got := TitreLisible("Vidéo. $content.TitleNoTags", ""); got != "Vidéo." {
		t.Errorf("veut le chapeau seul, a %q", got)
	}
}

// Une abréviation porte un point qui ne termine pas la phrase.
func TestUnPointDAbreviationNeCoupePas(t *testing.T) {
	got := TitreLisible("Portrait. $x.y",
		"M. Dupont a présenté son rapport au conseil municipal ce mardi. Il a été adopté.")
	veut := "Portrait. M. Dupont a présenté son rapport au conseil municipal ce mardi."
	if got != veut {
		t.Errorf("veut %q\n  a  %q", veut, got)
	}
}

// Réparer deux fois donne le même résultat : la passe peut repasser.
func TestReparerEstIdempotent(t *testing.T) {
	corps := "Une dépêche parfaitement ordinaire et suffisamment longue pour servir."
	une := TitreLisible("Vidéo. $content.TitleNoTags", corps)
	if deux := TitreLisible(une, corps); deux != une {
		t.Errorf("non idempotent :\n  1 %q\n  2 %q", une, deux)
	}
}

func TestUnTitreNeDevientPasUnArticle(t *testing.T) {
	long := ""
	for i := 0; i < 40; i++ {
		long += "mot "
	}
	got := TitreLisible("Vidéo. $a.b", long+"fin.")
	if n := len([]rune(got)); n > maxTitre+1 {
		t.Errorf("titre de %d caractères : %q", n, got)
	}
}
