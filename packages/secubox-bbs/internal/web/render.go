package web

// Rendu des corps de messages.
//
// POURQUOI PAS DE BIBLIOTHEQUE MARKDOWN, ET PAS DE HTML STOCKE
//
// L'editeur de la maquette a l'air d'un traitement de texte, mais ce qu'il
// enregistre est du Markdown, pas du HTML. La difference decide de la surface
// d'attaque :
//
//   - stocker du HTML obligerait a l'ASSAINIR a l'affichage. Un assainisseur
//     est une liste de ce a quoi on a pense ; il vieillit mal et il faut le
//     suivre.
//
//   - stocker du Markdown permet de CONSTRUIRE le HTML. Ce qui n'est pas
//     explicitement produit ici n'existe pas dans la page. C'est une liste
//     blanche, pas une liste noire.
//
// Le rendu est volontairement pauvre : gras, italique, code, titres, listes,
// citations, liens. Ce que la grammaire ne comprend pas s'affiche tel quel.

import (
	"html/template"
	"strings"
)

// schemasAutorises : la liste est BLANCHE.
//
// `[clic](javascript:…)` est la voie la plus courte entre « un membre peut
// ecrire » et « un membre peut agir a la place d'un autre ». Interdire
// javascript: ne suffirait pas — il faudrait aussi penser a data:, vbscript:,
// et aux prochains. Autoriser trois schemas connus ferme la question.
var schemasAutorises = []string{"http://", "https://", "mailto:"}

func lienSur(url string) bool {
	u := strings.ToLower(strings.TrimSpace(url))
	for _, s := range schemasAutorises {
		if strings.HasPrefix(u, s) {
			return true
		}
	}
	// Un chemin relatif interne reste acceptable : il ne peut pas changer
	// d'origine. Mais pas `//ailleurs.example` qui, lui, en change.
	return strings.HasPrefix(u, "/") && !strings.HasPrefix(u, "//")
}

// Render transforme un corps Markdown en HTML sur.
func Render(src string) template.HTML {
	var b strings.Builder
	lignes := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")

	enListe, enCitation := false, false
	fermer := func() {
		if enListe {
			b.WriteString("</ul>\n")
			enListe = false
		}
		if enCitation {
			b.WriteString("</blockquote>\n")
			enCitation = false
		}
	}

	for _, l := range lignes {
		t := strings.TrimRight(l, " \t")
		switch {
		case strings.TrimSpace(t) == "":
			fermer()

		case strings.HasPrefix(t, "## "):
			fermer()
			// h3 et non h1 : le titre du fil occupe deja le premier niveau de
			// la page. Un h1 dans un message casserait la structure du document
			// pour un lecteur d'ecran.
			b.WriteString("<h3>" + string(inline(t[3:])) + "</h3>\n")

		case strings.HasPrefix(t, "- "):
			if enCitation {
				b.WriteString("</blockquote>\n")
				enCitation = false
			}
			if !enListe {
				b.WriteString("<ul>\n")
				enListe = true
			}
			b.WriteString("<li>" + string(inline(t[2:])) + "</li>\n")

		case strings.HasPrefix(t, "> "):
			if enListe {
				b.WriteString("</ul>\n")
				enListe = false
			}
			if !enCitation {
				b.WriteString("<blockquote>\n")
				enCitation = true
			}
			b.WriteString("<p>" + string(inline(t[2:])) + "</p>\n")

		default:
			fermer()
			b.WriteString("<p>" + string(inline(t)) + "</p>\n")
		}
	}
	fermer()
	return template.HTML(b.String())
}

// inline echappe D'ABORD, puis reintroduit les seules balises produites ici.
//
// L'ordre n'est pas negociable : echapper apres aurait neutralise nos propres
// balises, et melanger les deux etapes est exactement l'erreur qui produit les
// failles d'injection.
func inline(s string) template.HTML {
	e := template.HTMLEscapeString(s)
	e = liens(e)
	e = paires(e, "**", "<strong>", "</strong>")
	e = paires(e, "`", "<code>", "</code>")
	e = paires(e, "*", "<em>", "</em>")
	return template.HTML(e)
}

func paires(s, marque, ouvre, ferme string) string {
	var b strings.Builder
	ouvert := false
	for {
		i := strings.Index(s, marque)
		if i < 0 {
			break
		}
		b.WriteString(s[:i])
		if ouvert {
			b.WriteString(ferme)
		} else {
			b.WriteString(ouvre)
		}
		ouvert = !ouvert
		s = s[i+len(marque):]
	}
	b.WriteString(s)
	out := b.String()
	// Marque impaire : on ne devine pas ou l'auteur voulait fermer, on rend le
	// texte tel qu'il l'a ecrit.
	if ouvert {
		return strings.Replace(out, ouvre, marque, 1)
	}
	return out
}

func liens(s string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, "[")
		if i < 0 {
			break
		}
		j := strings.Index(s[i:], "](")
		k := -1
		if j >= 0 {
			k = strings.Index(s[i+j:], ")")
		}
		if j < 0 || k < 0 {
			b.WriteString(s[:i+1])
			s = s[i+1:]
			continue
		}
		texte := s[i+1 : i+j]
		url := s[i+j+2 : i+j+k]
		b.WriteString(s[:i])
		if lienSur(url) {
			// noopener : une page ouverte depuis un lien peut sinon manipuler
			// celle qui l'a ouverte. noreferrer : l'adresse d'un fil interne
			// n'a pas a etre transmise au site visite.
			b.WriteString(`<a href="` + template.HTMLEscapeString(url) +
				`" rel="noopener noreferrer">` + texte + `</a>`)
		} else {
			// Ni lien, ni suppression : le lecteur voit ce qui etait ecrit et
			// peut juger lui-meme.
			b.WriteString(texte + " (" + url + ")")
		}
		s = s[i+j+k+1:]
	}
	b.WriteString(s)
	return b.String()
}
