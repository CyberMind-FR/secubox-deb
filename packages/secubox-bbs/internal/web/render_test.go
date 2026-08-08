package web

import "testing"

func TestLeHtmlEcritParUnMembreEstAffichePasExecute(t *testing.T) {
	// Les corps sont du Markdown ecrit par des humains. Si le rendu laissait
	// passer du HTML brut, n'importe quel membre pourrait poser un script dans
	// un message — et le BBS est justement l'endroit ou l'on colle ce qu'on a
	// trouve ailleurs.
	out := string(Render(`<script>alert(1)</script> et <img src=x onerror=alert(2)>`))
	// On verifie qu'aucune BALISE de l'entree ne subsiste. Chercher
	// « onerror= » serait un faux positif : la chaine apparait bien dans la
	// sortie, mais comme du texte echappe, donc inoffensive. Ce qui compte est
	// le « < » ouvrant, pas le nom de l'attribut.
	for _, balise := range []string{"<script", "<img", "<b>", "<iframe"} {
		if contains(out, balise) {
			t.Errorf("balise %s rendue telle quelle : %s", balise, out)
		}
	}
	if !contains(out, "&lt;script") {
		t.Errorf("le texte n'a pas ete echappe : %s", out)
	}
}

func TestUnLienJavascriptNEstPasUnLien(t *testing.T) {
	// `[clic](javascript:…)` est la voie la plus courte entre « un membre peut
	// ecrire » et « un membre peut agir a la place d'un autre ». Le schema est
	// donc sur liste BLANCHE : ce qui n'est pas http, https ou mailto n'est pas
	// un lien du tout.
	for _, mauvais := range []string{
		"[clic](javascript:alert(1))",
		"[clic](JaVaScRiPt:alert(1))",
		"[clic](data:text/html;base64,PHNjcmlwdD4=)",
		"[clic](vbscript:msgbox)",
	} {
		out := string(Render(mauvais))
		if contains(out, "href=") {
			t.Errorf("%s a produit un lien : %s", mauvais, out)
		}
	}
}

func TestUnLienNormalResteUnLien(t *testing.T) {
	out := string(Render("[le site](https://cybermind.fr) et [ecrire](mailto:a@b.fr)"))
	if !contains(out, `href="https://cybermind.fr"`) {
		t.Errorf("lien http perdu : %s", out)
	}
	if !contains(out, `href="mailto:a@b.fr"`) {
		t.Errorf("lien mailto perdu : %s", out)
	}
	if !contains(out, `rel="noopener`) {
		t.Errorf("lien sortant sans rel=noopener : %s", out)
	}
}

func TestLaMiseEnFormeSimpleFonctionne(t *testing.T) {
	out := string(Render("## Titre\n\nUn **gras** et un `code`.\n\n- un\n- deux\n\n> cite"))
	for _, veut := range []string{"<h3>", "<strong>gras</strong>", "<code>code</code>",
		"<ul>", "<li>un</li>", "<blockquote>"} {
		if !contains(out, veut) {
			t.Errorf("%s absent du rendu : %s", veut, out)
		}
	}
}

func TestUneSyntaxeInconnueResteDuTexte(t *testing.T) {
	// Le principe : ce que le rendu ne comprend pas s'affiche tel quel. Il ne
	// devine pas, et surtout il ne laisse rien passer « au cas ou ».
	out := string(Render("un <b>gras html</b> et une {{template}}"))
	if contains(out, "<b>") {
		t.Errorf("HTML inconnu interprete : %s", out)
	}
	if !contains(out, "{{template}}") {
		t.Errorf("texte perdu : %s", out)
	}
}

func contains(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}
