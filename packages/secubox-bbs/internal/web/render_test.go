package web

import (
	"strings"
	"testing"
)

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

func TestUneAdresseNueDevientUnLien(t *testing.T) {
	// Les corps importes sont pleins d'adresses ecrites telles quelles —
	// « Retrouvez le podcast sur https://bit.ly/… ». Sans reconnaissance
	// automatique, elles s'affichent en texte mort : il faut les selectionner
	// et les recopier. Sur un telephone, autant dire qu'elles n'existent pas.
	out := string(Render("Retrouvez le podcast sur https://bit.ly/bureaudescomplots et dites-nous."))
	if !contains(out, `href="https://bit.ly/bureaudescomplots"`) {
		t.Errorf("adresse nue non reconnue : %s", out)
	}
	if !contains(out, "et dites-nous") {
		t.Errorf("le texte qui suit a ete avale : %s", out)
	}
}

func TestLaPonctuationFinaleNEntrePasDansLeLien(t *testing.T) {
	// « Voir https://exemple.fr. » — le point termine la phrase, il ne fait pas
	// partie de l'adresse. Idem pour une parenthese fermante ou une virgule.
	for _, cas := range []struct{ src, veut string }{
		{"Voir https://exemple.fr.", `href="https://exemple.fr"`},
		{"Voir https://exemple.fr, puis", `href="https://exemple.fr"`},
		{"(https://exemple.fr)", `href="https://exemple.fr"`},
	} {
		out := string(Render(cas.src))
		if !contains(out, cas.veut) {
			t.Errorf("%q -> %s", cas.src, out)
		}
	}
}

func TestUneAdresseNueEnSchemaInterditNEstPasUnLien(t *testing.T) {
	// La meme liste blanche que pour les liens ecrits : reconnaitre
	// automatiquement ne doit pas ouvrir une porte que la syntaxe explicite
	// tient fermee.
	for _, mauvais := range []string{
		"javascript:alert(1)", "data:text/html,<script>", "vbscript:x", "file:///etc/passwd",
	} {
		if out := string(Render("essai " + mauvais)); contains(out, "href=") {
			t.Errorf("%s a produit un lien : %s", mauvais, out)
		}
	}
}

func TestUneAdresseDejaDansUnLienNEstPasDoublee(t *testing.T) {
	out := string(Render("[le site](https://cybermind.fr)"))
	if n := compte(out, "href="); n != 1 {
		t.Errorf("%d liens au lieu d'un : %s", n, out)
	}
}

func compte(h, n string) int {
	c := 0
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			c++
		}
	}
	return c
}

func TestUnePieceJointeLocaleDevientUnLecteur(t *testing.T) {
	cas := []struct{ src, attendu string }{
		{"voir /f/12.png", `<img class="jointe"`},
		{"ecouter /f/7.ogg", `<audio class="jointe"`},
		{"la video /f/9.mp4", `<video class="jointe"`},
	}
	for _, c := range cas {
		got := string(Render(c.src))
		if !strings.Contains(got, c.attendu) {
			t.Errorf("%q ne produit pas %s :\n%s", c.src, c.attendu, got)
		}
	}
}

func TestSeulesNosAdressesSontIntegrees(t *testing.T) {
	// Integrer une adresse quelconque ferait charger une ressource DISTANTE
	// depuis la page : chaque lecteur serait signale au serveur d'en face, et
	// qui controle ce serveur obtiendrait un point d'entree dans la page.
	got := string(Render("photo https://ailleurs.example/piege.png"))
	if strings.Contains(got, "<img") {
		t.Errorf("une image distante a ete integree :\n%s", got)
	}
	if !strings.Contains(got, "<a href=") {
		t.Errorf("l'adresse distante devrait rester un simple lien :\n%s", got)
	}
}

func TestUneAdresseDeposeeNEstPasUnVecteur(t *testing.T) {
	// Le chemin est un NUMERO. Une adresse fabriquee a la main ne doit ni
	// remonter l'arborescence ni produire de balise.
	for _, mauvais := range []string{
		"/f/../../etc/passwd",
		"/f/1;rm -rf",
		"/f/<script>alert(1)</script>",
	} {
		got := string(Render("essai " + mauvais))
		if strings.Contains(got, "<img") || strings.Contains(got, "<script") {
			t.Errorf("%q a produit une balise :\n%s", mauvais, got)
		}
	}
}
