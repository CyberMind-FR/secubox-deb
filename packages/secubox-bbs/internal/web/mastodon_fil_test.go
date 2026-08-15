package web

import (
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/mastodon"
)

// LA FRONTIERE DE CONFIANCE DE TOUTE LA FONCTIONNALITE. Le contenu d'une
// publication est du HTML produit par une instance TIERCE. Le rendre tel quel
// donnerait a cette instance le droit d'executer du script chez nos membres.
func TestLeContenuDistantEstDebaliseEtNonFiltre(t *testing.T) {
	cas := []struct{ brut, attendu string }{
		{`<p>bonjour</p>`, "bonjour"},
		{`<p>a<br>b</p>`, "a\nb"},
		{`<p>un</p><p>deux</p>`, "un\n\ndeux"},
		{`<p><a href="https://x.fr">lien</a></p>`, "lien"},
		// Ce qui doit surtout ne pas ressortir vivant :
		{`<script>alert(1)</script>bonjour`, "alert(1)bonjour"},
		{`<img src=x onerror=alert(1)>ok`, "ok"},
		{`<p onclick="alert(1)">texte</p>`, "texte"},
		{`<iframe src="https://mal.fr"></iframe>fin`, "fin"},
	}
	for _, c := range cas {
		if got := mastodon.TexteDe(c.brut); got != c.attendu {
			t.Errorf("TexteDe(%q) = %q, attendu %q", c.brut, got, c.attendu)
		}
	}
}

// AUCUNE BALISE NE SURVIT, quelle qu'elle soit. On ne filtre pas par liste
// blanche — c'est l'exercice qu'on rate — on debalise entierement.
func TestAucuneBaliseNeSurvit(t *testing.T) {
	for _, brut := range []string{
		`<b>gras</b>`, `<span class="h-card">@moi</span>`,
		`<a href="javascript:alert(1)">clic</a>`,
		`<svg><animate onbegin=alert(1)></svg>x`,
		`<p>a</p><!-- commentaire --><p>b</p>`,
	} {
		if got := mastodon.TexteDe(brut); strings.ContainsAny(got, "<>") {
			t.Errorf("une balise survit dans TexteDe(%q) = %q", brut, got)
		}
	}
}

// L'ORDRE COMPTE. On debalise AVANT de decoder les entites : dans l'autre sens,
// `&lt;script&gt;` serait devenu une vraie balise. Ici il ressort en TEXTE, que
// le gabarit echappera — ce qui est le comportement voulu, a condition que le
// resultat ne soit jamais marque `template.HTML`.
func TestLesEntitesSontDecodeesApresLeDebalisage(t *testing.T) {
	got := mastodon.TexteDe(`<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>`)
	if got != "<script>alert(1)</script>" {
		t.Errorf("resultat = %q", got)
	}
	// Et le gabarit ne doit pas se voir confier ce texte comme du HTML.
	g := gabaritSansCommentaires(t, "templates/mastodon.html")
	if !strings.Contains(g, "{{.Texte}}") {
		t.Error("le gabarit ne rend pas le texte de la publication")
	}
	// ON SCANNE LE GABARIT SANS SES COMMENTAIRES : la premiere version de ce
	// test se declenchait sur le commentaire qui met justement en garde contre
	// le contournement — un test qui echoue sur sa propre documentation.
	for _, danger := range []string{"safeHTML", "{{.Texte | ", "| safe"} {
		if strings.Contains(g, danger) {
			t.Errorf("le gabarit contourne l'echappement : %s", danger)
		}
	}
}

// LE FORMULAIRE DE LIAISON DOIT RESTER VISIBLE. En inserant le bloc du fil,
// une premiere version avait referme la carte trop tot et enferme la branche
// « pas encore relie » dans un conteneur masque : la fonctionnalite devenait
// inatteignable pour qui n'avait justement pas encore lie son compte.
func TestLeGabaritSertLesDeuxEtatsDuCompte(t *testing.T) {
	g := gabaritSansCommentaires(t, "templates/mastodon.html")
	for _, attendu := range []string{
		`action="/mastodon/lier"`,   // branche « pas encore relie »
		`action="/mastodon/delier"`, // branche « relie »
		`name="instance"`,
	} {
		if !strings.Contains(g, attendu) {
			t.Errorf("le gabarit ne contient pas %s", attendu)
		}
	}
	if strings.Contains(g, "s-cache") {
		t.Error("un conteneur masque subsiste dans le gabarit")
	}
}

// AUCUNE IMAGE DISTANTE N'EST CHARGEE AUTOMATIQUEMENT : elle signalerait chaque
// lecture au serveur d'en face, qui sur une publication federee n'est pas le
// notre.
func TestLesMediasDistantsNeSontPasChargesAutomatiquement(t *testing.T) {
	g := gabaritSansCommentaires(t, "templates/mastodon.html")
	i := strings.Index(g, "range .Medias")
	if i < 0 {
		t.Fatal("le bloc des medias est absent")
	}
	bloc := g[i:]
	if j := strings.Index(bloc, "{{end}}"); j > 0 {
		bloc = bloc[:j]
	}
	if strings.Contains(bloc, "<img") || strings.Contains(bloc, "Apercu") {
		t.Error("une image distante serait chargee a l'affichage")
	}
}

// gabaritSansCommentaires rend un gabarit prive de ses commentaires `{{/* */}}`,
// pour que les tests portent sur ce qui est RENDU et non sur ce qui est ecrit
// a cote.
func gabaritSansCommentaires(t *testing.T, nom string) string {
	t.Helper()
	src, err := assets.ReadFile(nom)
	if err != nil {
		t.Fatalf("lecture de %s : %v", nom, err)
	}
	s := string(src)
	for {
		i := strings.Index(s, "{{/*")
		if i < 0 {
			return s
		}
		j := strings.Index(s[i:], "*/}}")
		if j < 0 {
			return s[:i]
		}
		s = s[:i] + s[i+j+4:]
	}
}
