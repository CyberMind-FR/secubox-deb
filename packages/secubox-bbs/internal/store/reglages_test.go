package store

import (
	"path/filepath"
	"testing"
)

func baseSeule(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "bbs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestUneCleAbsenteNEstPasUneErreur(t *testing.T) {
	// L'absence de reglage est l'etat NORMAL d'une installation neuve. La
	// remonter comme une erreur ferait echouer le rendu de la page entiere
	// tant que le sysop n'a rien colle.
	s := baseSeule(t)
	v, err := s.Reglage(CleMastodonInvite)
	if err != nil {
		t.Fatalf("cle absente remontee en erreur : %v", err)
	}
	if v != "" {
		t.Errorf("valeur = %q, attendu vide", v)
	}
}

func TestPoserPuisRelirePuisRemplacer(t *testing.T) {
	s := baseSeule(t)
	if err := s.PoseReglage(CleMastodonInvite, "https://social.example/invite/AAA"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Reglage(CleMastodonInvite); v != "https://social.example/invite/AAA" {
		t.Errorf("relecture = %q", v)
	}
	// Le remplacement ne doit pas creer une seconde ligne : la cle est primaire,
	// un INSERT nu echouerait et le sysop ne pourrait jamais corriger sa saisie.
	if err := s.PoseReglage(CleMastodonInvite, "https://social.example/invite/BBB"); err != nil {
		t.Fatalf("remplacement refuse : %v", err)
	}
	if v, _ := s.Reglage(CleMastodonInvite); v != "https://social.example/invite/BBB" {
		t.Errorf("apres remplacement = %q", v)
	}
}

func TestPoserUneValeurVideEffaceLeReglage(t *testing.T) {
	// Sinon « retirer le lien » laisserait une ligne vide, que la page rendrait
	// comme un lien pose mais sans destination.
	s := baseSeule(t)
	s.PoseReglage(CleMastodonInvite, "https://social.example/invite/AAA")
	if err := s.PoseReglage(CleMastodonInvite, "   "); err != nil {
		t.Fatal(err)
	}
	v, err := s.Reglage(CleMastodonInvite)
	if err != nil {
		t.Fatal(err)
	}
	if v != "" {
		t.Errorf("valeur = %q apres effacement", v)
	}
}

func TestSeulsHttpEtHttpsSontAcceptes(t *testing.T) {
	// Le lien est colle par le sysop puis rendu dans un href visible de tous les
	// membres. Un javascript: y deviendrait actif sur chaque page du module.
	refuses := []string{
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"file:///etc/passwd",
		"https://",                  // pas d'hote
		"social.example/invite/AAA", // pas de schema : url.Parse l'accepte en chemin
		"",
		"   ",
	}
	for _, mauvais := range refuses {
		if LienExterneValide(mauvais) {
			t.Errorf("lien accepte a tort : %q", mauvais)
		}
	}
	acceptes := []string{
		"https://social.gk2.secubox.in/invite/abc123",
		"http://192.168.1.200:3000/invite/x",
	}
	for _, bon := range acceptes {
		if !LienExterneValide(bon) {
			t.Errorf("lien legitime refuse : %q", bon)
		}
	}
}
