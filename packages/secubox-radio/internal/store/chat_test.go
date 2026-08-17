package store

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// LE CURSEUR EST UN IDENTIFIANT, PAS UN HORODATAGE. Deux phrases dites la meme
// seconde portent le meme horodatage : l'une des deux serait perdue, ou
// repetee a chaque sondage.
func TestDeuxPhrasesDansLaMemeSecondeNeSePerdentPas(t *testing.T) {
	s := banc(t)
	a, err := s.Dis(1, "alice", "premiere", 0, t0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Dis(2, "bob", "seconde", 0, t0) // MEME seconde
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == b.ID {
		t.Fatal("deux phrases partagent le meme identifiant")
	}
	// Un auditeur qui a vu la premiere doit recevoir la seconde, et elle seule.
	suite, err := s.Depuis(a.ID, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(suite) != 1 || suite[0].Corps != "seconde" {
		t.Errorf("suite = %+v, attendue la seule seconde phrase", suite)
	}
}

func TestLesPhrasesReviennentDansLOrdre(t *testing.T) {
	s := banc(t)
	for i, m := range []string{"un", "deux", "trois"} {
		if _, err := s.Dis(1, "alice", m, 0, t0.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	l, _ := s.Depuis(0, 50)
	if len(l) != 3 || l[0].Corps != "un" || l[2].Corps != "trois" {
		t.Errorf("ordre casse : %+v", l)
	}
}

// UN NOUVEL ARRIVANT RECOIT LA CONVERSATION EN COURS, pas le debut de
// l'histoire. Demander « les N premieres apres 0 » aurait rendu les plus
// anciennes — exactement l'inverse de ce qu'on veut lire en arrivant.
func TestUnArrivantRecoitLaConversationEnCoursPasSonDebut(t *testing.T) {
	s := banc(t)
	for i := 0; i < 30; i++ {
		if _, err := s.Dis(int64(i%5+1), "u", "phrase", 0,
			t0.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	l, err := s.Depuis(0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 10 {
		t.Fatalf("%d phrases rendues au lieu de 10", len(l))
	}
	// La derniere rendue doit etre la derniere dite.
	if l[len(l)-1].ID != 30 {
		t.Errorf("la derniere phrase rendue est la %d, attendue la 30e", l[len(l)-1].ID)
	}
	if l[0].ID != 21 {
		t.Errorf("la premiere rendue est la %d : on rend le debut de l'histoire", l[0].ID)
	}
}

// ── ANTI-FLOT ───────────────────────────────────────────────────────────────
//
// Un chat sans limite se fait noyer par le premier script venu, et il suffit
// d'un doigt reste appuye.
func TestUnFlotEstArrete(t *testing.T) {
	s := banc(t)
	for i := 0; i < MaxParFenetre; i++ {
		if _, err := s.Dis(1, "alice", "spam", 0, t0); err != nil {
			t.Fatalf("phrase %d refusee : %v", i, err)
		}
	}
	if _, err := s.Dis(1, "alice", "de trop", 0, t0); !errors.Is(err, ErrTropVite) {
		t.Errorf("la phrase de trop est passee : %v", err)
	}
	// ...mais la limite est PAR PERSONNE : un bavard ne doit pas faire taire
	// les autres.
	if _, err := s.Dis(2, "bob", "bonjour", 0, t0); err != nil {
		t.Errorf("un tiers est bloque par le flot d'un autre : %v", err)
	}
	// ...et elle se relache avec le temps.
	if _, err := s.Dis(1, "alice", "plus tard", 0, t0.Add(FenetreAntiFlot+time.Second)); err != nil {
		t.Errorf("la limite ne se relache pas : %v", err)
	}
}

// ── BORNES ──────────────────────────────────────────────────────────────────

func TestUnePhraseVideEstRefusee(t *testing.T) {
	s := banc(t)
	for _, vide := range []string{"", "   ", "\n\t "} {
		if _, err := s.Dis(1, "alice", vide, 0, t0); !errors.Is(err, ErrPhraseVide) {
			t.Errorf("phrase %q acceptee : %v", vide, err)
		}
	}
}

// ON COUPE EN RUNES, PAS EN OCTETS : couper au milieu d'un caractere accentue
// produirait une sequence invalide, que l'affichage rendrait en losange noir.
func TestUnePhraseLongueEstCoupeeProprement(t *testing.T) {
	s := banc(t)
	long := strings.Repeat("é", LongueurMaxChat+50)
	p, err := s.Dis(1, "alice", long, 0, t0)
	if err != nil {
		t.Fatal(err)
	}
	if n := utf8.RuneCountInString(p.Corps); n != LongueurMaxChat {
		t.Errorf("%d runes conservees au lieu de %d", n, LongueurMaxChat)
	}
	if !utf8.ValidString(p.Corps) {
		t.Error("la coupure a produit une chaine invalide")
	}
}

// LE CORPS EST RANGE, PAS FILTRE. On ne nettoie pas un balisage : l'affichage
// echappe, et « nettoyer » ici donnerait l'illusion qu'il peut se relacher.
func TestLeCorpsNestPasFiltre(t *testing.T) {
	s := banc(t)
	p, err := s.Dis(1, "alice", "  <b>gras</b> & co  ", 0, t0)
	if err != nil {
		t.Fatal(err)
	}
	if p.Corps != "<b>gras</b> & co" {
		t.Errorf("corps = %q — il a ete filtre, ou mal range", p.Corps)
	}
}

// La phrase retient la piste qui passait : sans elle, « celle-la est terrible »
// ne veut plus rien dire une heure apres.
func TestUnePhraseRetientLaPisteQuiPassait(t *testing.T) {
	s := banc(t)
	pi, _, _ := s.Ajoute("https://youtu.be/ABC", "", 1, t0)
	p, err := s.Dis(1, "alice", "celle-la est terrible", pi.ID, t0)
	if err != nil {
		t.Fatal(err)
	}
	if p.PisteID != pi.ID {
		t.Errorf("piste = %d, attendue %d", p.PisteID, pi.ID)
	}
	l, _ := s.Depuis(0, 10)
	if len(l) != 1 || l[0].PisteID != pi.ID {
		t.Errorf("la piste n'est pas relue : %+v", l)
	}
}

// La suppression d'une piste ne doit pas emporter la conversation.
func TestSupprimerUnePisteNEffacePasLeChat(t *testing.T) {
	s := banc(t)
	pi, _, _ := s.Ajoute("https://youtu.be/ABC", "", 1, t0)
	if _, err := s.Dis(1, "alice", "bonjour", pi.ID, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Retire(pi.ID); err != nil {
		t.Fatal(err)
	}
	l, err := s.Depuis(0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 1 {
		t.Fatalf("la conversation a disparu avec la piste : %d phrases", len(l))
	}
	if l[0].PisteID != 0 {
		t.Errorf("la phrase pointe encore une piste supprimee : %d", l[0].PisteID)
	}
}

func TestLaPurgeNeGardeQueLeRecent(t *testing.T) {
	s := banc(t)
	_, _ = s.Dis(1, "alice", "vieux", 0, t0.Add(-48*time.Hour))
	_, _ = s.Dis(1, "alice", "recent", 0, t0)
	n, err := s.PurgeChat(t0.Add(-24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d phrases purgees", n)
	}
	l, _ := s.Depuis(0, 10)
	if len(l) != 1 || l[0].Corps != "recent" {
		t.Errorf("apres purge : %+v", l)
	}
}
