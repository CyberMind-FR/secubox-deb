package store

import (
	"path/filepath"
	"testing"
	"time"
)

var t0 = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

func banc(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "radio.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// ── NORMALISATION DE LA SOURCE ──────────────────────────────────────────────
//
// Sans elle, la meme chanson entre trois fois et la playlist se remplit de
// doublons que personne ne comprend — le desaccord ne se voit qu'a l'ecoute.
func TestLaMemeChansonNeRentrePasDeuxFois(t *testing.T) {
	memes := []string{
		"https://www.youtube.com/watch?v=ABC123",
		"https://youtu.be/ABC123",
		"https://youtube.com/watch?v=ABC123&t=42s",
		"https://m.youtube.com/watch?v=ABC123",
		"https://music.youtube.com/watch?v=ABC123&list=XYZ",
		"https://www.youtube.com/shorts/ABC123",
	}
	ref := CleSource(memes[0])
	for _, m := range memes[1:] {
		if got := CleSource(m); got != ref {
			t.Errorf("CleSource(%q) = %q, attendu %q", m, got, ref)
		}
	}
	// ...et deux chansons differentes restent differentes.
	if CleSource("https://youtu.be/ABC123") == CleSource("https://youtu.be/XYZ789") {
		t.Error("deux videos distinctes partagent la meme cle")
	}
}

// ON NE REND JAMAIS UNE CLE VIDE POUR UNE ENTREE NON VIDE : deux adresses
// inconnues deviendraient « egales » et la seconde ecraserait la premiere.
func TestUneAdresseInconnueGardeUneCleDistincte(t *testing.T) {
	a := CleSource("https://exemple.fr/piste/1")
	b := CleSource("https://exemple.fr/piste/2")
	if a == "" || b == "" {
		t.Fatal("cle vide pour une adresse non vide")
	}
	if a == b {
		t.Error("deux adresses distinctes partagent la meme cle")
	}
	// Les parametres de suivi ne creent pas de doublon.
	if CleSource("https://exemple.fr/p?utm_source=x") != CleSource("https://exemple.fr/p") {
		t.Error("un parametre de suivi cree un doublon")
	}
}

func TestAjouterDeuxFoisRendLaMemePiste(t *testing.T) {
	s := banc(t)
	a, neuf, err := s.Ajoute("https://youtu.be/ABC", "Un titre", 1, t0)
	if err != nil || !neuf {
		t.Fatalf("premier ajout : %v neuf=%v", err, neuf)
	}
	b, neuf, err := s.Ajoute("https://www.youtube.com/watch?v=ABC&t=9", "", 2, t0)
	if err != nil {
		t.Fatal(err)
	}
	if neuf {
		t.Error("le doublon a ete traite comme une piste neuve")
	}
	if a.ID != b.ID {
		t.Errorf("deux identifiants pour la meme chanson : %d et %d", a.ID, b.ID)
	}
}

// REPROPOSER UNE PISTE INDISPONIBLE LA REMET EN JEU : c'est souvent ce que
// veut dire le geste — « reessaie celle-la ».
func TestReproposerUnePisteIndisponibleLaRemetEnJeu(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Ajoute("https://youtu.be/ABC", "", 1, t0)
	if err := s.MarqueIndisponible(p.ID, "geo-bloque"); err != nil {
		t.Fatal(err)
	}
	if q, _ := s.ParID(p.ID); !q.Indisponible {
		t.Fatal("la piste n'est pas marquee indisponible")
	}
	q, neuf, err := s.Ajoute("https://youtu.be/ABC", "", 2, t0)
	if err != nil || neuf {
		t.Fatalf("re-ajout : %v neuf=%v", err, neuf)
	}
	if q.Indisponible {
		t.Error("la piste reste ecartee alors qu'on la repropose")
	}
}

// ── COEURS ──────────────────────────────────────────────────────────────────
//
// UNE TABLE, PAS UN COMPTEUR : un entier ne saurait ni empecher le double
// vote, ni dire QUI a aime.
func TestUnCoeurNeCompteQuUneFoisParPersonne(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Ajoute("https://youtu.be/ABC", "", 1, t0)
	for i := 0; i < 3; i++ {
		if err := s.PoseCoeur(p.ID, 7, t0); err != nil {
			t.Fatalf("pose %d : %v", i, err)
		}
	}
	if q, _ := s.ParID(p.ID); q.Coeurs != 1 {
		t.Errorf("%d coeurs pour une seule personne", q.Coeurs)
	}
	_ = s.PoseCoeur(p.ID, 8, t0)
	if q, _ := s.ParID(p.ID); q.Coeurs != 2 {
		t.Errorf("%d coeurs pour deux personnes", q.Coeurs)
	}
}

func TestOnPeutRetirerSonCoeurEtLuiSeul(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Ajoute("https://youtu.be/ABC", "", 1, t0)
	_ = s.PoseCoeur(p.ID, 7, t0)
	_ = s.PoseCoeur(p.ID, 8, t0)
	if err := s.RetireCoeur(p.ID, 7); err != nil {
		t.Fatal(err)
	}
	q, _ := s.ParID(p.ID)
	if q.Coeurs != 1 {
		t.Errorf("%d coeurs apres retrait", q.Coeurs)
	}
	if a, _ := s.ACoeur(p.ID, 7); a {
		t.Error("le coeur retire est toujours la")
	}
	if a, _ := s.ACoeur(p.ID, 8); !a {
		t.Error("le retrait a emporte le coeur d'un autre")
	}
}

// ── LECTURES ────────────────────────────────────────────────────────────────

func TestLaDerniereLectureAlimenteLeRepos(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Ajoute("https://youtu.be/ABC", "", 1, t0)
	if q, _ := s.ParID(p.ID); q.JoueeLe != 0 {
		t.Fatal("une piste neuve porte deja une lecture")
	}
	_ = s.NoteLecture(p.ID, t0.Add(-2*time.Hour), 111)
	_ = s.NoteLecture(p.ID, t0.Add(-30*time.Minute), 222)
	q, _ := s.ParID(p.ID)
	if q.JoueeLe != t0.Add(-30*time.Minute).Unix() {
		t.Errorf("derniere lecture = %d, attendue la plus recente", q.JoueeLe)
	}
}

// LE JOURNAL EST APPEND-ONLY : c'est lui qui rend le tirage explicable.
func TestLHistoriqueDesLecturesEstConserve(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Ajoute("https://youtu.be/ABC", "", 1, t0)
	for i := 0; i < 3; i++ {
		_ = s.NoteLecture(p.ID, t0.Add(time.Duration(i)*time.Hour), int64(100+i))
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM lectures WHERE piste_id = ?`, p.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("%d lectures conservees sur 3", n)
	}
}

// ── TIRAGE ──────────────────────────────────────────────────────────────────
//
// UNE PISTE PAS ENCORE EN CACHE EST ECARTEE : la tirer donnerait un silence.
// Elle reste dans la file, visible, avec son etat.
func TestUnePisteSansCacheNestPasTirable(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Ajoute("https://youtu.be/ABC", "", 1, t0)
	tp, _, err := s.PourTirage()
	if err != nil {
		t.Fatal(err)
	}
	if len(tp) != 1 {
		t.Fatalf("%d pistes", len(tp))
	}
	if !tp[0].Indisponible {
		t.Error("une piste non recuperee est proposee au tirage : elle donnerait un silence")
	}
	// ...et elle le devient une fois en cache.
	if err := s.PoseCache(p.ID, "/data/1.opus", "audio/ogg", 4096, 210000, "Titre", "Auteur"); err != nil {
		t.Fatal(err)
	}
	tp, _, _ = s.PourTirage()
	if tp[0].Indisponible {
		t.Error("une piste en cache reste ecartee du tirage")
	}
	q, _ := s.ParID(p.ID)
	if !q.EnCache() || q.Titre != "Titre" || q.DureeMS != 210000 {
		t.Errorf("cache mal enregistre : %+v", q)
	}
}

// La file reste dans l'ordre d'ajout : c'est ce que l'interface affiche.
func TestLaFileGardeLOrdreDAjout(t *testing.T) {
	s := banc(t)
	for i, u := range []string{"https://youtu.be/A", "https://youtu.be/B", "https://youtu.be/C"} {
		if _, _, err := s.Ajoute(u, "", 1, t0.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	l, err := s.Toutes()
	if err != nil || len(l) != 3 {
		t.Fatalf("%d pistes, %v", len(l), err)
	}
	if l[0].Source != "yt:A" || l[2].Source != "yt:C" {
		t.Errorf("ordre casse : %s, %s, %s", l[0].Source, l[1].Source, l[2].Source)
	}
}

// Le depart d'un membre ne retire pas sa musique de l'antenne.
func TestUneAdresseVideEstRefusee(t *testing.T) {
	s := banc(t)
	if _, _, err := s.Ajoute("   ", "", 1, t0); err == nil {
		t.Error("une adresse vide a ete acceptee")
	}
}
