package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

// #1091 — l'auteur edite SES messages ; un sysop corrige CEUX DES AUTRES. Toute
// edition laisse une trace (edited_at/edited_by + journal d'audit).

func magasinEdition(t *testing.T) (s *Store, auteur, autre, sysop, cat int64) {
	t.Helper()
	var err error
	s, err = Open(filepath.Join(t.TempDir(), "bbs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if auteur, err = s.CreateUser("alice", "Alice", RoleMember); err != nil {
		t.Fatal(err)
	}
	if autre, err = s.CreateUser("bob", "Bob", RoleMember); err != nil {
		t.Fatal(err)
	}
	if sysop, err = s.CreateUser("gk2", "Gandalf", RoleSysop); err != nil {
		t.Fatal(err)
	}
	if cat, err = s.CreateCategory("place", "Place", ""); err != nil {
		t.Fatal(err)
	}
	return
}

func premierPost(t *testing.T, s *Store, fil int64) int64 {
	t.Helper()
	ps, err := s.PostsOf(fil)
	if err != nil || len(ps) == 0 {
		t.Fatalf("aucun post: %v", err)
	}
	return ps[0].ID
}

func corpsDuPost(t *testing.T, s *Store, fil, post int64) string {
	t.Helper()
	ps, _ := s.PostsOf(fil)
	for _, p := range ps {
		if p.ID == post {
			b, err := s.Body(p)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
	}
	t.Fatalf("post %d introuvable", post)
	return ""
}

func TestAuteurEditeSonPropreMessage(t *testing.T) {
	s, auteur, _, _, cat := magasinEdition(t)
	fil, _ := s.NewThread(cat, auteur, "Sujet", "texte initial", VisPublic)
	post := premierPost(t, s, fil)

	if err := s.EditerPost(auteur, RoleMember, post, "texte corrige par l'auteur"); err != nil {
		t.Fatal(err)
	}
	if got := corpsDuPost(t, s, fil, post); got != "texte corrige par l'auteur" {
		t.Fatalf("corps = %q", got)
	}
	var ed int64
	s.db.QueryRow(`SELECT COALESCE(edited_at,0) FROM posts WHERE id=?`, post).Scan(&ed)
	if ed == 0 {
		t.Fatal("edited_at non pose")
	}
}

func TestUnMembreNePeutEditerLeMessageDUnAutre(t *testing.T) {
	s, auteur, autre, _, cat := magasinEdition(t)
	fil, _ := s.NewThread(cat, auteur, "Sujet", "texte initial", VisPublic)
	post := premierPost(t, s, fil)

	err := s.EditerPost(autre, RoleMember, post, "detournement")
	if !errors.Is(err, ErrDroitEdition) {
		t.Fatalf("attendu ErrDroitEdition, obtenu %v", err)
	}
	if got := corpsDuPost(t, s, fil, post); got != "texte initial" {
		t.Fatalf("corps modifie sans droit : %q", got)
	}
}

func TestLeSysopCorrigeLeMessageDUnAutre(t *testing.T) {
	s, auteur, _, sysop, cat := magasinEdition(t)
	fil, _ := s.NewThread(cat, auteur, "Sujet", "faute d'ortografe", VisPublic)
	post := premierPost(t, s, fil)

	if err := s.EditerPost(sysop, RoleSysop, post, "faute d'orthographe"); err != nil {
		t.Fatal(err)
	}
	if got := corpsDuPost(t, s, fil, post); got != "faute d'orthographe" {
		t.Fatalf("corps = %q", got)
	}
	var by int64
	s.db.QueryRow(`SELECT COALESCE(edited_by,0) FROM posts WHERE id=?`, post).Scan(&by)
	if by != sysop {
		t.Fatalf("edited_by = %d, veut %d", by, sysop)
	}
	// Une correction de moderation est journalisee distinctement.
	var n int
	s.db.QueryRow(`SELECT count(*) FROM audit WHERE action='post.corrige' AND target=?`,
		fmt.Sprintf("post:%d", post)).Scan(&n)
	if n != 1 {
		t.Fatalf("journal post.corrige manquant (n=%d)", n)
	}
}

func TestEditerRefuseUnCorpsVide(t *testing.T) {
	s, auteur, _, _, cat := magasinEdition(t)
	fil, _ := s.NewThread(cat, auteur, "Sujet", "texte", VisPublic)
	post := premierPost(t, s, fil)

	if err := s.EditerPost(auteur, RoleMember, post, "   "); err == nil {
		t.Fatal("un corps vide doit etre refuse")
	}
	if got := corpsDuPost(t, s, fil, post); got != "texte" {
		t.Fatalf("le corps a change malgre le refus : %q", got)
	}
}
