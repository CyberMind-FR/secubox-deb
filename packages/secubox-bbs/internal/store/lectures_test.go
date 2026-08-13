package store

import (
	"path/filepath"
	"testing"
)

func magasinLectures(t *testing.T) (*Store, int64, int64) {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "bbs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	uid, err := s.CreateUser("gk2", "Gandalf", RoleSysop)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := s.CreateCategory("place", "Place publique", "")
	if err != nil {
		t.Fatal(err)
	}
	return s, uid, cat
}

func TestUnFilJamaisOuvertEstNonLu(t *testing.T) {
	// C'est ce qu'attend le lecteur d'un fil qu'il n'a jamais vu. L'inverse —
	// tout considerer comme lu par defaut — masquerait tout le contenu
	// existant a un nouveau membre.
	s, uid, cat := magasinLectures(t)
	id, err := s.NewThread(cat, uid, "Bonjour", "corps", VisPublic)
	if err != nil {
		t.Fatal(err)
	}
	nl, err := s.FilsNonLus(uid)
	if err != nil {
		t.Fatal(err)
	}
	if !nl[id] {
		t.Error("un fil jamais ouvert n'est pas signale comme non-lu")
	}
}

func TestOuvrirUnFilLeMarqueLu(t *testing.T) {
	s, uid, cat := magasinLectures(t)
	id, _ := s.NewThread(cat, uid, "Bonjour", "corps", VisPublic)
	if err := s.MarqueLu(uid, id); err != nil {
		t.Fatal(err)
	}
	nl, _ := s.FilsNonLus(uid)
	if nl[id] {
		t.Error("le fil reste non-lu apres ouverture")
	}
}

func TestUneReponseRendLeFilNonLuANouveau(t *testing.T) {
	// LA RAISON D'ETRE de la fonction : savoir ce qui a bouge DEPUIS la
	// derniere visite, pas seulement ce qu'on n'a jamais ouvert.
	s, uid, cat := magasinLectures(t)
	id, _ := s.NewThread(cat, uid, "Bonjour", "corps", VisPublic)
	s.MarqueLu(uid, id)

	// Une reponse posterieure : last_post_at avance au-dela de lu_at.
	if _, err := s.db.Exec(
		`UPDATE threads SET last_post_at = last_post_at + 3600 WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	nl, _ := s.FilsNonLus(uid)
	if !nl[id] {
		t.Error("un fil ayant recu une reponse reste marque lu")
	}
}

func TestMarquerLuEstIdempotent(t *testing.T) {
	// Appele a CHAQUE ouverture : un second passage ne doit pas echouer sur la
	// cle primaire.
	s, uid, cat := magasinLectures(t)
	id, _ := s.NewThread(cat, uid, "Bonjour", "corps", VisPublic)
	for i := 0; i < 3; i++ {
		if err := s.MarqueLu(uid, id); err != nil {
			t.Fatalf("passage %d : %v", i, err)
		}
	}
}

func TestLaLectureEstPROPREACHAQUEMEMBRE(t *testing.T) {
	// Sans cela, ouvrir un fil le marquerait lu pour tout le monde — et
	// l'indicateur ne voudrait plus rien dire.
	s, uid, cat := magasinLectures(t)
	autre, err := s.CreateUser("amie", "Amie", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := s.NewThread(cat, uid, "Bonjour", "corps", VisPublic)
	s.MarqueLu(uid, id)

	nl, _ := s.FilsNonLus(autre)
	if !nl[id] {
		t.Error("la lecture d'un membre a marque le fil lu pour un autre")
	}
}

func TestUnVisiteurNonConnecteNAPasDHistorique(t *testing.T) {
	// Ne RIEN marquer est plus honnete que de tout marquer comme neuf : le
	// geste « marquer lu » n'existe pas pour lui, la page clignoterait a vie.
	s, uid, cat := magasinLectures(t)
	s.NewThread(cat, uid, "Bonjour", "corps", VisPublic)
	nl, err := s.FilsNonLus(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(nl) != 0 {
		t.Errorf("%d fil(s) non-lus pour un visiteur anonyme", len(nl))
	}
	if err := s.MarqueLu(0, 1); err != nil {
		t.Errorf("marquer lu en anonyme a echoue : %v", err)
	}
}

func TestLeCompteParSalonSuitLesNonLus(t *testing.T) {
	s, uid, cat := magasinLectures(t)
	a, _ := s.NewThread(cat, uid, "Un", "corps", VisPublic)
	s.NewThread(cat, uid, "Deux", "corps", VisPublic)

	c, err := s.NonLusParSalon(uid)
	if err != nil {
		t.Fatal(err)
	}
	if c[cat] != 2 {
		t.Fatalf("compte = %d, attendu 2", c[cat])
	}
	s.MarqueLu(uid, a)
	c, _ = s.NonLusParSalon(uid)
	if c[cat] != 1 {
		t.Errorf("compte apres lecture = %d, attendu 1", c[cat])
	}
}

func TestToutMarquerLuFaitRetomberLeCompteur(t *testing.T) {
	// LE GESTE QUI MANQUE LE PLUS a qui revient apres deux semaines. Sans lui,
	// la seule facon de faire retomber le compteur est d'ouvrir deux cents fils
	// un par un — donc de ne jamais le faire.
	s, uid, cat := magasinLectures(t)
	for i := 0; i < 5; i++ {
		s.NewThread(cat, uid, "Fil", "corps", VisPublic)
	}
	if err := s.MarqueToutLu(uid); err != nil {
		t.Fatal(err)
	}
	nl, _ := s.FilsNonLus(uid)
	if len(nl) != 0 {
		t.Errorf("%d fil(s) encore non-lus apres « tout marquer lu »", len(nl))
	}
}
