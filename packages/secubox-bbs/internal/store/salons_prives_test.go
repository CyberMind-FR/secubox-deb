package store

import (
	"path/filepath"
	"testing"
)

func magasinSalons(t *testing.T) (s *Store, sysop, alice, bob, prive, ouvert int64) {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "bbs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	if sysop, err = s.CreateUser("gk2", "Gandalf", RoleSysop); err != nil {
		t.Fatal(err)
	}
	if alice, err = s.CreateUser("alice", "Alice", RoleMember); err != nil {
		t.Fatal(err)
	}
	if bob, err = s.CreateUser("bob", "Bob", RoleMember); err != nil {
		t.Fatal(err)
	}
	if prive, err = s.CreeSousSalon(sysop, "prive", "Bureau", "", 0); err != nil {
		t.Fatal(err)
	}
	if ouvert, err = s.CreeSousSalon(sysop, "ouvert", "Place", "", 0); err != nil {
		t.Fatal(err)
	}
	if err := s.RendPrive(prive, true); err != nil {
		t.Fatal(err)
	}
	return
}

func TestUnSalonEstOuvertParDefaut(t *testing.T) {
	// La confidentialite se DEMANDE. Un salon cree ne doit pas se refermer tout
	// seul : l'inverse ferait disparaitre des salons existants a la migration.
	s, _, alice, _, _, ouvert := magasinSalons(t)
	if p, _ := s.EstPrive(ouvert); p {
		t.Fatal("un salon neuf est prive")
	}
	vu, err := s.PeutVoirSalon(ouvert, alice, false)
	if err != nil || !vu {
		t.Errorf("salon ouvert invisible : %v %v", vu, err)
	}
}

func TestUnSalonPriveEstFermeAQuiNEstPasConvie(t *testing.T) {
	s, _, alice, _, prive, _ := magasinSalons(t)
	vu, err := s.PeutVoirSalon(prive, alice, false)
	if err != nil {
		t.Fatal(err)
	}
	if vu {
		t.Error("un salon prive est visible sans invitation")
	}
}

func TestUnMembreConvieVoitLeSalon(t *testing.T) {
	s, sysop, alice, _, prive, _ := magasinSalons(t)
	if err := s.AjouteMembre(prive, alice, sysop); err != nil {
		t.Fatal(err)
	}
	if vu, _ := s.PeutVoirSalon(prive, alice, false); !vu {
		t.Error("le membre convie ne voit pas le salon")
	}
	// Idempotent : convier deux fois n'est pas une erreur.
	if err := s.AjouteMembre(prive, alice, sysop); err != nil {
		t.Errorf("second ajout refuse : %v", err)
	}
}

func TestLeSysopVoitToutMemeSansEtreMembre(t *testing.T) {
	// Sans cela, un sysop pourrait creer un salon prive, en perdre l'acces, et
	// plus personne ne pourrait le moderer.
	s, sysop, _, _, prive, _ := magasinSalons(t)
	if vu, _ := s.PeutVoirSalon(prive, sysop, true); !vu {
		t.Error("le sysop ne voit pas un salon prive")
	}
}

func TestUnVisiteurNonConnecteNeVoitAucunSalonPrive(t *testing.T) {
	s, _, _, _, prive, _ := magasinSalons(t)
	if vu, _ := s.PeutVoirSalon(prive, 0, false); vu {
		t.Error("un salon prive est visible sans etre connecte")
	}
}

func TestLaListeDesSalonsCachesNeFuitPasLeurExistence(t *testing.T) {
	s, sysop, alice, bob, prive, ouvert := magasinSalons(t)
	if err := s.AjouteMembre(prive, alice, sysop); err != nil {
		t.Fatal(err)
	}
	// Alice est membre : rien ne lui est cache.
	caches, err := s.SalonsCachesPour(alice, false)
	if err != nil {
		t.Fatal(err)
	}
	if caches[prive] {
		t.Error("le salon est cache a son propre membre")
	}
	// Bob ne l'est pas : le salon doit disparaitre de son rail.
	caches, _ = s.SalonsCachesPour(bob, false)
	if !caches[prive] {
		t.Error("un salon prive resterait affiche a un non-membre")
	}
	if caches[ouvert] {
		t.Error("un salon ouvert est cache")
	}
}

func TestRetirerUnMembreRefermeLaPorte(t *testing.T) {
	s, sysop, alice, _, prive, _ := magasinSalons(t)
	_ = s.AjouteMembre(prive, alice, sysop)
	if err := s.RetireMembre(prive, alice); err != nil {
		t.Fatal(err)
	}
	if vu, _ := s.PeutVoirSalon(prive, alice, false); vu {
		t.Error("l'acces survit au retrait")
	}
}

func TestUneInvitationDeSalonNeCreeAucunCompte(t *testing.T) {
	// LE POINT LE PLUS IMPORTANT. Le code rattache un compte DEJA existant ; il
	// n'est pas une porte d'entree sur la board. Partage par megarde, il ne
	// donne acces a rien tant que celui qui le ramasse n'a pas de compte.
	s, sysop, _, _, prive, _ := magasinSalons(t)
	code, err := s.NouvelleInvitationSalon(prive, sysop)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RejoinsSalon(code, 0); err == nil {
		t.Error("une invitation servie sans compte a ete acceptee")
	}
}

func TestUneInvitationOuvreLeBonSalonUneSeuleFois(t *testing.T) {
	s, sysop, alice, bob, prive, _ := magasinSalons(t)
	code, err := s.NouvelleInvitationSalon(prive, sysop)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := s.RejoinsSalon(code, alice)
	if err != nil {
		t.Fatalf("invitation refusee : %v", err)
	}
	if cat != prive {
		t.Errorf("mauvais salon ouvert : %d", cat)
	}
	if vu, _ := s.PeutVoirSalon(prive, alice, false); !vu {
		t.Error("l'invitation n'a pas donne l'acces")
	}
	// Rejouee, elle ne vaut plus rien — sans quoi un code partage ferait entrer
	// tout le monde.
	if _, err := s.RejoinsSalon(code, bob); err == nil {
		t.Error("invitation rejouable")
	}
	if vu, _ := s.PeutVoirSalon(prive, bob, false); vu {
		t.Error("un tiers est entre avec un code deja servi")
	}
}

func TestUnCodeInconnuEstRefuse(t *testing.T) {
	s, _, alice, _, _, _ := magasinSalons(t)
	if _, err := s.RejoinsSalon("code-invente", alice); err == nil {
		t.Error("code inconnu accepte")
	}
}

func TestLaConsoleListeLesMembres(t *testing.T) {
	s, sysop, alice, _, prive, _ := magasinSalons(t)
	_ = s.AjouteMembre(prive, alice, sysop)
	m, err := s.MembresDuSalon(prive)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 {
		t.Fatalf("membres = %d", len(m))
	}
}
