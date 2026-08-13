package store

import (
	"bytes"
	"path/filepath"
	"testing"
)

// La page annoncait « aucun fichier depose » alors que neuf l'etaient, et
// « aucun fil publie » alors que deux l'etaient — le compteur du menu, lui,
// affichait bien 2. Un message vide en dur est indiscernable d'un vide reel :
// c'est ce qui a laisse le defaut passer (#1020).

func magasinPages(t *testing.T) (*Store, int64) {
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
	return s, uid
}

func TestLaBibliothequeMontreLesFichiersDeTousLesMembres(t *testing.T) {
	// LA BIBLIOTHEQUE EST COMMUNE. Filtree par proprietaire, elle aurait
	// montre une page vide a tous ceux qui n'ont rien depose — la plupart.
	s, uid := magasinPages(t)
	autre, err := s.CreateUser("amie", "Amie", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeposeFichier(uid, "a.png", "image/png", bytes.NewReader(pngValide)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeposeFichier(autre, "b.png", "image/png", bytes.NewReader(pngValide)); err != nil {
		t.Fatal(err)
	}
	fs, err := s.TousFichiers(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("%d fichier(s), attendu 2 — la bibliotheque filtre par proprietaire", len(fs))
	}
}

func TestChaqueFichierPorteLeNomDeSonDeposant(t *testing.T) {
	// Sans le deposant, une bibliotheque commune devient un tas anonyme : on ne
	// peut plus demander le contexte d'un fichier a qui l'a mis la.
	s, uid := magasinPages(t)
	if _, err := s.DeposeFichier(uid, "a.png", "image/png", bytes.NewReader(pngValide)); err != nil {
		t.Fatal(err)
	}
	fs, _ := s.TousFichiers(50)
	if len(fs) != 1 || fs[0].Deposant != "Gandalf" {
		t.Fatalf("deposant = %q, attendu Gandalf", fs[0].Deposant)
	}
}

func TestUnFichierSupprimeDisparaitDeLaBibliotheque(t *testing.T) {
	s, uid := magasinPages(t)
	f, _ := s.DeposeFichier(uid, "a.png", "image/png", bytes.NewReader(pngValide))
	if err := s.SupprimeFichier(uid, f.ID); err != nil {
		t.Fatal(err)
	}
	fs, _ := s.TousFichiers(50)
	if len(fs) != 0 {
		t.Errorf("%d fichier(s) apres suppression", len(fs))
	}
}

func TestUneBibliothequeVideRendUneListeVideSansErreur(t *testing.T) {
	// Le cas nominal d'un BBS neuf. Il doit se distinguer d'une ERREUR de
	// lecture, que la page annonce au lieu de l'avaler.
	s, _ := magasinPages(t)
	fs, err := s.TousFichiers(50)
	if err != nil {
		t.Fatalf("erreur sur bibliotheque vide : %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("%d fichier(s) sur un magasin neuf", len(fs))
	}
}

func TestAucunBilletSurUnMagasinNeuf(t *testing.T) {
	s, _ := magasinPages(t)
	bs, err := s.Billets(50)
	if err != nil {
		t.Fatalf("erreur : %v", err)
	}
	if len(bs) != 0 {
		t.Errorf("%d billet(s)", len(bs))
	}
}
