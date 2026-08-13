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

// ── Passerelles media (#1020) ─────────────────────────────────────────────

func filPasserelle(t *testing.T, s *Store, uid, cat int64, titre, source string) {
	t.Helper()
	id, err := s.NewThread(cat, uid, titre, "corps", VisPublic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE threads SET source = ? WHERE id = ?`, source, id); err != nil {
		t.Fatal(err)
	}
}

func TestLaPageMediaMontreLesFilsDesPasserelles(t *testing.T) {
	// LE CAS DE GK2 : la page annoncait « aucune passerelle raccordee » alors
	// que 222 fils y etaient — 122 emissions et 100 videos.
	s, uid := magasinPages(t)
	cat, err := s.CreateCategory("emissions", "Emissions", "")
	if err != nil {
		t.Skip("CreateCategory indisponible : " + err.Error())
	}
	filPasserelle(t, s, uid, cat, "Episode 1", "podcaster")
	filPasserelle(t, s, uid, cat, "Video 1", "peertube")

	fs, err := s.MediasParSource(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("%d fil(s) media, attendu 2", len(fs))
	}
}

func TestLesBilletsNeSontPasDesMedias(t *testing.T) {
	// `billets` est aussi une passerelle, mais ce qu'elle depose est du TEXTE.
	// L'afficher sous « Media » noierait ce qu'on vient y chercher.
	s, uid := magasinPages(t)
	cat, err := s.CreateCategory("archives", "Archives", "")
	if err != nil {
		t.Skip("CreateCategory indisponible")
	}
	filPasserelle(t, s, uid, cat, "Un billet", "billets")
	fs, _ := s.MediasParSource(50)
	if len(fs) != 0 {
		t.Errorf("%d fil(s) — un billet a ete pris pour un media", len(fs))
	}
}

func TestUnFilHumainNEstPasUnMedia(t *testing.T) {
	// Sans source, c'est quelqu'un qui a ecrit. La page Media ne doit pas
	// aspirer les conversations du salon.
	s, uid := magasinPages(t)
	cat, err := s.CreateCategory("place", "Place publique", "")
	if err != nil {
		t.Skip("CreateCategory indisponible")
	}
	if _, err := s.NewThread(cat, uid, "Bonjour", "corps", VisPublic); err != nil {
		t.Fatal(err)
	}
	fs, _ := s.MediasParSource(50)
	if len(fs) != 0 {
		t.Errorf("%d fil(s) — un fil humain a ete pris pour un media", len(fs))
	}
}
