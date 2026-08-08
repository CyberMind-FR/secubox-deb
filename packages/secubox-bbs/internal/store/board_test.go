package store

import "testing"

func TestListeDesFilsNExposeQueLeSalonDemande(t *testing.T) {
	s := ouvre(t)
	c1, uid := salon(t, s)
	s.db.Exec(`INSERT INTO categories(slug,title) VALUES('prive','Prive')`)
	s.NewThread(c1, uid, "Dans l'atelier", "a", VisLocal)
	s.NewThread(2, uid, "Ailleurs", "b", VisLocal)

	th, err := s.Threads(c1, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(th) != 1 || th[0].Title != "Dans l'atelier" {
		t.Fatalf("%d fils, %+v", len(th), th)
	}
}

func TestListePubliqueNeMontreQueLesFilsPublics(t *testing.T) {
	// Cette liste alimente la page vue depuis internet. Un fil local qui y
	// apparaitrait divulguerait deja son TITRE — souvent l'essentiel.
	s := ouvre(t)
	cat, uid := salon(t, s)
	s.NewThread(cat, uid, "Coordonnees du medecin de garde", "…", VisLocal)
	s.NewThread(cat, uid, "Fil affichable", "…", VisPublic)

	th, err := s.Threads(cat, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(th) != 1 {
		t.Fatalf("%d fils publics, attendu 1", len(th))
	}
	if th[0].Title != "Fil affichable" {
		t.Errorf("titre local divulgue : %q", th[0].Title)
	}
}

func TestLeCompteDeReponsesIgnoreLesMessagesSupprimes(t *testing.T) {
	s := ouvre(t)
	cat, uid := salon(t, s)
	th, _ := s.NewThread(cat, uid, "Fil", "premier", VisLocal)
	p, _ := s.Reply(th, uid, "seconde", VisLocal)
	s.db.Exec(`UPDATE posts SET deleted_at = unixepoch() WHERE id = ?`, p)

	list, _ := s.Threads(cat, false)
	if list[0].Posts != 1 {
		t.Errorf("%d messages comptes, attendu 1", list[0].Posts)
	}
}

func TestDeuxFilsDeMemeTitreDansUnSalonSontAcceptes(t *testing.T) {
	// « Question du jour » sera ecrit dix fois. Refuser le second parce que son
	// SLUG existe deja est un defaut du programme, pas une regle du forum —
	// et le message qu'il produisait (« enregistrement impossible ») ne disait
	// rien de la cause.
	s := ouvre(t)
	cat, uid := salon(t, s)
	if _, err := s.NewThread(cat, uid, "Question du jour", "a", VisLocal); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NewThread(cat, uid, "Question du jour", "b", VisLocal); err != nil {
		t.Fatalf("second fil de meme titre refuse : %v", err)
	}
	th, _ := s.Threads(cat, false)
	if len(th) != 2 {
		t.Fatalf("%d fils, attendu 2", len(th))
	}
	if th[0].Slug == th[1].Slug {
		t.Errorf("deux fils partagent le slug %q", th[0].Slug)
	}
}
