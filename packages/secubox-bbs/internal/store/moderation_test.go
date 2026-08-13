package store

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func magasinMod(t *testing.T) (*Store, int64, int64) {
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

// ── La regle qui commande : on masque, on n'efface pas ────────────────────

func TestRetirerUnMessageLeMasqueMaisNeLEffacePas(t *testing.T) {
	// Une moderation contestee doit pouvoir etre EXAMINEE. Un effacement
	// definitif rend le desaccord indecidable : parole contre parole, sans piece.
	s, uid, cat := magasinMod(t)
	fil, err := s.NewThread(cat, uid, "Sujet", "corps", VisPublic)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := s.Reply(fil, uid, "message a retirer", VisPublic)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RetireMessage(uid, msg, "hors sujet"); err != nil {
		t.Fatal(err)
	}
	// Toujours en base…
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM posts WHERE id = ?`, msg).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal("le message a ete efface au lieu d'etre masque")
	}
	// …mais hors de ce qui sort de la maison.
	pub, _ := s.PublicPostsOf(fil)
	for _, p := range pub {
		if p.ID == msg {
			t.Error("le message retire figure encore dans les messages publics")
		}
	}
}

func TestUnRetraitSeDefait(t *testing.T) {
	// La symetrie n'est pas un ornement : une moderation sans retour en arriere
	// pousse a ne jamais moderer, de peur de se tromper.
	s, uid, cat := magasinMod(t)
	fil, _ := s.NewThread(cat, uid, "Sujet", "corps", VisPublic)
	msg, _ := s.Reply(fil, uid, "message", VisPublic)
	s.RetireMessage(uid, msg, "erreur")
	if err := s.RetablitMessage(uid, msg); err != nil {
		t.Fatal(err)
	}
	pub, _ := s.PublicPostsOf(fil)
	trouve := false
	for _, p := range pub {
		if p.ID == msg {
			trouve = true
		}
	}
	if !trouve {
		t.Error("le message retabli ne reparait pas")
	}
}

// ── Tout geste est journalise ─────────────────────────────────────────────

func TestChaqueGesteDeModerationEstJournalise(t *testing.T) {
	// Un pouvoir de moderation sans trace n'est pas un pouvoir encadre.
	s, uid, cat := magasinMod(t)
	fil, _ := s.NewThread(cat, uid, "Ancien titre", "corps", VisPublic)
	msg, _ := s.Reply(fil, uid, "message", VisPublic)

	s.RenommeFil(uid, fil, "Nouveau titre")
	s.VerrouilleFil(uid, fil, true)
	s.EpingleFil(uid, fil, true)
	s.RetireMessage(uid, msg, "motif")

	m, err := s.Moderations(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 4 {
		t.Fatalf("%d entree(s) au journal, attendu 4", len(m))
	}
	for _, e := range m {
		if e.Acteur != "Gandalf" {
			t.Errorf("acteur = %q, attendu Gandalf", e.Acteur)
		}
	}
}

func TestLAncienTitreEstConserveAuJournal(t *testing.T) {
	// Sans lui, la correction serait indistinguable d'une reecriture de
	// l'histoire.
	s, uid, cat := magasinMod(t)
	fil, _ := s.NewThread(cat, uid, "Ancien titre", "corps", VisPublic)
	s.RenommeFil(uid, fil, "Nouveau titre")
	m, _ := s.Moderations(10)
	if len(m) == 0 || !strings.Contains(m[0].Detail, "Ancien titre") {
		t.Errorf("l'ancien titre ne figure pas au journal : %+v", m)
	}
}

// ── Gardes ────────────────────────────────────────────────────────────────

func TestUnTitreVideEstRefuse(t *testing.T) {
	s, uid, cat := magasinMod(t)
	fil, _ := s.NewThread(cat, uid, "Titre", "corps", VisPublic)
	if err := s.RenommeFil(uid, fil, "   "); err == nil {
		t.Error("un titre vide a ete accepte")
	}
}

func TestUneCibleInexistanteEstSignalee(t *testing.T) {
	// Rendre nil sur une cible absente laisserait croire au moderateur que son
	// geste a porte.
	s, uid, _ := magasinMod(t)
	if err := s.RenommeFil(uid, 99999, "x"); !errors.Is(err, ErrIntrouvable) {
		t.Errorf("renomme sur fil absent : %v", err)
	}
	if err := s.RetireMessage(uid, 99999, ""); !errors.Is(err, ErrIntrouvable) {
		t.Errorf("retrait sur message absent : %v", err)
	}
	if err := s.VerrouilleFil(uid, 99999, true); !errors.Is(err, ErrIntrouvable) {
		t.Errorf("verrou sur fil absent : %v", err)
	}
}

func TestDeplacerVersUnSalonInconnuEstRefuse(t *testing.T) {
	// Sinon le fil disparait : il pointe vers un salon que rien n'affiche.
	s, uid, cat := magasinMod(t)
	fil, _ := s.NewThread(cat, uid, "Titre", "corps", VisPublic)
	if err := s.DeplaceFil(uid, fil, 99999); err == nil {
		t.Error("deplacement vers un salon inconnu accepte")
	}
}

func TestDeplacerUnFilLeChangeDeSalon(t *testing.T) {
	s, uid, cat := magasinMod(t)
	autre, err := s.CreateCategory("technique", "Technique", "")
	if err != nil {
		t.Fatal(err)
	}
	fil, _ := s.NewThread(cat, uid, "Titre", "corps", VisPublic)
	if err := s.DeplaceFil(uid, fil, autre); err != nil {
		t.Fatal(err)
	}
	th, _ := s.ThreadByID(fil)
	if th.CategoryID != autre {
		t.Errorf("salon = %d, attendu %d", th.CategoryID, autre)
	}
}

// ── Sous-salons ───────────────────────────────────────────────────────────

func TestUnSousSalonSeRattacheASonParent(t *testing.T) {
	s, uid, cat := magasinMod(t)
	id, err := s.CreeSousSalon(uid, "reseau", "Réseau", "", cat)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Arbre(false)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range a {
		if c.ID == id && c.Parent != cat {
			t.Errorf("parent = %d, attendu %d", c.Parent, cat)
		}
	}
}

func TestUnParentInconnuEstRefuse(t *testing.T) {
	// Creer sous un parent inexistant produirait un salon orphelin, visible
	// nulle part, que personne ne penserait a chercher.
	s, uid, _ := magasinMod(t)
	if _, err := s.CreeSousSalon(uid, "x", "X", "", 99999); err == nil {
		t.Error("parent inconnu accepte")
	}
}

func TestUnSalonSansIdentifiantNiTitreEstRefuse(t *testing.T) {
	s, uid, _ := magasinMod(t)
	if _, err := s.CreeSousSalon(uid, "", "Titre", "", 0); err == nil {
		t.Error("identifiant vide accepte")
	}
	if _, err := s.CreeSousSalon(uid, "slug", "  ", "", 0); err == nil {
		t.Error("titre vide accepte")
	}
}

// ── Depublication ─────────────────────────────────────────────────────────

func TestDepublierRetireLeBillet(t *testing.T) {
	s, uid, cat := magasinMod(t)
	fil, _ := s.NewThread(cat, uid, "Sujet", "corps", VisPublic)
	if err := s.MarkPublished(fil, "abc123", "https://exemple.fr/b/1", 3, 1); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.EstPublie(fil); !ok {
		t.Fatal("le billet n'a pas ete enregistre")
	}
	if err := s.Depublie(uid, fil); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.EstPublie(fil); ok {
		t.Error("le fil est encore publie apres depublication")
	}
}

func TestLIdentifiantDistantPartAuJournalALaDepublication(t *testing.T) {
	// Sans lui, republier plus tard creerait un SECOND billet au lieu de
	// remplacer le premier — et l'ancien resterait en ligne, orphelin.
	s, uid, cat := magasinMod(t)
	fil, _ := s.NewThread(cat, uid, "Sujet", "corps", VisPublic)
	s.MarkPublished(fil, "abc123", "https://exemple.fr/b/1", 3, 1)
	s.Depublie(uid, fil)
	m, _ := s.Moderations(10)
	trouve := false
	for _, e := range m {
		if strings.Contains(e.Detail, "abc123") {
			trouve = true
		}
	}
	if !trouve {
		t.Error("l'identifiant du billet ne figure pas au journal de depublication")
	}
}

func TestDepublierUnFilNonPublieEstSignale(t *testing.T) {
	s, uid, cat := magasinMod(t)
	fil, _ := s.NewThread(cat, uid, "Sujet", "corps", VisPublic)
	if err := s.Depublie(uid, fil); !errors.Is(err, ErrIntrouvable) {
		t.Errorf("depublication d'un fil non publie : %v", err)
	}
}

func TestRepublierRemplaceLeBilletPrecedent(t *testing.T) {
	// MarkPublished doit ecraser, pas dupliquer : thread_id est cle primaire.
	s, uid, cat := magasinMod(t)
	fil, _ := s.NewThread(cat, uid, "Sujet", "corps", VisPublic)
	s.MarkPublished(fil, "abc", "https://exemple.fr/b/1", 3, 0)
	if err := s.MarkPublished(fil, "def", "https://exemple.fr/b/2", 5, 1); err != nil {
		t.Fatal(err)
	}
	b, ok := s.EstPublie(fil)
	if !ok || b.BilletID != "def" || b.Repris != 5 {
		t.Errorf("republication : %+v", b)
	}
}
