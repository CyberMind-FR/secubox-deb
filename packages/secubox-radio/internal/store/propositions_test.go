package store

import (
	"errors"
	"testing"
	"time"
)

// UNE PROPOSITION N'EST PAS A L'ANTENNE. La rendre dans la playlist l'aurait
// fait entrer dans le tirage par la porte de derriere, puisque `PourTirage`
// s'appuie sur cette liste.
func TestUnePropositionNestPasDansLaPlaylist(t *testing.T) {
	s := banc(t)
	if _, _, err := s.Propose("https://youtu.be/ABC", "Un titre", 7, t0); err != nil {
		t.Fatal(err)
	}
	l, err := s.Toutes()
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 0 {
		t.Errorf("%d pistes a l'antenne alors qu'il n'y a qu'une proposition", len(l))
	}
	props, err := s.Propositions()
	if err != nil || len(props) != 1 {
		t.Fatalf("%d propositions, %v", len(props), err)
	}
	if props[0].Etat != EtatPropose {
		t.Errorf("etat = %q", props[0].Etat)
	}
}

// LE SYSOP AJOUTE DIRECTEMENT. `Ajoute` et `Propose` sont deux fonctions et
// non un drapeau : un drapeau finit par etre passe a l'envers.
func TestLAjoutDuSysopEntreDirectement(t *testing.T) {
	s := banc(t)
	if _, _, err := s.Ajoute("https://youtu.be/SYS", "", 1, t0); err != nil {
		t.Fatal(err)
	}
	l, _ := s.Toutes()
	if len(l) != 1 || l[0].Etat != EtatValide {
		t.Errorf("l'ajout du sysop n'est pas a l'antenne : %+v", l)
	}
}

// LES COEURS SUIVENT LA VALIDATION. C'est tout l'interet d'une seule ligne qui
// change d'etat : l'enthousiasme qui a fait entrer le titre devient son poids
// de tirage. Avec une table separee, ils seraient restes sur une ligne
// disparue.
func TestLesCoeursSurvivventALaValidation(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Propose("https://youtu.be/ABC", "", 7, t0)
	_ = s.PoseCoeur(p.ID, 8, t0)
	_ = s.PoseCoeur(p.ID, 9, t0)

	if err := s.Valide(p.ID, 1, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	q, err := s.ParID(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if q.Etat != EtatValide {
		t.Errorf("etat = %q", q.Etat)
	}
	if q.Coeurs != 2 {
		t.Errorf("%d coeurs apres validation, attendu 2", q.Coeurs)
	}
	if q.ID != p.ID {
		t.Error("la validation a change l'identifiant de la piste")
	}
}

// ── LA GARDE QUI FAIT TENIR TOUT LE MODELE ──────────────────────────────────
//
// Sans elle, un membre ecarte par le sysop n'a qu'a recoller son lien pour
// revenir : la validation ne vaudrait plus rien, et la file de propositions
// serait videe de son sens.
func TestUnRefusNeSeContournePasEnReproposant(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Propose("https://youtu.be/NON", "", 7, t0)
	if err := s.Refuse(p.ID, 1, t0, "hors sujet"); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.Propose("https://www.youtube.com/watch?v=NON&t=12", "", 8, t0.Add(time.Hour))
	if !errors.Is(err, ErrDejaRefusee) {
		t.Fatalf("la reproposition a ete acceptee : %v", err)
	}
	// ...et elle n'est toujours ni a l'antenne, ni dans la file du sysop.
	if l, _ := s.Toutes(); len(l) != 0 {
		t.Error("la piste refusee est passee a l'antenne")
	}
	if pr, _ := s.Propositions(); len(pr) != 0 {
		t.Error("la piste refusee est revenue dans la file de validation")
	}
	// Le sysop, lui, peut revenir sur sa decision.
	if err := s.Valide(p.ID, 1, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.Toutes(); len(l) != 1 {
		t.Error("le sysop ne peut pas revenir sur un refus")
	}
}

// REFUS DU SYSOP ET ECHEC TECHNIQUE SONT DEUX CHOSES. Les confondre creerait
// exactement le contournement ci-dessus.
func TestUnEchecTechniqueNestPasUnRefus(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Propose("https://youtu.be/ABC", "", 7, t0)
	_ = s.Valide(p.ID, 1, t0)
	_ = s.MarqueIndisponible(p.ID, "geo-bloque")

	q, _, err := s.Propose("https://youtu.be/ABC", "", 8, t0.Add(time.Hour))
	if err != nil {
		t.Fatalf("reproposer une piste en echec technique a ete refuse : %v", err)
	}
	if q.Indisponible {
		t.Error("la piste reste ecartee alors qu'on la repropose")
	}
}

// UN REFUS PORTE UN MOTIF : sans lui, la question « pourquoi pas celle-la » se
// repose chaque semaine.
func TestUnRefusGardeSonMotifEtSonAuteur(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Propose("https://youtu.be/ABC", "", 7, t0)
	if err := s.Refuse(p.ID, 42, t0, "déjà passé hier"); err != nil {
		t.Fatal(err)
	}
	ref, err := s.Refusees()
	if err != nil || len(ref) != 1 {
		t.Fatalf("%d refusees, %v", len(ref), err)
	}
	if ref[0].Motif != "déjà passé hier" {
		t.Errorf("motif = %q", ref[0].Motif)
	}
}

// LA FILE DU SYSOP EST TRIEE PAR SOUTIEN. Trier par date ferait remonter ce
// qui vient d'arriver ; trier par coeurs fait remonter ce que la communaute
// demande. C'est la seule liste ou le coeur agit comme un vote.
func TestLaFileDeValidationRemonteLesPlusSoutenues(t *testing.T) {
	s := banc(t)
	a, _, _ := s.Propose("https://youtu.be/A", "", 7, t0)
	b, _, _ := s.Propose("https://youtu.be/B", "", 7, t0.Add(time.Minute))
	c, _, _ := s.Propose("https://youtu.be/C", "", 7, t0.Add(2*time.Minute))
	for _, u := range []int64{10, 11, 12} {
		_ = s.PoseCoeur(b.ID, u, t0)
	}
	_ = s.PoseCoeur(c.ID, 10, t0)

	pr, err := s.Propositions()
	if err != nil || len(pr) != 3 {
		t.Fatalf("%d propositions, %v", len(pr), err)
	}
	if pr[0].ID != b.ID || pr[1].ID != c.ID || pr[2].ID != a.ID {
		t.Errorf("ordre = %d,%d,%d — attendu %d,%d,%d (par soutien)",
			pr[0].ID, pr[1].ID, pr[2].ID, b.ID, c.ID, a.ID)
	}
}

// Une proposition ne doit pas atteindre le tirage, meme mise en cache.
func TestUnePropositionNeVaJamaisAuTirage(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Propose("https://youtu.be/ABC", "", 7, t0)
	_ = s.PoseCache(p.ID, "/data/1.opus", "audio/ogg", 4096, 210000, "T", "A")
	tp, _, err := s.PourTirage()
	if err != nil {
		t.Fatal(err)
	}
	if len(tp) != 0 {
		t.Errorf("%d pistes tirables alors qu'il n'y a qu'une proposition", len(tp))
	}
}

func TestValiderUnePisteInconnueEstUneErreur(t *testing.T) {
	s := banc(t)
	if err := s.Valide(999, 1, t0); !errors.Is(err, ErrPisteInconnue) {
		t.Errorf("valider l'inexistant : %v", err)
	}
}
