package store

import "testing"

// LE PRÉCHARGEMENT DU TITRE NE REMPLIT QUE LE VIDE. Une proposition n'affiche
// que son URL brute tant que personne ne l'a validée ; on pose son titre dès
// que la passerelle le connaît (#1131p). Mais un titre SAISI à la main est un
// choix — PoseTitre ne l'écrase jamais, et un titre vide ne fait rien.
func TestPoseTitreNeRemplitQueLeVide(t *testing.T) {
	s := banc(t)
	const uid = int64(1)

	sansTitre, _, _ := s.Ajoute("https://youtu.be/AAA", "", uid, t0)
	if err := s.PoseTitre(sansTitre.ID, "Le Vrai Titre"); err != nil {
		t.Fatal(err)
	}
	if q, _ := s.ParID(sansTitre.ID); q.Titre != "Le Vrai Titre" {
		t.Fatalf("titre non préchargé : %q", q.Titre)
	}

	avecTitre, _, _ := s.Ajoute("https://youtu.be/BBB", "Titre Choisi", uid, t0)
	if err := s.PoseTitre(avecTitre.ID, "Autre Chose"); err != nil {
		t.Fatal(err)
	}
	if q, _ := s.ParID(avecTitre.ID); q.Titre != "Titre Choisi" {
		t.Fatalf("un titre saisi a été écrasé : %q", q.Titre)
	}

	// Un titre vide ne touche à rien.
	if err := s.PoseTitre(sansTitre.ID, "   "); err != nil {
		t.Fatal(err)
	}
	if q, _ := s.ParID(sansTitre.ID); q.Titre != "Le Vrai Titre" {
		t.Fatalf("un titre vide a écrasé : %q", q.Titre)
	}
}
