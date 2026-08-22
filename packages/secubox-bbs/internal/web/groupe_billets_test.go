package web

import "testing"

// LES BILLETS DE MÊME TITRE SE REGROUPENT (#1131ab) — comme un podcast regroupe
// ses épisodes. Le premier (le plus récent) reste en principal ; les suivants,
// de même titre, deviennent ses `Autres`. Un titre unique n'est pas touché.
func TestGroupeBilletsParTitre(t *testing.T) {
	in := []billetVue{
		{Titre: "Le podcast", Lien: "/b/ep3"}, // le plus récent
		{Titre: "Un solo", Lien: "/b/solo"},
		{Titre: "Le podcast", Lien: "/b/ep2"},
		{Titre: "Le podcast", Lien: "/b/ep1"},
	}
	out := groupeBilletsParTitre(in)
	if len(out) != 2 {
		t.Fatalf("attendu 2 groupes (Le podcast + Un solo), obtenu %d", len(out))
	}
	// Le principal du groupe podcast = le premier vu (le plus récent).
	if out[0].Titre != "Le podcast" || out[0].Lien != "/b/ep3" {
		t.Fatalf("principal inattendu : %+v", out[0])
	}
	if len(out[0].Autres) != 2 {
		t.Fatalf("attendu 2 autres épisodes, obtenu %d", len(out[0].Autres))
	}
	if out[0].Autres[0].Lien != "/b/ep2" || out[0].Autres[1].Lien != "/b/ep1" {
		t.Fatalf("autres dans le mauvais ordre : %+v", out[0].Autres)
	}
	// Un billet à titre unique n'a aucun « autre ».
	if out[1].Titre != "Un solo" || len(out[1].Autres) != 0 {
		t.Fatalf("un titre unique ne doit pas être regroupé : %+v", out[1])
	}
}
