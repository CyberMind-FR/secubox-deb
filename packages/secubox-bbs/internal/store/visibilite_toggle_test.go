package store

import "testing"

// UN FIL DOIT POUVOIR CHANGER DE VISIBILITÉ APRÈS COUP. La visibilité était
// figée à la création : impossible de rendre public un fil local (ou l'inverse)
// sans repasser par la base (#1131h). Le geste appartient à l'AUTEUR et au
// sysop — comme l'édition ; un tiers ne peut pas exposer le fil d'autrui.
func TestBasculeVisibiliteFil(t *testing.T) {
	s := ouvre(t)
	cat, auteur := salon(t, s)
	autre, err := s.CreateUser("bob", "Bob", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	tid, err := s.NewThread(cat, auteur, "Mon fil", "corps", VisLocal)
	if err != nil {
		t.Fatal(err)
	}

	// UN TIERS NE PEUT PAS : exposer le fil d'autrui n'est pas son geste.
	if _, err := s.BasculeVisibiliteFil(tid, autre, RoleMember); err != ErrDroitEdition {
		t.Fatalf("un tiers a pu changer la visibilité : %v", err)
	}
	// L'AUTEUR bascule local → public.
	nv, err := s.BasculeVisibiliteFil(tid, auteur, RoleMember)
	if err != nil || nv != VisPublic {
		t.Fatalf("auteur local→public : nv=%q err=%v", nv, err)
	}
	// LE SYSOP rebascule public → local, sur le fil d'un autre.
	nv, err = s.BasculeVisibiliteFil(tid, autre, RoleSysop)
	if err != nil || nv != VisLocal {
		t.Fatalf("sysop public→local : nv=%q err=%v", nv, err)
	}
	// LE CHANGEMENT PERSISTE.
	if th, _ := s.ThreadByID(tid); th.Visibility != VisLocal {
		t.Fatalf("visibilité persistée = %q, attendu local", th.Visibility)
	}
}
