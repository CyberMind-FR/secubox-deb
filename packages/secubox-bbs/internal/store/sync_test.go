package store

import "testing"

func TestUnCompteSecuboxEstCreeSansMotDePasseLocal(t *testing.T) {
	// Le BBS ne copie AUCUN mot de passe. Une empreinte recopiee serait une
	// seconde copie a maintenir : un changement cote SecuBox ne s'y
	// refleterait pas, une revocation non plus, et le compte resterait ouvert
	// ici apres avoir ete ferme la-bas.
	s, _ := auth(t)
	n, err := s.SyncExternalUsers([]ExternalUser{
		{Handle: "gk2", Display: "gk2", Role: RoleSysop},
		{Handle: "cedre83", Display: "cedre83", Role: RoleMember},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n.Crees != 2 {
		t.Fatalf("%d comptes crees, attendu 2", n.Crees)
	}
	src, err := s.AuthSource("cedre83")
	if err != nil {
		t.Fatal(err)
	}
	if src != "secubox" {
		t.Errorf("origine d'authentification : %q", src)
	}
}

func TestUneSecondeSynchronisationNeDupliquePas(t *testing.T) {
	s, _ := auth(t)
	u := []ExternalUser{{Handle: "gk2", Display: "gk2", Role: RoleSysop}}
	s.SyncExternalUsers(u)
	n, err := s.SyncExternalUsers(u)
	if err != nil {
		t.Fatal(err)
	}
	if n.Crees != 0 {
		t.Errorf("%d comptes recrees", n.Crees)
	}
	cs, _ := s.Users()
	if len(cs) != 1 {
		t.Errorf("%d comptes au total", len(cs))
	}
}

func TestUnCompteDesactiveChezSecuboxEstDesactiveIci(t *testing.T) {
	// Une revocation doit se propager. Sans cela, fermer un compte cote
	// SecuBox le laisserait ouvert sur le BBS — exactement ce qu'on croit
	// avoir empeche.
	s, _ := auth(t)
	s.SyncExternalUsers([]ExternalUser{{Handle: "parti", Display: "Parti", Role: RoleMember}})
	if _, err := s.UserByHandle("parti"); err != nil {
		t.Fatal("compte absent apres creation")
	}
	n, err := s.SyncExternalUsers([]ExternalUser{
		{Handle: "parti", Display: "Parti", Role: RoleMember, Disabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	if n.Desactives != 1 {
		t.Errorf("%d desactives, attendu 1", n.Desactives)
	}
	if _, err := s.UserByHandle("parti"); err == nil {
		t.Error("le compte reste utilisable apres desactivation chez SecuBox")
	}
}

func TestUnCompteLOCALNEstJamaisTOUCHE(t *testing.T) {
	// Les membres venus par invitation n'existent pas chez SecuBox. Une
	// synchronisation qui les desactiverait parce qu'ils sont « absents de la
	// liste » viderait le BBS de ses membres au premier passage.
	s, a := auth(t)
	uid, _ := s.CreateUser("marie", "Marie", RoleMember)
	a.SetPassword(uid, "une phrase de passe assez longue")

	if _, err := s.SyncExternalUsers([]ExternalUser{
		{Handle: "gk2", Display: "gk2", Role: RoleSysop}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserByHandle("marie"); err != nil {
		t.Error("un membre local a ete desactive par la synchronisation")
	}
	if src, _ := s.AuthSource("marie"); src != "local" {
		t.Errorf("l'origine d'un compte local a ete changee : %q", src)
	}
}

func TestUnCompteSecuboxRedevenuPresentEstReactive(t *testing.T) {
	s, _ := auth(t)
	s.SyncExternalUsers([]ExternalUser{{Handle: "x", Display: "X", Role: RoleMember, Disabled: true}})
	s.SyncExternalUsers([]ExternalUser{{Handle: "x", Display: "X", Role: RoleMember}})
	if _, err := s.UserByHandle("x"); err != nil {
		t.Error("compte non reactive")
	}
}
