package store

import "testing"

func TestLAnnuaireCherchePseudoEtNom(t *testing.T) {
	// Le selecteur affichait TOUS les comptes en pastilles : illisible des
	// quelques dizaines de membres. L'annuaire est une RECHERCHE — on tape ce
	// dont on se souvient, pseudonyme ou nom affiche, et rarement les deux.
	s, alice, _ := deuxMembres(t)
	s.CreateUser("cedre83", "Cèdre du Var", RoleMember)
	s.CreateUser("gandalf", "Gérald K.", RoleMember)

	par_pseudo, err := s.Annuaire(alice, "cedre", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(par_pseudo) != 1 || par_pseudo[0].Handle != "cedre83" {
		t.Errorf("recherche par pseudonyme : %d resultats", len(par_pseudo))
	}

	par_nom, _ := s.Annuaire(alice, "gérald", 20)
	if len(par_nom) != 1 || par_nom[0].Handle != "gandalf" {
		t.Errorf("recherche par nom affiche : %d resultats", len(par_nom))
	}

	// INSENSIBLE A LA CASSE ET AUX FRAGMENTS : personne ne tape le pseudonyme
	// exact, et exiger la casse rendrait la recherche inutilisable sur telephone.
	if r, _ := s.Annuaire(alice, "CEDRE", 20); len(r) != 1 {
		t.Errorf("recherche insensible a la casse : %d resultats", len(r))
	}
}

func TestLAnnuaireNeSePropsePasSoiMemeNiLesComptesFermes(t *testing.T) {
	// S'y proposer soi-meme est une impasse : l'envoi le refuse ensuite. Et un
	// compte ferme ne recevra jamais le message — le proposer serait mentir.
	s, alice, bob := deuxMembres(t)
	s.DisableUser(bob)

	tous, err := s.Annuaire(alice, "", 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range tous {
		if c.ID == alice {
			t.Error("l'annuaire se propose a soi-meme")
		}
		if c.Handle == "bob" {
			t.Error("l'annuaire propose un compte desactive")
		}
	}
}

func TestLeCarnetGardeCeQuOnYMetEtRienDePlus(t *testing.T) {
	s, alice, bob := deuxMembres(t)
	carol, _ := s.CreateUser("carol", "Carol", RoleMember)

	if err := s.AjouteAuCarnet(alice, bob, "le voisin du dessus"); err != nil {
		t.Fatal(err)
	}
	// Deux fois le meme contact ne cree pas de doublon : on reclique sans y
	// penser, et une erreur a cet endroit n'apprendrait rien.
	if err := s.AjouteAuCarnet(alice, bob, ""); err != nil {
		t.Fatalf("second ajout refuse : %v", err)
	}

	carnet, err := s.Carnet(alice)
	if err != nil {
		t.Fatal(err)
	}
	if len(carnet) != 1 {
		t.Fatalf("%d entrees, attendu 1", len(carnet))
	}
	if carnet[0].Handle != "bob" {
		t.Errorf("contact = %q", carnet[0].Handle)
	}
	// LA NOTE SURVIT au second ajout : la reecrire avec une chaine vide
	// effacerait ce que l'on avait pris la peine d'ecrire.
	if carnet[0].Note != "le voisin du dessus" {
		t.Errorf("note = %q, attendu conservee", carnet[0].Note)
	}

	// LE CARNET EST UNIDIRECTIONNEL : bob n'a rien demande et n'a rien.
	if c, _ := s.Carnet(bob); len(c) != 0 {
		t.Error("l'ajout a cree une relation reciproque")
	}
	_ = carol
}

func TestRetirerDuCarnetNeTouchePasAuCompte(t *testing.T) {
	// Un carnet est un raccourci, pas une relation : le vider ne doit rien
	// changer au compte ni aux messages deja echanges.
	s, alice, bob := deuxMembres(t)
	s.AjouteAuCarnet(alice, bob, "")
	s.Envoyer(alice, bob, "un message qui doit survivre")

	if err := s.RetireDuCarnet(alice, bob); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.Carnet(alice); len(c) != 0 {
		t.Error("le contact est encore au carnet")
	}
	if _, err := s.UserByHandle("bob"); err != nil {
		t.Error("le compte a ete touche")
	}
	if fil, _ := s.Conversation(alice, bob); len(fil) != 1 {
		t.Error("la conversation a ete touchee")
	}
}

func TestLAnnuaireSignaleQuiEstDejaAuCarnet(t *testing.T) {
	// Sans ce drapeau, la liste de resultats ne sait pas quel bouton montrer —
	// « ajouter » ou « retirer » — et proposerait d'ajouter ce qui y est deja.
	s, alice, bob := deuxMembres(t)
	s.AjouteAuCarnet(alice, bob, "")

	r, err := s.Annuaire(alice, "bob", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(r) != 1 {
		t.Fatalf("%d resultats", len(r))
	}
	if !r[0].AuCarnet {
		t.Error("un contact du carnet n'est pas signale comme tel")
	}
}

func TestLAnnuaireEstBorne(t *testing.T) {
	// Une recherche vide sur un millier de comptes rendrait un millier de
	// lignes : la page redeviendrait le mur de pastilles qu'on vient de retirer.
	s, alice, _ := deuxMembres(t)
	for i := 0; i < 30; i++ {
		s.CreateUser("membre"+string(rune('a'+i)), "Membre", RoleMember)
	}
	r, err := s.Annuaire(alice, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(r) != 10 {
		t.Errorf("%d resultats malgre une borne a 10", len(r))
	}
}
