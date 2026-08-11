package store

import "testing"

func TestUnMembreInviteEtLaChaineResteLisible(t *testing.T) {
	// Depuis #1008 tout membre invite, sans quota. La tracabilite est la seule
	// contrepartie : si le panneau sysop ne montrait pas qui a invite qui, une
	// inscription en cascade serait indebrouillable.
	s, alice, _ := deuxMembres(t)

	code, err := s.NewInvite(alice)
	if err != nil {
		t.Fatalf("un membre ne peut pas inviter : %v", err)
	}
	dave, err := s.RedeemInvite(code, "dave", "Dave")
	if err != nil {
		t.Fatalf("invitation inutilisable : %v", err)
	}
	if dave == 0 {
		t.Fatal("aucun compte cree")
	}

	invs, err := s.Invites()
	if err != nil {
		t.Fatal(err)
	}
	if len(invs) != 1 {
		t.Fatalf("%d invitations listees, attendu 1", len(invs))
	}
	if invs[0].Emetteur != "alice" {
		t.Errorf("emetteur = %q, attendu alice", invs[0].Emetteur)
	}
	if invs[0].Beneficiaire != "dave" {
		t.Errorf("beneficiaire = %q, attendu dave", invs[0].Beneficiaire)
	}
	if !invs[0].Used {
		t.Error("invitation non marquee comme utilisee")
	}
}

func TestUnCompteFermeNInvitePas(t *testing.T) {
	// La vue s'appuie sur le fait qu'un compte ferme ne peut pas etre connecte
	// (`DisableUser` supprime les sessions, `UserBySession` ecarte les comptes
	// desactives). Ce refus est la SECONDE barriere : si l'une des deux tombait,
	// un compte ferme pourrait continuer a ouvrir la porte a des inconnus, ce
	// qui est exactement ce que fermer un compte veut empecher.
	s, alice, _ := deuxMembres(t)
	if err := s.DisableUser(alice); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NewInvite(alice); err == nil {
		t.Error("un compte desactive a pu emettre une invitation")
	}
}

func TestUneInvitationSansEmetteurResteListable(t *testing.T) {
	// `bbsctl` tourne sans session et emet donc des invitations sans emetteur.
	// La jointure de listage ne doit pas les faire disparaitre : une invitation
	// ouverte invisible dans la console est une porte qu'on ne peut pas fermer.
	s := baseSeule(t)
	if _, err := s.NewInviteFor(0, "amorcage"); err != nil {
		t.Fatal(err)
	}
	invs, err := s.Invites()
	if err != nil {
		t.Fatal(err)
	}
	if len(invs) != 1 {
		t.Fatalf("%d invitations listees, attendu 1", len(invs))
	}
	if invs[0].Emetteur != "" {
		t.Errorf("emetteur = %q, attendu vide", invs[0].Emetteur)
	}
}
