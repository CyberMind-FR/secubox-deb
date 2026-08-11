package store

import (
	"path/filepath"
	"strings"
	"testing"
)

// deuxMembres cree une base et deux comptes actifs. Les tests de messagerie ont
// tous besoin d'au moins deux personnes : un envoi a soi-meme est refuse.
func deuxMembres(t *testing.T) (*Store, int64, int64) {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "bbs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	alice, err := s.CreateUser("alice", "Alice", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := s.CreateUser("bob", "Bob", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	return s, alice, bob
}

func TestUnMessageArriveEtCompteCommeNonLu(t *testing.T) {
	s, alice, bob := deuxMembres(t)

	if _, err := s.Envoyer(alice, bob, "on se voit demain ?"); err != nil {
		t.Fatalf("envoi refuse : %v", err)
	}

	n, err := s.NonLus(bob)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("non-lus de bob = %d, attendu 1", n)
	}
	// L'EXPEDITEUR NE SE COMPTE PAS LUI-MEME. Sans cette verification, un
	// compteur qui joint les deux sens afficherait un non-lu a alice pour son
	// propre message — elle chercherait un message qu'elle a ecrit.
	if n, _ := s.NonLus(alice); n != 0 {
		t.Errorf("non-lus d'alice = %d, attendu 0 : son propre envoi ne la concerne pas", n)
	}
}

func TestLaConversationRendLesDeuxSens(t *testing.T) {
	// Une conversation qui ne montrerait que les messages recus afficherait un
	// monologue : on relit les reponses sans jamais voir ses propres questions.
	s, alice, bob := deuxMembres(t)
	s.Envoyer(alice, bob, "premiere")
	s.Envoyer(bob, alice, "deuxieme")
	s.Envoyer(alice, bob, "troisieme")

	fil, err := s.Conversation(alice, bob)
	if err != nil {
		t.Fatal(err)
	}
	if len(fil) != 3 {
		t.Fatalf("conversation = %d messages, attendu 3", len(fil))
	}
	for i, veut := range []string{"premiere", "deuxieme", "troisieme"} {
		if fil[i].Body != veut {
			t.Errorf("message %d = %q, attendu %q (ordre chronologique)", i, fil[i].Body, veut)
		}
	}
	// Vue depuis bob, la meme conversation, avec les memes messages.
	autre, _ := s.Conversation(bob, alice)
	if len(autre) != 3 {
		t.Errorf("vue de bob = %d messages, attendu 3", len(autre))
	}
}

func TestUnTiersNeVoitPasLaConversation(t *testing.T) {
	// Le controle d'acces est DANS la requete, pas dans la vue. Un filtre pose
	// seulement au rendu laisserait une future API renvoyer le fil entier.
	s, alice, bob := deuxMembres(t)
	carol, _ := s.CreateUser("carol", "Carol", RoleMember)
	s.Envoyer(alice, bob, "entre nous")

	fil, err := s.Conversation(carol, alice)
	if err != nil {
		t.Fatal(err)
	}
	if len(fil) != 0 {
		t.Errorf("carol voit %d messages d'une conversation qui ne la concerne pas", len(fil))
	}
	if n, _ := s.NonLus(carol); n != 0 {
		t.Errorf("carol a %d non-lus, attendu 0", n)
	}
}

func TestMarquerLuNeToucheQueLesMessagesRecus(t *testing.T) {
	s, alice, bob := deuxMembres(t)
	// CAROL EST LA POUR PROUVER LE FILTRE PAR INTERLOCUTEUR. Sans un troisieme
	// expediteur, une requete qui marquerait TOUS les recus de bob passerait le
	// test : avec un seul correspondant, les deux comportements coincident.
	carol, _ := s.CreateUser("carol", "Carol", RoleMember)
	s.Envoyer(alice, bob, "pour bob")
	s.Envoyer(carol, bob, "de carol, non lue")
	s.Envoyer(bob, alice, "pour alice")

	if err := s.MarquerLu(bob, alice); err != nil {
		t.Fatal(err)
	}
	// Il reste celui de carol : lire une conversation ne lit pas les autres.
	if n, _ := s.NonLus(bob); n != 1 {
		t.Errorf("non-lus de bob = %d, attendu 1 (celui de carol)", n)
	}
	if fil, _ := s.Conversation(bob, alice); len(fil) != 2 || !fil[0].Lu {
		t.Error("la conversation avec alice n'est pas marquee lue")
	}
	// ALICE N'A RIEN LU. Une requete qui marquerait la conversation entiere
	// ferait disparaitre le signal de son cote : elle ne saurait jamais qu'un
	// message l'attend.
	if n, _ := s.NonLus(alice); n != 1 {
		t.Errorf("non-lus d'alice = %d, attendu 1 : bob lisant ne lit pas pour elle", n)
	}
}

func TestEnvoiRefuseVersSoiMeme(t *testing.T) {
	s, alice, _ := deuxMembres(t)
	if _, err := s.Envoyer(alice, alice, "note pour moi"); err == nil {
		t.Error("envoi a soi-meme accepte : la boite de reception deviendrait un bloc-notes")
	}
}

func TestEnvoiRefuseVersUnCompteDesactive(t *testing.T) {
	// Ecrire a un compte ferme donnerait l'illusion d'avoir prevenu quelqu'un
	// qui ne se connectera plus. L'echec doit etre visible a l'envoi.
	s, alice, bob := deuxMembres(t)
	if err := s.DisableUser(bob); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Envoyer(alice, bob, "toujours la ?"); err == nil {
		t.Error("envoi vers un compte desactive accepte")
	}
}

func TestEnvoiRefuseDepuisUnCompteDesactive(t *testing.T) {
	s, alice, bob := deuxMembres(t)
	if err := s.DisableUser(alice); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Envoyer(alice, bob, "encore moi"); err == nil {
		t.Error("envoi depuis un compte desactive accepte")
	}
}

func TestEnvoiRefuseVide(t *testing.T) {
	s, alice, bob := deuxMembres(t)
	if _, err := s.Envoyer(alice, bob, "   \n  "); err == nil {
		t.Error("message vide accepte : il occuperait la boite sans rien dire")
	}
}

func TestLaListeDesConversationsResumeChaqueInterlocuteur(t *testing.T) {
	s, alice, bob := deuxMembres(t)
	carol, _ := s.CreateUser("carol", "Carol", RoleMember)
	s.Envoyer(bob, alice, "de bob")
	s.Envoyer(carol, alice, "de carol")
	s.Envoyer(carol, alice, "encore carol")
	s.MarquerLu(alice, bob)

	convs, err := s.Conversations(alice)
	if err != nil {
		t.Fatal(err)
	}
	if len(convs) != 2 {
		t.Fatalf("%d conversations, attendu 2 (bob et carol)", len(convs))
	}
	// La plus recente d'abord : une boite qui trie par ordre d'arrivee du
	// premier message enterre les echanges vivants sous les anciens.
	if convs[0].Handle != "carol" {
		t.Errorf("premiere conversation = %q, attendu carol (la plus recente)", convs[0].Handle)
	}
	if convs[0].NonLus != 2 {
		t.Errorf("non-lus avec carol = %d, attendu 2", convs[0].NonLus)
	}
	if convs[1].NonLus != 0 {
		t.Errorf("non-lus avec bob = %d, attendu 0 (deja lu)", convs[1].NonLus)
	}
	if convs[0].Dernier != "encore carol" {
		t.Errorf("apercu = %q, attendu le dernier message", convs[0].Dernier)
	}
}

func TestLesMessagesNeSontPasDansLaSauvegarde(t *testing.T) {
	// Propriete annoncee a l'utilisateur sur la page /mp. Si un jour les
	// messages passaient sur disque, ce test tomberait — et c'est le but :
	// la promesse ne doit pas se defaire en silence.
	s, alice, bob := deuxMembres(t)
	s.Envoyer(alice, bob, "un secret qui ne doit pas sortir")
	// UN FIL PUBLIC EST CREE EXPRES. Sans lui, l'archive serait vide et le test
	// passerait meme si `Backup` ne faisait rien du tout — il constaterait une
	// absence sans avoir rien mis a l'epreuve. Le fil prouve que l'archive
	// fonctionne ; le message prouve qu'elle ne prend pas ce qu'elle ne doit pas.
	cat, _ := salon(t, s)
	if _, err := s.NewThread(cat, alice, "Un fil", "un propos public", VisLocal); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(t.TempDir(), "sauvegarde.tar.gz")
	if err := s.Backup(dest); err != nil {
		t.Fatal(err)
	}
	_, contenu := lireArchive(t, dest)
	if !strings.Contains(contenu, "un propos public") {
		t.Fatal("l'archive ne contient meme pas le contenu public : le test ne prouverait rien")
	}
	if strings.Contains(contenu, "un secret qui ne doit pas sortir") {
		t.Error("un message prive figure dans la sauvegarde")
	}
}
