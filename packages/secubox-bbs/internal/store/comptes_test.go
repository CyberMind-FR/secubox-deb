package store

import (
	"path/filepath"
	"testing"
)

func auth(t *testing.T) (*Store, *Auth) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "bbs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	a, err := OpenAuth(filepath.Join(dir, "passwd"))
	if err != nil {
		t.Fatal(err)
	}
	return s, a
}

func TestChangerDeMotDePasseExigeLAncien(t *testing.T) {
	// Sans cette verification, un navigateur laisse ouvert suffit a changer le
	// mot de passe — et donc a verrouiller le compte de son proprietaire. La
	// session prouve qu'on est entre ; elle ne prouve pas qu'on est le
	// titulaire.
	_, a := auth(t)
	a.SetPassword(1, "le-mot-de-passe-actuel")

	if err := a.ChangePassword(1, "un-mauvais-ancien", "le-nouveau-mot-de-passe"); err == nil {
		t.Error("changement accepte avec un mauvais ancien mot de passe")
	}
	if !a.Verify(1, "le-mot-de-passe-actuel") {
		t.Error("l'ancien mot de passe ne fonctionne plus apres un echec")
	}
	if err := a.ChangePassword(1, "le-mot-de-passe-actuel", "le-nouveau-mot-de-passe"); err != nil {
		t.Fatalf("changement legitime refuse : %v", err)
	}
	if !a.Verify(1, "le-nouveau-mot-de-passe") {
		t.Error("le nouveau mot de passe ne fonctionne pas")
	}
	if a.Verify(1, "le-mot-de-passe-actuel") {
		t.Error("l'ancien mot de passe fonctionne encore")
	}
}

func TestUnMotDePasseTropCourtEstRefuse(t *testing.T) {
	_, a := auth(t)
	a.SetPassword(1, "le-mot-de-passe-actuel")
	if err := a.ChangePassword(1, "le-mot-de-passe-actuel", "court"); err == nil {
		t.Error("mot de passe trop court accepte")
	}
	if !a.Verify(1, "le-mot-de-passe-actuel") {
		t.Error("l'ancien mot de passe a ete perdu malgre le refus")
	}
}

func TestChangerDeMotDePasseRevoqueLesAutresSessions(t *testing.T) {
	// On change son mot de passe surtout quand on craint qu'il ait fuite.
	// Laisser vivre les sessions ouvertes ailleurs viderait le geste de son
	// sens : celui qui a le mot de passe vole reste connecte.
	s, _ := auth(t)
	uid, _ := s.CreateUser("gk2", "G", RoleSysop)
	ancienne, _ := s.NewSession(uid, "", "")
	courante, _ := s.NewSession(uid, "", "")

	if err := s.RevokeOtherSessions(uid, courante); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserBySession(ancienne); err == nil {
		t.Error("une session ouverte ailleurs a survecu au changement")
	}
	if _, err := s.UserBySession(courante); err != nil {
		t.Error("la session courante a ete revoquee — l'utilisateur se deconnecte lui-meme")
	}
}

func TestLaDerniereConnexionEstEnregistree(t *testing.T) {
	s, _ := auth(t)
	uid, _ := s.CreateUser("gk2", "G", RoleSysop)
	u, _ := s.UserInfo(uid)
	if u.LastLogin != 0 {
		t.Errorf("date de connexion inventee sur un compte neuf : %d", u.LastLogin)
	}
	if err := s.NoteLogin(uid, "192.168.1.10"); err != nil {
		t.Fatal(err)
	}
	u, _ = s.UserInfo(uid)
	if u.LastLogin == 0 {
		t.Error("la connexion n'a pas ete enregistree")
	}
}

func TestLaListeDesComptesNeRevelePasLesHashes(t *testing.T) {
	// Cette liste est rendue par une page. Rien de ce qui sert a
	// s'authentifier ne doit pouvoir y transiter, meme tronque.
	s, a := auth(t)
	uid, _ := s.CreateUser("gk2", "G", RoleSysop)
	a.SetPassword(uid, "une phrase de passe assez longue")

	us, err := s.Users()
	if err != nil {
		t.Fatal(err)
	}
	if len(us) != 1 {
		t.Fatalf("%d comptes", len(us))
	}
	d := dumpAll(t, s)
	if contientTexte(d, "argon2") {
		t.Error("un hash se trouve dans la base")
	}
}

func TestUnCompteDesactivePuisReactiveRetrouveSonAcces(t *testing.T) {
	// Desactiver n'est pas supprimer : le geste doit etre reversible, sinon
	// personne n'ose desactiver et les comptes s'accumulent.
	s, _ := auth(t)
	uid, _ := s.CreateUser("gk2", "G", RoleMember)
	s.DisableUser(uid)
	if _, err := s.UserByHandle("gk2"); err == nil {
		t.Error("un compte desactive reste resolvable")
	}
	if err := s.EnableUser(uid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserByHandle("gk2"); err != nil {
		t.Errorf("un compte reactive reste inaccessible : %v", err)
	}
}

func contientTexte(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}

func TestEmettreUneInvitationSansEmetteurConnu(t *testing.T) {
	// `bbsctl invite` tourne en ligne de commande, sans session : il n'a aucun
	// utilisateur a qui attribuer l'invitation. Le premier jet passait 0, qui
	// n'est l'identifiant de personne — clef etrangere violee, invitation
	// jamais creee, et un message d'erreur qui ne disait pas pourquoi.
	s, _ := auth(t)
	code, err := s.NewInviteFor(0, "cedre")
	if err != nil {
		t.Fatalf("invitation refusee sans emetteur : %v", err)
	}
	if len(code) < 16 {
		t.Errorf("code trop court : %q", code)
	}
	inv, err := s.Invites()
	if err != nil {
		t.Fatal(err)
	}
	if len(inv) != 1 || inv[0].Label != "cedre" {
		t.Fatalf("libelle perdu : %+v", inv)
	}
	if inv[0].Code != "" {
		t.Error("le code est conserve en clair dans la base")
	}
}

func TestUneInvitationEmisePourQuelquUnResteUtilisableParQuiLaDetient(t *testing.T) {
	// Le libelle est INDICATIF. Le code n'est lie a personne : pretendre le
	// contraire donnerait une fausse assurance, alors que quiconque a le lien
	// peut s'en servir.
	s, _ := auth(t)
	code, _ := s.NewInviteFor(0, "cedre")
	if _, err := s.RedeemInvite(code, "quelquun-dautre", "Autre"); err != nil {
		t.Errorf("invitation refusee a un autre pseudonyme : %v", err)
	}
}

func TestLaReinitialisationSysopRespecteLaPolitique(t *testing.T) {
	// LA POLITIQUE NE DOIT PAS AVOIR DE PORTE DEROBEE. La longueur minimale
	// n'etait imposee que par `ChangePassword` — le chemin en libre-service.
	// Une reinitialisation par le sysop qui appellerait `SetPassword` en direct
	// poserait un mot de passe de trois lettres sans que rien ne s'y oppose, et
	// c'est justement le chemin qu'on emprunte quand quelqu'un est bloque
	// dehors, donc dans l'urgence.
	_, a := auth(t)
	if err := a.ResetPassword(1, "court"); err == nil {
		t.Error("mot de passe trop court accepte a la reinitialisation")
	}
	if err := a.ResetPassword(1, "une-phrase-assez-longue"); err != nil {
		t.Fatalf("reinitialisation legitime refusee : %v", err)
	}
	if !a.Verify(1, "une-phrase-assez-longue") {
		t.Error("le mot de passe reinitialise ne fonctionne pas")
	}
	// Aucun ancien mot de passe n'est demande : c'est le propre du geste, on
	// l'emploie quand le titulaire ne peut plus entrer.
}

func TestUnMotDePassePosePar_bbsctl_EstVuParLeDaemon(t *testing.T) {
	// LE DAEMON GARDE LE FICHIER EN MEMOIRE. `bbsctl` tourne dans un AUTRE
	// processus : il reecrit le fichier, mais le service continue de verifier
	// contre la carte chargee a son demarrage.
	//
	// Deux consequences, toutes deux observees sur gk2 le 2026-08-11 :
	//   - la reinitialisation de secours reste sans effet jusqu'au redemarrage,
	//     le jour meme ou l'on en a besoin parce que plus personne n'entre ;
	//   - pire, la premiere ecriture du service reecrit le fichier depuis sa
	//     carte perimee et EFFACE le mot de passe pose par bbsctl.
	dir := t.TempDir()
	chemin := filepath.Join(dir, "passwd")

	service, err := OpenAuth(chemin) // le « daemon »
	if err != nil {
		t.Fatal(err)
	}
	service.SetPassword(1, "le-mot-de-passe-initial")

	console, err := OpenAuth(chemin) // « bbsctl », autre processus
	if err != nil {
		t.Fatal(err)
	}
	if err := console.ResetPassword(1, "pose-depuis-la-console"); err != nil {
		t.Fatal(err)
	}

	if !service.Verify(1, "pose-depuis-la-console") {
		t.Error("le service ignore le mot de passe pose par la console")
	}
	if service.Verify(1, "le-mot-de-passe-initial") {
		t.Error("l'ancien mot de passe fonctionne encore cote service")
	}

	// Et une ecriture du service ne doit pas ressusciter sa carte perimee.
	service.SetPassword(2, "un-autre-compte-entier")
	relu, err := OpenAuth(chemin)
	if err != nil {
		t.Fatal(err)
	}
	if !relu.Verify(1, "pose-depuis-la-console") {
		t.Error("l'ecriture du service a efface le mot de passe pose par la console")
	}
}
