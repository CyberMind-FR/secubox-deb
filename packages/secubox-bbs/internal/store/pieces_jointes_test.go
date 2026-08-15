package store

import (
	"bytes"
	"path/filepath"
	"testing"
)

// magasinAvecMedia monte un magasin, un membre, un salon, un fil et un vocal
// deja depose — le point de depart de tout message vocal.
func magasinAvecMedia(t *testing.T) (s *Store, uid, filID, fileID int64) {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "bbs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	uid, err = s.CreateUser("gk2", "Gandalf", RoleSysop)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := s.CreeSousSalon(uid, "salon", "Salon", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	filID, err = s.NewThread(cat, uid, "Un fil", "corps", VisLocal)
	if err != nil {
		t.Fatal(err)
	}
	// Un OGG minimal : le magasin decide du type par le CONTENU, donc l'en-tete
	// doit etre reel — un octet de travers et le depot serait refuse, ce qui
	// masquerait ce que ce test veut mesurer.
	ogg := append([]byte("OggS\x00\x02"), bytes.Repeat([]byte{0}, 64)...)
	f, err := s.DeposeFichier(uid, "vocal.ogg", "audio/ogg", bytes.NewReader(ogg))
	if err != nil {
		t.Fatalf("depot du vocal refuse : %v", err)
	}
	return s, uid, filID, f.ID
}

func TestUnVocalSAttacheAUnMessageDeForum(t *testing.T) {
	s, uid, filID, fileID := magasinAvecMedia(t)
	postID, err := s.Reply(filID, uid, "ecoute ca", VisLocal)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AttachePost(postID, fileID, 0); err != nil {
		t.Fatalf("attachement refuse : %v", err)
	}
	pj, err := s.PiecesDuPost(postID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pj) != 1 || pj[0].ID != fileID {
		t.Fatalf("piece jointe absente : %+v", pj)
	}
	if !pj[0].EstAudio() {
		t.Errorf("type perdu en chemin : %q", pj[0].Mime)
	}
}

func TestUneCibleEXCLUSIVEMENT(t *testing.T) {
	// LE COEUR DE LA MIGRATION. Sans la contrainte, une meme ligne pourrait
	// viser un fil public ET un message prive : le vocal d'une conversation
	// privee apparaitrait dans un salon, sans qu'aucune erreur ne le signale.
	s, _, _, fileID := magasinAvecMedia(t)

	_, err := s.db.Exec(
		`INSERT INTO pieces_jointes (file_id, post_id, message_id, rang, cree_le)
		 VALUES (?, 1, 1, 0, 0)`, fileID)
	if err == nil {
		t.Error("deux cibles acceptees : la fuite est possible")
	}
	_, err = s.db.Exec(
		`INSERT INTO pieces_jointes (file_id, rang, cree_le) VALUES (?, 0, 0)`, fileID)
	if err == nil {
		t.Error("aucune cible acceptee : la piece jointe serait orpheline")
	}
}

func TestUnMemeFichierNeSAttachePasDeuxFois(t *testing.T) {
	// Un double clic sur « envoyer » ne doit pas afficher le vocal en double.
	s, uid, filID, fileID := magasinAvecMedia(t)
	postID, _ := s.Reply(filID, uid, "x", VisLocal)

	if err := s.AttachePost(postID, fileID, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.AttachePost(postID, fileID, 1); err == nil {
		t.Error("doublon accepte")
	}
}

func TestUnFichierSupprimeNApparaitPlus(t *testing.T) {
	// La suppression DOUCE ne casse pas le lien — mais la piece ne doit plus
	// etre servie. Ecarter le fichier dans la REQUETE plutot que dans chaque
	// gabarit, c'est ne pas dependre de la vigilance de l'affichage.
	s, uid, filID, fileID := magasinAvecMedia(t)
	postID, _ := s.Reply(filID, uid, "x", VisLocal)
	if err := s.AttachePost(postID, fileID, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(
		`UPDATE files SET deleted_at = 1 WHERE id = ?`, fileID); err != nil {
		t.Fatal(err)
	}
	pj, err := s.PiecesDuPost(postID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pj) != 0 {
		t.Errorf("un media retire reste servi : %+v", pj)
	}
}

func TestLOrdreEstCeluiQuOnDonne(t *testing.T) {
	s, uid, filID, premier := magasinAvecMedia(t)
	postID, _ := s.Reply(filID, uid, "x", VisLocal)

	ogg := append([]byte("OggS\x00\x02"), bytes.Repeat([]byte{1}, 64)...)
	second, err := s.DeposeFichier(uid, "second.ogg", "audio/ogg", bytes.NewReader(ogg))
	if err != nil {
		t.Fatal(err)
	}
	// On attache le SECOND d'abord, avec un rang superieur : si l'ordre suivait
	// l'insertion, il sortirait en tete.
	if err := s.AttachePost(postID, second.ID, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.AttachePost(postID, premier, 0); err != nil {
		t.Fatal(err)
	}
	pj, _ := s.PiecesDuPost(postID)
	if len(pj) != 2 || pj[0].ID != premier {
		t.Errorf("ordre non respecte : %+v", pj)
	}
}

func TestLaDureeEstFacultativeEtSurLeFichier(t *testing.T) {
	s, _, _, fileID := magasinAvecMedia(t)

	// Inconnue au depart : un media depose sans duree ne doit pas faire echouer
	// la lecture.
	ms, err := s.DureeDe(fileID)
	if err != nil || ms != 0 {
		t.Fatalf("duree inconnue mal rendue : %d, %v", ms, err)
	}
	if err := s.DefinitDuree(fileID, 23_400); err != nil {
		t.Fatal(err)
	}
	if ms, _ = s.DureeDe(fileID); ms != 23_400 {
		t.Errorf("duree = %d", ms)
	}
	if err := s.DefinitDuree(fileID, -1); err == nil {
		t.Error("duree negative acceptee")
	}
}
