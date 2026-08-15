package store

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
)

// webmMinimal : l'en-tete EBML que `DetectContentType` reconnait. Le magasin
// decide par le CONTENU — un octet de travers et le depot serait refuse, ce qui
// masquerait ce que ces tests mesurent.
func webmMinimal() []byte {
	return append([]byte{0x1A, 0x45, 0xDF, 0xA3}, bytes.Repeat([]byte{0}, 600)...)
}

func magasinNote(t *testing.T) (*Store, int64) {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "bbs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	uid, err := s.CreateUser("gk2", "Gandalf", RoleSysop)
	if err != nil {
		t.Fatal(err)
	}
	return s, uid
}

// LE CAS DE CHROME. Son enregistreur ne sait produire que du WebM, y compris
// pour une note VOCALE. Le renifleur voit un conteneur Matroska et rend
// `video/webm` sans pouvoir savoir s'il porte une piste video : sans departage,
// une note vocale s'affichait en rectangle noir.
func TestUneNoteVocaleEnWebmEstServieCommeDuSon(t *testing.T) {
	s, uid := magasinNote(t)
	f, err := s.DeposeFichier(uid, "vocal-1.webm", "audio/webm;codecs=opus",
		bytes.NewReader(webmMinimal()))
	if err != nil {
		t.Fatalf("note vocale refusee : %v", err)
	}
	if !f.EstAudio() {
		t.Errorf("la note vocale est servie comme %q, donc en lecteur video", f.Mime)
	}
	if f.Mime != "audio/webm" {
		t.Errorf("type = %q, attendu audio/webm", f.Mime)
	}
}

// LA REGRESSION QUE LE DEPARTAGE POURRAIT CAUSER. Le meme conteneur, annonce
// comme video, doit rester une video : c'est le cas de loin le plus courant, et
// le departage ne doit pas le detourner.
func TestUneNoteVideoEnWebmResteUneVideo(t *testing.T) {
	s, uid := magasinNote(t)
	f, err := s.DeposeFichier(uid, "video-1.webm", "video/webm;codecs=vp9,opus",
		bytes.NewReader(webmMinimal()))
	if err != nil {
		t.Fatalf("note video refusee : %v", err)
	}
	if !f.EstVideo() {
		t.Errorf("la note video est servie comme %q", f.Mime)
	}
}

// SANS ANNONCE, LE CONTENU SEUL DECIDE. Un WebM depose par un client muet reste
// une video : c'est le comportement d'avant, et il ne doit pas changer.
func TestUnWebmSansAnnonceResteUneVideo(t *testing.T) {
	s, uid := magasinNote(t)
	f, err := s.DeposeFichier(uid, "x.webm", "", bytes.NewReader(webmMinimal()))
	if err != nil {
		t.Fatal(err)
	}
	if f.Mime != "video/webm" {
		t.Errorf("type = %q sans annonce, attendu video/webm", f.Mime)
	}
}

// L'ANNONCE DEPARTAGE, ELLE N'OUVRE RIEN. C'est la garantie qui rend le
// mecanisme sur : un client qui annonce un type accepte ne doit pas pouvoir
// faire passer un contenu qui, lui, ne l'est pas.
func TestLAnnonceNElargitPasLaListeBlanche(t *testing.T) {
	s, uid := magasinNote(t)
	// Un binaire ELF annonce en note vocale : le contenu doit l'emporter.
	elf := append([]byte{0x7F, 'E', 'L', 'F'}, bytes.Repeat([]byte{0}, 600)...)
	if _, err := s.DeposeFichier(uid, "vocal.webm", "audio/webm", bytes.NewReader(elf)); err == nil {
		t.Error("un ELF annonce en note vocale a ete accepte")
	} else if !errors.Is(err, ErrTypeRefuse) {
		t.Errorf("refus pour une autre raison que le type : %v", err)
	}
}

// FIREFOX PRODUIT DE L'OGG, et le renifleur rend alors `application/ogg`. Ce
// departage-la existait deja ; ce test le fige, car les deux enregistreurs
// passent desormais par le meme chemin.
func TestUneNoteVocaleEnOggEstServieCommeDuSon(t *testing.T) {
	s, uid := magasinNote(t)
	ogg := append([]byte("OggS\x00\x02"), bytes.Repeat([]byte{0}, 600)...)
	f, err := s.DeposeFichier(uid, "vocal-2.ogg", "audio/ogg;codecs=opus", bytes.NewReader(ogg))
	if err != nil {
		t.Fatalf("note vocale Ogg refusee : %v", err)
	}
	if !f.EstAudio() {
		t.Errorf("la note vocale Ogg est servie comme %q", f.Mime)
	}
}
