package store

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// Entetes reels, tronques : ce qui compte est le debut du fichier, c'est lui
// que le renifleur lit.
var (
	pngValide  = append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0}, 64)...)
	jpegValide = append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, bytes.Repeat([]byte{0}, 64)...)
	ogg        = append([]byte("OggS"), bytes.Repeat([]byte{0}, 64)...)
	svg        = []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
	html       = []byte("<!doctype html><html><body>bonjour</body></html>")
	elf        = append([]byte("\x7fELF"), bytes.Repeat([]byte{0}, 64)...)
)

func magasinFichiers(t *testing.T) (*Store, int64) {
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

func TestUnePngEstAccepteeEtRelisible(t *testing.T) {
	s, uid := magasinFichiers(t)
	f, err := s.DeposeFichier(uid, "photo du dongle.png", "image/png", bytes.NewReader(pngValide))
	if err != nil {
		t.Fatalf("depot refuse : %v", err)
	}
	if f.Mime != "image/png" {
		t.Errorf("mime = %q", f.Mime)
	}
	if f.Size != int64(len(pngValide)) {
		t.Errorf("taille = %d, attendu %d", f.Size, len(pngValide))
	}
	relu, err := s.Fichier(f.ID)
	if err != nil {
		t.Fatalf("relecture : %v", err)
	}
	if relu.Name != "photo du dongle.png" {
		t.Errorf("nom affiche perdu : %q", relu.Name)
	}
	// LE CHEMIN N'EST JAMAIS CONSTRUIT A PARTIR DU NOM FOURNI. Un nom peut
	// contenir des separateurs, des `..`, ou n'etre qu'un point — le chemin sur
	// disque est derive de l'identifiant.
	if strings.ContainsAny(relu.Path, " ") || strings.Contains(relu.Path, "..") {
		t.Errorf("chemin derive du nom fourni : %q", relu.Path)
	}
}

func TestLeTypeAnnONCEParLeClientNEstJamaisCru(t *testing.T) {
	// C'est LA regle. Un client qui annonce « image/png » en envoyant un
	// executable ferait servir cet executable en image — et un navigateur
	// indulgent finirait par l'executer.
	s, uid := magasinFichiers(t)
	if _, err := s.DeposeFichier(uid, "innocent.png", "image/png", bytes.NewReader(elf)); err == nil {
		t.Error("un binaire annonce comme image a ete accepte")
	}
	// Et l'inverse : un fichier valide mal annonce est accepte pour ce qu'il
	// EST, pas pour ce qu'on en dit.
	f, err := s.DeposeFichier(uid, "truc.bin", "application/octet-stream", bytes.NewReader(pngValide))
	if err != nil {
		t.Fatalf("png annoncee en binaire refusee : %v", err)
	}
	if f.Mime != "image/png" {
		t.Errorf("mime retenu = %q, attendu celui du CONTENU", f.Mime)
	}
}

func TestLeSvgEstRefuse(t *testing.T) {
	// UN SVG EST UN DOCUMENT EXECUTABLE : il embarque du script, et servi en
	// ligne il s'execute dans l'origine du BBS — donc avec la session du
	// lecteur. Aucune miniature ne vaut ca.
	s, uid := magasinFichiers(t)
	if _, err := s.DeposeFichier(uid, "logo.svg", "image/svg+xml", bytes.NewReader(svg)); err == nil {
		t.Error("un SVG a ete accepte")
	}
}

func TestLeHtmlEtLesExecutablesSontRefuses(t *testing.T) {
	s, uid := magasinFichiers(t)
	for nom, contenu := range map[string][]byte{
		"page.html": html,
		"outil":     elf,
	} {
		if _, err := s.DeposeFichier(uid, nom, "application/octet-stream", bytes.NewReader(contenu)); err == nil {
			t.Errorf("%s accepte", nom)
		}
	}
}

func TestLAudioEtLaVideoSontAcceptes(t *testing.T) {
	s, uid := magasinFichiers(t)
	if _, err := s.DeposeFichier(uid, "emission.ogg", "audio/ogg", bytes.NewReader(ogg)); err != nil {
		t.Errorf("audio refuse : %v", err)
	}
	if _, err := s.DeposeFichier(uid, "photo.jpg", "image/jpeg", bytes.NewReader(jpegValide)); err != nil {
		t.Errorf("jpeg refuse : %v", err)
	}
}

func TestUnFichierTropGrosEstRefuseSansEcrireSurLeDisque(t *testing.T) {
	// La borne protege l'eMMC — dont le remplissage a deja mis la board en 502.
	// Elle doit s'appliquer AVANT l'ecriture : refuser apres avoir ecrit trois
	// gigaoctets ne protege de rien.
	s, uid := magasinFichiers(t)
	gros := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0}, int(TailleMaxFichier)+1024)...)
	f, err := s.DeposeFichier(uid, "enorme.png", "image/png", bytes.NewReader(gros))
	if err == nil {
		t.Fatalf("fichier hors borne accepte (%d octets)", f.Size)
	}
	if !strings.Contains(err.Error(), "trop") {
		t.Errorf("message peu clair : %v", err)
	}
	// Rien ne doit trainer : un depot refuse ne laisse pas de fichier orphelin.
	if fs, _ := s.Fichiers(uid, 10); len(fs) != 0 {
		t.Errorf("%d fichier(s) enregistre(s) malgre le refus", len(fs))
	}
}

func TestUnFichierVideEstRefuse(t *testing.T) {
	s, uid := magasinFichiers(t)
	if _, err := s.DeposeFichier(uid, "rien.png", "image/png", bytes.NewReader(nil)); err == nil {
		t.Error("fichier vide accepte")
	}
}

func TestSupprimerUnFichierLeRetireDeLIndexEtDuDisque(t *testing.T) {
	s, uid := magasinFichiers(t)
	f, _ := s.DeposeFichier(uid, "a.png", "image/png", bytes.NewReader(pngValide))
	if err := s.SupprimeFichier(uid, f.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fichier(f.ID); err == nil {
		t.Error("le fichier est encore resolu apres suppression")
	}
}

func TestOnNeSupprimePasLeFichierDUnAutre(t *testing.T) {
	// Sans cette garde, connaitre un identifiant suffirait a effacer la piece
	// jointe de quelqu'un d'autre.
	s, uid := magasinFichiers(t)
	autre, _ := s.CreateUser("amie", "Amie", RoleMember)
	f, _ := s.DeposeFichier(uid, "a.png", "image/png", bytes.NewReader(pngValide))
	if err := s.SupprimeFichier(autre, f.ID); err == nil {
		t.Error("un tiers a supprime le fichier")
	}
	if _, err := s.Fichier(f.ID); err != nil {
		t.Error("le fichier a disparu malgre le refus")
	}
}

func TestLeTypeAnnonceNePeutPasElargirLaListeBlanche(t *testing.T) {
	// Le type annonce sert a DEPARTAGER un conteneur ambigu (Ogg porte audio ou
	// video). Il ne doit jamais servir a faire entrer un type absent de la
	// liste : c'est la difference entre « lequel des deux » et « lequel je
	// veux ».
	s, uid := magasinFichiers(t)
	f, err := s.DeposeFichier(uid, "piege.ogg", "text/html", bytes.NewReader(ogg))
	if err != nil {
		t.Fatalf("ogg refuse : %v", err)
	}
	if f.Mime == "text/html" {
		t.Fatal("le type annonce a traverse la liste blanche")
	}
	if f.Mime != "audio/ogg" {
		t.Errorf("mime = %q, attendu audio/ogg (defaut du conteneur)", f.Mime)
	}
}
