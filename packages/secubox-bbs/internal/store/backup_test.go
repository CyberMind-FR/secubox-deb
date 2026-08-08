package store

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLaSauvegardeEmporteLesCorpsPasSeulementLIndex(t *testing.T) {
	// Une sauvegarde qui ne prendrait que la base serait VIDE de contenu tout
	// en paraissant complete — le pire des cas, parce qu'on ne s'en apercoit
	// qu'au moment de restaurer.
	s := ouvre(t)
	cat, uid := salon(t, s)
	s.NewThread(cat, uid, "Un fil", "le corps qui doit etre sauve", VisLocal)

	arc := filepath.Join(t.TempDir(), "sauvegarde.tar.gz")
	if err := s.Backup(arc); err != nil {
		t.Fatal(err)
	}
	noms, corps := lireArchive(t, arc)

	var aDuContenu bool
	for _, n := range noms {
		if strings.HasPrefix(n, "content/") {
			aDuContenu = true
		}
	}
	if !aDuContenu {
		t.Fatalf("aucun fichier de contenu dans l'archive : %v", noms)
	}
	if !strings.Contains(corps, "le corps qui doit etre sauve") {
		t.Error("le corps des messages n'est pas dans la sauvegarde")
	}
}

func TestLaSauvegardeNEmporteJamaisLesSecrets(t *testing.T) {
	// secrets/ contient les hashes de mots de passe. Une archive de contenu
	// circule : on l'envoie sur un disque externe, on la copie sur une autre
	// machine, on la transmet pour depannage. Les identifiants n'ont rien a
	// faire dedans.
	s := ouvre(t)
	cat, uid := salon(t, s)
	s.NewThread(cat, uid, "Fil", "corps", VisLocal)
	if err := os.MkdirAll(filepath.Join(s.root, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(s.root, "secrets", "passwd"), []byte("gk2:$argon2id$SECRET"), 0o600)

	arc := filepath.Join(t.TempDir(), "s.tar.gz")
	if err := s.Backup(arc); err != nil {
		t.Fatal(err)
	}
	noms, corps := lireArchive(t, arc)
	for _, n := range noms {
		if strings.Contains(n, "secrets") {
			t.Errorf("secrets/ present dans l'archive : %s", n)
		}
	}
	if strings.Contains(corps, "argon2id") {
		t.Error("un hash de mot de passe se trouve dans l'archive")
	}
}

func TestUneSauvegardeSeRestaureSansLaBase(t *testing.T) {
	// La preuve que l'index est jetable : on restaure UNIQUEMENT les fichiers,
	// on reconstruit, et tout est la. Si ce test tombe, il faut sauvegarder la
	// base a froid — donc arreter le service a chaque sauvegarde.
	src := ouvre(t)
	cat, uid := salon(t, src)
	th, _ := src.NewThread(cat, uid, "Le fil d'origine", "un corps precis", VisPublic)
	src.Reply(th, uid, "une reponse locale", VisLocal)

	arc := filepath.Join(t.TempDir(), "s.tar.gz")
	if err := src.Backup(arc); err != nil {
		t.Fatal(err)
	}

	// Machine neuve : rien d'autre que l'archive.
	dst := ouvre(t)
	if err := extraire(arc, dst.root); err != nil {
		t.Fatal(err)
	}
	if err := dst.Reindex(); err != nil {
		t.Fatal(err)
	}

	posts, err := dst.PostsOf(th)
	if err != nil || len(posts) != 2 {
		t.Fatalf("%d messages restaures (%v), attendu 2", len(posts), err)
	}
	body, err := dst.Body(posts[0])
	if err != nil || !strings.Contains(body, "un corps precis") {
		t.Errorf("corps perdu a la restauration : %v %q", err, body)
	}
	if posts[1].Visibility != VisLocal {
		t.Errorf("visibilite perdue : %q", posts[1].Visibility)
	}
}

func lireArchive(t *testing.T, p string) ([]string, string) {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var noms []string
	var sb strings.Builder
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		noms = append(noms, h.Name)
		io.Copy(&sb, tr)
	}
	return noms, sb.String()
}

func extraire(arc, dest string) error {
	f, err := os.Open(arc)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		p := filepath.Join(dest, h.Name)
		if h.Typeflag == tar.TypeDir {
			os.MkdirAll(p, 0o750)
			continue
		}
		os.MkdirAll(filepath.Dir(p), 0o750)
		out, err := os.Create(p)
		if err != nil {
			return err
		}
		io.Copy(out, tr)
		out.Close()
	}
}
