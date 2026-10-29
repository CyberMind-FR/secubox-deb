// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — tests de l'analyseur multipart (#3257)
package main

import (
	"fmt"
	"strings"
	"testing"
)

// partieTest décrit une partie d'un corps multipart fabriqué pour les tests.
// Réutilisé par les tests du gestionnaire HTTP (même paquet).
type partieTest struct {
	nom, filename string
	fichier       bool
	contenu       string
}

// corpsMultipart fabrique un corps multipart/form-data. Une partie « fichier »
// porte toujours un paramètre filename, même vide. lf = fins de ligne LF seules.
func corpsMultipart(boundary string, parties []partieTest, lf bool) []byte {
	nl := "\r\n"
	if lf {
		nl = "\n"
	}
	var b strings.Builder
	for _, p := range parties {
		b.WriteString("--" + boundary + nl)
		b.WriteString(`Content-Disposition: form-data; name="` + p.nom + `"`)
		if p.fichier {
			b.WriteString(`; filename="` + p.filename + `"`)
		}
		b.WriteString(nl + nl + p.contenu + nl)
	}
	b.WriteString("--" + boundary + "--" + nl)
	return []byte(b.String())
}

const ctTest = "multipart/form-data; boundary=BND"

func corpsImbrique() []byte {
	ps := []partieTest{{nom: nomProgressPHP, contenu: "x"}}
	for i := 0; i < 900; i++ {
		ps = append(ps, partieTest{nom: fmt.Sprintf("files[R%05d][a][a][a]", i), filename: "f.txt", fichier: true, contenu: "y"})
	}
	return corpsMultipart("BND", ps, false)
}

func TestEstMultipartPHP(t *testing.T) {
	cas := map[string]bool{
		"multipart/form-data; boundary=x":   true,
		"Multipart/Form-Data;boundary=x":    true,
		"multipart/form-data, x":            true,
		"multipart/form-data x":             true,
		"multipart/form-dataX":              false,
		"multipart/mixed; boundary=x":       false,
		"application/x-www-form-urlencoded": false,
		"":                                  false,
	}
	for ct, want := range cas {
		if got := estMultipartPHP(ct); got != want {
			t.Errorf("estMultipartPHP(%q) = %v, attendu %v", ct, got, want)
		}
	}
}

func TestBoundaryPHP(t *testing.T) {
	cas := []struct {
		ct   string
		want string
		ok   bool
	}{
		{`multipart/form-data; boundary=abc`, "abc", true},
		{`multipart/form-data; boundary="a;b"`, "a;b", true},
		{`multipart/form-data; BOUNDARY=Q`, "Q", true},
		{`multipart/form-data; boundary=abc; charset=utf-8`, "abc", true},
		{`multipart/form-data; boundary=abc,def`, "abc", true},
		{`multipart/form-data; boundary="abc`, "", false},
		{`multipart/form-data`, "", false},
		{`multipart/form-data; boundary=`, "", false},
	}
	for _, c := range cas {
		got, ok := boundaryPHP(c.ct)
		if got != c.want || ok != c.ok {
			t.Errorf("boundaryPHP(%q) = (%q,%v), attendu (%q,%v)", c.ct, got, ok, c.want, c.ok)
		}
	}
}

func TestAnalyserMultipartExploitProgress(t *testing.T) {
	corps := corpsMultipart("BND", []partieTest{
		{nom: nomProgressPHP, contenu: "x"},
		{nom: "a", filename: "1", fichier: true},
		{nom: "b", filename: "2", fichier: true},
		{nom: "c", filename: "3", fichier: true},
	}, false)
	r := analyserMultipart(corps, ctTest, false, LimitesMultipart{})
	if r.Statut != MultipartAnalyse || r.Parties != 4 || r.PartiesFichier != 3 || !r.Progress || r.FichiersApresProgress != 3 {
		t.Fatalf("résultat inattendu : %+v", r)
	}
}

func TestAnalyserMultipartProgressApresFichiers(t *testing.T) {
	corps := corpsMultipart("BND", []partieTest{
		{nom: "a", filename: "1", fichier: true},
		{nom: "b", filename: "2", fichier: true},
		{nom: nomProgressPHP, contenu: "x"},
	}, false)
	r := analyserMultipart(corps, ctTest, false, LimitesMultipart{})
	if r.FichiersApresProgress != 0 || !r.Progress || r.PartiesFichier != 2 {
		t.Fatalf("résultat inattendu : %+v", r)
	}
}

func TestAnalyserMultipartImbrique(t *testing.T) {
	r := analyserMultipart(corpsImbrique(), ctTest, false, LimitesMultipart{})
	if r.Statut != MultipartAnalyse || r.Parties != 901 || r.PartiesFichier != 900 || r.ProfondeurMax != 4 {
		t.Fatalf("résultat inattendu : %+v", r)
	}
	if r.LongueurNomMax != len(nomProgressPHP) {
		t.Errorf("LongueurNomMax = %d", r.LongueurNomMax)
	}
}

func TestAnalyserMultipartTronque(t *testing.T) {
	c := corpsImbrique()
	r := analyserMultipart(c[:len(c)/2], ctTest, true, LimitesMultipart{})
	if r.Statut != MultipartTronque || r.Parties < 1 || r.Parties >= 901 {
		t.Fatalf("résultat inattendu : %+v", r)
	}
}

func TestAnalyserMultipartCoupeSansTronque(t *testing.T) {
	c := corpsImbrique()
	r := analyserMultipart(c[:len(c)/2], ctTest, false, LimitesMultipart{})
	if r.Statut != MultipartMalforme {
		t.Fatalf("résultat inattendu : %+v", r)
	}
}

func TestAnalyserMultipartLimite(t *testing.T) {
	r := analyserMultipart(corpsImbrique(), ctTest, false, LimitesMultipart{PartiesMax: 500})
	if r.Statut != MultipartLimite || r.Parties != 500 {
		t.Fatalf("résultat inattendu : %+v", r)
	}
}

func TestAnalyserMultipartSansBoundary(t *testing.T) {
	r := analyserMultipart(corpsImbrique(), "multipart/form-data", false, LimitesMultipart{})
	if r.Statut != MultipartMalforme || r.Parties != 0 {
		t.Fatalf("résultat inattendu : %+v", r)
	}
}

func TestAnalyserMultipartLF(t *testing.T) {
	ps := []partieTest{
		{nom: nomProgressPHP, contenu: "x"},
		{nom: "a[b]", filename: "1", fichier: true},
		{nom: "c", filename: "2", fichier: true},
	}
	crlf := analyserMultipart(corpsMultipart("BND", ps, false), ctTest, false, LimitesMultipart{})
	lf := analyserMultipart(corpsMultipart("BND", ps, true), ctTest, false, LimitesMultipart{})
	if lf.Statut != MultipartAnalyse || lf != crlf {
		t.Fatalf("LF %+v, CRLF %+v", lf, crlf)
	}
}

func TestAnalyserMultipartFilename(t *testing.T) {
	un := func(p partieTest) ResultatMultipart {
		return analyserMultipart(corpsMultipart("BND", []partieTest{p}, false), ctTest, false, LimitesMultipart{})
	}
	if r := un(partieTest{nom: "f", filename: "<?PHP x", fichier: true}); !r.FilenamePHP || r.FilenameObjet {
		t.Errorf("<?PHP : %+v", r)
	}
	if r := un(partieTest{nom: "f", filename: "a|O:8:", fichier: true}); !r.FilenameObjet || r.FilenamePHP {
		t.Errorf("|O: : %+v", r)
	}
	if r := un(partieTest{nom: "f", filename: "photo.jpg", fichier: true, contenu: "<?php echo 1;"}); r.FilenamePHP || r.FilenameObjet {
		t.Errorf("contenu ne doit pas compter : %+v", r)
	}
}

func TestAnalyserMultipartDispositionLaxiste(t *testing.T) {
	brut := func(disp string) []byte {
		return []byte("--BND\r\nContent-Disposition: " + disp + "\r\n\r\nv\r\n--BND--\r\n")
	}
	r := analyserMultipart(brut("form-data; name="+nomProgressPHP), ctTest, false, LimitesMultipart{})
	if !r.Progress {
		t.Errorf("nom sans guillemets : %+v", r)
	}
	r = analyserMultipart(brut(`form-data; name="x"; filename=`), ctTest, false, LimitesMultipart{})
	if r.PartiesFichier != 1 {
		t.Errorf("filename vide : %+v", r)
	}
	r = analyserMultipart(brut(`form-data; NAME="a\"b[c]"; FileName*="z"`), ctTest, false, LimitesMultipart{})
	if r.PartiesFichier != 1 || r.LongueurNomMax != len(`a"b[c]`) || r.ProfondeurMax != 1 {
		t.Errorf("échappements : %+v", r)
	}
}

// R6 : un `;` entre guillemets ne coupe pas la valeur.
func TestAnalyserMultipartFilenamePointVirgule(t *testing.T) {
	corps := []byte("--BND\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a;<?php\"\r\n\r\nv\r\n--BND--\r\n")
	r := analyserMultipart(corps, ctTest, false, LimitesMultipart{})
	if !r.FilenamePHP {
		t.Fatalf("filename avec ; non détecté : %+v", r)
	}
}

// Plusieurs filename dans une disposition : aucun ne masque les autres.
func TestAnalyserMultipartPlusieursFilename(t *testing.T) {
	for _, disp := range []string{
		`form-data; name="f"; filename="<?php"; filename="a"`,
		`form-data; name="f"; filename*="<?php"; filename="a"`,
	} {
		corps := []byte("--BND\r\nContent-Disposition: " + disp + "\r\n\r\nv\r\n--BND--\r\n")
		if r := analyserMultipart(corps, ctTest, false, LimitesMultipart{}); !r.FilenamePHP || r.PartiesFichier != 1 {
			t.Errorf("%s : %+v", disp, r)
		}
	}
	corps := []byte("--BND\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a|O:1\"; filename=\"b\"\r\n\r\nv\r\n--BND--\r\n")
	if r := analyserMultipart(corps, ctTest, false, LimitesMultipart{}); !r.FilenameObjet {
		t.Errorf("|O: masqué : %+v", r)
	}
}

// R5 : un io.EOF nu ne prouve pas un corps complet (coupure en plein en-tête).
func TestAnalyserMultipartCoupureEnPleinEntete(t *testing.T) {
	// Les deux coupures : la seconde (valeur de nom entamée) fait rendre par Go
	// un io.EOF NU ; c'est elle qui prouve la condition sur la frontière finale.
	for _, c := range []string{"--BND\r\nContent-Disp", "--BND\r\nContent-Disposition: form-data; name=\"fi"} {
		coupe := []byte(c)
		testerCoupure(t, coupe)
	}
}

func testerCoupure(t *testing.T, coupe []byte) {
	t.Helper()
	if r := analyserMultipart(coupe, ctTest, true, LimitesMultipart{}); r.Statut != MultipartTronque {
		t.Errorf("tronque=true : %+v", r)
	}
	if r := analyserMultipart(coupe, ctTest, false, LimitesMultipart{}); r.Statut != MultipartMalforme {
		t.Errorf("tronque=false : %+v", r)
	}
}

func TestAnalyserMultipartCoupureApresUnePartie(t *testing.T) {
	deux := []byte("--BND\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--BND\r\nContent-Disposition: form-data; name=\"b")
	if r := analyserMultipart(deux, ctTest, true, LimitesMultipart{}); r.Statut != MultipartTronque || r.Parties != 1 {
		t.Errorf("tronque : %+v", r)
	}
	if r := analyserMultipart(deux, ctTest, false, LimitesMultipart{}); r.Statut != MultipartMalforme {
		t.Errorf("sans tronque : %+v", r)
	}
}

// Corps complet : EOF après la frontière finale, avec ou sans fin de ligne.
func TestAnalyserMultipartFrontiereFinale(t *testing.T) {
	for _, corps := range []string{
		"--BND\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--BND--\r\n",
		"--BND\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--BND--",
	} {
		if r := analyserMultipart([]byte(corps), ctTest, true, LimitesMultipart{}); r.Statut != MultipartAnalyse || r.Parties != 1 {
			t.Errorf("%q : %+v", corps, r)
		}
	}
}

func TestAnalyserMultipartEnvoiLegitime(t *testing.T) {
	corps := corpsMultipart("BND", []partieTest{
		{nom: "titre", contenu: "bonjour"},
		{nom: "photo", filename: "p.jpg", fichier: true, contenu: "binaire"},
	}, false)
	r := analyserMultipart(corps, ctTest, false, LimitesMultipart{})
	if r.Statut != MultipartAnalyse || r.Parties != 2 || r.PartiesFichier != 1 || r.ProfondeurMax != 0 || r.Progress {
		t.Fatalf("résultat inattendu : %+v", r)
	}
	s := r.Signaux()
	if s["parties"] != 2 || s["fichiers"] != 1 || s["profondeur"] != 0 || s["nom_max"] != 5 || s["fichiers_apres_progress"] != 0 {
		t.Errorf("signaux : %v", s)
	}
}

func FuzzAnalyserMultipart(f *testing.F) {
	f.Add(corpsImbrique()[:400], ctTest, true, 50)
	f.Add([]byte("--BND\r\nContent-Disposition: form-data; name=\"a\"; filename=\n\r\n\r\n--BND--"), ctTest, false, 0)
	f.Add([]byte(""), "multipart/form-data; boundary=\"", false, 1)
	f.Fuzz(func(t *testing.T, corps []byte, ct string, tronque bool, max int) {
		if max < 0 || max > 5000 {
			max = 0
		}
		r := analyserMultipart(corps, ct, tronque, LimitesMultipart{PartiesMax: max})
		plafond := max
		if plafond == 0 {
			plafond = partiesMaxDefaut
		}
		if r.Parties > plafond {
			t.Fatalf("Parties %d > %d", r.Parties, plafond)
		}
		switch r.Statut {
		case MultipartAnalyse, MultipartTronque, MultipartMalforme, MultipartLimite:
		default:
			t.Fatalf("statut inconnu %q", r.Statut)
		}
		if r.Statut == MultipartLimite && r.Parties != plafond {
			t.Fatalf("limite : Parties %d != plafond %d", r.Parties, plafond)
		}
		if r.PartiesFichier > r.Parties || r.FichiersApresProgress > r.PartiesFichier {
			t.Fatalf("compteurs incohérents : %+v", r)
		}
		if !r.Progress && r.FichiersApresProgress != 0 {
			t.Fatalf("fichiers après progress sans progress : %+v", r)
		}
		_ = r.Signaux()
	})
}

func BenchmarkAnalyserMultipart(b *testing.B) {
	c := corpsImbrique()
	b.SetBytes(int64(len(c)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyserMultipart(c, ctTest, false, LimitesMultipart{})
	}
}
