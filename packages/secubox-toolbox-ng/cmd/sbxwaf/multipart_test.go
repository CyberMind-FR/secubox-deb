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

// fabriquerMultipart fabrique un corps multipart/form-data. Une partie « fichier »
// porte toujours un paramètre filename, même vide. lf = fins de ligne LF seules.
func fabriquerMultipart(boundary string, parties []partieTest, lf bool) []byte {
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
	return fabriquerMultipart("BND", ps, false)
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
		// rfc1867.c:767-789 : une frontière VIDE est acceptée par PHP (adapté, R13 ;
		// l'ancien attendu « échec » laissait un corps lu par PHP sans analyse).
		{`multipart/form-data; boundary=`, "", true},
		{`multipart/form-data; boundary=;x`, "", true},
	}
	for _, c := range cas {
		got, ok := boundaryPHP(c.ct)
		if got != c.want || ok != c.ok {
			t.Errorf("boundaryPHP(%q) = (%q,%v), attendu (%q,%v)", c.ct, got, ok, c.want, c.ok)
		}
	}
}

func TestAnalyserMultipartExploitProgress(t *testing.T) {
	corps := fabriquerMultipart("BND", []partieTest{
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
	corps := fabriquerMultipart("BND", []partieTest{
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
	crlf := analyserMultipart(fabriquerMultipart("BND", ps, false), ctTest, false, LimitesMultipart{})
	lf := analyserMultipart(fabriquerMultipart("BND", ps, true), ctTest, false, LimitesMultipart{})
	if lf.Statut != MultipartAnalyse || lf != crlf {
		t.Fatalf("LF %+v, CRLF %+v", lf, crlf)
	}
}

func TestAnalyserMultipartFilename(t *testing.T) {
	un := func(p partieTest) ResultatMultipart {
		return analyserMultipart(fabriquerMultipart("BND", []partieTest{p}, false), ctTest, false, LimitesMultipart{})
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
	// Adapté (R13, M6) : PHP compare la clé à « filename » par strcasecmp ;
	// `FileName*` n'est pas un filename, la partie reste un champ ordinaire.
	r = analyserMultipart(brut(`form-data; NAME="a\"b[c]"; FileName*="z"`), ctTest, false, LimitesMultipart{})
	if r.PartiesFichier != 0 || r.LongueurNomMax != len(`a"b[c]`) || r.ProfondeurMax != 1 {
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

// Plusieurs filename dans une disposition : PHP garde le DERNIER (rfc1867.c:888,
// efree puis réaffectation). Adapté (R13) : l'ancien attendu « aucun ne masque
// les autres » supposait qu'on ignorait lequel PHP retient ; la source le dit.
// `filename*` n'est jamais retenu.
func TestAnalyserMultipartPlusieursFilename(t *testing.T) {
	cas := map[string]bool{
		`form-data; name="f"; filename="a"; filename="<?php"`:  true,
		`form-data; name="f"; filename="<?php"; filename="a"`:  false,
		`form-data; name="f"; filename*="<?php"; filename="a"`: false,
		`form-data; name="f"; filename="a"; filename*="<?php"`: false,
	}
	for disp, want := range cas {
		corps := []byte("--BND\r\nContent-Disposition: " + disp + "\r\n\r\nv\r\n--BND--\r\n")
		if r := analyserMultipart(corps, ctTest, false, LimitesMultipart{}); r.FilenamePHP != want || r.PartiesFichier != 1 {
			t.Errorf("%s : %+v, FilenamePHP attendu %v", disp, r, want)
		}
	}
	corps := []byte("--BND\r\nContent-Disposition: form-data; name=\"f\"; filename=\"b\"; filename=\"a|O:1\"\r\n\r\nv\r\n--BND--\r\n")
	if r := analyserMultipart(corps, ctTest, false, LimitesMultipart{}); !r.FilenameObjet {
		t.Errorf("|O: du filename retenu : %+v", r)
	}
}

// R5 : une coupure en plein en-tête n'est jamais un corps complet (sans
// fermeture vue : « tronque » si le préfixe est coupé, « malforme » sinon).
func TestAnalyserMultipartCoupureEnPleinEntete(t *testing.T) {
	// Deux coupures : avant le « : », et dans une valeur de nom entamée.
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

// Corps complet : la dernière recherche de frontière a vu « --b-- », avec ou
// sans fin de ligne → analyse. Adapté (R13) : avec un préfixe TRONQUÉ, le statut
// reste « tronque » même après « --b-- », car find_boundary (rfc1867.c:383)
// continue de chercher « --b » dans l'épilogue : PHP lirait des parties au-delà
// du préfixe (voir TestPHPPartiesApresLaFermeture).
func TestAnalyserMultipartFrontiereFinale(t *testing.T) {
	for _, corps := range []string{
		"--BND\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--BND--\r\n",
		"--BND\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--BND--",
	} {
		if r := analyserMultipart([]byte(corps), ctTest, false, LimitesMultipart{}); r.Statut != MultipartAnalyse || r.Parties != 1 {
			t.Errorf("complet %q : %+v", corps, r)
		}
		if r := analyserMultipart([]byte(corps), ctTest, true, LimitesMultipart{}); r.Statut != MultipartTronque || r.Parties != 1 {
			t.Errorf("tronqué %q : %+v", corps, r)
		}
	}
}

func TestAnalyserMultipartEnvoiLegitime(t *testing.T) {
	corps := fabriquerMultipart("BND", []partieTest{
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

// Invariants : jamais de panique ; statut connu ; compteurs cohérents ; aucune
// lecture hors du préfixe (même résultat sur une tranche bornée par sa capacité
// et sur une tranche suivie d'octets empoisonnés) ; préfixe jamais modifié.
func FuzzAnalyserMultipart(f *testing.F) {
	f.Add(corpsImbrique()[:400], ctTest, true, 50)
	f.Add([]byte("--BND\r\nContent-Disposition: form-data; name=\"a\"; filename=\n\r\n\r\n--BND--"), ctTest, false, 0)
	f.Add([]byte(""), "multipart/form-data; boundary=\"", false, 1)
	f.Add([]byte(corpsSondeP3()), ctTest, false, 0)
	f.Add([]byte(corpsMaxFileSize("MAX_FILE_SIZE")), ctTest, false, 0)
	f.Add([]byte("--\r\nContent-Disposition: form-data; name='a;b' x; filename=\"\\\"\"\r\n z\r\n\r\nv\n----"), "multipart/form-data; boundary=", true, 0)
	f.Fuzz(func(t *testing.T, corps []byte, ct string, tronque bool, max int) {
		if max < 0 || max > 5000 {
			max = 0
		}
		copie := append([]byte(nil), corps...)
		poison := append(append([]byte(nil), corps...), []byte(corpsSondeP3())...)
		r := analyserMultipart(corps[:len(corps):len(corps)], ct, tronque, LimitesMultipart{PartiesMax: max})
		if r2 := analyserMultipart(poison[:len(corps)], ct, tronque, LimitesMultipart{PartiesMax: max}); r2 != r {
			t.Fatalf("lecture hors du préfixe : %+v / %+v", r, r2)
		}
		if string(copie) != string(corps) {
			t.Fatal("préfixe modifié")
		}
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
		if r.LongueurNomMax > len(corps) || r.ProfondeurMax > len(corps) {
			t.Fatalf("mesures plus grandes que le préfixe : %+v", r)
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
