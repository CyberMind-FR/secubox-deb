// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — parité avec main/rfc1867.c (PHP 8.2) (#3257, R13)
//
// Les sondes P1 à P7 de la relecture finale (I1) et les tolérances de PHP que
// mime/multipart ne reproduisait pas. Chaque attendu est tiré de la lecture de
// rfc1867.c (branche PHP-8.2), pas du balayeur : la fonction citée dit pourquoi.
package main

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func analyser(corps string) ResultatMultipart {
	return analyserMultipart([]byte(corps), ctTest, false, LimitesMultipart{})
}

const (
	cdProgress   = "Content-Disposition: form-data; name=\"" + nomProgressPHP + "\""
	deuxFichiers = "--BND\r\nContent-Disposition: form-data; name=\"f1\"; filename=\"a\"\r\n\r\ny\r\n" +
		"--BND\r\nContent-Disposition: form-data; name=\"f2\"; filename=\"b\"\r\n\r\ny\r\n"
)

// P1 : php_ap_getword_conf (rfc1867.c:560) accepte « ' » comme « " ».
func TestPHPSondeP1NomEntreApostrophes(t *testing.T) {
	r := analyser("--BND\r\nContent-Disposition: form-data; name='" + nomProgressPHP + "'\r\n\r\nx\r\n" +
		deuxFichiers + "--BND--\r\n")
	if r.Statut != MultipartAnalyse || !r.Progress || r.FichiersApresProgress != 2 || r.Parties != 3 {
		t.Fatalf("P1 : %+v", r)
	}
}

// P2 : multipart_buffer_headers (rfc1867.c:409) ignore une première ligne
// d'en-tête sans « : » (rien à quoi la coller) au lieu de refuser la partie.
func TestPHPSondeP2LigneSansDeuxPoints(t *testing.T) {
	var b strings.Builder
	b.WriteString("--BND\r\nX-Rien\r\n" + cdProgress + "\r\n\r\nx\r\n")
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&b, "--BND\r\nContent-Disposition: form-data; name=\"files[R%05d][a][a][a][a][a][a][a][a][a][a][a]\"; filename=\"f\"\r\n\r\ny\r\n", i)
	}
	b.WriteString("--BND--\r\n")
	r := analyser(b.String())
	if r.Statut != MultipartAnalyse || r.Parties != 61 || r.PartiesFichier != 60 || !r.Progress ||
		r.FichiersApresProgress != 60 || r.ProfondeurMax != 12 {
		t.Fatalf("P2 : %+v", r)
	}
}

// P3 : find_boundary (rfc1867.c:383) compare chaque LIGNE à « --b » après
// retrait de CRLF ou de LF seul (next_line, rfc1867.c:324) ; le corps d'une
// partie s'arrête au premier « \n--b » (multipart_buffer_read, rfc1867.c:634).
// Une première frontière en CRLF n'impose donc rien aux suivantes.
func corpsSondeP3() string {
	var b strings.Builder
	b.WriteString("--BND\r\n" + cdProgress + "\r\n\r\nx")
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&b, "\n--BND\r\nContent-Disposition: form-data; name=\"files[R%05d][a][a][a][a][a][a][a][a][a][a][a]\"; filename=\"f<?php\"\r\n\r\ny", i)
	}
	b.WriteString("\r\n--BND--\r\n")
	return b.String()
}

func TestPHPSondeP3LFNuAvantLesFrontieres(t *testing.T) {
	r := analyser(corpsSondeP3())
	if r.Statut != MultipartAnalyse || r.Parties != 61 || r.PartiesFichier != 60 || !r.Progress ||
		r.FichiersApresProgress != 60 || r.ProfondeurMax != 12 || !r.FilenamePHP {
		t.Fatalf("P3 : %+v", r)
	}
}

// P4 : php_ap_getword (rfc1867.c:506) ne coupe pas sur « ; » entre apostrophes.
func TestPHPSondeP4FilenameApostrophesPointVirgule(t *testing.T) {
	r := analyser("--BND\r\nContent-Disposition: form-data; name=\"f\"; filename='a;<?php x'\r\n\r\ny\r\n--BND--\r\n")
	if !r.FilenamePHP || r.PartiesFichier != 1 {
		t.Fatalf("P4 : %+v", r)
	}
}

// P5 : une valeur sans guillemets s'arrête au premier blanc (php_ap_getword_conf).
func TestPHPSondeP5NomNuCoupeAuBlanc(t *testing.T) {
	r := analyser("--BND\r\nContent-Disposition: form-data; name=" + nomProgressPHP + " z\r\n\r\nx\r\n" +
		deuxFichiers + "--BND--\r\n")
	if !r.Progress || r.FichiersApresProgress != 2 {
		t.Fatalf("P5 : %+v", r)
	}
}

// P6 : « X-A : b » a pour clé « X-A » suivi d'un blanc ; PHP ne le garde pas
// (php_mime_should_save_hdr) et ne refuse rien.
func TestPHPSondeP6BlancAvantDeuxPoints(t *testing.T) {
	r := analyser("--BND\r\nX-A : b\r\n" + cdProgress + "\r\n\r\nx\r\n" + deuxFichiers + "--BND--\r\n")
	if r.Statut != MultipartAnalyse || r.Parties != 3 || !r.Progress || r.FichiersApresProgress != 2 {
		t.Fatalf("P6 : %+v", r)
	}
}

// P7 : sans frontière finale, PHP traite toutes les parties (la boucle de
// rfc1867_post_handler, rfc1867.c:830, ne s'arrête qu'à la fin des données).
// Les comptes sont complets ; le statut reste « malforme » (corps complet sans
// fermeture), les signatures s'évaluent quel que soit le statut.
func TestPHPSondeP7SansFrontiereFinale(t *testing.T) {
	r := analyser("--BND\r\n" + cdProgress + "\r\n\r\nx\r\n" + deuxFichiers)
	if r.Statut != MultipartMalforme || r.Parties != 3 || !r.Progress || r.FichiersApresProgress != 2 {
		t.Fatalf("P7 : %+v", r)
	}
}

// Après « --b-- », find_boundary cherche encore une ligne « --b » : des parties
// placées dans l'épilogue sont lues par PHP.
func TestPHPPartiesApresLaFermeture(t *testing.T) {
	r := analyser("--BND\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--BND--\r\n" +
		"--BND\r\n" + cdProgress + "\r\n\r\nv\r\n" + deuxFichiers + "--BND--\r\n")
	if r.Statut != MultipartAnalyse || r.Parties != 4 || !r.Progress || r.FichiersApresProgress != 2 {
		t.Fatalf("épilogue : %+v", r)
	}
}

// Une frontière vide est acceptée par PHP (rfc1867.c:767-789 : seule une
// frontière entre guillemets non fermés, ou trop longue, est refusée).
func TestPHPFrontiereVide(t *testing.T) {
	corps := "--\r\n" + cdProgress + "\r\n\r\nx\r\n" +
		"--\r\nContent-Disposition: form-data; name=\"f1\"; filename=\"a\"\r\n\r\ny\r\n" +
		"--\r\nContent-Disposition: form-data; name=\"f2\"; filename=\"b\"\r\n\r\ny\r\n----\r\n"
	for _, ct := range []string{"multipart/form-data; boundary=", "multipart/form-data; boundary=;charset=x"} {
		r := analyserMultipart([]byte(corps), ct, false, LimitesMultipart{})
		if r.Statut != MultipartAnalyse || !r.Progress || r.FichiersApresProgress != 2 {
			t.Errorf("%q : %+v", ct, r)
		}
	}
}

// Frontière de plus de FILLUNIT - 4 = 5116 octets : PHP refuse tout (rfc1867.c:793).
func TestPHPFrontiereTropLongue(t *testing.T) {
	for _, n := range []int{5116, 5117} {
		b := strings.Repeat("b", n)
		corps := "--" + b + "\r\n" + cdProgress + "\r\n\r\nx\r\n--" + b + "--\r\n"
		r := analyserMultipart([]byte(corps), "multipart/form-data; boundary="+b, false, LimitesMultipart{})
		if n == 5116 && (r.Parties != 1 || !r.Progress) {
			t.Errorf("5116 : lue par PHP : %+v", r)
		}
		if n == 5117 && (r.Statut != MultipartMalforme || r.Parties != 0) {
			t.Errorf("5117 : refusée par PHP : %+v", r)
		}
	}
}

// Les lignes sont des chaînes C : strcmp s'arrête au premier octet nul.
func TestPHPOctetNulDansLaLigneDeFrontiere(t *testing.T) {
	r := analyser("--BND\x00bourre\r\n" + cdProgress + "\r\n\r\nx\r\n" + deuxFichiers + "--BND--\r\n")
	if !r.Progress || r.Parties != 3 {
		t.Fatalf("NUL : %+v", r)
	}
}

// next_line (rfc1867.c:324) rend une ligne sans LF par morceaux de bufsize
// (5120) octets. Une partie SAUTÉE (sans Content-Disposition) est parcourue
// ligne à ligne par find_boundary : « --b » collé à 5120 octets de bourre y est
// une frontière. Une partie LUE (multipart_buffer_read) ne s'arrête qu'à
// « \n--b » : le même « --b » reste dans sa valeur.
func corpsMorceaux(premiere string, bourre int) string {
	return "--BND\r\n" + premiere + "\r\n\r\n" + strings.Repeat("A", bourre) + "--BND\r\n" +
		cdProgress + "\r\n\r\nv\r\n" + deuxFichiers + "--BND--\r\n"
}

func TestPHPMorceauxDeLigneEnModeLignes(t *testing.T) {
	r := analyser(corpsMorceaux("X-Autre: 1", 5120))
	if r.Parties != 3 || !r.Progress || r.FichiersApresProgress != 2 {
		t.Errorf("partie sautée, 5120 octets : PHP voit la frontière cachée : %+v", r)
	}
	r = analyser(corpsMorceaux("X-Autre: 1", 5119))
	if r.Parties != 2 || r.Progress {
		t.Errorf("partie sautée, 5119 octets : morceau mal aligné, pas de frontière : %+v", r)
	}
	r = analyser(corpsMorceaux("Content-Disposition: form-data; name=\"a\"", 5120))
	if r.Parties != 3 || r.Progress {
		t.Errorf("partie lue : le « --BND » sans LF reste dans la valeur : %+v", r)
	}
}

// MAX_FILE_SIZE (rfc1867.c:1017, :1161) : un fichier qui le dépasse est
// abandonné après deux lectures de 5119 octets ; find_boundary reprend alors
// ligne à ligne. 10238 + 5120 octets de bourre alignent « --b » sur un morceau.
func corpsMaxFileSize(champ string) string {
	return "--BND\r\nContent-Disposition: form-data; name=\"" + champ + "\"\r\n\r\n1\r\n" +
		"--BND\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a\"\r\n\r\n" +
		strings.Repeat("A", 2*5119+5120) + "--BND\r\n" + cdProgress + "\r\n\r\nv\r\n" + deuxFichiers + "--BND--\r\n"
}

func TestPHPMaxFileSizeRepasseEnModeLignes(t *testing.T) {
	r := analyser(corpsMaxFileSize("max_file_size"))
	if r.Parties != 5 || !r.Progress || r.FichiersApresProgress != 2 {
		t.Errorf("MAX_FILE_SIZE=1 (casse indifférente) : %+v", r)
	}
	r = analyser(corpsMaxFileSize("autre"))
	if r.Parties != 4 || r.Progress {
		t.Errorf("sans MAX_FILE_SIZE : %+v", r)
	}
}

// M6 et session.c:3084-3090 : le suivi de progression ne naît que d'un champ
// ORDINAIRE (sans filename) de valeur non vide.
func TestPHPProgressChampOrdinaireNonVide(t *testing.T) {
	r := analyser("--BND\r\n" + cdProgress + "; filename=\"x\"\r\n\r\nv\r\n" + deuxFichiers + "--BND--\r\n")
	if r.Progress || r.PartiesFichier != 3 {
		t.Errorf("progress porteur d'un filename = partie fichier : %+v", r)
	}
	r = analyser("--BND\r\n" + cdProgress + "\r\n\r\n\r\n" + deuxFichiers + "--BND--\r\n")
	if r.Progress {
		t.Errorf("valeur vide : pas de suivi : %+v", r)
	}
}

// M6 : `filename*` n'est pas `filename` (strcasecmp exact, rfc1867.c:888) ; la
// clé n'est pas rognée à droite (« name » suivi d'un blanc n'est pas name).
func TestPHPClesDeDispositionExactes(t *testing.T) {
	r := analyser("--BND\r\nContent-Disposition: form-data; name=\"f\"; filename*=\"<?php\"\r\n\r\nv\r\n--BND--\r\n")
	if r.PartiesFichier != 0 || r.FilenamePHP {
		t.Errorf("filename* ignoré par PHP : %+v", r)
	}
	r = analyser("--BND\r\nContent-Disposition: form-data; name =" + nomProgressPHP + "\r\n\r\nv\r\n" + deuxFichiers + "--BND--\r\n")
	if r.Progress {
		t.Errorf("« name  » n'est pas name : %+v", r)
	}
}

// En-têtes : une ligne qui commence par un blanc, ou sans « : », se colle à la
// précédente (rfc1867.c:441-470) ; le premier Content-Disposition gagne.
func TestPHPEntetesSuiteEtDoublon(t *testing.T) {
	r := analyser("--BND\r\nContent-Disposition: form-data;\r\n name=\"" + nomProgressPHP + "\"\r\n\r\nx\r\n" + deuxFichiers + "--BND--\r\n")
	if !r.Progress {
		t.Errorf("suite par un blanc : %+v", r)
	}
	r = analyser("--BND\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD\r\n_PROGRESS\"\r\n\r\nx\r\n" + deuxFichiers + "--BND--\r\n")
	if !r.Progress {
		t.Errorf("suite sans deux-points : %+v", r)
	}
	r = analyser("--BND\r\nContent-Disposition: form-data; name=\"a\"\r\n" + cdProgress + "\r\n\r\nx\r\n" + deuxFichiers + "--BND--\r\n")
	if r.Progress {
		t.Errorf("doublon : le premier gagne : %+v", r)
	}
	r = analyser("--BND\r\nContent-Disposition : form-data; name=\"a\"\r\n\r\nx\r\n--BND--\r\n")
	if r.Parties != 0 {
		t.Errorf("« Content-Disposition  » n'est pas gardé : partie sans disposition, non comptée : %+v", r)
	}
}

// « File Upload Mime headers garbled » (rfc1867.c:1038) : une disposition sans
// name ni filename arrête PHP ; rien de ce qui suit n'est lu.
func TestPHPDispositionSansNomArretePHP(t *testing.T) {
	r := analyser("--BND\r\nContent-Disposition: form-data\r\n\r\nx\r\n--BND\r\n" + cdProgress + "\r\n\r\nv\r\n" + deuxFichiers + "--BND--\r\n")
	if r.Statut != MultipartMalforme || r.Parties != 1 || r.Progress || r.PartiesFichier != 0 {
		t.Fatalf("garbled : %+v", r)
	}
}

// Le préfixe n'est jamais lu au-delà de sa longueur ni modifié (PHP écrit des
// NUL dans SON tampon ; le balayeur ne touche pas au préfixe capturé).
func TestPHPPrefixeNiDepasseNiModifie(t *testing.T) {
	plein := []byte(corpsSondeP3())
	for _, n := range []int{0, 1, 7, 40, len(plein) / 2, len(plein) - 3, len(plein)} {
		copie := append([]byte(nil), plein[:n]...)
		borne := analyserMultipart(plein[:n:n], ctTest, true, LimitesMultipart{})
		large := analyserMultipart(plein[:n], ctTest, true, LimitesMultipart{})
		if !reflect.DeepEqual(borne, large) {
			t.Errorf("n=%d : lecture au-delà du préfixe : %+v / %+v", n, borne, large)
		}
		if string(copie) != string(plein[:n]) {
			t.Errorf("n=%d : préfixe modifié", n)
		}
	}
}

// R16 (re-relecture, S1/S2) : skip_upload est COLLANT chez PHP (déclaré
// rfc1867.c:717, jamais remis à 0). Après un fichier sauté pour crochets
// invalides, tous les fichiers suivants sont sautés, donc parcourus ligne à
// ligne : « --b » aligné sur un morceau de 5120 octets y est une frontière.
func corpsS1() string {
	return "--BND\r\nContent-Disposition: form-data; name=\"bad]\"; filename=\"a\"\r\n\r\ny\r\n" +
		"--BND\r\nContent-Disposition: form-data; name=\"ok\"; filename=\"a\"\r\n\r\n" +
		strings.Repeat("A", 5120) +
		"--BND\r\nContent-Disposition: form-data; name=\"t[a][a][a][a][a][a][a][a][a][a][a][a][a]\"\r\n\r\nv\r\n--BND--\r\n"
}

func corpsS2() string {
	var b strings.Builder
	b.WriteString("--BND\r\nContent-Disposition: form-data; name=\"bad]\"; filename=\"a\"\r\n\r\ny\r\n")
	b.WriteString("--BND\r\nContent-Disposition: form-data; name=\"ok\"; filename=\"a\"\r\n\r\n")
	for i := 0; i < 60; i++ {
		b.WriteString(strings.Repeat("A", 5120))
		fmt.Fprintf(&b, "--BND\r\nContent-Disposition: form-data; name=\"files[R%05d][a][a][a][a][a][a][a][a][a][a][a]\"; filename=\"f\"\r\n\r\n", i)
	}
	b.WriteString(strings.Repeat("A", 5120))
	b.WriteString("--BND\r\nContent-Disposition: form-data; name=\"t[a][a][a][a][a][a][a][a][a][a][a][a][a]\"\r\n\r\nv\r\n--BND--\r\n")
	return b.String()
}

func TestPHPSondeS1SkipUploadCollant(t *testing.T) {
	if r := analyser(corpsS1()); r.Parties != 3 || r.ProfondeurMax != 13 {
		t.Fatalf("S1 : PHP voit 3 parties, profondeur 13 : %+v", r)
	}
}

func TestPHPSondeS2SkipUploadCollantEnChaine(t *testing.T) {
	if r := analyser(corpsS2()); r.Parties != 63 || r.ProfondeurMax != 13 || r.PartiesFichier != 62 {
		t.Fatalf("S2 : PHP voit 63 parties (62 fichiers), profondeur 13 : %+v", r)
	}
}
