// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — analyseur multipart lu comme PHP le lit (#3257)
//
// LE PROBLÈME. Les envois PHP2Shell (CVE-2026-109618/109619) tiennent dans la
// STRUCTURE du multipart : un champ PHP_SESSION_UPLOAD_PROGRESS suivi de
// centaines de parties fichier aux noms imbriqués (`files[R00001][a][a]…`), ou
// un filename qui transporte « <?php » ou « |O: ». Le contenu des parties n'a
// aucun intérêt : `corpsbinaire.go` classe donc tout multipart comme binaire et
// ne lit rien. Cette fonction pure lit les EN-TÊTES des parties, sur le préfixe
// capturé du corps, et rend des compteurs et des booléens.
//
// LIRE COMME PHP, PAS COMME GO (R13, relecture finale I1). Un détecteur qui lit
// autrement que la cible se contourne par la différence : `mime/multipart`
// restait en CRLF après une première frontière CRLF, refusait une ligne
// d'en-tête sans « : », ignorait les apostrophes et s'arrêtait à « --b-- ». Le
// balayeur ci-dessous TRANSCRIT donc main/rfc1867.c de PHP 8.2 : même tampon
// (FILLUNIT, lignes coupées à bufsize), mêmes fonctions, mêmes chaînes C
// (arrêt au premier octet nul). Chaque fonction cite celle qu'elle reproduit.
//
// Référence : https://raw.githubusercontent.com/php/php-src/PHP-8.2/main/rfc1867.c
// récupéré le 2026-10-29, sha256 266a40d6835904e10a4c091352ba5ddb7eec2c1cbde79b5c60e7178209eff847
// (numéros de ligne de ce fichier), et ext/session/session.c (même branche,
// sha256 75686555e71d19ebd4668f910f00fb35c4c7bf9e57b867555833d9f935a3d2cd)
// pour le suivi de progression.
//
// RÉGLAGES DE PHP SUPPOSÉS (valeurs par défaut) : file_uploads=On,
// max_file_uploads=20, upload_max_filesize >= la fenêtre de capture (1 Mio),
// mbstring.encoding_translation=Off (php_ap_getword, pas la variante mbstring),
// session.upload_progress.name=PHP_SESSION_UPLOAD_PROGRESS, et un suivi de
// session qui n'annule pas l'envoi. Un réglage différent ne change que la façon
// dont PHP SAUTE le corps d'un fichier (lu, ou parcouru ligne à ligne), donc
// seulement l'alignement des lignes de plus de 5120 octets.
//
// CE QUI EST VOLONTAIREMENT ÉVITÉ : toute copie du contenu d'un FICHIER ; le
// résultat ne porte que des entiers et des booléens, sauf Champs (#3273) : la
// valeur d'un champ ordinaire n'est copiée que si son nom normalisé est l'un
// des noms retenus (nomsRetenusPHP), au plus parametresRetenusMax, et elle
// n'est JAMAIS journalisée (seuls des booléens et des compteurs sortent).
// Pour un fichier lu, 64 octets au plus sont examinés (magiqueNonRaster), sur
// place, sans copie conservée. Seuls sont copiés la valeur du
// Content-Disposition (en-tête, bornée par le préfixe) et les noms
// déséchappés, le temps de les mesurer. Le préfixe n'est jamais modifié (PHP
// écrit des NUL dans SON tampon ; ici on ne fait que découper).

package main

import (
	"bytes"
	"strconv"
	"strings"
)

// StatutMultipart dit jusqu'où l'analyse a pu aller.
type StatutMultipart string

const (
	MultipartAnalyse  StatutMultipart = "analyse"  // corps complet lu, fermeture « --b-- » vue en dernier
	MultipartTronque  StatutMultipart = "tronque"  // préfixe coupé : PHP aurait lu la suite
	MultipartMalforme StatutMultipart = "malforme" // corps complet mais sans fermeture, ou arrêt de PHP
	MultipartLimite   StatutMultipart = "limite"   // plafond de parties atteint
)

// partiesMaxDefaut borne le travail par corps : 2000 parties dépassent tout
// formulaire légitime tout en gardant l'analyse en temps constant.
const partiesMaxDefaut = 2000

// nomProgressPHP est le champ qui déclenche le suivi de progression de session.
const nomProgressPHP = "PHP_SESSION_UPLOAD_PROGRESS"

const (
	// fillUnitPHP : FILLUNIT (rfc1867.c:209), taille minimale du tampon et des lectures.
	fillUnitPHP = 1024 * 5
	// frontiereMaxPHP : au-delà, « Boundary too large » et rien n'est lu (rfc1867.c:793).
	frontiereMaxPHP = fillUnitPHP - len("\r\n--")
	// maxFileUploadsPHP : max_file_uploads par défaut (upload_cnt, rfc1867.c:725).
	maxFileUploadsPHP = 20
)

// LimitesMultipart borne l'analyse. PartiesMax 0 vaut partiesMaxDefaut.
type LimitesMultipart struct{ PartiesMax int }

// ResultatMultipart ne contient que des compteurs et des booléens : ni nom, ni valeur.
type ResultatMultipart struct {
	Statut                StatutMultipart
	Parties               int  // parties AVEC Content-Disposition (body_parts_cnt de PHP)
	PartiesFichier        int  // parties que PHP traite comme fichier (un filename, même vide)
	ProfondeurMax         int  // nombre de '[' du nom le plus imbriqué
	LongueurNomMax        int  // en octets
	Progress              bool // champ ordinaire PHP_SESSION_UPLOAD_PROGRESS de valeur non vide
	FichiersApresProgress int  // parties fichier vues APRÈS ce champ
	FilenamePHP           bool // le filename retenu par PHP contient "<?php" (insensible à la casse)
	FilenameObjet         bool // le filename retenu par PHP contient "|O:"
	FilenameSession       bool // le filename retenu contient '|' ET un jeton de sérialisation PHP [abdisNO]:[0-9;] (R-RC2)
	NonRaster             bool // un fichier LU commence par un format non raster (R-IMG1, 64 octets)
	// Champs : champs ordinaires dont le nom normalisé est retenu
	// (nomsRetenusPHP), valeur copiée, au plus parametresRetenusMax. Jamais journalisés.
	Champs []ParametrePHP
}

// minusculesASCII ne touche que A-Z : la longueur en octets reste identique.
func minusculesASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// estMultipartPHP reproduit le test de SAPI.c : minuscules, coupure au premier
// `;`, `,` ou espace, comparaison à multipart/form-data.
func estMultipartPHP(contentType string) bool {
	ct := minusculesASCII(contentType)
	if i := strings.IndexAny(ct, ";, "); i >= 0 {
		ct = ct[:i]
	}
	return ct == "multipart/form-data"
}

// boundaryPHP extrait la frontière comme rfc1867_post_handler (rfc1867.c:753-789) :
// strstr « boundary » sensible à la casse, puis insensible ; strchr du « = » ;
// valeur entre guillemets jusqu'au guillemet suivant (absent : échec), sinon
// jusqu'au premier `,` ou `;` (strpbrk). Une valeur VIDE est acceptée par PHP.
// Le Content-Type est une chaîne C : il s'arrête au premier octet nul.
func boundaryPHP(contentType string) (string, bool) {
	if i := strings.IndexByte(contentType, 0); i >= 0 {
		contentType = contentType[:i]
	}
	i := strings.Index(contentType, "boundary")
	if i < 0 {
		i = strings.Index(minusculesASCII(contentType), "boundary")
	}
	if i < 0 {
		return "", false
	}
	reste := contentType[i:]
	eq := strings.IndexByte(reste, '=')
	if eq < 0 {
		return "", false
	}
	val := reste[eq+1:]
	if strings.HasPrefix(val, `"`) {
		fin := strings.IndexByte(val[1:], '"')
		if fin < 0 {
			return "", false
		}
		val = val[1 : 1+fin]
	} else if fin := strings.IndexAny(val, ",;"); fin >= 0 {
		val = val[:fin]
	}
	return val, true
}

// ── Chaînes C ────────────────────────────────────────────────────────────

// isspaceC : isspace() de la locale C.
func isspaceC(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// chaineC coupe au premier octet nul : strcmp, strchr, estrdup et
// smart_string_appends s'arrêtent là.
func chaineC(b []byte) []byte {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return b[:i]
	}
	return b
}

// egalSansCasse : strcasecmp(a, b) == 0 en ASCII.
func egalSansCasse(a []byte, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 32
		}
		if y >= 'A' && y <= 'Z' {
			y += 32
		}
		if x != y {
			return false
		}
	}
	return true
}

// ── Le tampon de PHP (multipart_buffer, rfc1867.c:211) ────────────────────
//
// Le tampon de PHP est une fenêtre glissante sur le corps : buf_begin et
// bytes_in_buffer. Ici, la fenêtre est data[pos : pos+dispo] ; aucune copie.

type tamponPHP struct {
	data      []byte // le préfixe capturé, jamais modifié
	pos       int    // buf_begin
	dispo     int    // bytes_in_buffer
	taille    int    // bufsize
	frontiere []byte // boundary = "--" + b
	suivante  []byte // boundary_next = "\n--" + b
	fermeture []byte // "--" + b + "--" (statut seulement : PHP n'en fait rien)

	// bord : un remplissage a buté sur la fin du préfixe. Avec un préfixe
	// tronqué, PHP aurait eu d'autres octets à cet endroit.
	bord bool
	// fermee : la DERNIÈRE recherche de frontière, celle qui a échoué, a vu
	// une ligne « --b-- ».
	fermee bool

	valeur []byte // buf_value de multipart_buffer_headers
	cd     []byte // Content-Disposition retenu
}

// nouveauTamponPHP : multipart_buffer_new (rfc1867.c:284) ; bufsize vaut
// boundary_len + 6, au moins FILLUNIT.
func nouveauTamponPHP(data []byte, b string) *tamponPHP {
	taille := len(b) + 6
	if taille < fillUnitPHP {
		taille = fillUnitPHP
	}
	return &tamponPHP{
		data: data, taille: taille,
		frontiere: []byte("--" + b), suivante: []byte("\n--" + b), fermeture: []byte("--" + b + "--"),
	}
}

// remplir : fill_buffer (rfc1867.c:238). Décale (implicite ici) et remplit
// jusqu'à bufsize, ou jusqu'à la fin des données. Rend le nombre d'octets ajoutés.
func (m *tamponPHP) remplir() int {
	avant := m.dispo
	reste := len(m.data) - m.pos
	m.dispo = m.taille
	if reste < m.taille {
		m.dispo = reste
		m.bord = true
	}
	return m.dispo - avant
}

// epuise : multipart_buffer_eof (rfc1867.c:278).
func (m *tamponPHP) epuise() bool {
	return m.dispo == 0 && m.remplir() < 1
}

// ligneSuivante : next_line (rfc1867.c:324). Cherche un LF dans le tampon ;
// retire CR+LF ou LF seul. Sans LF : échec si le tampon n'est pas plein, sinon
// le tampon ENTIER est rendu comme une ligne partielle de bufsize octets.
func (m *tamponPHP) ligneSuivante() ([]byte, bool) {
	fen := m.data[m.pos : m.pos+m.dispo]
	if i := bytes.IndexByte(fen, '\n'); i >= 0 {
		l := fen[:i]
		if i > 0 && fen[i-1] == '\r' {
			l = fen[:i-1]
		}
		m.pos += i + 1
		m.dispo -= i + 1
		return chaineC(l), true
	}
	if m.dispo < m.taille {
		return nil, false
	}
	// line[bufsize] = 0 ; bytes_in_buffer = 0 : le prochain fill_buffer
	// repart après ces bufsize octets.
	m.pos += m.dispo
	m.dispo = 0
	return chaineC(fen), true
}

// ligne : get_line (rfc1867.c:359) — un essai, un remplissage, un second essai.
func (m *tamponPHP) ligne() ([]byte, bool) {
	if l, ok := m.ligneSuivante(); ok {
		return l, true
	}
	m.remplir()
	return m.ligneSuivante()
}

// chercherFrontiere : find_boundary (rfc1867.c:383). Lit des lignes jusqu'à
// une ligne EXACTEMENT égale à « --b » (strcmp). « --b-- » n'y est pas égale :
// PHP continue de chercher dans l'épilogue. On note seulement, pour le statut,
// qu'une fermeture a été vue pendant la passe qui échoue (ligne, ou reste sans
// LF à la fin des données).
func (m *tamponPHP) chercherFrontiere() bool {
	m.fermee = false
	for {
		l, ok := m.ligne()
		if !ok {
			if bytes.HasPrefix(chaineC(m.data[m.pos:m.pos+m.dispo]), m.fermeture) {
				m.fermee = true
			}
			return false
		}
		if bytes.Equal(l, m.frontiere) {
			m.fermee = false
			return true
		}
		if bytes.HasPrefix(l, m.fermeture) {
			m.fermee = true
		}
	}
}

// entetes : multipart_buffer_headers (rfc1867.c:409). Cherche la frontière,
// puis lit les lignes jusqu'à une ligne vide (ou la fin des données) :
//   - une ligne qui commence par un blanc n'est jamais un nouvel en-tête ;
//   - sinon, la clé est le texte avant le premier « : », SANS rognage ;
//   - seuls Content-Disposition et Content-Type sont gardés, le premier de
//     chaque (php_mime_should_save_hdr, « ignore duplicates ») ;
//   - une ligne sans « : » (ou commençant par un blanc) se colle, sans
//     séparateur, à la valeur en cours ; sans valeur en cours, elle est ignorée.
//
// Rend la valeur du premier Content-Disposition, et ok=false si aucune
// frontière n'a été trouvée (fin du traitement chez PHP).
func (m *tamponPHP) entetes() (cd []byte, aCD bool, ok bool) {
	if !m.chercherFrontiere() {
		return nil, false, false
	}
	const (
		aucune = iota
		cleCD
		cleCT
	)
	cle, enCours, vuCT := aucune, false, false
	m.valeur, m.cd = m.valeur[:0], m.cd[:0]
	vider := func() {
		if enCours && cle != aucune {
			if cle == cleCD {
				m.cd = append(m.cd, m.valeur...)
				aCD = true
			} else {
				vuCT = true
			}
		}
		enCours, cle = false, aucune
		m.valeur = m.valeur[:0]
	}
	for {
		l, lu := m.ligne()
		if !lu || len(l) == 0 {
			break
		}
		dp := -1
		if !isspaceC(l[0]) {
			dp = bytes.IndexByte(l, ':')
		}
		switch {
		case dp >= 0:
			vider()
			nom := l[:dp]
			switch {
			case egalSansCasse(nom, "Content-Disposition") && !aCD:
				cle = cleCD
			case egalSansCasse(nom, "Content-Type") && !vuCT:
				cle = cleCT
			}
			if cle != aucune {
				// do { value++; } while (isspace(*value));
				v := l[dp+1:]
				i := 0
				for i < len(v) && isspaceC(v[i]) {
					i++
				}
				m.valeur = append(m.valeur, v[i:]...)
				enCours = true
			}
		case enCours:
			m.valeur = append(m.valeur, l...)
		}
	}
	vider()
	return m.cd, aCD, true
}

// memstrPHP : php_ap_memstr (rfc1867.c:610). Première position d'une
// correspondance complète ; avec partiel, sinon la première correspondance
// partielle qui touche la fin du tampon. Les complètes précèdent toujours les
// partielles (une partielle commence à moins de len(n) octets de la fin).
func memstrPHP(h, n []byte, partiel bool) int {
	if i := bytes.Index(h, n); i >= 0 {
		return i
	}
	if !partiel {
		return -1
	}
	debut := len(h) - len(n) + 1
	if debut < 0 {
		debut = 0
	}
	for p := debut; p < len(h); p++ {
		if h[p] == n[0] && bytes.Equal(h[p:], n[:len(h)-p]) {
			return p
		}
	}
	return -1
}

// lire : multipart_buffer_read (rfc1867.c:634). Remplit si besoin, lit au plus
// octets-1 octets et jamais au-delà d'une frontière « \n--b » (même partielle) ;
// un CR juste avant la frontière n'est pas consommé.
func (m *tamponPHP) lire(octets int) int {
	if octets > m.dispo {
		m.remplir()
	}
	fen := m.data[m.pos : m.pos+m.dispo]
	max := len(fen)
	borne := memstrPHP(fen, m.suivante, true)
	if borne >= 0 {
		max = borne
	}
	n := octets - 1
	if max < n {
		n = max
	}
	if n > 0 {
		if borne >= 0 && fen[n-1] == '\r' {
			n--
		}
		m.pos += n
		m.dispo -= n
	}
	return n
}

// lireCorps : multipart_buffer_read_body (rfc1867.c:680). Les lectures sont
// contiguës : la valeur est data[début:pos]. Rend une vue, jamais une copie.
func (m *tamponPHP) lireCorps() []byte {
	debut := m.pos
	for m.lire(fillUnitPHP) > 0 {
	}
	return m.data[debut:m.pos]
}

// ── Content-Disposition ─────────────────────────────────────────────────

// getwordPHP : php_ap_getword (rfc1867.c:506). Coupe à arret HORS de
// guillemets doubles ou simples (un antislash devant le même guillemet ne le
// ferme pas) ; saute ensuite tous les arret consécutifs.
func getwordPHP(ligne []byte, arret byte) (mot, reste []byte) {
	pos := 0
	for pos < len(ligne) && ligne[pos] != arret {
		if q := ligne[pos]; q == '"' || q == '\'' {
			pos++
			for pos < len(ligne) && ligne[pos] != q {
				if ligne[pos] == '\\' && pos+1 < len(ligne) && ligne[pos+1] == q {
					pos += 2
				} else {
					pos++
				}
			}
			if pos < len(ligne) {
				pos++
			}
		} else {
			pos++
		}
	}
	if pos >= len(ligne) {
		return ligne, ligne[len(ligne):]
	}
	mot = ligne[:pos]
	for pos < len(ligne) && ligne[pos] == arret {
		pos++
	}
	return mot, ligne[pos:]
}

// substringConfPHP : substring_conf (rfc1867.c:542). Copie jusqu'au guillemet ;
// « \\ » donne « \ », et « \" » (ou « \' ») le guillemet quand quote est posé.
func substringConfPHP(s []byte, quote byte) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s) && s[i] != quote; i++ {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '\\' || (quote != 0 && s[i+1] == quote)) {
			i++
		}
		out = append(out, s[i])
	}
	return out
}

// getwordConfPHP : php_ap_getword_conf (rfc1867.c:560). Saute les blancs ;
// valeur entre « " » ou « ' » jusqu'au même guillemet, sinon jusqu'au premier blanc.
func getwordConfPHP(s []byte) []byte {
	i := 0
	for i < len(s) && isspaceC(s[i]) {
		i++
	}
	s = s[i:]
	if len(s) == 0 {
		return s
	}
	if s[0] == '"' || s[0] == '\'' {
		return substringConfPHP(s[1:], s[0])
	}
	fin := 0
	for fin < len(s) && !isspaceC(s[fin]) {
		fin++
	}
	return substringConfPHP(s[:fin], 0)
}

// dispositionPHP lit name et filename comme rfc1867_post_handler
// (rfc1867.c:856-899) : blancs de tête sautés, paires coupées par getword(';'),
// une paire sans « = » ignorée, clé = getword('=') comparée par strcasecmp à
// « name » ou « filename » exactement (`filename*` et « name  » ne comptent
// pas), valeur par getword_conf. Le DERNIER name et le DERNIER filename gagnent.
func dispositionPHP(cd []byte) (nom []byte, aNom bool, filename []byte, aFilename bool) {
	i := 0
	for i < len(cd) && isspaceC(cd[i]) {
		i++
	}
	cd = cd[i:]
	for len(cd) > 0 {
		var paire []byte
		paire, cd = getwordPHP(cd, ';')
		j := 0
		for j < len(cd) && isspaceC(cd[j]) {
			j++
		}
		cd = cd[j:]
		if bytes.IndexByte(paire, '=') < 0 {
			continue
		}
		cle, val := getwordPHP(paire, '=')
		switch {
		case egalSansCasse(cle, "name"):
			nom, aNom = getwordConfPHP(val), true
		case egalSansCasse(cle, "filename"):
			filename, aFilename = getwordConfPHP(val), true
		}
	}
	return nom, aNom, filename, aFilename
}

// crochetsValidesPHP : « New Rule: never repair potential malicious user
// input » (rfc1867.c:1048-1072). Un nom mal crocheté fait SAUTER le fichier.
func crochetsValidesPHP(nom []byte) bool {
	c := 0
	for i := 0; i < len(nom); i++ {
		if nom[i] == '[' {
			c++
		} else if nom[i] == ']' {
			c--
			if i+1 < len(nom) && nom[i+1] != '[' {
				return false
			}
		}
		if c < 0 {
			return false
		}
	}
	return c == 0
}

// strtollPHP : strtoll(value, NULL, 10) sur une chaîne C (MAX_FILE_SIZE,
// rfc1867.c:1017) : blancs, signe, chiffres ; saturation en cas de dépassement.
func strtollPHP(v []byte) int64 {
	v = chaineC(v)
	i := 0
	for i < len(v) && isspaceC(v[i]) {
		i++
	}
	neg := false
	if i < len(v) && (v[i] == '+' || v[i] == '-') {
		neg = v[i] == '-'
		i++
	}
	const lim = int64(^uint64(0) >> 1)
	var n int64
	for ; i < len(v) && v[i] >= '0' && v[i] <= '9'; i++ {
		d := int64(v[i] - '0')
		if n > (lim-d)/10 {
			if neg {
				return -lim - 1
			}
			return lim
		}
		n = n*10 + d
	}
	if neg {
		return -n
	}
	return n
}

// ── L'analyse : la boucle de rfc1867_post_handler (rfc1867.c:830) ─────────

// analyserMultipart parcourt le préfixe exactement comme PHP parcourrait le
// corps, sans jamais conserver le contenu d'une partie. tronque dit que le
// préfixe a été coupé avant la fin du corps.
//
// Statut : « limite » au plafond de parties ; « tronque » si le préfixe est
// coupé et que l'analyse en a atteint la fin (PHP aurait lu plus loin, et ne
// s'arrête jamais à « --b-- ») ; sinon « analyse » si la dernière recherche de
// frontière a vu « --b-- », « malforme » dans tous les autres cas (corps sans
// fermeture, disposition sans name ni filename qui arrête PHP, frontière
// absente, invalide ou trop longue). Les signatures s'évaluent sur les
// compteurs quel que soit le statut.
func analyserMultipart(prefixe []byte, contentType string, tronque bool, lim LimitesMultipart) ResultatMultipart {
	r := ResultatMultipart{Statut: MultipartMalforme}
	boundary, ok := boundaryPHP(contentType)
	if !ok || len(boundary) > frontiereMaxPHP {
		return r
	}
	plafond := lim.PartiesMax
	if plafond <= 0 {
		plafond = partiesMaxDefaut
	}
	m := nouveauTamponPHP(prefixe, boundary)
	fin := func(defaut StatutMultipart) ResultatMultipart {
		r.Statut = defaut
		if tronque && m.bord {
			r.Statut = MultipartTronque
		}
		return r
	}
	mesurer := func(nom []byte) {
		if len(nom) > r.LongueurNomMax {
			r.LongueurNomMax = len(nom)
		}
		if d := bytes.Count(nom, []byte("[")); d > r.ProfondeurMax {
			r.ProfondeurMax = d
		}
	}
	uploadCnt := maxFileUploadsPHP
	var maxFileSize int64
	anonyme := 0
	// skipCollant : skip_upload de PHP, déclaré au niveau de la fonction
	// (rfc1867.c:717) et JAMAIS remis à 0. Après un premier fichier sauté,
	// tous les fichiers suivants le sont : PHP parcourt leur corps ligne à
	// ligne (R16, sondes S1 et S2 de la re-relecture).
	skipCollant := false
	for !m.epuise() {
		cd, aCD, trouve := m.entetes()
		if !trouve {
			break
		}
		if !aCD {
			// Partie sans disposition (rfc1867.c:848) : ni comptée, ni lue ; la
			// recherche de frontière suivante la parcourt ligne à ligne.
			continue
		}
		// --body_parts_cnt (rfc1867.c:852) : notre plafond tient lieu de max_multipart_body_parts.
		if r.Parties >= plafond {
			r.Statut = MultipartLimite
			return r
		}
		r.Parties++
		nom, aNom, filename, aFilename := dispositionPHP(cd)

		// Champ ordinaire (rfc1867.c:934) : sa valeur est lue jusqu'à « \n--b ».
		if !aFilename && aNom {
			mesurer(nom)
			valeur := m.lireCorps()
			// session.c:3084-3090 : nom exact et valeur non vide.
			if string(nom) == nomProgressPHP && len(valeur) > 0 {
				r.Progress = true
			}
			if egalSansCasse(nom, "MAX_FILE_SIZE") {
				maxFileSize = strtollPHP(valeur)
			}
			// Champ retenu (#3273) : nom normalisé comme PHP (php_register_variable_ex).
			if len(r.Champs) < parametresRetenusMax {
				if n, ok := nomPHP(string(nom)); ok && nomsRetenusPHP[n] {
					r.Champs = append(r.Champs, ParametrePHP{Nom: n, Valeur: string(valeur)})
				}
			}
			continue
		}

		// Partie fichier. upload_cnt épuisé : fichier sauté (rfc1867.c:1027-1036).
		saute := skipCollant
		if uploadCnt <= 0 {
			saute = true
			if uploadCnt == 0 {
				uploadCnt--
			}
		}
		// « File Upload Mime headers garbled » : PHP s'arrête (rfc1867.c:1038).
		if !aNom && !aFilename {
			return fin(MultipartMalforme)
		}
		if !aNom {
			nom = []byte(strconv.Itoa(anonyme)) // rfc1867.c:1043-1045
			anonyme++
		}
		mesurer(nom)
		if !saute && !crochetsValidesPHP(nom) {
			saute = true
		}
		skipCollant = saute
		r.PartiesFichier++
		if r.Progress {
			r.FichiersApresProgress++
		}
		r.FilenamePHP = r.FilenamePHP || strings.Contains(minusculesASCII(string(filename)), "<?php")
		r.FilenameObjet = r.FilenameObjet || bytes.Contains(filename, []byte("|O:"))
		r.FilenameSession = r.FilenameSession || filenameSessionPHP(filename)

		// Sauté (rfc1867.c:1098) ou filename vide (UPLOAD_ERROR_D, rfc1867.c:1104) :
		// corps non lu, la recherche de frontière suivante le parcourt ligne à ligne.
		if saute || len(filename) == 0 {
			continue
		}
		// Lecture du fichier (rfc1867.c:1114-1188). MAX_FILE_SIZE dépassé : la
		// boucle s'arrête après une lecture de plus, au milieu du corps.
		pos0 := m.pos
		blen := m.lire(fillUnitPHP)
		// R-IMG1 : 64 octets au plus, dans la première lecture (déjà faite par PHP).
		if !r.NonRaster && blen > 0 {
			n := blen
			if n > magiqueOctets {
				n = magiqueOctets
			}
			r.NonRaster = magiqueNonRaster(m.data[pos0:pos0+n]) != ""
		}
		uploadCnt--
		var total int64
		annule := false
		for !annule && blen > 0 {
			if maxFileSize != 0 && total+int64(blen) > maxFileSize {
				annule = true // UPLOAD_ERROR_B
			} else {
				total += int64(blen)
			}
			blen = m.lire(fillUnitPHP)
		}
	}
	if m.fermee {
		return fin(MultipartAnalyse)
	}
	return fin(MultipartMalforme)
}

// Signaux expose les mesures numériques au moteur de signatures (clés stables).
func (r ResultatMultipart) Signaux() map[string]int {
	return map[string]int{
		"parties":                 r.Parties,
		"fichiers":                r.PartiesFichier,
		"profondeur":              r.ProfondeurMax,
		"nom_max":                 r.LongueurNomMax,
		"fichiers_apres_progress": r.FichiersApresProgress,
	}
}
