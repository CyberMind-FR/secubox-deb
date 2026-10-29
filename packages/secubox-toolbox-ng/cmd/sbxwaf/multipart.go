// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — analyseur multipart à la manière de PHP (#3257)
//
// LE PROBLÈME. Les envois PHP2Shell (CVE-2026-109618/109619) tiennent dans la
// STRUCTURE du multipart : un champ PHP_SESSION_UPLOAD_PROGRESS suivi de
// centaines de parties fichier aux noms imbriqués (`files[R00001][a][a]…`), ou
// un filename qui transporte « <?php » ou « |O: ». Le contenu des parties n'a
// aucun intérêt : `corpsbinaire.go` classe donc tout multipart comme binaire et
// ne lit rien. Cette fonction pure lit seulement les EN-TÊTES des parties, sur
// le préfixe déjà tamponné du corps, et rend des compteurs et des booléens.
//
// CE QUI EST VOLONTAIREMENT ÉVITÉ.
//
//   - `ReadForm` : il matérialise les parties (mémoire, fichiers temporaires) ;
//   - `Part.FileName()` : il applique `filepath.Base`, qui MASQUE le « <?php » ou
//     le « |O: » placé avant un séparateur de chemin ; on lit donc l'en-tête brut ;
//   - tout stockage du contenu, d'un nom de champ ou d'un nom de fichier : le
//     résultat ne porte que des entiers et des booléens (jamais journalisés en clair).
//
// LA LECTURE DE PHP (main/SAPI.c, main/rfc1867.c) est laxiste : type de contenu
// coupé au premier `;`, `,` ou espace, paramètres sans guillemets acceptés,
// `filename` même vide = partie fichier. Un détecteur plus strict que PHP se
// laisserait contourner par exactement ces tolérances ; on les reproduit.

package main

import (
	"bytes"
	"io"
	"mime/multipart"
	"strings"
)

// StatutMultipart dit jusqu'où l'analyse a pu aller.
type StatutMultipart string

const (
	MultipartAnalyse  StatutMultipart = "analyse"  // corps lu jusqu'à la fermeture
	MultipartTronque  StatutMultipart = "tronque"  // préfixe coupé : comptes partiels
	MultipartMalforme StatutMultipart = "malforme" // structure invalide sans troncature
	MultipartLimite   StatutMultipart = "limite"   // plafond de parties atteint
)

// partiesMaxDefaut borne le travail par corps : 2000 parties dépassent tout
// formulaire légitime tout en gardant l'analyse en temps constant.
const partiesMaxDefaut = 2000

// nomProgressPHP est le champ qui déclenche le suivi de progression de session.
const nomProgressPHP = "PHP_SESSION_UPLOAD_PROGRESS"

// LimitesMultipart borne l'analyse. PartiesMax 0 vaut partiesMaxDefaut.
type LimitesMultipart struct{ PartiesMax int }

// ResultatMultipart ne contient que des compteurs et des booléens : ni nom, ni valeur.
type ResultatMultipart struct {
	Statut                StatutMultipart
	Parties               int
	PartiesFichier        int
	ProfondeurMax         int  // nombre de '[' du nom le plus imbriqué
	LongueurNomMax        int  // en octets
	Progress              bool // un champ nommé exactement PHP_SESSION_UPLOAD_PROGRESS
	FichiersApresProgress int  // parties fichier vues APRÈS ce champ
	FilenamePHP           bool // un filename contient "<?php" (insensible à la casse)
	FilenameObjet         bool // un filename contient "|O:"
}

// minusculesASCII ne touche que A-Z : la longueur en octets reste identique,
// ce qui permet de réutiliser une position trouvée dans la copie en minuscules.
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

// boundaryPHP extrait la frontière comme PHP : « boundary » sensible à la casse
// d'abord, insensible seulement si rien n'est trouvé, puis le « = » suivant.
// Valeur entre guillemets jusqu'au guillemet suivant (absent : échec), sinon
// jusqu'au premier `,` ou `;`. Valeur vide : échec.
func boundaryPHP(contentType string) (string, bool) {
	i := strings.Index(contentType, "boundary")
	if i < 0 {
		i = strings.Index(minusculesASCII(contentType), "boundary")
	}
	if i < 0 {
		return "", false
	}
	reste := contentType[i+len("boundary"):]
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
	if val == "" {
		return "", false
	}
	return val, true
}

// dispositionLaxiste lit name et filename d'un Content-Disposition. Le
// découpage se fait sur `;` hors guillemets (un `;` entre guillemets reste dans
// la valeur : sinon « filename="a;<?php" » échapperait à la détection).
// `filename*` compte comme `filename`. aFilename vaut vrai même pour une valeur vide.
func dispositionLaxiste(disp string) (nom string, filename string, aFilename bool) {
	for _, morceau := range decouperHorsGuillemets(disp) {
		eq := strings.IndexByte(morceau, '=')
		if eq < 0 {
			continue
		}
		cle := minusculesASCII(strings.TrimSpace(morceau[:eq]))
		cle = strings.TrimSuffix(cle, "*")
		if cle != "name" && cle != "filename" {
			continue
		}
		val := valeurDisposition(strings.TrimSpace(morceau[eq+1:]))
		if cle == "name" {
			nom = val
		} else {
			filename, aFilename = val, true
		}
	}
	return nom, filename, aFilename
}

// decouperHorsGuillemets coupe sur `;` sans tenir compte de ceux qui sont
// entre guillemets (un antislash y échappe le caractère suivant).
func decouperHorsGuillemets(s string) []string {
	var out []string
	debut, guill := 0, false
	for i := 0; i < len(s); i++ {
		switch {
		case guill && s[i] == '\\':
			i++
		case s[i] == '"':
			guill = !guill
		case s[i] == ';' && !guill:
			out = append(out, s[debut:i])
			debut = i + 1
		}
	}
	return append(out, s[debut:])
}

// valeurDisposition retire les guillemets et déséchappe \" et \\ ; une valeur
// sans guillemets est prise telle quelle.
func valeurDisposition(v string) string {
	if !strings.HasPrefix(v, `"`) {
		return v
	}
	var b strings.Builder
	for i := 1; i < len(v); i++ {
		c := v[i]
		if c == '\\' && i+1 < len(v) && (v[i+1] == '"' || v[i+1] == '\\') {
			i++
			b.WriteByte(v[i])
			continue
		}
		if c == '"' {
			break
		}
		b.WriteByte(c)
	}
	return b.String()
}

// analyserMultipart parcourt les en-têtes des parties du préfixe, sans jamais
// lire ni conserver leur contenu. tronque dit que le préfixe a été coupé avant
// la fin du corps : une erreur de lecture est alors attendue, pas suspecte.
func analyserMultipart(prefixe []byte, contentType string, tronque bool, lim LimitesMultipart) ResultatMultipart {
	r := ResultatMultipart{Statut: MultipartMalforme}
	boundary, ok := boundaryPHP(contentType)
	if !ok {
		return r
	}
	max := lim.PartiesMax
	if max <= 0 {
		max = partiesMaxDefaut
	}
	lecteur := multipart.NewReader(bytes.NewReader(prefixe), boundary)
	for {
		p, err := lecteur.NextRawPart()
		if err != nil {
			// Go rend un io.EOF nu aussi bien à la fermeture du corps qu'à une
			// coupure en plein en-tête : seule la frontière finale vue prouve
			// que le corps est complet.
			switch {
			case err == io.EOF && frontiereFinaleVue(prefixe, boundary):
				r.Statut = MultipartAnalyse
			case tronque:
				r.Statut = MultipartTronque
			}
			return r
		}
		if r.Parties >= max {
			r.Statut = MultipartLimite
			return r
		}
		r.Parties++
		nom, filename, fichier := dispositionLaxiste(p.Header.Get("Content-Disposition"))
		if n := len(nom); n > r.LongueurNomMax {
			r.LongueurNomMax = n
		}
		if d := strings.Count(nom, "["); d > r.ProfondeurMax {
			r.ProfondeurMax = d
		}
		if fichier {
			r.PartiesFichier++
			if r.Progress {
				r.FichiersApresProgress++
			}
			if strings.Contains(minusculesASCII(filename), "<?php") {
				r.FilenamePHP = true
			}
			if strings.Contains(filename, "|O:") {
				r.FilenameObjet = true
			}
		}
		if nom == nomProgressPHP {
			r.Progress = true
		}
	}
}

// frontiereFinaleVue cherche « --boundary-- » en début de ligne.
func frontiereFinaleVue(prefixe []byte, boundary string) bool {
	fin := []byte("--" + boundary + "--")
	return bytes.HasPrefix(prefixe, fin) || bytes.Contains(prefixe, append([]byte("\n"), fin...))
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
