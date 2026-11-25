// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package reseau

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Classes de réseau reconnues (#3919).
const (
	ClasseAcces            = "acces"
	ClasseCDN              = "cdn"
	ClasseHebergeur        = "hebergeur"
	ClasseProxyLoue        = "proxy_loue"
	ClasseScannerRecherche = "scanner_recherche"
	ClasseMobilePartage    = "mobile_partage"
	ClasseRelaisViePrivee  = "relais_vie_privee"
	ClasseInconnu          = "inconnu"
)

// classesCatalogue : classes qu'un catalogue peut porter (« inconnu » est le
// défaut implicite, jamais une affectation).
var classesCatalogue = map[string]bool{
	ClasseAcces: true, ClasseCDN: true, ClasseHebergeur: true,
	ClasseProxyLoue: true, ClasseScannerRecherche: true,
	ClasseMobilePartage: true, ClasseRelaisViePrivee: true,
}

// LireCatalogue lit le sous-ensemble TOML restreint du catalogue :
//
//	[classes]
//	nom_de_classe = [123, 456]   (tableau possiblement sur plusieurs lignes)
//
// Commentaires `#` et lignes vides acceptés. Pas de bibliothèque TOML : le
// format est volontairement minuscule et relu aussi par tomllib côté Python.
// Une classe inconnue ou un ASN non numérique est une erreur, jamais ignorée :
// un catalogue silencieusement tronqué fausserait toutes les classifications.
func LireCatalogue(r io.Reader) (map[uint32]string, error) {
	res := map[uint32]string{}
	sc := bufio.NewScanner(r)
	n := 0
	dansClasses := false
	classe := ""    // classe dont le tableau est en cours
	ouvert := false // tableau ouvert, pas encore fermé
	for sc.Scan() {
		n++
		ligne := sc.Text()
		if i := strings.Index(ligne, "#"); i >= 0 {
			ligne = ligne[:i]
		}
		ligne = strings.TrimSpace(ligne)
		if ligne == "" {
			continue
		}
		if !ouvert {
			if strings.HasPrefix(ligne, "[") {
				dansClasses = ligne == "[classes]"
				continue
			}
			if !dansClasses {
				continue
			}
			cle, val, ok := strings.Cut(ligne, "=")
			if !ok {
				return nil, fmt.Errorf("ligne %d : « clé = [..] » attendu", n)
			}
			classe = strings.TrimSpace(cle)
			if !classesCatalogue[classe] {
				return nil, fmt.Errorf("ligne %d : classe inconnue %q", n, classe)
			}
			val = strings.TrimSpace(val)
			if !strings.HasPrefix(val, "[") {
				return nil, fmt.Errorf("ligne %d : tableau attendu", n)
			}
			ligne = val[1:]
			ouvert = true
		}
		fin := false
		if i := strings.Index(ligne, "]"); i >= 0 {
			ligne = ligne[:i]
			fin = true
		}
		for _, jeton := range strings.Split(ligne, ",") {
			jeton = strings.TrimSpace(jeton)
			if jeton == "" {
				continue
			}
			asn, err := strconv.ParseUint(jeton, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("ligne %d : ASN invalide %q", n, jeton)
			}
			res[uint32(asn)] = classe
		}
		if fin {
			ouvert = false
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if ouvert {
		return nil, fmt.Errorf("tableau %q non fermé", classe)
	}
	return res, nil
}

// lireFichierCatalogue ouvre et lit un catalogue.
func lireFichierCatalogue(chemin string) (map[uint32]string, error) {
	f, err := os.Open(chemin)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return LireCatalogue(f)
}
