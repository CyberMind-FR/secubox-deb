// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — fonctions de lecture Roundcube (#3273, R-RC1 à R-RC3)
//
// Ces fonctions sont pures : elles reçoivent une valeur déjà décodée et rendent
// un booléen. Aucune valeur n'est conservée ni journalisée ; seul le verdict
// (et, pour R-RC1, le drapeau « ! » en tête) quitte la fonction.

package main

import (
	"bytes"
	"strings"
)

// Noms (déjà normalisés, nomsphp.go) dont R-RC3 cherche CR, LF ou NUL. Tous
// doivent figurer dans nomsRetenusPHP, sans quoi leur valeur n'est jamais lue.
var (
	// Paramètres transmis tels quels à IMAP (commits f62879d, b18a8fa, 73233ab, 242c6d6).
	nomsIMAPRoundcube = []string{"_uid", "_flag", "_q", "_filter", "_headers", "_scope", "_mbox", "_search"}
	// Paramètres lus à l'envoi (commit 79adcfc). _to, _cc, _bcc et _message en
	// sont exclus : zones de texte multi-lignes par nature (spécification § 3.2).
	nomsEnvoiRoundcube = []string{"_subject", "_from", "_replyto", "_followupto", "_charset"}
)

// fromInvalideRoundcube reproduit le correctif 1.6.11 de
// program/actions/settings/upload.php : retirer ^(add|edit)- de _from, puis
// exiger rcube_utils::is_simple_string, soit ^[\w.-]+$ (ici ASCII). Une valeur
// vide n'est pas signalée. bang : le reste commence par « ! », la primitive de
// CVE-2025-49113 et de CVE-2026-114724 (désynchronisation de la session).
// Écart connu : PCRE accepte un « \n » final avec « $ » ; ici il est signalé.
func fromInvalideRoundcube(v string) (invalide, bang bool) {
	if v == "" {
		return false, false
	}
	reste := v
	switch {
	case strings.HasPrefix(reste, "add-"):
		reste = reste[len("add-"):]
	case strings.HasPrefix(reste, "edit-"):
		reste = reste[len("edit-"):]
	}
	bang = strings.HasPrefix(reste, "!")
	if reste == "" {
		return true, bang
	}
	for i := 0; i < len(reste); i++ {
		c := reste[i]
		simple := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '_' || c == '.' || c == '-'
		if !simple {
			return true, bang
		}
	}
	return false, bang
}

// crlfDans : CR, LF ou NUL (commits f62879d et b18a8fa : « [\r\n] » rejeté).
func crlfDans(v string) bool { return strings.ContainsAny(v, "\r\n\x00") }

// drapeauInvalideRoundcube : un octet de [\x00-\x20\x7f(){"*%], les caractères
// que rcube_imap_generic::modFlag rejette depuis le commit 242c6d6.
func drapeauInvalideRoundcube(v string) bool {
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c <= 0x20, c == 0x7f:
			return true
		case c == '(', c == ')', c == '{', c == '"', c == '*', c == '%':
			return true
		}
	}
	return false
}

// filenameSessionPHP (R-RC2) : le filename contient '|' ET un jeton de
// sérialisation PHP « [abdisNO]:[0-9;] ». Un nom de fichier réel ne porte pas
// cette combinaison (Windows interdit '|'). La PoC de CVE-2025-49113 envoie
// x|b:0;preferences_time|b:0;preferences|s:179:"a:3:{... (le nom ne contient
// pas |O: : l'objet est dans _from). Parcours linéaire, sans copie.
func filenameSessionPHP(filename []byte) bool {
	if bytes.IndexByte(filename, '|') < 0 {
		return false
	}
	for i := 0; i+2 < len(filename); i++ {
		if filename[i+1] != ':' {
			continue
		}
		if c := filename[i]; c == 'a' || c == 'b' || c == 'd' || c == 'i' || c == 's' || c == 'N' || c == 'O' {
			if d := filename[i+2]; d == ';' || d >= '0' && d <= '9' {
				return true
			}
		}
	}
	return false
}
