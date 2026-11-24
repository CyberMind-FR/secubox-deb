// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

// LEURRES IMAP (143) ET POP3 (110), EN CLAIR, PERMANENTS (#3924).
// Réponses d'échec temporaires : [UNAVAILABLE] (RFC 5530), [SYS/TEMP] (RFC 3206).

import (
	"bytes"
	"strconv"
)

const (
	imapAccueil  = "* OK [CAPABILITY IMAP4rev1 SASL-IR AUTH=PLAIN AUTH=LOGIN] IMAP4 ready\r\n"
	imapCapacite = "* CAPABILITY IMAP4rev1 SASL-IR AUTH=PLAIN AUTH=LOGIN\r\n"
	imapSature   = "* BYE [UNAVAILABLE] Service temporarily unavailable\r\n"
	imapRefus    = " NO [UNAVAILABLE] Temporary authentication failure\r\n"
	imapIndispo  = " NO [UNAVAILABLE] Service temporarily unavailable\r\n"
	imapBad      = " BAD Command not valid here\r\n"

	pop3Accueil  = "+OK POP3 ready\r\n"
	pop3Sature   = "-ERR [SYS/TEMP] Service temporarily unavailable\r\n"
	pop3Refus    = "-ERR [SYS/TEMP] Temporary authentication failure\r\n"
	pop3Capacite = "+OK\r\nUSER\r\nSASL PLAIN LOGIN\r\nRESP-CODES\r\n.\r\n"
)

// etiquette valide une étiquette IMAP : seul octet du client qu'on recopie.
func etiquette(b []byte) string {
	if len(b) == 0 || len(b) > 32 {
		return ""
	}
	for _, c := range b {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '.' || c == '_' || c == '-') {
			return ""
		}
	}
	return string(b)
}

func dialogueIMAP(s *sessionMail) {
	if s.ecrit(imapAccueil) != nil {
		return
	}
	for i := 0; i < mailCommandes; i++ {
		lig, err := s.lec.ligne()
		if err != nil {
			if err == errMailBorne {
				_ = s.ecrit(imapSature)
			}
			return
		}
		e, reste, _ := bytes.Cut(lig, []byte{' '})
		tag := etiquette(e)
		if tag == "" {
			_ = s.ecrit(imapSature)
			return
		}
		verbe, args := mot(reste)
		rep := ""
		switch string(verbe) {
		case "CAPABILITY":
			rep = imapCapacite + tag + " OK done\r\n"
		case "NOOP":
			rep = tag + " OK done\r\n"
		case "ID":
			rep = "* ID NIL\r\n" + tag + " OK done\r\n"
		case "LOGOUT":
			_ = s.ecrit("* BYE\r\n" + tag + " OK done\r\n")
			return
		case "LOGIN":
			complet, err := s.loginIMAP(args)
			if err != nil {
				_ = s.ecrit(imapSature)
				return
			}
			rep = tag + imapBad
			if complet {
				rep = tag + imapRefus
			}
		case "AUTHENTICATE":
			meca, initiale := mot(args)
			if _, err := s.sasl(meca, initiale, func(b string) error { return s.ecrit("+ " + b + "\r\n") }); err != nil {
				return
			}
			rep = tag + imapRefus
		case "STARTTLS":
			rep = tag + imapIndispo
		default:
			// L'étiquette n'est recopiée que devant un verbe connu : une ligne
			// de secret envoyée hors tour ne doit jamais revenir à l'émetteur.
			_ = s.ecrit(imapSature)
			return
		}
		if s.ecrit(rep) != nil {
			return
		}
		if s.essais >= mailEssaisMax {
			break
		}
	}
	_ = s.ecrit(imapSature)
}

// loginIMAP lit « LOGIN compte secret » (atome, chaîne entre guillemets ou
// littéral). Le compte est copié, le secret sauté.
func (s *sessionMail) loginIMAP(args []byte) (complet bool, err error) {
	brut, reste, err := s.chaineIMAP(args)
	if err != nil || brut == nil {
		return false, err
	}
	compte := compteDe(brut)
	// Le littéral lu par chaineIMAP est dans le tampon : la suite de la ligne
	// n'est demandée qu'APRÈS avoir copié le compte.
	if reste == nil {
		if reste, err = s.lec.ligne(); err != nil {
			return false, err
		}
	}
	secret, suite, err := s.chaineIMAP(bytes.TrimLeft(reste, " "))
	if err != nil || secret == nil {
		return false, err
	}
	zero(secret)
	if suite == nil {
		if _, err := s.lec.ligne(); err != nil {
			return false, err
		}
	}
	s.note(compte)
	return true, nil
}

// chaineIMAP rend une chaîne et le reste de la ligne ; `reste` nil après un
// littéral (la ligne continue sur le réseau). Chaîne nil : ligne mal formée.
func (s *sessionMail) chaineIMAP(b []byte) (val, reste []byte, err error) {
	if len(b) == 0 {
		return nil, nil, nil
	}
	switch b[0] {
	case '"':
		n := 1 // les échappements sont défaits sur place
		for i := 1; i < len(b); i++ {
			switch {
			case b[i] == '\\' && i+1 < len(b):
				i++
				b[n] = b[i]
				n++
			case b[i] == '"':
				return b[1:n], b[i+1:], nil
			default:
				b[n] = b[i]
				n++
			}
		}
		return nil, nil, nil
	case '{':
		if b[len(b)-1] != '}' {
			return nil, nil, nil
		}
		chiffres := b[1 : len(b)-1]
		synchro := true
		if k := len(chiffres); k > 0 && chiffres[k-1] == '+' {
			chiffres, synchro = chiffres[:k-1], false
		}
		if len(chiffres) > 4 {
			return nil, nil, errMailBorne
		}
		n, err := strconv.Atoi(string(chiffres))
		if err != nil || n < 0 || n > mailLitteral {
			return nil, nil, errMailBorne
		}
		if synchro {
			if err := s.ecrit("+ OK\r\n"); err != nil {
				return nil, nil, err
			}
		}
		lu, err := s.lec.octets(n)
		if err != nil {
			return nil, nil, err
		}
		return lu[:len(lu):len(lu)], nil, nil
	}
	i := bytes.IndexByte(b, ' ')
	if i < 0 {
		return b, b[len(b):], nil
	}
	return b[:i], b[i+1:], nil
}

func dialoguePOP3(s *sessionMail) {
	if s.ecrit(pop3Accueil) != nil {
		return
	}
	compte := ""
	for i := 0; i < mailCommandes; i++ {
		lig, err := s.lec.ligne()
		if err != nil {
			if err == errMailBorne {
				_ = s.ecrit(pop3Sature)
			}
			return
		}
		verbe, args := mot(lig)
		rep := pop3Sature
		switch string(verbe) {
		case "CAPA":
			rep = pop3Capacite
		case "NOOP":
			rep = "+OK\r\n"
		case "USER":
			compte, rep = compteDe(args), "+OK\r\n"
		case "PASS":
			zero(args)
			s.note(compte)
			compte, rep = "", pop3Refus
		case "APOP":
			nom, _, _ := bytes.Cut(args, []byte{' '})
			s.note(compteDe(nom))
			rep = pop3Refus
		case "AUTH":
			if len(args) == 0 {
				rep = "+OK\r\nPLAIN\r\nLOGIN\r\n.\r\n"
				break
			}
			meca, initiale := mot(args)
			if _, err := s.sasl(meca, initiale, func(b string) error { return s.ecrit("+ " + b + "\r\n") }); err != nil {
				return
			}
			rep = pop3Refus
		case "QUIT":
			_ = s.ecrit("+OK\r\n")
			return
		case "STLS":
		default:
			_ = s.ecrit(pop3Sature)
			return
		}
		if s.ecrit(rep) != nil {
			return
		}
		if s.essais >= mailEssaisMax {
			return
		}
	}
}
