// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

// LEURRE SMTP (#3924), ports 25 et 587. TOUTE réponse d'échec est un 4xx : un
// 5xx ferait rendre son message à un expéditeur légitime. Ni STARTTLS, ni
// PIPELINING, ni CHUNKING annoncés ; DATA et BDAT ne sont jamais acceptés.

const (
	smtpAccueil = "220 mail ESMTP\r\n"
	smtpSature  = "421 4.3.2 Service temporarily unavailable, try again later\r\n"
	smtpRefus   = "451 4.3.2 Service temporarily unavailable, try again later\r\n"
	smtpAuth    = "454 4.7.0 Temporary authentication failure\r\n"
	smtpTLS     = "454 4.7.0 TLS not available due to temporary reason\r\n"
	smtpOk      = "250 2.0.0 Ok\r\n"
	smtpAdieu   = "221 2.0.0 Bye\r\n"
	smtpEhlo25  = "250-mail\r\n250 ENHANCEDSTATUSCODES\r\n"
	smtpEhlo587 = "250-mail\r\n250-AUTH PLAIN LOGIN\r\n250 ENHANCEDSTATUSCODES\r\n"
)

func dialogueSMTP25(s *sessionMail)  { dialogueSMTP(s, smtpEhlo25) }
func dialogueSMTP587(s *sessionMail) { dialogueSMTP(s, smtpEhlo587) }

func dialogueSMTP(s *sessionMail, ehlo string) {
	if s.ecrit(smtpAccueil) != nil {
		return
	}
	for i := 0; i < mailCommandes; i++ {
		lig, err := s.lec.ligne()
		if err != nil {
			if err == errMailBorne {
				_ = s.ecrit(smtpSature)
			}
			return
		}
		verbe, reste := mot(lig)
		rep := ""
		switch string(verbe) {
		case "EHLO":
			rep = ehlo
		case "HELO":
			rep = "250 mail\r\n"
		case "NOOP", "RSET":
			rep = smtpOk
		case "MAIL", "RCPT", "DATA", "BDAT", "VRFY", "EXPN", "ETRN":
			rep = smtpRefus
		case "STARTTLS":
			rep = smtpTLS
		case "QUIT":
			_ = s.ecrit(smtpAdieu)
			return
		case "AUTH":
			meca, initiale := mot(reste)
			if _, err := s.sasl(meca, initiale, func(b string) error { return s.ecrit("334 " + b + "\r\n") }); err != nil {
				return
			}
			if s.essais >= mailEssaisMax {
				_ = s.ecrit(smtpAuth)
				_ = s.ecrit(smtpSature)
				return
			}
			rep = smtpAuth
		default:
			// Inconnue (HTTP, corps de BDAT, bruit) : on ferme, en temporaire.
			_ = s.ecrit(smtpSature)
			return
		}
		if s.ecrit(rep) != nil {
			return
		}
	}
	_ = s.ecrit(smtpSature)
}
