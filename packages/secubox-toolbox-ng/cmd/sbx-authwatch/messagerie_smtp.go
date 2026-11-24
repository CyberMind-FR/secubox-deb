// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

// LEURRES SMTP (#3924), ports 25 et 587.
//
// PORT 25 : 421 DÈS LA BANNIÈRE, SANS CAPTURE. Un échec temporaire APRÈS l'EHLO
// ne suffit pas à protéger un message : c'est l'EXPÉDITEUR qui, sur la seule
// liste des extensions annoncées, peut conclure à un échec définitif —
// SMTPUTF8 absent (RFC 6531), BINARYMIME/CHUNKING absents (RFC 3030),
// DELIVERBY en mode « return » (RFC 2852), REQUIRETLS, qui ne s'annonce que
// DANS une session TLS que nous refusons (RFC 8689). Tout annoncer
// n'est donc pas possible, et le comportement de Gmail ou de Microsoft ne se
// vérifie pas. Le 421 à l'ouverture précède toute négociation (RFC 5321 § 3.8
// et § 4.2.1 : « service not available », transitoire) : l'expéditeur, TLS
// obligatoire (MTA-STS, DANE) compris, essaie un autre MX ou remet en file,
// exactement comme devant un port fermé. La sûreté du courrier passe avant la
// capture.
//
// PORT 587 : soumission, pas de relais entre serveurs. STARTTLS est annoncé puis
// refusé (454, RFC 3207) et AUTH N'EST PAS ANNONCÉ : un client bien réglé
// s'arrête avant d'envoyer son mot de passe en clair. AUTH envoyé quand même
// est lu (compte seul). Jamais un 5xx, jamais un 354.

const (
	smtpSature  = "421 4.3.2 Service temporarily unavailable, try again later\r\n"
	smtpAccueil = "220 mail ESMTP\r\n"
	smtpRefus   = "451 4.3.2 Service temporarily unavailable, try again later\r\n"
	smtpAuth    = "454 4.7.0 Temporary authentication failure\r\n"
	smtpTLS     = "454 4.7.0 TLS not available due to temporary reason\r\n"
	smtpOk      = "250 2.0.0 Ok\r\n"
	smtpAdieu   = "221 2.0.0 Bye\r\n"
	smtpEhlo    = "250-mail\r\n250-PIPELINING\r\n250-SIZE\r\n250-STARTTLS\r\n250-8BITMIME\r\n250-DSN\r\n250-SMTPUTF8\r\n250 ENHANCEDSTATUSCODES\r\n"
)

// dialogueSMTP25 : la bannière est la réponse. Rien n'est lu.
func dialogueSMTP25(s *sessionMail) { _ = s.ecrit(smtpSature) }

func dialogueSMTP587(s *sessionMail) {
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
			rep = smtpEhlo
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
			if err := s.sasl(meca, initiale, func(b string) error { return s.ecrit("334 " + b + "\r\n") }); err != nil {
				return
			}
			if s.essais >= mailEssaisMax {
				_ = s.ecrit(smtpAuth)
				_ = s.ecrit(smtpSature)
				return
			}
			rep = smtpAuth
		default:
			// Inconnue (HTTP, secret hors tour, bruit) : on ferme, en temporaire.
			_ = s.ecrit(smtpSature)
			return
		}
		if s.ecrit(rep) != nil {
			return
		}
	}
	_ = s.ecrit(smtpSature)
}
