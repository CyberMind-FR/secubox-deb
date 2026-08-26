// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import "testing"

// Les lignes ci-dessous sont PRELEVEES VERBATIM sur gk2. C'est la seule
// garantie qui vaille : un motif valide contre une ligne inventee ne prouve
// rien sur le journal reel.
func TestReconnaitreLignesReelles(t *testing.T) {
	cas := []struct {
		nom       string
		ligne     string
		ip        string
		categorie string
	}{
		{
			"postfix smtps, releve le 25 aout",
			"postfix/smtps/smtpd[8189]: warning: unknown[178.178.222.60]: SASL LOGIN authentication failed: (reason unavailable), sasl_username=business",
			"178.178.222.60", "auth_smtp:sasl_failed",
		},
		{
			"postfix submission, releve le 26 aout",
			"postfix/submission/smtpd[9784]: warning: unknown[122.187.229.218]: SASL LOGIN authentication failed: (reason unavailable), sasl_username=gk",
			"122.187.229.218", "auth_smtp:sasl_failed",
		},
		{
			"dovecot imap-login, releve le 24 aout",
			"dovecot[37002]: imap-login: Disconnected: Connection closed (auth failed, 2 attempts in 8 secs): user=<gk2>, method=PLAIN, rip=91.204.14.9, lip=10.100.0.1",
			"91.204.14.9", "auth_imap:failed",
		},
		{
			"dovecot pop3-login abandonne",
			"dovecot[160]: pop3-login: Disconnected: Aborted login by logging out (no auth attempts in 0 secs): user=<>, rip=203.0.113.44, lip=10.100.0.1",
			"203.0.113.44", "auth_imap:no_auth",
		},
		{
			"sshd compte inexistant",
			"sshd[1234]: Invalid user admin from 45.83.64.1 port 51234",
			"45.83.64.1", "auth_ssh:invalid_user",
		},
		{
			"sshd mot de passe refuse",
			"sshd[1234]: Failed password for root from 45.83.64.2 port 51234 ssh2",
			"45.83.64.2", "auth_ssh:failed_password",
		},
		{
			"sshd trop de tentatives",
			"sshd[1234]: error: maximum authentication attempts exceeded for root from 45.83.64.3 port 51234 ssh2 [preauth]",
			"45.83.64.3", "auth_ssh:max_attempts",
		},
	}
	for _, c := range cas {
		sig, ok := Reconnaitre(c.ligne)
		if !ok {
			t.Errorf("%s : ligne non reconnue", c.nom)
			continue
		}
		if sig.IP != c.ip {
			t.Errorf("%s : adresse %q, attendu %q", c.nom, sig.IP, c.ip)
		}
		if sig.Categorie != c.categorie {
			t.Errorf("%s : categorie %q, attendu %q", c.nom, sig.Categorie, c.categorie)
		}
	}
}

// Un « invalid user » ne doit pas etre classe en simple mot de passe refuse :
// l'ordre des motifs porte une information de gravite.
func TestInvalidUserPrimeSurFailedPassword(t *testing.T) {
	sig, ok := Reconnaitre("sshd[1]: Failed password for invalid user oracle from 1.2.3.4 port 22 ssh2")
	if !ok {
		t.Fatal("ligne non reconnue")
	}
	if sig.Severite != "high" {
		t.Errorf("un compte inexistant doit peser high, obtenu %q (%s)", sig.Severite, sig.Categorie)
	}
}

func TestLignesSansSignal(t *testing.T) {
	for _, l := range []string{
		"",
		"sshd[1]: Accepted publickey for gandalf from 192.168.1.10 port 51234 ssh2",
		"postfix/smtpd[1]: connect from mail.example.com[203.0.113.9]",
		"dovecot: imap(gk2): Logged out in=123 out=456",
		"CRON[999]: (root) CMD (/usr/sbin/logrotate)",
	} {
		if sig, ok := Reconnaitre(l); ok {
			t.Errorf("faux positif sur %q -> %+v", l, sig)
		}
	}
}

// Une capture qui n'est pas une adresse ne doit jamais devenir un bannissement.
func TestCaptureNonAdresseIgnoree(t *testing.T) {
	if _, ok := Reconnaitre("sshd[1]: Invalid user test from notanip port 22"); ok {
		t.Error("une capture non-IP ne doit pas produire de signal")
	}
}

func TestPoidsProportionneALaGravite(t *testing.T) {
	if Poids("high") <= Poids("medium") {
		t.Error("un signal fort doit peser plus qu'un signal faible")
	}
}
