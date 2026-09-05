// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbx-authwatch — motifs d'echec d'authentification (#1220)
//
// CE QUE CE FICHIER RECONNAIT. Des lignes de journal, telles qu'elles sont
// reellement ecrites sur la box — pas telles qu'on les imagine. Chaque motif
// ci-dessous a ete etabli sur des lignes prelevees dans le journal de gk2, et
// le fichier de tests en conserve un exemplaire verbatim. Un motif qui ne
// correspond a rien de reel est pire qu'absent : il donne l'illusion d'une
// couverture.
//
// POURQUOI CE N'EST PAS DU HTTP. sbxwaf est place derriere HAProxy : il ne voit
// que ce qui parle HTTP. La force brute SSH, les echecs SASL de postfix, les
// tentatives IMAP de dovecot lui sont invisibles. C'est precisement la surface
// que l'ancien relais de ban externe couvrait et qu'on a perdue en le retirant (#1218). Ici on la
// reprend, en alimentant LE MEME ensemble nft et LE MEME journal de menaces —
// pour que la correlation, les pays et le rapport PDF retrouvent ces sources
// sans qu'aucun de ces trois consommateurs ait a changer.
package main

import (
	"net"
	"regexp"
	"strings"
)

// Signal decrit un echec d'authentification reconnu dans une ligne de journal.
type Signal struct {
	IP        string // adresse du client fautif
	Service   string // "ssh" | "smtp" | "imap"
	Categorie string // categorie portee au journal de menaces
	Severite  string // "high" | "medium"
	Detail    string // ce qui a ete reconnu, pour l'audit
	Cible     string // compte vise, quand la ligne le porte (#1220)
}

type motif struct {
	service   string
	categorie string
	severite  string
	detail    string
	re        *regexp.Regexp
}

func reI(s string) *regexp.Regexp { return regexp.MustCompile("(?i)" + s) }

// motifs — chacun DOIT capturer l'adresse dans un groupe nomme `ip`.
//
// Les severites ne sont pas decoratives : elles decident du poids. Un « invalid
// user » est un balayage de comptes, jamais une faute de frappe d'un utilisateur
// legitime — d'ou `high`. Un mot de passe refuse sur un compte EXISTANT peut
// etre un humain qui se trompe : `medium`, et c'est la repetition qui tranche.
var motifs = []motif{
	// ── SSH ───────────────────────────────────────────────────────────────
	{"ssh", "auth_ssh:invalid_user", "high", "compte inexistant",
		reI(`invalid user\s+\S+\s+from\s+(?P<ip>[0-9a-f.:]+)`)},
	{"ssh", "auth_ssh:failed_password", "medium", "mot de passe refuse",
		reI(`failed password for(?:\s+invalid user)?\s+\S+\s+from\s+(?P<ip>[0-9a-f.:]+)`)},
	{"ssh", "auth_ssh:max_attempts", "high", "trop de tentatives dans une session",
		reI(`maximum authentication attempts exceeded for\s+\S+\s+from\s+(?P<ip>[0-9a-f.:]+)`)},
	{"ssh", "auth_ssh:preauth_abort", "medium", "rupture avant authentification",
		reI(`connection (?:closed|reset) by(?: authenticating user \S+)?\s+(?P<ip>[0-9a-f.:]+).*\[preauth\]`)},
	{"ssh", "auth_ssh:bad_protocol", "high", "protocole invalide",
		reI(`bad protocol version identification.*from\s+(?P<ip>[0-9a-f.:]+)`)},

	// ── SMTP (postfix) ────────────────────────────────────────────────────
	// Ligne reelle relevee sur gk2 :
	//   postfix/submission/smtpd[…]: warning: unknown[85.19.195.12]:
	//   SASL LOGIN authentication failed: (reason unavailable), sasl_username=…
	{"smtp", "auth_smtp:sasl_failed", "high", "authentification SASL refusee",
		reI(`\[(?P<ip>[0-9a-f.:]+)\]:\s*SASL\s+\S+\s+authentication failed`)},
	{"smtp", "auth_smtp:auth_command", "high", "commande AUTH sans TLS ou refusee",
		reI(`warning:\s+\S*\[(?P<ip>[0-9a-f.:]+)\]:\s*(?:non-SMTP command|improper command pipelining)`)},

	// ── IMAP / POP3 (dovecot) ─────────────────────────────────────────────
	// Ligne reelle relevee sur gk2 :
	//   dovecot[…]: imap-login: Disconnected: Connection closed
	//   (auth failed, 2 attempts in 8 secs): user=<gk2>, method=PLAIN, rip=…
	{"imap", "auth_imap:failed", "high", "authentification IMAP/POP3 refusee",
		reI(`auth failed,\s*\d+\s+attempts.*?rip=(?P<ip>[0-9a-f.:]+)`)},
	{"imap", "auth_imap:no_auth", "medium", "connexion abandonnee sans tentative",
		reI(`aborted login by logging out \(no auth attempts.*?rip=(?P<ip>[0-9a-f.:]+)`)},
}

// Reconnaitre rend le signal porte par une ligne, s'il y en a un.
//
// Le PREMIER motif qui correspond gagne : l'ordre ci-dessus place les signaux
// les plus specifiques avant les plus larges, pour qu'un « invalid user » ne
// soit pas classe en simple « failed password ».
func Reconnaitre(ligne string) (Signal, bool) {
	if strings.TrimSpace(ligne) == "" {
		return Signal{}, false
	}
	for _, m := range motifs {
		sm := m.re.FindStringSubmatch(ligne)
		if sm == nil {
			continue
		}
		idx := m.re.SubexpIndex("ip")
		if idx < 0 || idx >= len(sm) {
			continue
		}
		ip := strings.Trim(sm[idx], "[]")
		// Une capture qui n'est pas une adresse n'est pas un signal : mieux
		// vaut manquer une ligne que bannir une chaine quelconque.
		if net.ParseIP(ip) == nil {
			continue
		}
		return Signal{
			IP:        ip,
			Service:   m.service,
			Categorie: m.categorie,
			Severite:  m.severite,
			Detail:    m.detail,
			Cible:     cible(ligne),
		}, true
	}
	return Signal{}, false
}

// motifsCible extraient le COMPTE VISE. C'est le pivot qui manquait : sur gk2,
// 339 des 388 adresses d'une campagne SASL n'apparaissent qu'UNE FOIS en sept
// jours — un compteur par adresse ne verrait jamais rien. Le compte, lui, est
// stable : « gerald@gk2.net » a ete tente 39 fois depuis autant de sources.
// C'est la correlation que l'ancien relais externe apportait et qu'on reconstitue ici.
var motifsCible = []*regexp.Regexp{
	reI(`sasl_username=([^\s,]+)`), // postfix
	reI(`user=<([^>]*)>`),          // dovecot
	reI(`(?:invalid user|password for(?: invalid user)?)\s+(\S+)\s+from`), // sshd
}

func cible(ligne string) string {
	for _, re := range motifsCible {
		if sm := re.FindStringSubmatch(ligne); sm != nil && strings.TrimSpace(sm[1]) != "" {
			return strings.ToLower(strings.TrimSpace(sm[1]))
		}
	}
	return ""
}

// Poids convertit une severite en increment de compteur. Un signal fort compte
// double : trois « invalid user » suffisent la ou il faut six mots de passe
// refuses. La progressivite est conservee, la patience est proportionnee au
// doute qu'on a sur l'intention.
func Poids(sev string) int {
	if sev == "high" {
		return 2
	}
	return 1
}

// estAdresse dit si une capture est une adresse exploitable. Partage avec les
// filtres declares : mieux vaut manquer une ligne que bannir une chaine
// quelconque capturee par un motif approximatif.
func estAdresse(ip string) bool {
	return net.ParseIP(strings.Trim(ip, "[]")) != nil
}
