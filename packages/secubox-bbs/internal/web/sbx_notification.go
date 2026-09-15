// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: BBS — NOTIFIER UNE RÉPONSE (#1361).
//
// TROIS CHOSES SÉPARÉES, ET C'EST CE QUI REND L'ENSEMBLE SÛR :
//
//     SI l'on notifie    la préférence du membre, dans la base du BBS
//     OÙ l'on notifie    le registre des appareils, relu à CHAQUE envoi
//     PAR OÙ            le relais du conteneur mail, 10.100.0.10:25
//
// L'adresse n'est jamais recopiée ici. Un appareil révoqué cesse d'être notifié
// sans qu'aucun message n'ait eu à circuler — voir sbx_adresse.go.
//
// L'ENVOI NE BLOQUE JAMAIS L'ÉCRITURE. Une réponse publiée doit l'être même si
// le relais est éteint, lent, ou que le conteneur redémarre. La notification
// part donc dans une goroutine, et son échec ne remonte pas : quelqu'un qui
// écrit dans un forum n'a pas à voir une erreur SMTP.
//
// CE QUE ÇA COÛTE, ET QU'ON ASSUME : une notification perdue est perdue. Il n'y
// a pas de file qui survit au redémarrage. Poser cette file est la prochaine
// étape si les pertes se voient ; l'écrire d'emblée serait construire une
// machinerie avant d'avoir mesuré le besoin.
package web

import (
	"fmt"
	"log"
	"net/smtp"
	"strings"
	"time"
)

// Le relais. Même valeur que `smtp_hote`/`smtp_port` de metrics.toml, où le
// motif d'envoi de SecuBox est déjà éprouvé.
const (
	relaisSMTP     = "10.100.0.10:25"
	expediteurSMTP = "gk2@secubox.in"
	delaiSMTP      = 20 * time.Second
)

// notifieReponse prévient les participants d'un fil qu'une réponse est arrivée.
//
// Appelée APRÈS que la réponse est enregistrée : on ne notifie que ce qui
// existe déjà. L'inverse annoncerait des messages qu'une erreur ferait
// disparaître.
func (s *Server) notifieReponse(threadID, auteurID int64, titre string) {
	go func() {
		defer func() {
			// Une notification ne doit JAMAIS emporter le serveur. Le forum
			// fonctionne sans elle ; l'inverse n'est pas vrai.
			if r := recover(); r != nil {
				log.Printf("bbs: notification, panique ignoree: %v", r)
			}
		}()

		qui, err := s.st.ParticipantsFil(threadID, auteurID)
		if err != nil || len(qui) == 0 {
			return
		}
		auteur := "quelqu'un"
		if u, err := s.st.UserInfo(auteurID); err == nil && u.Handle != "" {
			auteur = u.Handle
		}

		for _, id := range qui {
			if !s.st.NotifEmailActif(id) {
				continue
			}
			u, err := s.st.UserInfo(id)
			if err != nil {
				continue
			}
			adresse := s.adresseSbx(u.Handle)
			if adresse == "" {
				// Pas d'adresse déclarée, ou appareil révoqué : on se tait.
				continue
			}
			if err := s.envoie(adresse, titre, auteur, threadID); err != nil {
				log.Printf("bbs: notification a %s: %v", u.Handle, err)
			}
		}
	}()
}

func (s *Server) envoie(adresse, titre, auteur string, threadID int64) error {
	// L'EN-TÊTE EST CONSTRUIT À PARTIR DE TEXTE VENU DES MEMBRES : un titre de
	// fil peut contenir n'importe quoi, y compris un saut de ligne. En glisser
	// un dans un `Subject:` injecterait des en-têtes arbitraires — un `Bcc:`,
	// par exemple. On les retire, on ne les échappe pas : un titre de fil n'a
	// aucune raison d'en contenir.
	nettoie := func(v string) string {
		v = strings.ReplaceAll(v, "\r", " ")
		v = strings.ReplaceAll(v, "\n", " ")
		if len(v) > 120 {
			v = v[:120]
		}
		return strings.TrimSpace(v)
	}
	titre = nettoie(titre)
	auteur = nettoie(auteur)

	corps := fmt.Sprintf(""+
		"From: SecuBox BBS <%s>\r\n"+
		"To: <%s>\r\n"+
		"Subject: [BBS] %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\n"+
		"\r\n"+
		"%s a repondu dans le fil : %s\r\n\r\n"+
		"Lire : https://bbs.gk2.secubox.in/t/%d\r\n\r\n"+
		"-- \r\n"+
		"Vous recevez ce message parce que vous participez a ce fil.\r\n"+
		"Pour ne plus en recevoir : https://bbs.gk2.secubox.in/reglages\r\n",
		expediteurSMTP, adresse, titre, auteur, titre, threadID)

	c, err := smtp.Dial(relaisSMTP)
	if err != nil {
		return err
	}
	defer c.Close()
	// Le lien est LAN vers le conteneur : pas de STARTTLS exigé ici, comme dans
	// le motif des rapports (secubox-metrics/api/rapport.py).
	if err := c.Mail(expediteurSMTP); err != nil {
		return err
	}
	if err := c.Rcpt(adresse); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(corps)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// titreDuFil rend le titre d'un fil, ou une mention neutre.
//
// UN TITRE MANQUANT N'EMPECHE PAS DE NOTIFIER : la notification dit d'abord
// qu'il s'est passe quelque chose, et porte un lien. Abandonner l'envoi parce
// qu'on ne sait pas nommer le fil serait perdre l'essentiel pour l'accessoire.
func titreDuFil(s *Server, threadID int64) string {
	if t, err := s.st.ThreadByID(threadID); err == nil && strings.TrimSpace(t.Title) != "" {
		return t.Title
	}
	return "un fil"
}
