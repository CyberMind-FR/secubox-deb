// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbx-authwatch — leurres de service (#1220)
//
// MEME RAISONNEMENT QUE LE VHOST NON ROUTE, transpose du HTTP au reseau.
// sbxwaf classe comme sonde tout Host qu'il ne sert pas : un navigateur
// n'envoie jamais un nom qu'on ne publie pas. Ici : personne ne se connecte
// legitimement a un service qu'on N'OFFRE PAS. Un paquet SYN sur 3389 quand
// aucun RDP ne tourne n'a aucune lecture innocente — c'est un balayage, et le
// signal est certain des la premiere connexion.
//
// D'OU LA FORCE DU SIGNAL. Les motifs de journal demandent de la patience :
// un mot de passe refuse peut etre un humain. Un leurre, non. On bannit au
// premier contact, sans compteur — la seule reserve etant la liste blanche et
// les adresses privees, traitees en amont par l'appelant.
//
// CE QUE LE LEURRE NE FAIT PAS. Il n'imitera aucun protocole : ni banniere RDP,
// ni poignee de main VNC. Repondre, c'est entretenir une conversation avec un
// balayeur et s'exposer a ses propres failles d'implementation. On accepte, on
// note, on ferme.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

// Leurre est un port d'ecoute sans service derriere.
type Leurre struct {
	Port    int
	Service string // nom lisible porte au journal : "rdp", "vnc"…
}

// LeurresConnus — les ports que les balayeurs visitent en premier. La liste
// n'a pas vocation a etre exhaustive : chaque port ouvert est une promesse
// qu'on doit tenir (l'accepter et le fermer proprement), et un port de trop
// est un bruit de plus dans le journal.
var LeurresConnus = []Leurre{
	{3389, "rdp"},
	{5900, "vnc"},
	{23, "telnet"},
	{445, "smb"},
	{3306, "mysql"},
	{5432, "postgres"},
	{6379, "redis"},
	{27017, "mongodb"},
	{9200, "elasticsearch"},
	{1433, "mssql"},
}

// AnalyseLeurres traduit une specification « 3389:rdp,5900:vnc » ou « defaut ».
func AnalyseLeurres(spec string) ([]Leurre, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	if spec == "defaut" {
		return LeurresConnus, nil
	}
	var out []Leurre
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		morceaux := strings.SplitN(part, ":", 2)
		port, err := strconv.Atoi(strings.TrimSpace(morceaux[0]))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("port de leurre invalide : %q", part)
		}
		nom := "inconnu"
		if len(morceaux) == 2 && strings.TrimSpace(morceaux[1]) != "" {
			nom = strings.TrimSpace(morceaux[1])
		} else {
			for _, l := range LeurresConnus {
				if l.Port == port {
					nom = l.Service
					break
				}
			}
		}
		out = append(out, Leurre{Port: port, Service: nom})
	}
	return out, nil
}

// EcouteLeurre ouvre le port et pousse un signal par connexion entrante.
//
// DEUX RÉGIMES. Par défaut, la connexion est fermée IMMÉDIATEMENT, sans un
// octet échangé — c'est le comportement d'origine, et il reste le défaut.
//
// Avec `bannieres=true`, le leurre envoie une annonce STATIQUE (voir
// banniere.go) et capture, sans jamais l'interpréter, la première trame du
// client. Le signal cesse alors de dire seulement « on a été touché » pour dire
// « touché PAR CECI » — la trame décrit l'outil bien mieux qu'un numéro de port.
//
// Le second régime traite chaque connexion dans sa propre goroutine, bornée par
// un sémaphore : échanger prend du temps, et le faire dans la boucle d'accept
// suffirait à bloquer le leurre avec une seule connexion muette.
func EcouteLeurre(ctx context.Context, l Leurre, signaux chan<- Signal) error {
	return EcouteLeurreAvecBanniere(ctx, l, signaux, false)
}

// EcouteLeurreAvecBanniere — cf. EcouteLeurre. `bannieres` arme le second régime.
func EcouteLeurreAvecBanniere(ctx context.Context, l Leurre, signaux chan<- Signal,
	bannieres bool) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", fmt.Sprintf(":%d", l.Port))
	if err != nil {
		return fmt.Errorf("leurre %s (port %d) : %w", l.Service, l.Port, err)
	}
	log.Printf("sbx-authwatch: leurre %s en ecoute sur :%d", l.Service, l.Port)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	jetons := make(chan struct{}, banniereParallelisme)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// Une erreur transitoire (limite de descripteurs) ne doit pas
			// fermer le leurre definitivement.
			time.Sleep(200 * time.Millisecond)
			continue
		}
		hote, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if hote == "" {
			_ = conn.Close()
			continue
		}

		if !bannieres {
			// Régime d'origine : on accepte, on note, on ferme.
			_ = conn.Close()
			emet(ctx, signaux, l, hote, "", 0)
			continue
		}

		// Régime bannière. Le sémaphore n'est pas une précaution de style :
		// sans lui, mille connexions muettes tiendraient chacune une goroutine
		// et un tampon pendant l'échéance, sur une box qui n'a pas cette marge.
		select {
		case jetons <- struct{}{}:
		default:
			// Plafond atteint : on retombe sur le régime d'origine plutôt que
			// de refuser le signal. Mieux vaut savoir moins que ne rien savoir.
			_ = conn.Close()
			emet(ctx, signaux, l, hote, "", 0)
			continue
		}
		go func(c net.Conn, ip string) {
			defer func() { <-jetons; _ = c.Close() }()
			extrait, n := Echange(c, l.Service)
			emet(ctx, signaux, l, ip, extrait, n)
		}(conn, hote)
	}
}

// emet pousse le signal, en y joignant ce que le client a dit s'il a dit
// quelque chose. Le détail reste une PHRASE : l'extrait est déjà assaini par
// resumeTrame, jamais des octets bruts.
func emet(ctx context.Context, signaux chan<- Signal, l Leurre, ip, extrait string, n int) {
	detail := fmt.Sprintf("connexion sur un service inexistant (port %d)", l.Port)
	if n > 0 {
		detail = fmt.Sprintf("connexion sur un service inexistant (port %d) — "+
			"première trame %d o : %s", l.Port, n, extrait)
	}
	select {
	case signaux <- Signal{
		IP:        ip,
		Service:   l.Service,
		Categorie: "leurre:" + l.Service,
		Severite:  "high",
		Detail:    detail,
	}:
	case <-ctx.Done():
	}
}
