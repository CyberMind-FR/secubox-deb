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
// La connexion est fermee IMMEDIATEMENT, sans un octet echange. Le delai
// d'ecriture n'existe donc pas : il n'y a rien a ecrire.
func EcouteLeurre(ctx context.Context, l Leurre, signaux chan<- Signal) error {
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
		_ = conn.Close()
		if hote == "" {
			continue
		}
		select {
		case signaux <- Signal{
			IP:        hote,
			Service:   l.Service,
			Categorie: "leurre:" + l.Service,
			Severite:  "high",
			Detail:    fmt.Sprintf("connexion sur un service inexistant (port %d)", l.Port),
		}:
		case <-ctx.Done():
			return nil
		}
	}
}
