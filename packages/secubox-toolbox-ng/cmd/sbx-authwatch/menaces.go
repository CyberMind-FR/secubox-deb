// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbx-authwatch — ecriture au journal de menaces (#1220)
//
// C'EST ICI QUE LA CORRELATION SE RECONSTITUE. On ecrit dans le journal de
// menaces DU WAF, au format exact qu'il produit — meme fichier, memes clefs.
// Consequence : sans toucher a une ligne de leur code, le panneau WAF, le
// camembert des pays, les attaquants persistants et le rapport PDF envoye par
// courriel se mettent a compter SSH, SMTP et IMAP au meme titre que le HTTP.
//
// Les champs propres au web (methode, agent) restent vides : les remplir
// d'a-peu-pres rendrait le journal moins vrai. Deux exceptions assumees, parce
// qu'elles sont exactes et non approximatives :
//
//   - `host` porte le SERVICE vise (ssh, smtp, imap, ou le nom du leurre) ;
//   - `path` porte le COMPTE vise. Pour une requete web, `path` est ce qui
//     etait demande ; pour une tentative d'authentification, c'est le compte.
//     C'est la meme question — « qu'est-ce qui etait visé ? » — et cela rend le
//     champ exploitable par le panneau sans inventer une clef que les
//     consommateurs existants ne sauraient pas lire.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// entreeMenace reproduit exactement logEntry de sbxwaf/threatlog.go.
type entreeMenace struct {
	Timestamp string `json:"timestamp"`
	ClientIP  string `json:"client_ip"`
	Host      string `json:"host"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Category  string `json:"category"`
	Severity  string `json:"severity"`
	RuleID    string `json:"rule_id"`
	Action    string `json:"action"`
	UserAgent string `json:"user_agent"`
	Tool      string `json:"tool,omitempty"`
	JA4       string `json:"ja4,omitempty"`
}

type JournalMenaces struct {
	chemin string
	mu     sync.Mutex
}

func NewJournalMenaces(chemin string) *JournalMenaces {
	return &JournalMenaces{chemin: chemin}
}

// prive reproduit la regle du WAF : tout ce qui est interne est agrege sous
// « local » plutot que classe comme attaquant. Sans cela, un client LAN mal
// configure trusterait la tete des « attaquants persistants ».
func prive(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	return p.IsLoopback() || p.IsPrivate() || p.IsLinkLocalUnicast()
}

// Inscrit ajoute une ligne. Best-effort, comme cote WAF : un echec d'ecriture
// ne doit jamais interrompre la surveillance.
func (j *JournalMenaces) Inscrit(s Signal, action string, total int) {
	if j == nil || j.chemin == "" {
		return
	}
	ip := s.IP
	if prive(ip) {
		ip = "local"
	}
	e := entreeMenace{
		Timestamp: time.Now().Format(time.RFC3339),
		ClientIP:  ip,
		Host:      s.Service,
		Path:      s.Cible,
		Category:  s.Categorie,
		Severity:  s.Severite,
		RuleID:    fmt.Sprintf("%s/%d", s.Detail, total),
		Action:    action,
		Tool:      "authwatch",
	}
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	data = append(data, '\n')

	j.mu.Lock()
	defer j.mu.Unlock()
	f, err := os.OpenFile(j.chemin, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0640)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sbx-authwatch: journal %s : %v\n", j.chemin, err)
		return
	}
	defer f.Close()
	_, _ = f.Write(data)
}
