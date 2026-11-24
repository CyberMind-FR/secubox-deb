// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

// PORTS CHIFFRÉS D'EMBLÉE (465, 993, 995) — #3924. Ni certificat ni poignée de
// main : une alerte TLS, et on ferme. C'est ici que frappe le téléphone du
// propriétaire pendant que son courrier dort : on COMPTE l'adresse et sa
// cadence, dans un fichier d'état réservé à root, jamais au journal des menaces
// ni chez sbx-actord, et on ne bannit JAMAIS.

import (
	"sort"
	"sync"
	"time"
)

// alerteTLS : enregistrement « alert », fatal, internal_error.
const alerteTLS = "\x15\x03\x01\x00\x02\x02\x50"

// Le client est lu et jeté (au plus un tampon) avant l'alerte : fermer avec des
// octets non lus enverrait un RST qui l'avalerait.
func dialogueTLS(s *sessionMail) {
	s.lec.fin = time.Now().Add(2 * time.Second)
	s.lec.echeance()
	if s.lec.recoit() != nil {
		return
	}
	s.lec.efface()
	_ = s.ecrit(alerteTLS)
}

const (
	tlsAdressesMax = 1024 // par service ; la plus ancienne cède la place
	tlsOubli       = 24 * time.Hour
	tlsPubliees    = 50
)

type passageTLS struct {
	n                int
	premier, dernier time.Time
}

// DecompteTLS : connexions par service et par adresse, en mémoire bornée.
type DecompteTLS struct {
	mu    sync.Mutex
	total map[string]int
	par   map[string]map[string]*passageTLS
}

func NewDecompteTLS() *DecompteTLS {
	return &DecompteTLS{total: map[string]int{}, par: map[string]map[string]*passageTLS{}}
}

func (d *DecompteTLS) Note(service, ip string, quand time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.total[service]++
	m := d.par[service]
	if m == nil {
		m = map[string]*passageTLS{}
		d.par[service] = m
	}
	if p := m[ip]; p != nil {
		p.n++
		p.dernier = quand
		return
	}
	if len(m) >= tlsAdressesMax {
		vieille := ""
		for k, p := range m {
			if vieille == "" || p.dernier.Before(m[vieille].dernier) {
				vieille = k
			}
		}
		delete(m, vieille)
	}
	m[ip] = &passageTLS{n: 1, premier: quand, dernier: quand}
}

// AdresseTLS, ServiceTLS : ce que publie le fichier d'état.
type AdresseTLS struct {
	IP        string  `json:"ip"`
	N         int     `json:"n"`
	ParMinute float64 `json:"par_minute"`
	Premier   int64   `json:"premier"`
	Dernier   int64   `json:"dernier"`
}

type ServiceTLS struct {
	Connexions int          `json:"connexions"`
	Adresses   int          `json:"adresses"`
	Premieres  []AdresseTLS `json:"premieres"`
}

// Etat rend le décompte (les plus insistantes d'abord) et oublie ce qui n'a pas
// été revu depuis 24 h.
func (d *DecompteTLS) Etat(maintenant time.Time) map[string]ServiceTLS {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[string]ServiceTLS{}
	for svc, m := range d.par {
		tab := []AdresseTLS{}
		for ip, p := range m {
			if maintenant.Sub(p.dernier) > tlsOubli {
				delete(m, ip)
				continue
			}
			min := p.dernier.Sub(p.premier).Minutes()
			if min < 1 {
				min = 1
			}
			tab = append(tab, AdresseTLS{IP: ip, N: p.n, ParMinute: float64(int(float64(p.n)/min*100)) / 100,
				Premier: p.premier.Unix(), Dernier: p.dernier.Unix()})
		}
		sort.Slice(tab, func(i, j int) bool {
			if tab[i].N != tab[j].N {
				return tab[i].N > tab[j].N
			}
			return tab[i].IP < tab[j].IP
		})
		n := len(tab)
		if n > tlsPubliees {
			tab = tab[:tlsPubliees]
		}
		out[svc] = ServiceTLS{Connexions: d.total[svc], Adresses: n, Premieres: tab}
	}
	return out
}
