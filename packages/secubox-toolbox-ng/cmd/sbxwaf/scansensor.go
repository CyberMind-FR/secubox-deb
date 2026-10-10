// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
)

// Capteur PARE-FEU d'Actor Intelligence (#2240, phase 2).
//
// Le pare-feu est en DEFAULT DROP : tout ce qui n'est pas explicitement ouvert tombe en bout de chaîne `inet filter input`. Une règle ADDITIVE
// (nftables.d/zz-secubox-scan-tap.nft, paquet secubox-hub) y inscrit, pour chaque paquet ainsi rejeté, le couple (adresse source, port visé)
// dans un ensemble à durée de vie (10 min). Elle ne bloque ni n'accepte rien : elle regarde.
//
// Ce capteur relit l'ensemble toutes les 30 s et déduit un BALAYAGE VERTICAL : une même adresse qui frappe au moins `seuil` ports DISTINCTS
// fermés dans la fenêtre. Un seul port répété (un client mal configuré) ou deux ports (un client ordinaire) n'en sont pas un. Le résultat est une
// enveloppe `firewall` envoyée à actord, qui la corrèle avec le WAF et l'authwatch : c'est la seconde source indépendante qui permet, plus tard,
// de décider sur plusieurs capteurs (jamais sur un seul).
//
// Garde-fous : adresses privées, locales, lien-local et plages protégées jamais signalées ; pas de répétition d'un même balayage sauf s'il
// s'étend (×2) ; une panne de nft (ensemble absent, droits) se COMPTE et se journalise une fois, sans rien émettre ni casser le WAF.
type scanElem struct {
	IP   string
	Port int
	Age  int // secondes depuis la première vue (durée de vie de l'ensemble − expiration restante)
}

type scanEvent struct {
	IP     string
	Ports  int
	Age    int // ancienneté du plus vieux port vu, secondes
	Sample []int
}

type scanEmetteur interface{ Emit(*envelope.Envelope) bool }

type ScanSensor struct {
	runner    nftRunner
	emetteur  scanEmetteur
	table     string
	set4      string
	set6      string
	seuil     int
	protegees []*net.IPNet
	geo       *Geo
	now       func() time.Time

	erreurs    atomic.Uint64
	mu         sync.Mutex
	deja       map[string]scanVu
	journalise bool
}

type scanVu struct {
	ports int
	at    time.Time
}

func NewScanSensor(runner nftRunner, e scanEmetteur) *ScanSensor {
	return &ScanSensor{runner: runner, emetteur: e, table: "filter", set4: "sbx_scan_seen4", set6: "sbx_scan_seen6", seuil: 8,
		now: time.Now, deja: map[string]scanVu{}}
}

func (s *ScanSensor) Erreurs() uint64 { return s.erreurs.Load() }

// parseEnsembleScan lit la sortie de `nft -j list set` d'un ensemble `ip . port` à durée de vie.
func parseEnsembleScan(b []byte) ([]scanElem, error) {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Timeout int `json:"timeout"`
				Elem    []struct {
					Elem struct {
						Val struct {
							Concat []json.RawMessage `json:"concat"`
						} `json:"val"`
						Expires int `json:"expires"`
					} `json:"elem"`
				} `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("sortie nft illisible : %w", err)
	}
	var out []scanElem
	for _, bloc := range doc.Nftables {
		if bloc.Set == nil {
			continue
		}
		for _, e := range bloc.Set.Elem {
			c := e.Elem.Val.Concat
			if len(c) != 2 {
				continue
			}
			var ip string
			var port int
			if json.Unmarshal(c[0], &ip) != nil || json.Unmarshal(c[1], &port) != nil {
				continue
			}
			age := bloc.Set.Timeout - e.Elem.Expires
			if age < 0 {
				age = 0
			}
			out = append(out, scanElem{IP: ip, Port: port, Age: age})
		}
	}
	return out, nil
}

// analyserScans regroupe par adresse et retient celles qui ont frappé au moins `seuil` ports distincts.
func analyserScans(elems []scanElem, seuil int, protegees []*net.IPNet) []scanEvent {
	type acc struct {
		ports map[int]bool
		age   int
	}
	par := map[string]*acc{}
	for _, e := range elems {
		if adresseProtegee(e.IP, protegees) {
			continue
		}
		a := par[e.IP]
		if a == nil {
			a = &acc{ports: map[int]bool{}}
			par[e.IP] = a
		}
		a.ports[e.Port] = true
		if e.Age > a.age {
			a.age = e.Age
		}
	}
	var out []scanEvent
	for ip, a := range par {
		if len(a.ports) < seuil {
			continue
		}
		var ps []int
		for p := range a.ports {
			ps = append(ps, p)
		}
		sort.Ints(ps)
		if len(ps) > 8 {
			ps = ps[:8]
		}
		out = append(out, scanEvent{IP: ip, Ports: len(a.ports), Age: a.age, Sample: ps})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ports > out[j].Ports })
	return out
}

func (s *ScanSensor) lire(ctx context.Context, set string) []scanElem {
	out, err := s.runner(ctx, "-j", "list", "set", "inet", s.table, set)
	if err == nil {
		var el []scanElem
		if el, err = parseEnsembleScan(out); err == nil {
			return el
		}
	}
	s.erreurs.Add(1)
	s.mu.Lock()
	premiere := !s.journalise
	s.journalise = true
	s.mu.Unlock()
	if premiere {
		log.Printf("sbxwaf: capteur pare-feu — ensemble %s illisible (%v) ; la sonde nftables.d/zz-secubox-scan-tap.nft est-elle chargée ?", set, err)
	}
	return nil
}

// Tick relit les deux ensembles et émet une enveloppe par balayage nouveau ou qui s'étend.
func (s *ScanSensor) Tick() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	elems := append(s.lire(ctx, s.set4), s.lire(ctx, s.set6)...)
	now := s.now()
	s.mu.Lock()
	for ip, v := range s.deja {
		if now.Sub(v.at) > time.Hour {
			delete(s.deja, ip)
		}
	}
	s.mu.Unlock()
	for _, ev := range analyserScans(elems, s.seuil, s.protegees) {
		s.mu.Lock()
		v, connu := s.deja[ev.IP]
		neuf := !connu || ev.Ports >= 2*v.ports || now.Sub(v.at) >= 10*time.Minute
		if neuf {
			s.deja[ev.IP] = scanVu{ports: ev.Ports, at: now}
		}
		s.mu.Unlock()
		if !neuf || s.emetteur == nil {
			continue
		}
		sev := 30 + 4*ev.Ports
		if sev > 100 {
			sev = 100
		}
		env := &envelope.Envelope{EventID: envelope.NewEventID(), Timestamp: now.Unix(), Sensor: envelope.SensorFirewall, SrcIP: ev.IP,
			DstService: fmt.Sprintf("ports:%d", ev.Ports), Action: envelope.ActionBlock, RuleID: "fw.scan.vertical", Severity: sev,
			BehaviorTags: []string{"port_scan", "scan_vertical"}, GeoCountry: s.geo.Pays(ev.IP)}
		s.emetteur.Emit(env)
		log.Printf("sbxwaf: capteur pare-feu — balayage %s : %d ports distincts (depuis %ds), échantillon %v", ev.IP, ev.Ports, ev.Age, ev.Sample)
	}
}

// Veiller relance Tick à intervalle régulier.
func (s *ScanSensor) Veiller(pas time.Duration) {
	for {
		s.Tick()
		time.Sleep(pas)
	}
}
