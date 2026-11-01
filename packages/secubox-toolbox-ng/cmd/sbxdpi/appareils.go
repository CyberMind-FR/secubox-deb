// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

// SBX TV Privacy lot 4 (#3374) — agrégat PAR APPAREIL, opt-in et borné.
//
// sbxdpi reste « sans PII » pour tout le reste : seules les adresses listées par
// ad-guard dans le fichier de cibles (`DPI_TARGETS_FILE`, écrit par root via
// `secubox-adguard-tv dpi-cibles` : appareils du périmètre TV Privacy) sont
// comptées par adresse. Le résultat (`DPI_DEVICES_OUT`) est réécrit
// atomiquement à chaque flush, sur une fenêtre glissante de 10 minutes, et lu
// par le moteur d'ad-guard qui rattache chaque adresse à sa MAC. Sans cibles :
// rien n'est compté ni écrit.

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	maxClesAppareils  = 20000
	maxClesParAdresse = 2000
	fenetreMinutes    = 10
	maxCibles         = 256
)

type cleAppareil struct {
	local, appli, hote, distant, proto string
	port                               int
	minute                             int64
}

type valAppareil struct {
	categorie        string
	flux, octets     uint64
	premier, dernier int64
}

type suiviAppareils struct {
	mu        sync.Mutex
	ciblesF   string
	sortie    string
	mtime     time.Time
	cibles    map[string]bool
	cles      map[cleAppareil]*valAppareil
	parAdr    map[string]int
	aEcrire   bool
	dejaEcrit bool
	// proprietaire : UID exigé du fichier de cibles (S2 : root, qui seul l'écrit dans /run/secubox/sbxdpi-cibles/).
	proprietaire uint32
}

func newSuiviAppareils(ciblesF, sortie string) *suiviAppareils {
	return &suiviAppareils{ciblesF: ciblesF, sortie: sortie, cibles: map[string]bool{}, cles: map[cleAppareil]*valAppareil{},
		parAdr: map[string]int{}}
}

// lirePlafonne lit le fichier de cibles s'il est régulier, appartient au
// propriétaire attendu (root) et fait au plus 1 Mio — taille vérifiée AVANT lecture.
func (s *suiviAppareils) lirePlafonne(p string) []byte {
	st, err := os.Lstat(p)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return nil
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || sys.Uid != s.proprietaire {
		log.Printf("sbxdpi: cibles %s refusées (propriétaire inattendu)", p)
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil || len(b) > 1<<20 {
		return nil
	}
	return b
}

// recharger relit le fichier de cibles s'il a changé (mtime). Fichier absent,
// refusé ou invalide : aucune cible ; les clés des adresses retirées sont
// purgées aussitôt (m7).
func (s *suiviAppareils) recharger() {
	st, err := os.Stat(s.ciblesF)
	if err != nil {
		s.mu.Lock()
		s.cibles, s.mtime = map[string]bool{}, time.Time{}
		s.purgerHorsCibles()
		s.mu.Unlock()
		return
	}
	if st.ModTime().Equal(s.mtime) {
		return
	}
	var c struct {
		Version   int `json:"version"`
		Appareils []struct {
			Adresses []string `json:"adresses"`
		} `json:"appareils"`
	}
	nouv := map[string]bool{}
	if b := s.lirePlafonne(s.ciblesF); b != nil && json.Unmarshal(b, &c) == nil && c.Version == 1 {
		for _, a := range c.Appareils {
			for _, ip := range a.Adresses {
				if p := net.ParseIP(ip); p != nil && len(nouv) < maxCibles {
					nouv[p.String()] = true
				}
			}
		}
	}
	s.mu.Lock()
	s.cibles, s.mtime = nouv, st.ModTime()
	s.purgerHorsCibles()
	s.mu.Unlock()
}

// purgerHorsCibles retire les clés des adresses qui ne sont plus des cibles (mu tenu).
func (s *suiviAppareils) purgerHorsCibles() {
	for k := range s.cles {
		if !s.cibles[k.local] {
			delete(s.cles, k)
			s.parAdr[k.local]--
			s.aEcrire = true
		}
	}
}

// observe compte un événement de flux dont la source OU la destination est une
// cible. Le nom d'hôte suffit à identifier le distant ; sans nom, l'adresse
// distante est gardée (constat « adresse en dur » côté ad-guard).
func (s *suiviAppareils) observe(ev *dpiEvent, maintenant int64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cibles) == 0 {
		return
	}
	local, distant, port := "", "", 0
	src, dst := normIP(ev.SrcIP), normIP(ev.DstIP)
	switch {
	case s.cibles[src]:
		local, distant, port = src, dst, ev.DstPort
	case s.cibles[dst]:
		local, distant, port = dst, src, ev.SrcPort
	default:
		return
	}
	hote := strings.ToLower(strings.TrimSuffix(ev.host(), "."))
	if hote != "" {
		distant = ""
	}
	k := cleAppareil{local: local, appli: ev.app(), hote: hote, distant: distant, proto: strings.ToLower(ev.L4Proto), port: port,
		minute: maintenant / 60}
	v, ok := s.cles[k]
	if !ok {
		if len(s.cles) >= maxClesAppareils || s.parAdr[local] >= maxClesParAdresse {
			return // plafonds : on cesse d'ajouter des clés jusqu'à la prochaine purge
		}
		v = &valAppareil{premier: maintenant}
		s.cles[k] = v
		s.parAdr[local]++
	}
	if c := ev.category(); c != "" {
		v.categorie = c
	}
	switch ev.FlowEventName {
	case "end", "idle":
		v.octets += ev.SrcBytes + ev.DstBytes
	default:
		v.flux++
	}
	v.dernier = maintenant
	s.aEcrire = true
}

func normIP(s string) string {
	if p := net.ParseIP(s); p != nil {
		return p.String()
	}
	return ""
}

// purger retire les minutes sorties de la fenêtre glissante.
func (s *suiviAppareils) purger(maintenant int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	limite := maintenant/60 - fenetreMinutes
	for k := range s.cles {
		if k.minute < limite {
			delete(s.cles, k)
			s.parAdr[k.local]--
			s.aEcrire = true
		}
	}
}

type fluxAppareil struct {
	Local     string `json:"local"`
	Appli     string `json:"appli"`
	Categorie string `json:"categorie"`
	Hote      string `json:"hote"`
	Distant   string `json:"distant"`
	Port      int    `json:"port"`
	Proto     string `json:"proto"`
	Flux      uint64 `json:"flux"`
	Octets    uint64 `json:"octets"`
	Premier   int64  `json:"premier"`
	Dernier   int64  `json:"dernier"`
}

// ecrire réécrit le fichier atomiquement (0640) si quelque chose a changé. Sans
// cibles et sans fichier précédent : rien.
func (s *suiviAppareils) ecrire(maintenant int64) error {
	s.recharger()
	s.purger(maintenant)
	s.mu.Lock()
	if !s.aEcrire && (s.dejaEcrit || len(s.cibles) == 0) {
		s.mu.Unlock()
		return nil
	}
	if len(s.cibles) == 0 && len(s.cles) == 0 && !s.dejaEcrit {
		s.mu.Unlock()
		return nil
	}
	flux := make([]fluxAppareil, 0, len(s.cles))
	for k, v := range s.cles {
		proto := k.proto
		if proto != "tcp" && proto != "udp" {
			continue
		}
		flux = append(flux, fluxAppareil{Local: k.local, Appli: k.appli, Categorie: v.categorie, Hote: k.hote, Distant: k.distant,
			Port: k.port, Proto: proto, Flux: v.flux, Octets: v.octets, Premier: v.premier, Dernier: v.dernier})
	}
	s.aEcrire = false
	s.mu.Unlock()
	sort.Slice(flux, func(i, j int) bool { return flux[i].Dernier > flux[j].Dernier })
	b, err := json.Marshal(map[string]any{"version": 1, "genere": maintenant, "flux": flux})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.sortie), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.sortie), ".appareils.")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o640); err == nil {
		_, err = tmp.Write(b)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.sortie); err != nil {
		return err
	}
	s.mu.Lock()
	s.dejaEcrit = true
	s.mu.Unlock()
	return nil
}

func (s *suiviAppareils) flush() {
	if s == nil {
		return
	}
	if err := s.ecrire(time.Now().Unix()); err != nil {
		log.Printf("sbxdpi: appareils (lot 4) : %v", err)
	}
}
