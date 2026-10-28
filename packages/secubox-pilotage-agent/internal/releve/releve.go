// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package releve mesure la charge d'une box sur une durée donnée, à la demande
// du maître (Operate Device.X_SECUBOX_Releve.Mesurer()). Mêmes grandeurs que
// l'outil de banc mesure-box.sh. Fichiers /proc seulement : aucune commande, et
// jamais la ligne de commande d'un processus (seulement comm).
package releve

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/lecture"
)

const (
	DureeMin = 10 * time.Second
	DureeMax = 300 * time.Second

	tailleTop     = 10
	hzNoyau       = 100     // CLK_TCK de Linux
	maxProcessus  = 8192    // bornage du parcours de /proc
	plafondProc   = 1 << 20 // un fichier /proc
	plafondPetit  = 64 << 10
	plafondDiskst = 1 << 20
)

// ErrEnCours : un relevé occupe déjà l'agent.
var ErrEnCours = errors.New("relevé déjà en cours")

var enCours atomic.Bool

// ProcRel : un processus parmi les plus gourmands.
type ProcRel struct {
	Nom    string
	CPUPct float64
	PSSMo  int
}

// Releve : charge mesurée sur DureeS secondes.
type Releve struct {
	DureeS       int
	CPUPct       int
	CtxtParS     int64
	EcrituresKoS int64
	MemDispoMo   int
	SwapMo       int
	Top          []ProcRel
}

type echantillon struct {
	total, oisif uint64
	ctxt         uint64
	secteurs     uint64
	procs        map[int]uint64
}

// Mesurer prend deux échantillons séparés par duree (bornée à [10 s, 300 s]).
// attendre est injectée pour que les tests ne dorment pas. Un seul relevé à la fois.
func Mesurer(ctx context.Context, racine string, duree time.Duration, attendre func(context.Context, time.Duration) error) (Releve, error) {
	if !enCours.CompareAndSwap(false, true) {
		return Releve{}, ErrEnCours
	}
	defer enCours.Store(false)

	if duree < DureeMin {
		duree = DureeMin
	}
	if duree > DureeMax {
		duree = DureeMax
	}
	e1, err := prendre(ctx, racine)
	if err != nil {
		return Releve{}, err
	}
	if err := attendre(ctx, duree); err != nil {
		return Releve{}, err
	}
	e2, err := prendre(ctx, racine)
	if err != nil {
		return Releve{}, err
	}

	secs := uint64(duree / time.Second)
	r := Releve{DureeS: int(secs)}
	if dt := e2.total - e1.total; e2.total > e1.total {
		busy := 100 - 100*float64(e2.oisif-e1.oisif)/float64(dt)
		r.CPUPct = int(busy + 0.5)
	}
	if e2.ctxt >= e1.ctxt {
		r.CtxtParS = int64((e2.ctxt - e1.ctxt) / secs)
	}
	if e2.secteurs >= e1.secteurs {
		r.EcrituresKoS = int64((e2.secteurs - e1.secteurs) * 512 / 1024 / secs)
	}
	r.MemDispoMo, r.SwapMo = memoire(racine)
	r.Top = classer(racine, e1.procs, e2.procs, float64(secs))
	return r, nil
}

func prendre(ctx context.Context, racine string) (echantillon, error) {
	e := echantillon{procs: map[int]uint64{}}
	b, err := lecture.Lire(filepath.Join(racine, "proc/stat"), plafondProc)
	if err != nil {
		return e, err
	}
	for _, l := range strings.Split(string(b), "\n") {
		c := strings.Fields(l)
		switch {
		case len(c) >= 8 && c[0] == "cpu":
			for i := 1; i <= 7; i++ {
				v, _ := strconv.ParseUint(c[i], 10, 64)
				e.total += v
				if i == 4 || i == 5 { // idle + iowait
					e.oisif += v
				}
			}
		case len(c) >= 2 && c[0] == "ctxt":
			e.ctxt, _ = strconv.ParseUint(c[1], 10, 64)
		}
	}
	// Disques entiers mmcblk<N> seulement (pas les partitions mmcblk0p1, ni boot0).
	if f, err := lecture.Ouvrir(filepath.Join(racine, "proc/diskstats"), plafondDiskst); err == nil {
		_ = lecture.Lignes(ctx, f, func(l string) {
			c := strings.Fields(l)
			if len(c) < 10 || !strings.HasPrefix(c[2], "mmcblk") || !chiffres(c[2][6:]) {
				return
			}
			v, _ := strconv.ParseUint(c[9], 10, 64)
			e.secteurs += v
		})
		f.Close()
	}
	ents, err := os.ReadDir(filepath.Join(racine, "proc"))
	if err != nil {
		return e, err
	}
	for _, d := range ents {
		if err := ctx.Err(); err != nil {
			return e, err
		}
		pid, err := strconv.Atoi(d.Name())
		if err != nil || len(e.procs) >= maxProcessus {
			continue
		}
		b, err := lecture.Lire(filepath.Join(racine, "proc", d.Name(), "stat"), plafondPetit)
		if err != nil {
			continue
		}
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) < 13 {
			continue
		}
		u, e1 := strconv.ParseUint(f[11], 10, 64)
		sy, e2 := strconv.ParseUint(f[12], 10, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		e.procs[pid] = u + sy
	}
	return e, nil
}

func chiffres(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func memoire(racine string) (dispoMo, swapMo int) {
	b, err := lecture.Lire(filepath.Join(racine, "proc/meminfo"), plafondProc)
	if err != nil {
		return 0, 0
	}
	var dispo, st, sf int64
	for _, l := range strings.Split(string(b), "\n") {
		c := strings.Fields(l)
		if len(c) < 2 {
			continue
		}
		v, _ := strconv.ParseInt(c[1], 10, 64)
		switch c[0] {
		case "MemAvailable:":
			dispo = v
		case "SwapTotal:":
			st = v
		case "SwapFree:":
			sf = v
		}
	}
	return int(dispo / 1024), int((st - sf) / 1024)
}

func classer(racine string, p1, p2 map[int]uint64, secs float64) []ProcRel {
	var top []ProcRel
	for pid, v := range p2 {
		d, ok := p1[pid]
		if !ok || v <= d {
			continue
		}
		top = append(top, ProcRel{
			Nom:    nom(racine, pid),
			CPUPct: float64(v-d) * 100 / hzNoyau / secs,
			PSSMo:  pss(racine, pid),
		})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].CPUPct != top[j].CPUPct {
			return top[i].CPUPct > top[j].CPUPct
		}
		return top[i].Nom < top[j].Nom
	})
	if len(top) > tailleTop {
		top = top[:tailleTop]
	}
	return top
}

// nom lit comm (jamais cmdline : la ligne de commande peut porter des secrets).
func nom(racine string, pid int) string {
	b, err := lecture.Lire(filepath.Join(racine, "proc", strconv.Itoa(pid), "comm"), 256)
	if err != nil {
		return "?"
	}
	if n := strings.TrimSpace(string(b)); n != "" {
		return n
	}
	return "?"
}

// pss rend la mémoire du processus en Mo : Pss + SwapPss de smaps_rollup quand
// il est lisible, sinon le RSS de statm.
func pss(racine string, pid int) int {
	dir := filepath.Join(racine, "proc", strconv.Itoa(pid))
	if b, err := lecture.Lire(filepath.Join(dir, "smaps_rollup"), plafondPetit); err == nil {
		var ko int64
		trouve := false
		for _, l := range strings.Split(string(b), "\n") {
			c := strings.Fields(l)
			if len(c) >= 2 && (c[0] == "Pss:" || c[0] == "SwapPss:") {
				v, _ := strconv.ParseInt(c[1], 10, 64)
				ko += v
				trouve = true
			}
		}
		if trouve {
			return int(ko / 1024)
		}
	}
	if b, err := lecture.Lire(filepath.Join(dir, "statm"), plafondPetit); err == nil {
		if c := strings.Fields(string(b)); len(c) >= 2 {
			pages, _ := strconv.ParseInt(c[1], 10, 64)
			return int(pages * int64(os.Getpagesize()) / (1 << 20))
		}
	}
	return 0
}
