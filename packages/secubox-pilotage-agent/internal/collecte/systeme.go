// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package collecte lit l'état de la box (fichiers seulement, aucun processus
// lancé) et le présente sous des chemins TR-181.
package collecte

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
)

const (
	racineDevice = "Device.DeviceInfo."
	maxProcessus = 20  // seules les plus grosses entrées sont publiées
	tailleTick   = 100 // CLK_TCK de Linux
	kioParPage   = 4   // pages de 4 Kio (arm64 Debian, x86_64)
)

type systeme struct {
	racine string

	mu           sync.Mutex
	dernierTotal uint64
	dernierActif uint64
	deja         bool
}

// NouvelleSourceSysteme lit /proc et /sys sous racine (vide en production).
func NouvelleSourceSysteme(racine string) modele.Source {
	return &systeme{racine: racine}
}

func (s *systeme) Nom() string { return "systeme" }

// Chemins annonce les paramètres produits (GetSupportedDM).
func (s *systeme) Chemins() []string {
	l := []string{
		racineDevice + "Manufacturer",
		racineDevice + "ModelName",
		racineDevice + "SerialNumber",
		racineDevice + "UpTime",
		racineDevice + "MemoryStatus.Total",
		racineDevice + "MemoryStatus.Free",
		racineDevice + "MemoryStatus.X_SECUBOX_Available",
		racineDevice + "MemoryStatus.X_SECUBOX_SwapTotal",
		racineDevice + "MemoryStatus.X_SECUBOX_SwapUsed",
		racineDevice + "ProcessStatus.CPUUsage",
		racineDevice + "ProcessStatus.ProcessNumberOfEntries",
	}
	for _, f := range []string{"PID", "Command", "Size", "CPUTime", "State"} {
		l = append(l, racineDevice+"ProcessStatus.Process.{i}."+f)
	}
	return l
}

func (s *systeme) lire(rel string) (string, error) {
	b, err := lireBorne(filepath.Join(s.racine, rel), plafondProc)
	return string(b), err
}

func (s *systeme) Lire(ctx context.Context) (map[string]any, error) {
	p := map[string]any{}

	// Mémoire (Kio).
	mem, err := s.lire("proc/meminfo")
	if err != nil {
		return nil, err
	}
	mi := parseMeminfo(mem)
	p[racineDevice+"MemoryStatus.Total"] = mi["MemTotal"]
	p[racineDevice+"MemoryStatus.Free"] = mi["MemFree"]
	p[racineDevice+"MemoryStatus.X_SECUBOX_Available"] = mi["MemAvailable"]
	p[racineDevice+"MemoryStatus.X_SECUBOX_SwapTotal"] = mi["SwapTotal"]
	if mi["SwapTotal"] >= mi["SwapFree"] {
		p[racineDevice+"MemoryStatus.X_SECUBOX_SwapUsed"] = mi["SwapTotal"] - mi["SwapFree"]
	} else {
		p[racineDevice+"MemoryStatus.X_SECUBOX_SwapUsed"] = uint64(0)
	}

	// Disponibilité (secondes entières).
	if up, err := s.lire("proc/uptime"); err == nil {
		if f := strings.Fields(up); len(f) > 0 {
			if v, err := strconv.ParseFloat(f[0], 64); err == nil {
				p[racineDevice+"UpTime"] = uint64(v)
			}
		}
	}

	// Identité.
	modeleCarte := s.modeleCarte()
	if modeleCarte != "" {
		p[racineDevice+"ModelName"] = modeleCarte
	}
	p[racineDevice+"Manufacturer"] = s.fabricant(modeleCarte)
	if sn := s.numeroSerie(); sn != "" {
		p[racineDevice+"SerialNumber"] = sn
	}

	// CPU.
	p[racineDevice+"ProcessStatus.CPUUsage"] = s.usageCPU()

	// Processus.
	s.processus(ctx, p)
	return p, nil
}

func parseMeminfo(txt string) map[string]uint64 {
	m := map[string]uint64{}
	for _, l := range strings.Split(txt, "\n") {
		cle, reste, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		f := strings.Fields(reste)
		if len(f) == 0 {
			continue
		}
		if v, err := strconv.ParseUint(f[0], 10, 64); err == nil {
			m[cle] = v
		}
	}
	return m
}

func (s *systeme) modeleCarte() string {
	if b, err := s.lire("proc/device-tree/model"); err == nil {
		if m := strings.TrimSpace(strings.Trim(b, "\x00")); m != "" {
			return m
		}
	}
	if b, err := s.lire("sys/class/dmi/id/product_name"); err == nil {
		return strings.TrimSpace(b)
	}
	return ""
}

func (s *systeme) fabricant(modeleCarte string) string {
	switch {
	case strings.Contains(modeleCarte, "Globalscale"):
		return "Globalscale"
	case strings.Contains(modeleCarte, "Raspberry Pi"):
		return "Raspberry Pi"
	}
	if b, err := s.lire("sys/class/dmi/id/sys_vendor"); err == nil {
		return strings.TrimSpace(b)
	}
	return ""
}

// numeroSerie rend l'adresse MAC, sans « : », de la première carte physique
// (présence d'un lien « device », ce qui exclut lo, wg0, ponts…).
func (s *systeme) numeroSerie() string {
	noms, err := filepath.Glob(filepath.Join(s.racine, "sys/class/net/*/device"))
	if err != nil {
		return ""
	}
	sort.Strings(noms)
	for _, d := range noms {
		b, err := lireBorne(filepath.Join(filepath.Dir(d), "address"), plafondPetit)
		if err != nil {
			continue
		}
		if mac := strings.ReplaceAll(strings.TrimSpace(string(b)), ":", ""); mac != "" {
			return mac
		}
	}
	return ""
}

// usageCPU rend le pourcentage d'activité depuis la lecture précédente
// (0 à la première lecture).
func (s *systeme) usageCPU() float64 {
	txt, err := s.lire("proc/stat")
	if err != nil {
		return 0
	}
	ligne, _, _ := strings.Cut(txt, "\n")
	f := strings.Fields(ligne)
	if len(f) < 5 || f[0] != "cpu" {
		return 0
	}
	var total, inactif uint64
	for i, c := range f[1:] {
		v, err := strconv.ParseUint(c, 10, 64)
		if err != nil {
			return 0
		}
		total += v
		if i == 3 || i == 4 { // idle, iowait
			inactif += v
		}
	}
	actif := total - inactif
	s.mu.Lock()
	defer s.mu.Unlock()
	usage := 0.0
	if s.deja && total > s.dernierTotal {
		usage = float64(actif-s.dernierActif) * 100 / float64(total-s.dernierTotal)
	}
	s.dernierTotal, s.dernierActif, s.deja = total, actif, true
	return usage
}

type proc struct {
	pid int
	rss uint64 // Kio
}

// processus publie les maxProcessus plus gros RSS. Seul « comm » est lu, jamais
// la ligne de commande, qui peut porter un secret.
func (s *systeme) processus(ctx context.Context, p map[string]any) {
	entrees, err := os.ReadDir(filepath.Join(s.racine, "proc"))
	if err != nil {
		return
	}
	var tous []proc
	for _, e := range entrees {
		if ctx.Err() != nil {
			return
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !e.IsDir() {
			continue
		}
		b, err := s.lire(fmt.Sprintf("proc/%d/statm", pid))
		if err != nil {
			continue // processus disparu entre-temps
		}
		f := strings.Fields(b)
		if len(f) < 2 {
			continue
		}
		pages, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		tous = append(tous, proc{pid, pages * kioParPage})
	}
	p[racineDevice+"ProcessStatus.ProcessNumberOfEntries"] = len(tous)
	sort.Slice(tous, func(i, j int) bool {
		if tous[i].rss != tous[j].rss {
			return tous[i].rss > tous[j].rss
		}
		return tous[i].pid < tous[j].pid
	})
	if len(tous) > maxProcessus {
		tous = tous[:maxProcessus]
	}
	n := 0
	for _, pr := range tous {
		etat, cpu, ok := s.statProcessus(pr.pid)
		if !ok {
			continue
		}
		comm, _ := s.lire(fmt.Sprintf("proc/%d/comm", pr.pid))
		n++
		base := fmt.Sprintf("%sProcessStatus.Process.%d.", racineDevice, n)
		p[base+"PID"] = pr.pid
		p[base+"Command"] = strings.TrimSpace(comm)
		p[base+"Size"] = pr.rss
		p[base+"CPUTime"] = cpu
		p[base+"State"] = etat
	}
}

// statProcessus lit l'état et le temps CPU (ms) dans /proc/<pid>/stat. Le nom
// entre parenthèses peut contenir espaces et parenthèses : on coupe après la
// dernière « ) ».
func (s *systeme) statProcessus(pid int) (etat string, cpuMs uint64, ok bool) {
	b, err := s.lire(fmt.Sprintf("proc/%d/stat", pid))
	if err != nil {
		return "", 0, false
	}
	i := strings.LastIndexByte(b, ')')
	if i < 0 {
		return "", 0, false
	}
	f := strings.Fields(b[i+1:])
	if len(f) < 13 { // état = champ 3, utime = 14, stime = 15
		return "", 0, false
	}
	ut, err1 := strconv.ParseUint(f[11], 10, 64)
	st, err2 := strconv.ParseUint(f[12], 10, 64)
	if err1 != nil || err2 != nil {
		return "", 0, false
	}
	return f[0], (ut + st) * 1000 / tailleTick, true
}
