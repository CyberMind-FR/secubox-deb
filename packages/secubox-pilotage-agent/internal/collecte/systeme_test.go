// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package collecte

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
)

const (
	pTotal = "Device.DeviceInfo.MemoryStatus.Total"
	pProc  = "Device.DeviceInfo.ProcessStatus.Process."
)

func TestSystemeLitMemoireEtUptime(t *testing.T) {
	m := modele.NouveauModele(NouvelleSourceSysteme("testdata/gk5"))
	p := modele.Aplatir(m.Get(context.Background(), []string{"Device.DeviceInfo."}))
	attendu := map[string]any{
		pTotal: uint64(973824),
		"Device.DeviceInfo.MemoryStatus.X_SECUBOX_Available":     uint64(262144),
		"Device.DeviceInfo.MemoryStatus.Free":                    uint64(180224),
		"Device.DeviceInfo.MemoryStatus.X_SECUBOX_SwapTotal":     uint64(524288),
		"Device.DeviceInfo.MemoryStatus.X_SECUBOX_SwapUsed":      uint64(24288),
		"Device.DeviceInfo.UpTime":                               uint64(2036),
		"Device.DeviceInfo.Manufacturer":                         "Globalscale",
		"Device.DeviceInfo.ModelName":                            "Globalscale Marvell ESPRESSOBin Board V7 (eMMC)",
		"Device.DeviceInfo.SerialNumber":                         "021122334455",
		"Device.DeviceInfo.ProcessStatus.ProcessNumberOfEntries": 3,
		"Device.DeviceInfo.ProcessStatus.CPUUsage":               0.0,
	}
	for k, v := range attendu {
		if p[k] != v {
			t.Errorf("%s = %#v (%T), attendu %#v", k, p[k], p[k], v)
		}
	}
	if _, ok := p["Device.DeviceInfo.SoftwareVersion"]; ok {
		t.Error("SoftwareVersion relève de la source paquets")
	}
	// Le plus gros RSS vient en premier : uvicorn, 25000 pages de 4 Kio.
	if p[pProc+"1.PID"] != 412 || p[pProc+"1.Command"] != "uvicorn" || p[pProc+"1.Size"] != uint64(100000) {
		t.Errorf("processus 1 inattendu : %v", p)
	}
	if p[pProc+"1.CPUTime"] != uint64(35000) || p[pProc+"1.State"] != "S" {
		t.Errorf("CPUTime/State inattendus : %v %v", p[pProc+"1.CPUTime"], p[pProc+"1.State"])
	}
}

func TestSystemeNeDonneJamaisLaLigneDeCommande(t *testing.T) {
	raw, err := os.ReadFile("testdata/gk5/proc/412/cmdline")
	if err != nil || !strings.Contains(string(raw), "password=x") {
		t.Fatalf("la fixture doit contenir password=x : %v", err)
	}
	m := modele.NouveauModele(NouvelleSourceSysteme("testdata/gk5"))
	for k, v := range modele.Aplatir(m.Get(context.Background(), []string{"Device."})) {
		if strings.Contains(fmt.Sprint(v), "password") || strings.Contains(fmt.Sprint(v), "--token") {
			t.Errorf("%s fuit la ligne de commande : %v", k, v)
		}
	}
}

func TestSystemeCPUUsageMoyenneDeLaDerniereFenetreEchantillonnee(t *testing.T) {
	racine := t.TempDir()
	ecrire := func(rel, contenu string) {
		f := filepath.Join(racine, rel)
		os.MkdirAll(filepath.Dir(f), 0o755)
		if err := os.WriteFile(f, []byte(contenu), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ecrire("proc/meminfo", "MemTotal: 1 kB\nMemFree: 1 kB\nMemAvailable: 1 kB\n")
	ecrire("proc/uptime", "1.0 1.0\n")
	ecrire("proc/stat", "cpu  100 0 0 900 0 0 0 0 0 0\n")
	s := NouvelleSourceSysteme(racine)
	cpu := s.(EchantillonCPU)
	cpu.EchantillonnerCPU() // début de fenêtre (surveillance)
	usage := func() any {
		t.Helper()
		p, err := s.Lire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return p["Device.DeviceInfo.ProcessStatus.CPUUsage"]
	}
	if got := usage(); got != 0.0 {
		t.Fatalf("aucune fenêtre complète : CPUUsage = %v, attendu 0", got)
	}
	ecrire("proc/stat", "cpu  200 0 0 1000 0 0 0 0 0 0\n") // +100 actifs sur +200 au total
	cpu.EchantillonnerCPU()                                // fin de la fenêtre de 30 s
	// M1 : deux Get du maître à 1 ms d'intervalle, alors que /proc/stat bouge (100 % entre eux) : la même valeur,
	// celle de la fenêtre de la surveillance, et la base de la fenêtre suivante n'est pas déplacée.
	ecrire("proc/stat", "cpu  300 0 0 1000 0 0 0 0 0 0\n")
	a := usage()
	time.Sleep(time.Millisecond)
	ecrire("proc/stat", "cpu  301 0 0 1000 0 0 0 0 0 0\n")
	b := usage()
	if a != 50.0 || b != 50.0 {
		t.Fatalf("lectures du maître : %v puis %v, attendu 50 et 50", a, b)
	}
	ecrire("proc/stat", "cpu  400 0 0 1100 0 0 0 0 0 0\n") // depuis la fin de fenêtre précédente : +200 actifs sur +300
	cpu.EchantillonnerCPU()
	if got := usage(); got != 200.0*100/300 {
		t.Fatalf("fenêtre suivante = %v, attendu %v (la base ne bouge qu'à l'échantillon)", got, 200.0*100/300)
	}
}

func TestModeleBorneLesListes(t *testing.T) {
	racine := t.TempDir()
	ecrire := func(rel, contenu string) {
		f := filepath.Join(racine, rel)
		os.MkdirAll(filepath.Dir(f), 0o755)
		if err := os.WriteFile(f, []byte(contenu), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ecrire("proc/meminfo", "MemTotal: 10 kB\nMemFree: 5 kB\nMemAvailable: 6 kB\n")
	ecrire("proc/uptime", "10.5 10.0\n")
	ecrire("proc/stat", "cpu  1 0 1 8 0 0 0 0 0 0\n")
	for i := 1; i <= 500; i++ {
		d := fmt.Sprintf("proc/%d/", 100+i)
		ecrire(d+"stat", fmt.Sprintf("%d (p%d) R 1 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 1 1 1 0\n", 100+i, i))
		ecrire(d+"statm", fmt.Sprintf("10 %d 0 0 0 0 0\n", i))
		ecrire(d+"comm", fmt.Sprintf("p%d\n", i))
	}
	m := modele.NouveauModele(NouvelleSourceSysteme(racine))
	p := modele.Aplatir(m.Get(context.Background(), []string{"Device.DeviceInfo.ProcessStatus."}))
	if p["Device.DeviceInfo.ProcessStatus.ProcessNumberOfEntries"] != 500 {
		t.Errorf("ProcessNumberOfEntries = %v", p["Device.DeviceInfo.ProcessStatus.ProcessNumberOfEntries"])
	}
	n := 0
	for k := range p {
		if strings.HasSuffix(k, ".PID") {
			n++
		}
	}
	if n != 20 || p[pProc+"20.PID"] != 581 || p[pProc+"21.PID"] != nil {
		t.Errorf("%d entrées, 20.PID = %v", n, p[pProc+"20.PID"])
	}
}

func TestModelePrefixeEtCheminInconnu(t *testing.T) {
	m := modele.NouveauModele(NouvelleSourceSysteme("testdata/gk5"))
	r := m.Get(context.Background(), []string{"Device.DeviceInfo.MemoryStatus.", "Device.Rien"})
	if len(r[0].Params) != 5 {
		t.Errorf("MemoryStatus. rend %d params, attendu 5", len(r[0].Params))
	}
	if r[1].Erreur != "chemin inconnu" {
		t.Errorf("Erreur = %q", r[1].Erreur)
	}
	if sup := m.Supportes(); len(sup) == 0 || sup[0] > sup[len(sup)-1] {
		t.Errorf("Supportes non trié : %v", sup)
	}
}
