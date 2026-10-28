// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package notifs

import (
	"testing"
	"time"
)

type horlogeFausse struct{ t time.Time }

func (h *horlogeFausse) now() time.Time         { return h.t }
func (h *horlogeFausse) avance(d time.Duration) { h.t = h.t.Add(d) }

func nouveau() (*Detecteur, *horlogeFausse) {
	h := &horlogeFausse{t: time.Unix(1_800_000_000, 0)}
	return NouveauDetecteur(SeuilsParDefaut(), h.now), h
}

func unite(nom string, relances uint64) map[string]any {
	return map[string]any{
		"Device.X_SECUBOX_Services.1.Name":      nom,
		"Device.X_SECUBOX_Services.1.NRestarts": relances,
	}
}

func types(ev []Evenement) []string {
	var t []string
	for _, e := range ev {
		t = append(t, e.Type)
	}
	return t
}

func TestBoucleDetecteeUneFois(t *testing.T) {
	d, h := nouveau()
	if ev := d.Observer(unite("secubox-ndpisrvd.service", 10)); len(ev) != 0 {
		t.Fatalf("premier relevé : %v", ev)
	}
	h.avance(2 * time.Minute)
	ev := d.Observer(unite("secubox-ndpisrvd.service", 14))
	if len(ev) != 1 || ev[0].Type != "X_SECUBOX_ServiceLoop" || ev[0].Unite != "secubox-ndpisrvd.service" || ev[0].Valeur != 4 {
		t.Fatalf("événement attendu, obtenu %+v", ev)
	}
	h.avance(30 * time.Second)
	if ev := d.Observer(unite("secubox-ndpisrvd.service", 15)); len(ev) != 0 {
		t.Fatalf("pas de nouvel événement attendu : %+v", ev)
	}
}

func TestBoucleHorsFenetre(t *testing.T) {
	d, h := nouveau()
	d.Observer(unite("a.service", 10))
	h.avance(30 * time.Minute)
	if ev := d.Observer(unite("a.service", 14)); len(ev) != 0 {
		t.Fatalf("aucun événement attendu : %+v", ev)
	}
}

func TestBoucleIndexeParNomEtBorne(t *testing.T) {
	d, h := nouveau()
	d.Observer(unite("a.service", 1))
	h.avance(time.Minute)
	// l'unité change d'indice : elle doit rester reconnue par son nom
	ev := d.Observer(map[string]any{
		"Device.X_SECUBOX_Services.7.Name":      "a.service",
		"Device.X_SECUBOX_Services.7.NRestarts": uint64(5),
	})
	if len(ev) != 1 {
		t.Fatalf("boucle attendue malgré le changement d'indice : %+v", ev)
	}
	h.avance(time.Hour)
	d.Observer(unite("autre.service", 0))
	if len(d.unites) != 1 {
		t.Fatalf("état non élagué : %d unités", len(d.unites))
	}
}

func TestMemoireBasseSeReArme(t *testing.T) {
	d, _ := nouveau()
	mem := func(ko int) map[string]any {
		return map[string]any{"Device.DeviceInfo.MemoryStatus.X_SECUBOX_Available": uint64(ko)}
	}
	if ev := d.Observer(mem(150 * 1024)); len(ev) != 1 || ev[0].Type != "X_SECUBOX_MemoryLow" || ev[0].Valeur != 150 {
		t.Fatalf("150 Mo : %+v", ev)
	}
	if ev := d.Observer(mem(140 * 1024)); len(ev) != 0 {
		t.Fatalf("condition persistante : %+v", ev)
	}
	if ev := d.Observer(mem(300 * 1024)); len(ev) != 0 {
		t.Fatalf("300 Mo : %+v", ev)
	}
	if ev := d.Observer(mem(150 * 1024)); len(ev) != 1 {
		t.Fatalf("réarmement : %+v", ev)
	}
}

func TestSwapHaut(t *testing.T) {
	d, _ := nouveau()
	p := map[string]any{
		"Device.DeviceInfo.MemoryStatus.X_SECUBOX_SwapTotal": uint64(950 * 1024),
		"Device.DeviceInfo.MemoryStatus.X_SECUBOX_SwapUsed":  uint64(902 * 1024),
	}
	ev := d.Observer(p)
	if len(ev) != 1 || ev[0].Type != "X_SECUBOX_SwapHigh" || ev[0].Valeur != 94 {
		t.Fatalf("swap : %+v", ev)
	}
}

func TestSansSwapJamais(t *testing.T) {
	d, _ := nouveau()
	ev := d.Observer(map[string]any{
		"Device.DeviceInfo.MemoryStatus.X_SECUBOX_SwapTotal": uint64(0),
		"Device.DeviceInfo.MemoryStatus.X_SECUBOX_SwapUsed":  uint64(0),
	})
	if len(ev) != 0 {
		t.Fatalf("pas de swap : %+v", ev)
	}
}

func TestDemarrageUneSeuleFois(t *testing.T) {
	d, _ := nouveau()
	ev := d.Observer(map[string]any{"Device.DeviceInfo.UpTime": uint64(120)})
	if got := types(ev); len(got) != 1 || got[0] != "X_SECUBOX_Boot" {
		t.Fatalf("boot : %v", got)
	}
	if ev := d.Observer(map[string]any{"Device.DeviceInfo.UpTime": uint64(150)}); len(ev) != 0 {
		t.Fatalf("second boot : %+v", ev)
	}
}

func TestTypesInattendusSansPanique(t *testing.T) {
	d, _ := nouveau()
	d.Observer(map[string]any{
		"Device.DeviceInfo.UpTime":                           "x",
		"Device.DeviceInfo.MemoryStatus.X_SECUBOX_Available": []int{1},
		"Device.X_SECUBOX_Services.1.Name":                   42,
		"Device.X_SECUBOX_Services.1.NRestarts":              "y",
		"Device.DeviceInfo.MemoryStatus.X_SECUBOX_SwapTotal": nil,
	})
	d.Observer(nil)
}
