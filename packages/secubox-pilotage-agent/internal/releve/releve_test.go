// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
package releve

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

func ecrire(t *testing.T, racine, rel, contenu string) {
	t.Helper()
	p := filepath.Join(racine, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(contenu), 0o644); err != nil {
		t.Fatal(err)
	}
}

func stat(utime, stime int) string {
	return "42 (mon (démon)) S 1 1 1 0 -1 4194560 0 0 0 0 " +
		strconv.Itoa(utime) + " " + strconv.Itoa(stime) + " 0 0 20 0 1 0 100 0 0\n"
}

func echantillon1(t *testing.T, r string) {
	ecrire(t, r, "proc/stat", "cpu  1000 0 500 8000 100 0 20 0\nctxt 1000\n")
	ecrire(t, r, "proc/diskstats", "   179       0 mmcblk0 1 0 1 1 1 0 1000 1 0 1 1\n   179       1 mmcblk0p1 1 0 1 1 1 0 9999 1 0 1 1\n   8 0 sda 1 0 1 1 1 0 7777 1 0 1 1\n")
	ecrire(t, r, "proc/42/stat", stat(100, 50))
	ecrire(t, r, "proc/42/comm", "mon démon\n")
	ecrire(t, r, "proc/42/cmdline", "secret --token=x\x00")
	ecrire(t, r, "proc/42/smaps_rollup", "Rss: 2048 kB\nPss: 1024 kB\nSwapPss: 1024 kB\n")
	ecrire(t, r, "proc/7/stat", stat(10, 0))
	ecrire(t, r, "proc/7/comm", "calme\n")
	ecrire(t, r, "proc/7/statm", "5000 1000 100 1 0 200 0\n")
	ecrire(t, r, "proc/meminfo", "MemTotal: 1000000 kB\nMemAvailable: 512000 kB\nSwapTotal: 204800 kB\nSwapFree: 102400 kB\n")
}

func echantillon2(t *testing.T, r string) {
	// Δtotal = 1000, Δ(idle+iowait) = 500 : CPU 50 %
	ecrire(t, r, "proc/stat", "cpu  1250 0 750 8450 150 0 20 0\nctxt 1600\n")
	// +4096 secteurs sur mmcblk0 seulement : 2048 Kio sur 10 s
	ecrire(t, r, "proc/diskstats", "   179       0 mmcblk0 1 0 1 1 1 0 5096 1 0 1 1\n   179       1 mmcblk0p1 1 0 1 1 1 0 99999 1 0 1 1\n   8 0 sda 1 0 1 1 1 0 77777 1 0 1 1\n")
	ecrire(t, r, "proc/42/stat", stat(150, 100)) // +100 ticks / 10 s = 10 %
	ecrire(t, r, "proc/7/stat", stat(10, 0))
}

func TestReleveBorneLaDuree(t *testing.T) {
	for _, c := range []struct{ demande, attendu time.Duration }{
		{5 * time.Second, 10 * time.Second},
		{900 * time.Second, 300 * time.Second},
		{60 * time.Second, 60 * time.Second},
	} {
		r := t.TempDir()
		echantillon1(t, r)
		var vu time.Duration
		rel, err := Mesurer(context.Background(), r, c.demande, func(_ context.Context, d time.Duration) error { vu = d; return nil })
		if err != nil {
			t.Fatal(err)
		}
		if vu != c.attendu || rel.DureeS != int(c.attendu/time.Second) {
			t.Errorf("%v : attendu %v, vu %v, DureeS %d", c.demande, c.attendu, vu, rel.DureeS)
		}
	}
}

func TestReleveCalculeLeCPU(t *testing.T) {
	r := t.TempDir()
	echantillon1(t, r)
	rel, err := Mesurer(context.Background(), r, 10*time.Second, func(context.Context, time.Duration) error {
		echantillon2(t, r)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if rel.CPUPct != 50 {
		t.Errorf("CPUPct = %d", rel.CPUPct)
	}
	if rel.CtxtParS != 60 {
		t.Errorf("CtxtParS = %d", rel.CtxtParS)
	}
	if rel.EcrituresKoS != 204 { // 4096*512/1024/10 = 204 (entier)
		t.Errorf("EcrituresKoS = %d", rel.EcrituresKoS)
	}
	if rel.MemDispoMo != 500 || rel.SwapMo != 100 {
		t.Errorf("mem = %d, swap = %d", rel.MemDispoMo, rel.SwapMo)
	}
	if len(rel.Top) != 1 {
		t.Fatalf("Top = %+v", rel.Top)
	}
	p := rel.Top[0]
	if p.Nom != "mon démon" || p.CPUPct != 10 || p.PSSMo != 2 {
		t.Errorf("proc = %+v", p)
	}
}

func TestReleveLimiteLeTopADix(t *testing.T) {
	r := t.TempDir()
	echantillon1(t, r)
	for i := 100; i < 125; i++ {
		ecrire(t, r, "proc/"+strconv.Itoa(i)+"/stat", stat(0, 0))
		ecrire(t, r, "proc/"+strconv.Itoa(i)+"/comm", "p\n")
	}
	rel, err := Mesurer(context.Background(), r, 10*time.Second, func(context.Context, time.Duration) error {
		echantillon2(t, r)
		for i := 100; i < 125; i++ {
			ecrire(t, r, "proc/"+strconv.Itoa(i)+"/stat", stat(i, 0))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rel.Top) != 10 || rel.Top[0].CPUPct < rel.Top[9].CPUPct {
		t.Errorf("Top = %+v", rel.Top)
	}
}

func TestReleveUnSeulALaFois(t *testing.T) {
	r := t.TempDir()
	echantillon1(t, r)
	entre, libere := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = Mesurer(context.Background(), r, 10*time.Second, func(context.Context, time.Duration) error {
			close(entre)
			<-libere
			return nil
		})
	}()
	<-entre
	_, err := Mesurer(context.Background(), r, 10*time.Second, func(context.Context, time.Duration) error { return nil })
	if err == nil || err.Error() != "relevé déjà en cours" {
		t.Errorf("err = %v", err)
	}
	close(libere)
	wg.Wait()
	if _, err := Mesurer(context.Background(), r, 10*time.Second, func(context.Context, time.Duration) error { return nil }); err != nil {
		t.Errorf("le verrou doit être rendu : %v", err)
	}
}

func TestReleveAnnule(t *testing.T) {
	r := t.TempDir()
	echantillon1(t, r)
	ctx, annule := context.WithCancel(context.Background())
	annule()
	_, err := Mesurer(ctx, r, 10*time.Second, func(c context.Context, _ time.Duration) error { return c.Err() })
	if err == nil {
		t.Error("une annulation doit remonter")
	}
}

func TestReleveResoutApresLeTop(t *testing.T) {
	r := t.TempDir()
	echantillon1(t, r)
	for i := 100; i < 150; i++ {
		ecrire(t, r, "proc/"+strconv.Itoa(i)+"/stat", stat(0, 0))
	}
	var lectures int
	avant := lirePSS
	lirePSS = func(racine string, pid int) int { lectures++; return avant(racine, pid) }
	defer func() { lirePSS = avant }()
	rel, err := Mesurer(context.Background(), r, 10*time.Second, func(context.Context, time.Duration) error {
		echantillon2(t, r)
		for i := 100; i < 150; i++ {
			ecrire(t, r, "proc/"+strconv.Itoa(i)+"/stat", stat(i, 0))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if lectures > 10 || len(rel.Top) != 10 {
		t.Errorf("lectures PSS = %d, top = %d", lectures, len(rel.Top))
	}
}
