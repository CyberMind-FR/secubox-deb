// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func faux(t *testing.T, corps string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "systemctl")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+corps), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLanceurRendLaSortie(t *testing.T) {
	p := faux(t, "echo \"args=$*\"\n")
	b, err := lanceurSystemctl(p, 2*time.Second)(context.Background(), "show", "x")
	if err != nil || strings.TrimSpace(string(b)) != "args=show x" {
		t.Fatalf("%q %v", b, err)
	}
}

func TestLanceurTueAuDelai(t *testing.T) {
	pidf := filepath.Join(t.TempDir(), "pid")
	// le script lance un petit-fils qui garde la sortie ouverte : tout le groupe doit tomber
	fils := filepath.Join(t.TempDir(), "fils")
	p := faux(t, "echo $$ > "+pidf+"\nsleep 30 &\necho $! > "+fils+"\nwait\n")
	debut := time.Now()
	_, err := lanceurSystemctl(p, 500*time.Millisecond)(context.Background(), "show")
	if err == nil {
		t.Fatal("une erreur était attendue au délai")
	}
	if d := time.Since(debut); d > 2*time.Second {
		t.Fatalf("trop long : %v", d)
	}
	b, _ := os.ReadFile(pidf)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if pid == 0 {
		t.Fatal("pid non écrit")
	}
	fb, _ := os.ReadFile(fils)
	pf, _ := strconv.Atoi(strings.TrimSpace(string(fb)))
	if pf == 0 {
		t.Fatal("pid du petit-fils non écrit")
	}
	for _, p := range []int{pid, pf} {
		mort := false
		for i := 0; i < 100 && !mort; i++ { // borne : 2 s
			mort = !vivant(p)
			if !mort {
				time.Sleep(20 * time.Millisecond)
			}
		}
		if !mort {
			t.Fatalf("le processus %d existe encore", p)
		}
	}
}

// vivant : le processus existe et n'est pas un zombie en attente de récolte.
func vivant(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	s := string(b)
	return !strings.HasPrefix(strings.TrimSpace(s[strings.LastIndexByte(s, ')')+1:]), "Z")
}

func TestLanceurAnnulation(t *testing.T) {
	p := faux(t, "exec sleep 30\n")
	ctx, annule := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); annule() }()
	debut := time.Now()
	if _, err := lanceurSystemctl(p, 10*time.Second)(ctx, "show"); err == nil || time.Since(debut) > 2*time.Second {
		t.Fatalf("err=%v après %v", err, time.Since(debut))
	}
}

func TestLanceurSortieBornee(t *testing.T) {
	p := faux(t, "head -c 3000000 /dev/zero\n")
	b, err := lanceurSystemctl(p, 5*time.Second)(context.Background(), "show")
	if err != nil || len(b) > maxSortieSystemctl {
		t.Fatalf("len=%d err=%v", len(b), err)
	}
}

// TestLanceurEntree (R-L2-2) : l'entrée standard est écrite au programme (le code de maillage-rejoindre), l'argv
// reste celui reçu ; sans entrée, le programme lit une entrée vide (jamais celle de l'agent).
func TestLanceurEntree(t *testing.T) {
	p := faux(t, "printf 'args=%s;' \"$*\"; cat\n")
	b, err := lanceurEntree(p, 2*time.Second)(context.Background(), []byte("sbxmesh1.x.abcd\n"), "-n", "verbe")
	if err != nil || string(b) != "args=-n verbe;sbxmesh1.x.abcd\n" {
		t.Fatalf("%q %v", b, err)
	}
	b, err = lanceurSystemctl(p, 2*time.Second)(context.Background(), "show")
	if err != nil || string(b) != "args=show;" {
		t.Fatalf("%q %v", b, err)
	}
}
