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
	p := faux(t, "echo $$ > "+pidf+"\nsleep 30 &\nwait\n")
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
	time.Sleep(100 * time.Millisecond)
	if err := syscall.Kill(pid, 0); err == nil {
		t.Fatalf("le processus %d existe encore", pid)
	}
	if err := syscall.Kill(-pid, 0); err == nil {
		t.Fatalf("le groupe %d existe encore", pid)
	}
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
