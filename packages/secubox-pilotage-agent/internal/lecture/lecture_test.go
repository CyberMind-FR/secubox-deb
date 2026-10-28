// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
package lecture

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLireRefuseFifo(t *testing.T) {
	f := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(f, 0o600); err != nil {
		t.Skip(err)
	}
	fini := make(chan error, 1)
	go func() { _, err := Lire(f, 128); fini <- err }()
	select {
	case err := <-fini:
		if err == nil {
			t.Error("une FIFO doit être refusée")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Lire bloque sur une FIFO")
	}
}

func TestLireLimiteLaTaille(t *testing.T) {
	d := t.TempDir()
	gros := filepath.Join(d, "gros")
	if err := os.WriteFile(gros, []byte(strings.Repeat("a", 10000)), 0o600); err != nil {
		t.Fatal(err)
	}
	lien := filepath.Join(d, "lien")
	if err := os.Symlink(gros, lien); err != nil {
		t.Fatal(err)
	}
	b, err := Lire(lien, 128)
	if err != nil || len(b) != 128 {
		t.Errorf("len = %d, err = %v", len(b), err)
	}
}

func TestLireRefuseUnRepertoire(t *testing.T) {
	if _, err := Lire(t.TempDir(), 128); err == nil {
		t.Error("un répertoire doit être refusé")
	}
}
