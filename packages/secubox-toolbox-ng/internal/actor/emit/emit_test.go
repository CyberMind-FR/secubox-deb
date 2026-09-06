// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package emit

import (
	"bufio"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
)

func env(ip string) *envelope.Envelope {
	return &envelope.Envelope{EventID: envelope.NewEventID(), Timestamp: time.Now().Unix(),
		Sensor: envelope.SensorWAF, SrcIP: ip, Severity: 50}
}

func TestEmit_Recu(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "actord.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var recu atomic.Int64
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		sc := bufio.NewScanner(c)
		for sc.Scan() {
			if len(sc.Bytes()) > 0 {
				recu.Add(1)
			}
		}
	}()

	e := New(sock, 16)
	for i := 0; i < 3; i++ {
		if !e.Emit(env("203.0.113.7")) {
			t.Fatal("Emit aurait dû mettre en file")
		}
	}
	// laisser le goroutine d'envoi écouler la file
	deadline := time.Now().Add(2 * time.Second)
	for recu.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	e.Close()
	if recu.Load() != 3 {
		t.Fatalf("reçu %d enveloppes, attendu 3", recu.Load())
	}
	if e.Sent() != 3 {
		t.Errorf("Sent = %d, attendu 3", e.Sent())
	}
}

// Sans actord à l'écoute, Emit ne bloque JAMAIS le producteur et dépose.
func TestEmit_NonBloquantSansConsommateur(t *testing.T) {
	e := New(filepath.Join(t.TempDir(), "absent.sock"), 2)
	defer e.Close()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			e.Emit(env("1.2.3.4")) // ne doit jamais bloquer
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Emit a bloqué le producteur alors qu'actord est absent")
	}
	// laisser le loop tenter/échouer, puis vérifier qu'on a bien déposé.
	time.Sleep(100 * time.Millisecond)
	if e.Dropped() == 0 {
		t.Error("des enveloppes auraient dû être déposées (actord absent)")
	}
}
