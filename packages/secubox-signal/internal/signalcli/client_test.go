// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package signalcli

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Un backend qui meurt au demarrage (JVM sans sa bibliotheque native, #1385)
// est RECUEILLI et le client redevient « non demarre » — pas de zombie, pas
// d'appel qui attend son delai pour rien.
func TestBackendMortEstRecueilli(t *testing.T) {
	c := New("/bin/false", t.TempDir(), 5*time.Second)
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	limite := time.Now().Add(3 * time.Second)
	for {
		c.mu.Lock()
		vivant := c.cmd != nil
		c.mu.Unlock()
		if !vivant {
			break
		}
		if time.Now().After(limite) {
			t.Fatal("le processus mort n'a pas ete recueilli")
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, err := c.Call(context.Background(), "version", nil)
	if err == nil || !strings.Contains(err.Error(), "non demarre") {
		t.Fatalf("appel apres la mort du backend : %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop apres la mort : %v", err)
	}
}
