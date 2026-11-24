// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// #3899 : une adresse en attente n'est mise en file qu'une fois, même redemandée à chaque relevé.
func TestPTRUneSeuleMiseEnFile3899(t *testing.T) {
	n := nommeurNu(t)
	for i := 0; i < 5; i++ {
		n.Nomme("1.2.3.4")
	}
	if len(n.file) != 1 {
		t.Fatalf("adresse en attente remise en file : file=%d", len(n.file))
	}
}

// #3899 : cache plein → la nouvelle réponse est quand même mémorisée (sinon redemandée sans fin).
func TestPTRCachePleinMemoriseQuandMeme3899(t *testing.T) {
	n := nommeurNu(t)
	for i := 0; i < ptrCap; i++ {
		n.ptr[fmt.Sprintf("10.0.%d.%d", i/250, i%250)] = ""
	}
	n.inverse = func(context.Context, string) ([]string, error) { return []string{"hote.exemple."}, nil }
	n.Nomme("1.2.3.4")
	n.resoutPTR(context.Background(), <-n.file)
	if id := n.Nomme("1.2.3.4"); id.Nom != "hote.exemple" {
		t.Fatalf("réponse perdue cache plein : %+v", id)
	}
	if len(n.ptr) > ptrCap {
		t.Fatalf("cache au-delà du plafond : %d", len(n.ptr))
	}
	if len(n.file) != 0 {
		t.Fatalf("adresse connue remise en file")
	}
}

// #3899 : un échec expire (1 h) et la réponse est alors redemandée, une fois.
func TestPTREchecExpire3899(t *testing.T) {
	n := nommeurNu(t)
	maintenant := time.Unix(1_800_000_000, 0)
	n.now = func() time.Time { return maintenant }
	n.inverse = func(context.Context, string) ([]string, error) { return nil, fmt.Errorf("nxdomain") }
	n.Nomme("1.2.3.4")
	n.resoutPTR(context.Background(), <-n.file)
	n.Nomme("1.2.3.4")
	if len(n.file) != 0 {
		t.Fatalf("échec récent redemandé")
	}
	maintenant = maintenant.Add(ptrTTLNegatif + time.Second)
	n.Nomme("1.2.3.4")
	if len(n.file) != 1 {
		t.Fatalf("échec expiré non redemandé : file=%d", len(n.file))
	}
}
