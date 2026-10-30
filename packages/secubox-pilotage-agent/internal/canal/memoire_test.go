// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package canal

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/relais"
)

// PicMemoireAgentMax : plafond du tas mesuré pour un échange de taille maximale (4 Mio à l'aller et au retour) ;
// l'unité prend GOMEMLIMIT au-dessus et MemoryMax au-dessus encore (README, R-L5-21 M6).
const PicMemoireAgentMax = 28 << 20

// TestAgentMemoireEchangeMaximal (R-L5-21 M6) : l'agent tourne SEUL dans un processus enfant (ce binaire relancé,
// GOGC=10, HeapAlloc échantillonné toutes les 200 µs) ; le maître et le relais factices restent dans le parent.
func TestAgentMemoireEchangeMaximal(t *testing.T) {
	corps := base64.StdEncoding.EncodeToString(make([]byte, relais.CorpsMax))
	f := demarrerFauxRelais(t, func(relais.Demande) string {
		return `{"statut":200,"entetes":{},"corps_b64":"` + corps + `"}`
	})
	var servi atomic.Bool
	recu := make(chan int, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/canal/v1/requetes":
			if servi.CompareAndSwap(false, true) {
				io.WriteString(w, `[{"msg_id":"00000000000000a1","type":"HTTP","body":`+
					`{"methode":"POST","chemin":"/api/v1/demo/x","acteur":"admin","maitre":"gk2","portee":"admin","corps_b64":"`+corps+`"}}]`)
				return
			}
			time.Sleep(50 * time.Millisecond)
			w.WriteHeader(http.StatusNoContent)
		case "/canal/v1/http":
			b, _ := io.ReadAll(r.Body)
			select {
			case recu <- len(b):
			default:
			}
		default:
			io.Copy(io.Discard, r.Body)
		}
	}))
	defer srv.Close()
	enfant := exec.Command(os.Args[0], "-test.run=^TestAideAgentEnfant$")
	enfant.Env = append(os.Environ(), "SBX_AGENT_ENFANT="+strings.TrimPrefix(srv.URL, "http://"), "SBX_AGENT_RELAIS="+f.chemin, "GOGC=10")
	entree, _ := enfant.StdinPipe()
	var sortie bytes.Buffer
	enfant.Stdout = &sortie
	if err := enfant.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-recu:
		if n < len(corps) {
			t.Fatalf("HTTP_RESP tronquée : %d octets", n)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("aucune HTTP_RESP")
	}
	entree.Close()
	if err := enfant.Wait(); err != nil {
		t.Fatalf("enfant : %v\n%s", err, sortie.String())
	}
	var pic uint64
	s := sortie.String()
	if i := strings.Index(s, "PIC="); i < 0 {
		t.Fatalf("sortie de l'enfant : %q", s)
	} else {
		fmt.Sscanf(s[i+4:], "%d", &pic)
	}
	t.Logf("pic de tas de l'agent seul : %.1f Mio", float64(pic)/(1<<20))
	if pic > PicMemoireAgentMax {
		t.Fatalf("pic %.1f Mio > %d Mio", float64(pic)/(1<<20), PicMemoireAgentMax>>20)
	}
}

// TestAideAgentEnfant : l'agent seul, pour TestAgentMemoireEchangeMaximal (sans effet hors de ce test).
func TestAideAgentEnfant(t *testing.T) {
	maitre := os.Getenv("SBX_AGENT_ENFANT")
	if maitre == "" {
		t.Skip("processus enfant de TestAgentMemoireEchangeMaximal seulement")
	}
	c := NouveauClient(Config{Maitre: maitre, Attente: time.Second, CheminRelais: os.Getenv("SBX_AGENT_RELAIS"),
		PorteeAdmin: func(context.Context) bool { return true }, Ancre: func(context.Context) Verdict { return AncreOK }},
		modeleTest(nil), nil)
	ctx, fin := context.WithCancel(context.Background())
	var g sync.WaitGroup
	g.Add(1)
	go func() { defer g.Done(); _ = c.Tourner(ctx, nil) }()
	var pic atomic.Uint64
	arret := make(chan struct{})
	go func() {
		var ms runtime.MemStats
		for {
			select {
			case <-arret:
				return
			default:
			}
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > pic.Load() {
				pic.Store(ms.HeapAlloc)
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()
	_, _ = io.Copy(io.Discard, os.Stdin)
	close(arret)
	fin()
	g.Wait()
	fmt.Printf("PIC=%d\n", pic.Load())
}
