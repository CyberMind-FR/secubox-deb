// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package connectors

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
)

func clientVers(t *testing.T, corps string) *ClientYtsas {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(corps))
	}))
	t.Cleanup(srv.Close)
	return &ClientYtsas{Base: srv.URL, HTTP: &http.Client{Timeout: time.Second}}
}

func TestYouTubeReconnaitEtGardeLOriginal(t *testing.T) {
	yt := NouveauYouTube(clientVers(t, `{"video_id":"dQw4w9WgXcQ","state":"pending"}`), "gk2")
	c, err := yt.Resoudre("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
	if err != nil {
		t.Fatal(err)
	}
	if c.Genre != gateway.GenreVideo {
		t.Fatalf("genre %q", c.Genre)
	}
	if c.SourceURL != "https://www.youtube.com/watch?v=dQw4w9WgXcQ" {
		t.Fatalf("l'original (failover) doit être conservé : %q", c.SourceURL)
	}
	if c.Metadonnees["video_id"] != "dQw4w9WgXcQ" || c.Metadonnees["source"] != "youtube" || c.Metadonnees["etat"] != "pending" {
		t.Fatalf("tags de provenance manquants : %+v", c.Metadonnees)
	}
}

func TestYouTubeMiroirPoseUneReplique(t *testing.T) {
	yt := NouveauYouTube(clientVers(t, `{"video_id":"dQw4w9WgXcQ","state":"mirror","peertube_url":"https://peertube.gk2/w/xy"}`), "gk2")
	c, _ := yt.Resoudre("https://youtu.be/dQw4w9WgXcQ")
	if len(c.Repliques) != 1 || c.Repliques[0].Cible != "peertube" || c.Repliques[0].CibleURL != "https://peertube.gk2/w/xy" {
		t.Fatalf("réplique miroir attendue : %+v", c.Repliques)
	}
	if c.Metadonnees["etat"] != "mirror" {
		t.Fatalf("état %q", c.Metadonnees["etat"])
	}
}

func TestYouTubeYtsasHSRetombeSurWAN(t *testing.T) {
	yt := NouveauYouTube(&ClientYtsas{Base: "http://127.0.0.1:1", HTTP: &http.Client{Timeout: 150 * time.Millisecond}}, "gk2")
	c, err := yt.Resoudre("https://youtu.be/dQw4w9WgXcQ")
	if err != nil {
		t.Fatalf("un ytsas HS ne doit PAS faire échouer le rendu : %v", err)
	}
	if c.Metadonnees["etat"] != "pending" {
		t.Fatalf("ytsas HS → WAN (pending) attendu, eu %q", c.Metadonnees["etat"])
	}
	if c.SourceURL == "" {
		t.Fatal("l'original doit rester")
	}
}
