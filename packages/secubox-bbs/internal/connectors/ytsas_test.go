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
)

func TestClientYtsasResoudreMirror(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ytsas/resolve" {
			t.Fatalf("chemin %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"video_id":"dQw4w9WgXcQ","state":"mirror","peertube_url":"https://peertube.gk2/w/xy"}`))
	}))
	defer srv.Close()

	c := &ClientYtsas{Base: srv.URL, HTTP: &http.Client{Timeout: time.Second}}
	res, err := c.Resoudre("https://youtu.be/dQw4w9WgXcQ")
	if err != nil {
		t.Fatal(err)
	}
	if res.Etat != "mirror" || res.PeertubeURL != "https://peertube.gk2/w/xy" || res.VideoID != "dQw4w9WgXcQ" {
		t.Fatalf("résolution inattendue : %+v", res)
	}
}

func TestClientYtsasHorsService(t *testing.T) {
	c := &ClientYtsas{Base: "http://127.0.0.1:1", HTTP: &http.Client{Timeout: 200 * time.Millisecond}}
	if _, err := c.Resoudre("https://youtu.be/dQw4w9WgXcQ"); err == nil {
		t.Fatal("une panne ytsas doit remonter une erreur (le connecteur retombera sur WAN)")
	}
}
