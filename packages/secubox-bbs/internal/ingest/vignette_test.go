// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package ingest

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// #1049 — la mosaïque a besoin d'une VIGNETTE par tuile. PeerTube expose
// `thumbnailPath` ; le collecteur doit en faire une URL de poster (relayée
// localement plus loin), sinon la tuile n'a rien à montrer.
func TestDepuisPeerTubeExtraitLaVignette(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"data":[{"uuid":"u1","shortUUID":"s1",` +
				`"name":"Une vidéo","publishedAt":"2026-08-19T10:00:00.000Z",` +
				`"thumbnailPath":"/static/thumbnails/u1.jpg","privacy":{"id":1}}]}`))
		}))
	defer srv.Close()

	items, err := DepuisPeerTube(srv.URL, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("len = %d, veut 1", len(items))
	}
	want := srv.URL + "/static/thumbnails/u1.jpg"
	if items[0].Vignette != want {
		t.Fatalf("Vignette = %q, veut %q", items[0].Vignette, want)
	}
}
