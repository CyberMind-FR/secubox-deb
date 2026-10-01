// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"encoding/base64"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Registre de sessions DE TEST (#1814) : les jetons de membre des tests y sont
// inscrits, comme secubox-auth inscrit une session ouverte.
var (
	registreTestMu sync.Mutex
	registreTestID []map[string]any
)

func TestMain(m *testing.M) {
	d, _ := os.MkdirTemp("", "bbs-sessions-")
	os.Setenv("SECUBOX_AUTH_SESSIONS", filepath.Join(d, "sessions.json"))
	ecrisRegistreTest()
	code := m.Run()
	os.RemoveAll(d)
	os.Exit(code)
}

func ecrisRegistreTest() {
	b, _ := json.Marshal(registreTestID)
	_ = os.WriteFile(os.Getenv("SECUBOX_AUTH_SESSIONS"), b, 0o644)
}

func inscrisSessionTest() string {
	o := make([]byte, 8)
	_, _ = rand.Read(o)
	jti := hex.EncodeToString(o)
	registreTestMu.Lock()
	registreTestID = append(registreTestID, map[string]any{"id": jti})
	ecrisRegistreTest()
	registreTestMu.Unlock()
	return jti
}

func retireSessionTest(jti string) {
	registreTestMu.Lock()
	defer registreTestMu.Unlock()
	reste := registreTestID[:0]
	for _, l := range registreTestID {
		if l["id"] != jti {
			reste = append(reste, l)
		}
	}
	registreTestID = reste
	ecrisRegistreTest()
	// le cache se fie à mtime+taille : on s'assure que l'un des deux bouge
	time.Sleep(10 * time.Millisecond)
}

func TestControleSession(t *testing.T) {
	jti := inscrisSessionTest()
	now := float64(time.Now().Unix())
	cas := []struct {
		nom string
		cl  map[string]any
		ok  bool
	}{
		{"session vivante", map[string]any{"jti": jti, "exp": now + 60}, true},
		{"session inconnue", map[string]any{"jti": "absente", "exp": now + 60}, false},
		{"jeton d'intention", map[string]any{"jti": jti, "scope": "mfa-challenge"}, false},
		{"service connu, court", map[string]any{"iss": "metanews", "iat": now, "exp": now + 120}, true},
		{"service connu, trop long", map[string]any{"iss": "metanews", "iat": now, "exp": now + 3600}, false},
		{"service inconnu", map[string]any{"iss": "intrus", "iat": now, "exp": now + 60}, false},
		{"ni jti ni service", map[string]any{"sub": "gk2", "iat": now, "exp": now + 60}, false},
	}
	for _, c := range cas {
		err := controleSession(c.cl, emetteursPasserelle)
		if (err == nil) != c.ok {
			t.Errorf("%s : attendu ok=%v, eu %v", c.nom, c.ok, err)
		}
	}
}

func TestUneSessionDeconnecteeNeSertPlus(t *testing.T) {
	srv := bancAPI(t)
	tok := jetonHS256("le-secret-partage", "admin", time.Hour)
	if err := srv.verifieJeton("Bearer " + tok); err != nil {
		t.Fatalf("session vivante refusée : %v", err)
	}
	var cl map[string]any
	parts := splitJeton(tok)
	_ = json.Unmarshal(parts, &cl)
	retireSessionTest(cl["jti"].(string))
	if err := srv.verifieJeton("Bearer " + tok); err == nil {
		t.Fatal("une session retirée du registre doit être refusée")
	}
}

func splitJeton(tok string) []byte {
	var milieu string
	n := 0
	debut := 0
	for i, r := range tok {
		if r == '.' {
			if n == 0 {
				debut = i + 1
			} else {
				milieu = tok[debut:i]
			}
			n++
		}
	}
	b, _ := decodeB64(milieu)
	return b
}

func decodeB64(s string) ([]byte, error) {
	return base64RawURL(s)
}

func base64RawURL(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
