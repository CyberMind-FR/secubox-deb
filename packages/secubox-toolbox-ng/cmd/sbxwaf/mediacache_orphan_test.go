package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// ecritCorps writes a body under the layout loadIndex expects, and lets the
// caller decide whether the sidecar exists.
func ecritCorps(t *testing.T, dir, url, corps, annexe string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(url))
	key := hex.EncodeToString(sum[:])
	sub := filepath.Join(dir, key[:2])
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	body := filepath.Join(sub, key)
	if err := os.WriteFile(body, []byte(corps), 0o644); err != nil {
		t.Fatal(err)
	}
	if annexe != "" {
		if err := os.WriteFile(body+".m", []byte(annexe), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return body
}

// A body with no sidecar carries no Content-Type. Served anyway, net/http
// sniffs it and answers "text/plain" — which makes a browser drop the
// stylesheet and, under nosniff, the script too.
func TestOrphelinSansAnnexeNestPasServi(t *testing.T) {
	dir := t.TempDir()
	url := "https://radio.example/static/radio.js"
	body := ecritCorps(t, dir, url, "var x = 1;\n", "")

	mc := NewMediaCache(dir)
	if _, _, hit := mc.Get(url, ""); hit {
		t.Fatal("un corps sans annexe a ete servi : le type sera devine, donc faux")
	}
	if _, err := os.Stat(body); !os.IsNotExist(err) {
		t.Fatal("le corps orphelin est reste sur le disque, il sera repropose au prochain demarrage")
	}
}

// Same defect, other cause: the sidecar is there but unreadable.
func TestAnnexeIllisibleNestPasServie(t *testing.T) {
	dir := t.TempDir()
	url := "https://radio.example/static/radio.css"
	ecritCorps(t, dir, url, "body{}", "{ceci n'est pas du json")

	if _, _, hit := NewMediaCache(dir).Get(url, ""); hit {
		t.Fatal("annexe illisible servie quand meme")
	}
}

// The guard must not cost us a legitimate hit.
func TestAnnexeValideToujoursServie(t *testing.T) {
	dir := t.TempDir()
	url := "https://radio.example/static/bon.css"
	ecritCorps(t, dir, url, "body{color:red}",
		`{"ct":"text/css","ce":"","exp":33208444800,"url":"`+url+`"}`)

	corps, hd, hit := NewMediaCache(dir).Get(url, "")
	if !hit {
		t.Fatal("une entree saine a ete refusee")
	}
	if got := hd.Get("Content-Type"); got != "text/css" {
		t.Fatalf("type rejoue = %q", got)
	}
	if string(corps) != "body{color:red}" {
		t.Fatalf("corps rejoue = %q", corps)
	}
}
