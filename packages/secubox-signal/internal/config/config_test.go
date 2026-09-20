// SPDX-License-Identifier: LicenseRef-CMSD-1.0
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func ecrire(t *testing.T, contenu string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "signal.toml")
	if err := os.WriteFile(p, []byte(contenu), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFichierAbsentDonneLesDefauts(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "rien.toml"))
	if err != nil {
		t.Fatalf("un fichier absent ne doit pas etre une erreur : %v", err)
	}
	if c.SocketPath != "/run/secubox/signal.sock" {
		t.Errorf("socket = %q", c.SocketPath)
	}
}

// Le defaut le plus important du module : ne PAS conserver les corps.
func TestStoreBodyEstFauxParDefaut(t *testing.T) {
	if Defaults().StoreBody {
		t.Fatal("retention.store_body doit valoir false par defaut (RFC §7)")
	}
}

func TestLectureComplete(t *testing.T) {
	p := ecrire(t, `
[daemon]
socket = "/tmp/s.sock"
[retention]
store_body = true
hours = 72
[sentinel]
max_per_hour = 5
enabled = false
`)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.SocketPath != "/tmp/s.sock" || !c.StoreBody || c.RetentionHours != 72 {
		t.Errorf("relecture incorrecte : %+v", c)
	}
	if c.SentinelMaxHour != 5 || c.SentinelEnabled {
		t.Errorf("section sentinel incorrecte : %+v", c)
	}
}

// Une cle mal orthographiee doit ECHOUER. Ignorer en silence une faute sur
// `store_body` ou `max_per_hour` se paierait cher.
func TestCleInconnueEchoue(t *testing.T) {
	p := ecrire(t, "[retention]\nstore_bodies = true\n")
	if _, err := Load(p); err == nil {
		t.Fatal("une cle inconnue doit etre refusee, pas ignoree")
	}
}

func TestCommentairesEtLignesVides(t *testing.T) {
	p := ecrire(t, "# entete\n\n[daemon]\n  socket = \"/x\"  # en fin de ligne\n")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.SocketPath != "/x" {
		t.Errorf("socket = %q", c.SocketPath)
	}
}
