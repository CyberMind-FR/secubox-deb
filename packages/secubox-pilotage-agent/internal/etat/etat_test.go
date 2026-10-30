// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package etat

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// platBox : un relevé complet de box, secrets et données personnelles compris, comme les sources le rendent.
func platBox() map[string]any {
	return map[string]any{
		"Device.DeviceInfo.SerialNumber":                     "SN-0042-SECRET",
		"Device.DeviceInfo.ModelName":                        "ESPRESSObin",
		"Device.DeviceInfo.MemoryStatus.Total":               uint64(951 * 1024),
		"Device.DeviceInfo.MemoryStatus.X_SECUBOX_Available": uint64(534 * 1024),
		"Device.DeviceInfo.MemoryStatus.X_SECUBOX_SwapTotal": uint64(950 * 1024),
		"Device.DeviceInfo.MemoryStatus.X_SECUBOX_SwapUsed":  uint64(95 * 1024),
		"Device.DeviceInfo.ProcessStatus.Process.1.Command":  "sshd: alice@pts/0",
		"Device.X_SECUBOX_Mesh.Address":                      "10.10.0.5",
		"Device.X_SECUBOX_Exposure.Names":                    []any{"admin.gk5.secubox.in"},
		"Device.X_SECUBOX_Pilotage.MainsLiees":               true,
		"Device.X_SECUBOX_Pilotage.Profil":                   "distante",
		"Device.X_SECUBOX_Services.FailedNumberOfEntries":    uint64(2),
		"Device.X_SECUBOX_Services.1.Name":                   "secubox-dns-guard.service",
		"Device.X_SECUBOX_Services.1.ActiveState":            "failed",
		"Device.X_SECUBOX_Services.2.Name":                   "nginx.service",
		"Device.X_SECUBOX_Services.2.ActiveState":            "active",
		"Device.X_SECUBOX_Services.3.Name":                   "<script>alert(1)</script>.service",
		"Device.X_SECUBOX_Services.3.ActiveState":            "failed",
		"Device.X_SECUBOX_Services.4.Name":                   "secubox-wireguard.service",
		"Device.X_SECUBOX_Services.4.ActiveState":            "failed",
		"Device.X_SECUBOX_Pilotage.Jeton":                    "eyJhbGciOiJIUzI1NiJ9.secret",
	}
}

func TestDepuisReleve(t *testing.T) {
	e := Depuis("gk5", MaitreJoignable, platBox(), time.Unix(1800000000, 0))
	if e.Nom != "gk5" || e.Maitre != MaitreJoignable || !e.MainsLiees {
		t.Fatalf("état = %+v", e)
	}
	if e.MemDispoMo != 534 || e.MemTotaleMo != 951 || e.SwapPct != 10 {
		t.Errorf("mémoire = %+v", e)
	}
	// Seuls les noms d'unité sûrs ; le nom forgé est écarté, jamais affiché.
	if strings.Join(e.Echecs, ",") != "secubox-dns-guard.service,secubox-wireguard.service" {
		t.Errorf("échecs = %v", e.Echecs)
	}
}

// TestEtatSansSecret : la page ne contient rien d'autre que nom, maître, mains liées, mémoire et services en échec.
func TestEtatSansSecret(t *testing.T) {
	page := string(Rendre(Depuis("gk5", MaitreInjoignable, platBox(), time.Unix(1800000000, 0))))
	for _, interdit := range []string{"SN-0042", "10.10.0.5", "alice", "eyJ", "secret", "admin.gk5", "ESPRESSObin", "<script>alert",
		"Jeton", "jeton", "token", "password"} {
		if strings.Contains(page, interdit) {
			t.Errorf("la page contient %q", interdit)
		}
	}
	if regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`).MatchString(page) {
		t.Errorf("la page contient une adresse IPv4")
	}
	for _, attendu := range []string{"gk5", "injoignable", "534", "secubox-dns-guard.service"} {
		if !strings.Contains(page, attendu) {
			t.Errorf("la page ne contient pas %q", attendu)
		}
	}
	// Ni script, ni ressource externe, ni formulaire : la CSP du gabarit nginx (default-src 'none') le garantit aussi.
	for _, interdit := range []string{"<script", "<form", "<iframe", "<img", "<link", "http://", "https://", "style=\""} {
		if strings.Contains(page, interdit) {
			t.Errorf("la page contient %q", interdit)
		}
	}
}

func TestNomForgeEchappe(t *testing.T) {
	page := string(Rendre(Depuis("<b>x</b>", MaitreInconnu, nil, time.Unix(0, 0))))
	if strings.Contains(page, "<b>x</b>") {
		t.Errorf("nom non échappé")
	}
}

// TestEtatLocalSansMaitre : sans maître (aucune interface du maillage), la page est écrite quand même, à la cadence voulue.
func TestEtatLocalSansMaitre(t *testing.T) {
	d := t.TempDir()
	chemin := filepath.Join(d, "etat.html")
	ctx, fin := context.WithCancel(context.Background())
	tours := 0
	lire := func(ctx context.Context) Etat {
		tours++
		if tours == 2 {
			fin()
		}
		return Depuis("gk5", MaitreInconnu, map[string]any{"Device.DeviceInfo.MemoryStatus.X_SECUBOX_Available": uint64(300 * 1024)}, time.Now())
	}
	Tourner(ctx, time.Millisecond, chemin, lire)
	b, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "inconnu") || !strings.Contains(string(b), "300") {
		t.Errorf("page = %s", b)
	}
	st, _ := os.Stat(chemin)
	if st.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v", st.Mode())
	}
	if tours < 2 {
		t.Errorf("tours = %d", tours)
	}
	// Écriture atomique : aucun fichier temporaire ne reste.
	ents, _ := os.ReadDir(d)
	if len(ents) != 1 {
		t.Errorf("fichiers restants : %v", ents)
	}
}

func TestEcrireRefuseUnLien(t *testing.T) {
	d := t.TempDir()
	cible := filepath.Join(d, "ailleurs")
	os.WriteFile(cible, []byte("x"), 0o600)
	os.Symlink(cible, filepath.Join(d, temporaire))
	if err := Ecrire(filepath.Join(d, "etat.html"), []byte("y")); err == nil {
		t.Errorf("écriture à travers un lien acceptée")
	}
	if b, _ := os.ReadFile(cible); string(b) != "x" {
		t.Errorf("cible du lien modifiée")
	}
}

// TestHashStyle : l'empreinte de la feuille de style, que le gabarit nginx autorise seule (CSP style-src).
func TestHashStyle(t *testing.T) {
	h := sha256.Sum256([]byte(Style))
	if got := "sha256-" + base64.StdEncoding.EncodeToString(h[:]); got != EmpreinteStyle {
		t.Errorf("EmpreinteStyle = %s, attendu %s", EmpreinteStyle, got)
	}
	if !strings.Contains(string(Rendre(Etat{})), "<style>"+Style+"</style>") {
		t.Errorf("style absent ou altéré")
	}
}
