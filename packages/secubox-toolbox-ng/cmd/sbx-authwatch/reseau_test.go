// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reseau"
)

// classeurFactice répond comme un annuaire, sans base mmdb (#3919).
type classeurFactice struct{ vus []string }

func (c *classeurFactice) Classer(ip string) reseau.Info {
	c.vus = append(c.vus, ip)
	if ip == "8.8.8.8" {
		return reseau.Info{ASN: 15169, Org: "Exemple Net", Classe: "hebergeur"}
	}
	return reseau.Info{}
}

func lireLigne(t *testing.T, chemin string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(b))), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestInscritPoseLeReseau(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "menaces.log")
	j := NewJournalMenaces(chemin)
	cf := &classeurFactice{}
	j.SetReseau(cf)
	j.Inscrit(Signal{IP: "8.8.8.8", Service: "smtp", Categorie: "auth", Severite: "high", Cible: "x@exemple.test"}, "warning", 1)
	m := lireLigne(t, chemin)
	if m["asn"].(float64) != 15169 || m["asn_org"] != "Exemple Net" || m["reseau_classe"] != "hebergeur" {
		t.Fatalf("clés réseau absentes : %v", m)
	}
	if _, ok := m["campagne"]; ok {
		t.Fatalf("pas de campagne attendue : %v", m)
	}
}

func TestInscritSansReseauPourLocalOuInconnu(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "menaces.log")
	j := NewJournalMenaces(chemin)
	cf := &classeurFactice{}
	j.SetReseau(cf)
	j.Inscrit(Signal{IP: "192.168.1.5", Service: "ssh", Categorie: "auth", Severite: "low"}, "warning", 1)
	j.Inscrit(Signal{IP: "1.1.1.1", Service: "ssh", Categorie: "auth", Severite: "low"}, "warning", 1)
	b, _ := os.ReadFile(chemin)
	if strings.Contains(string(b), "asn") || strings.Contains(string(b), "reseau_classe") {
		t.Fatalf("clés réseau inattendues : %s", b)
	}
	if len(cf.vus) != 1 || cf.vus[0] != "1.1.1.1" {
		t.Fatalf("l'adresse locale ne doit pas être classée : %v", cf.vus)
	}
}

func TestInscritPoseLaCampagneSeulementSiEtablie(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "menaces.log")
	j := NewJournalMenaces(chemin)
	c := NewCampagnes(time.Hour, 3)
	j.SetCampagnes(c)
	now := time.Now()
	cible := "Gerald@exemple.test"
	for _, ip := range []string{"8.8.8.8", "1.1.1.1"} {
		c.Note(cible, ip, now)
	}
	j.Inscrit(Signal{IP: "8.8.8.8", Service: "smtp", Categorie: "auth", Severite: "high", Cible: cible}, "warning", 1)
	if _, ok := lireLigne(t, chemin)["campagne"]; ok {
		t.Fatal("campagne non établie : pas d'identifiant")
	}
	c.Note(cible, "9.9.9.9", now)
	os.Remove(chemin)
	j.Inscrit(Signal{IP: "8.8.8.8", Service: "smtp", Categorie: "auth", Severite: "high", Cible: cible}, "banned", 3)
	h := sha256.Sum256([]byte("gerald@exemple.test"))
	if got := lireLigne(t, chemin)["campagne"]; got != hex.EncodeToString(h[:])[:8] {
		t.Fatalf("identifiant de campagne = %v", got)
	}
}
