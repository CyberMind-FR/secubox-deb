// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fauxBanneurDuree struct {
	mu  sync.Mutex
	ips map[string]time.Duration
	cat map[string]string
}

func (f *fauxBanneurDuree) BanFor(ip, cat, sev string, d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ips == nil {
		f.ips, f.cat = map[string]time.Duration{}, map[string]string{}
	}
	f.ips[ip], f.cat[ip] = d, cat
}

// ecritLigne écrit une entrée du journal de menaces.
func ecritLigne(t *testing.T, f *os.File, ip, path, action, categorie, negspace, tool, ja4 string) {
	t.Helper()
	b, _ := json.Marshal(logEntry{Timestamp: time.Now().Format(time.RFC3339), ClientIP: ip, Host: "x.example.org", Method: "GET", Path: path,
		Category: categorie, Severity: "high", Action: action, Tool: tool, JA4: ja4, NegativeSpace: negspace})
	f.Write(append(b, '\n'))
}

// ecritCampagne : n adresses sondent le même jeu de chemins, `hv` en haute valeur chacune.
func ecritCampagne(t *testing.T, f *os.File, ips []string, hv int, tool string) {
	for _, ip := range ips {
		for i := 0; i < 6; i++ {
			ecritLigne(t, f, ip, fmt.Sprintf("/probe/%d", i), "detect", "recon", "known_negative", tool, "")
		}
		for i := 0; i < hv; i++ {
			ecritLigne(t, f, ip, "/.env", "detect", "recon", pathHighValueProbe, tool, "")
		}
	}
}

func montageCampagne(t *testing.T, mode string) (*CampagneBan, *os.File, *fauxBanneurDuree) {
	t.Helper()
	dir := t.TempDir()
	journal, err := os.Create(filepath.Join(dir, "waf-threats.log"))
	if err != nil {
		t.Fatal(err)
	}
	fb := &fauxBanneurDuree{}
	c := NewCampagneBan(journal.Name(), mode, NewBanStore(filepath.Join(dir, "bans.jsonl")), fb)
	c.protegees = parseCIDRs("203.0.113.200/32")
	return c, journal, fb
}

func TestCampagne_BanLesMembresAvecPreuveDeHauteValeur(t *testing.T) {
	c, j, fb := montageCampagne(t, "auto")
	ecritCampagne(t, j, []string{"198.51.100.10", "198.51.100.11", "198.51.100.12"}, 2, "scanner-x")
	c.Tick()
	if len(fb.ips) != 3 || fb.ips["198.51.100.10"] != 4*time.Hour || fb.cat["198.51.100.10"][:9] != "campagne:" {
		t.Fatalf("3 adresses bannies 4 h attendues, obtenu %v %v", fb.ips, fb.cat)
	}
}

func TestCampagne_UneAdresseSeuleOuSansHauteValeurNEstPasBannie(t *testing.T) {
	c, j, fb := montageCampagne(t, "auto")
	ecritCampagne(t, j, []string{"198.51.100.20"}, 3, "scanner-solo")                   // une seule adresse : pas une campagne
	ecritCampagne(t, j, []string{"198.51.100.30", "198.51.100.31"}, 0, "scanner-bruit") // campagne sans sonde de haute valeur
	c.Tick()
	if len(fb.ips) != 0 {
		t.Fatalf("aucun ban attendu, obtenu %v", fb.ips)
	}
}

func TestCampagne_RobotsConnusEtAutoTestJamaisBannis(t *testing.T) {
	c, j, fb := montageCampagne(t, "auto")
	for _, ip := range []string{"198.51.100.40", "198.51.100.41"} {
		for i := 0; i < 8; i++ {
			ecritLigne(t, j, ip, "/.env", "robot", "robots", pathHighValueProbe, "meta-externalagent", "")
		}
	}
	c.Tick()
	if len(fb.ips) != 0 {
		t.Fatalf("un robot connu ne doit jamais être banni, obtenu %v", fb.ips)
	}
}

func TestCampagne_ProtegeesEtPriveesEcartees(t *testing.T) {
	c, j, fb := montageCampagne(t, "auto")
	ecritCampagne(t, j, []string{"203.0.113.200", "192.168.1.77", "198.51.100.50", "198.51.100.51"}, 2, "scanner-y")
	c.Tick()
	if _, ok := fb.ips["203.0.113.200"]; ok {
		t.Fatal("plage protégée bannie")
	}
	if _, ok := fb.ips["192.168.1.77"]; ok {
		t.Fatal("adresse privée bannie")
	}
	if len(fb.ips) != 2 {
		t.Fatalf("les deux autres adresses attendues, obtenu %v", fb.ips)
	}
}

func TestCampagne_ModeProposeNAppliqueRienEtEcritLEtat(t *testing.T) {
	c, j, fb := montageCampagne(t, "propose")
	c.etat = filepath.Join(filepath.Dir(j.Name()), "etat.json")
	ecritCampagne(t, j, []string{"198.51.100.60", "198.51.100.61"}, 2, "scanner-z")
	c.Tick()
	if len(fb.ips) != 0 {
		t.Fatalf("propose n'applique rien, obtenu %v", fb.ips)
	}
	b, err := os.ReadFile(c.etat)
	if err != nil || !json.Valid(b) {
		t.Fatalf("état attendu, err=%v", err)
	}
}

func TestCampagne_PlafondHoraireEtRecidive(t *testing.T) {
	c, j, fb := montageCampagne(t, "auto")
	c.maxParHeure = 2
	ecritCampagne(t, j, []string{"198.51.100.70", "198.51.100.71", "198.51.100.72", "198.51.100.73"}, 2, "scanner-w")
	c.Tick()
	if len(fb.ips) != 2 {
		t.Fatalf("plafond de 2/h attendu, obtenu %d", len(fb.ips))
	}
	// récidive : une adresse déjà bannie par campagne il y a 2 jours monte à 24 h
	c2, j2, fb2 := montageCampagne(t, "auto")
	_ = c2.store.Append(BanRecord{IP: "198.51.100.80", Category: "campagne:abc", At: time.Now().Add(-48 * time.Hour).Unix(), Expires: time.Now().Add(-44 * time.Hour).Unix(), Action: "ban"})
	ecritCampagne(t, j2, []string{"198.51.100.80", "198.51.100.81"}, 2, "scanner-v")
	c2.Tick()
	if fb2.ips["198.51.100.80"] != 24*time.Hour || fb2.ips["198.51.100.81"] != 4*time.Hour {
		t.Fatalf("durées 24 h (récidive) et 4 h attendues, obtenu %v", fb2.ips)
	}
}

func TestCampagne_LaCleJA4NeMelangePasLesAdresses(t *testing.T) {
	// deux visiteurs ordinaires partagent le JA4 d'un navigateur courant ; seule l'adresse qui sonde en haute valeur compte.
	c, j, fb := montageCampagne(t, "auto")
	ecritCampagne(t, j, []string{"198.51.100.90", "198.51.100.91"}, 2, "scanner-q")
	for i := 0; i < 8; i++ {
		ecritLigne(t, j, "198.51.100.99", fmt.Sprintf("/page/%d", i), "warning", "scanner-q", "", "", "t13d1516h2_commun")
	}
	c.Tick()
	if _, ok := fb.ips["198.51.100.99"]; ok {
		t.Fatalf("une adresse sans preuve ne doit pas être bannie : %v", fb.ips)
	}
}
