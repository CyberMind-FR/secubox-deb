package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// LE TRAFIC INTERNE S'AGRÈGE SOUS « local » (#1131am) : loopback et LAN ne sont
// pas des attaquants. Sans cela, 127.0.0.1 (health checks, watchdog, agrégateur,
// fetch des métriques) trônait en tête des « attaquants persistants ». Une IP
// PUBLIQUE, elle, reste intacte.
func TestTraficInterneAgregeEnLocal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "waf-threats.log")
	tl := NewThreatLog(path)

	cas := map[string]string{
		"127.0.0.1":     "local", // loopback
		"192.168.1.254": "local", // passerelle LAN
		"10.100.0.1":    "local", // réseau interne
		"::1":           "local", // loopback v6
		"195.178.110.199": "195.178.110.199", // vrai attaquant externe : intact
		"local":           "local",             // idempotent
	}
	for ip := range cas {
		tl.Record(ThreatRecord{ClientIP: ip, Host: "x", Method: "GET", Path: "/",
			Category: "host_anomaly", Severity: "medium", RuleID: "r", Action: "detect"})
	}

	data, _ := os.ReadFile(path)
	got := map[string]bool{}
	for _, line := range splitNonEmpty(string(data)) {
		var e struct {
			ClientIP string `json:"client_ip"`
		}
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("ligne illisible : %v", err)
		}
		got[e.ClientIP] = true
	}
	// Tous les internes doivent être devenus « local » ; l'externe intact.
	if !got["local"] {
		t.Fatal("le trafic interne n'a pas été agrégé sous « local »")
	}
	if !got["195.178.110.199"] {
		t.Fatal("une IP externe a été altérée")
	}
	for _, interne := range []string{"127.0.0.1", "192.168.1.254", "10.100.0.1", "::1"} {
		if got[interne] {
			t.Errorf("l'IP interne %s figure encore telle quelle (faux positif)", interne)
		}
	}
}
