// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/mesure"
)

func parIP(ms []MesureActeur, ip string) []MesureActeur {
	var out []MesureActeur
	for _, m := range ms {
		for _, x := range m.IPs {
			if x == ip {
				out = append(out, m)
			}
		}
	}
	return out
}

func niveauMax(ms []MesureActeur) mesure.Niveau {
	n := mesure.Observe
	rang := map[mesure.Niveau]int{mesure.Observe: 0, mesure.Delay: 1, mesure.Challenge: 2, mesure.Tarpit: 3, mesure.Deny: 4, mesure.Quarantine: 4}
	for _, m := range ms {
		if rang[m.Niveau] > rang[n] {
			n = m.Niveau
		}
	}
	return n
}

func TestUnActeurMultiCapteursReçoitUneMesureReelle(t *testing.T) {
	s := serveur(t)
	scenario(t, s) // 203.0.113.9 : pare-feu + WAF + DPI, charges d'attaque
	ms, err := s.recalculerMesures(time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	got := parIP(ms, "203.0.113.9")
	if len(got) == 0 || niveauMax(got) == mesure.Observe {
		t.Fatalf("une attaque corrélée sur trois capteurs doit donner une mesure : %+v", ms)
	}
	for _, m := range got {
		if m.Niveau != mesure.Observe && (m.TTLs <= 0 || m.Raison == "" || m.Expire <= m.Depuis) {
			t.Fatalf("toute mesure porte durée, raison et échéance : %+v", m)
		}
	}
}

func TestUnAppareilDuLanEstMarqueLANEtNeRecoitPasDeMesureHTTP(t *testing.T) {
	s := serveur(t)
	base := time.Now().Unix() - 600
	for i := 0; i < 25; i++ {
		ingere(t, s, envelope.Envelope{Timestamp: base + int64(i), Sensor: "waf", SrcIP: "192.168.1.77", DstService: "git.gk2", Severity: 85, BehaviorTags: []string{"sqli", "high_value_probe"}})
	}
	evalues, err := s.evaluerActeurs(time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	vu := false
	for _, x := range evalues {
		for _, ip := range x.Acteur.IPs {
			if ip == "192.168.1.77" {
				vu = true
				if !x.LAN {
					t.Fatalf("toutes ses adresses sont privées : LAN : %+v", x.Acteur.IPs)
				}
			}
		}
	}
	if !vu {
		t.Fatal("l'appareil du LAN est évalué")
	}
	ms, _ := s.recalculerMesures(time.Now().Unix())
	for _, m := range parIP(ms, "192.168.1.77") {
		if m.Niveau != mesure.Quarantine {
			t.Fatalf("jamais de mesure HTTP pour le LAN, seulement l'isolement : %s", m.Niveau)
		}
	}
}

func TestUnActeurQuiInsisteMonteDeCran(t *testing.T) {
	s := serveur(t)
	ip := "198.51.100.44"
	maintenant := time.Now().Unix()
	pose := func(n int, dec int64) {
		for i := 0; i < n; i++ {
			ingere(t, s, envelope.Envelope{Timestamp: maintenant - dec + int64(i), Sensor: "waf", SrcIP: ip, DstService: "git.gk2", Severity: 85, BehaviorTags: []string{"sqli", "high_value_probe"}})
		}
	}
	pose(25, 300)
	s.evT = tampon[[]envelope.Envelope]{} // les événements sont mis en cache 10 s : on repart d'un cache vide pour chaque relevé
	m1, _ := s.recalculerMesures(maintenant)
	n1 := niveauMax(parIP(m1, ip))
	pose(40, 200) // l'acteur continue pendant sa mesure
	s.evT = tampon[[]envelope.Envelope]{}
	m2, _ := s.recalculerMesures(maintenant + 60)
	n2 := niveauMax(parIP(m2, ip))
	rang := map[mesure.Niveau]int{mesure.Observe: 0, mesure.Delay: 1, mesure.Challenge: 2, mesure.Tarpit: 3, mesure.Deny: 4}
	if n1 == mesure.Observe || rang[n2] <= rang[n1] {
		t.Fatalf("insister sous une mesure fait monter d'un cran : %s puis %s", n1, n2)
	}
}

func TestLeFichierDeMesuresEstAtomiqueDateEtLisible(t *testing.T) {
	s := serveur(t)
	scenario(t, s)
	chemin := filepath.Join(t.TempDir(), "actord-mesures.json")
	if err := s.publierMesuresUneFois(chemin, time.Now()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}
	var f FichierMesures
	if json.Unmarshal(b, &f) != nil || f.GenereLe == 0 || len(f.Mesures) == 0 {
		t.Fatalf("fichier daté avec les mesures actives : %s", b)
	}
	for _, m := range f.Mesures {
		if m.Niveau == mesure.Observe {
			t.Fatalf("OBSERVE n'est pas une mesure : elle n'est pas publiée : %+v", m)
		}
	}
	if _, err := os.Stat(chemin + ".tmp"); err == nil {
		t.Fatal("pas de fichier temporaire laissé")
	}
}

func TestLaVueReduiteDonneLesCompteursSansAdresse(t *testing.T) {
	s := serveur(t)
	scenario(t, s)
	s.recalculerMesures(time.Now().Unix())
	rec, corps := appelle(s, "/mesures", false)
	if rec.Code != 200 {
		t.Fatalf("%d", rec.Code)
	}
	if _, ok := corps["par_niveau"]; !ok {
		t.Fatalf("compteurs par niveau : %v", corps)
	}
	if body := rec.Body.String(); contient(body, "203.0.113.9") || contient(body, "ips") {
		t.Fatalf("la vue réduite ne porte jamais d'adresse : %s", body)
	}
	rec, corps = appelle(s, "/mesures", true)
	if _, ok := corps["mesures"]; !ok || rec.Code != 200 {
		t.Fatalf("la vue complète donne les mesures : %v", corps)
	}
}

func contient(s, sous string) bool {
	for i := 0; i+len(sous) <= len(s); i++ {
		if s[i:i+len(sous)] == sous {
			return true
		}
	}
	return false
}

// ── Une mesure ne vise que les adresses qui se sont elles-mêmes mal comportées ──────────────────────────────────────────────────────────────────
func TestIPsHostilesNeGardeQueLesAdressesQuiSeSontMalComportees(t *testing.T) {
	ips := []string{"198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.13"}
	hostiles := map[string]int{"198.51.100.10": 30, "198.51.100.11": 0, "198.51.100.12": mesure.SeuilHostilesIP - 1, "198.51.100.13": mesure.SeuilHostilesIP}
	got := ipsHostiles(ips, hostiles)
	if len(got) != 2 || got[0] != "198.51.100.10" || got[1] != "198.51.100.13" {
		t.Fatalf("seules les adresses qui ont elles-mêmes atteint le seuil : %v", got)
	}
	if len(ipsHostiles(ips, nil)) != 0 {
		t.Fatal("sans aucune preuve individuelle : personne")
	}
}

func TestUneAdresseInnocenteMelangeeAUnAttaquantNEstPasPunie(t *testing.T) {
	s := serveur(t)
	maintenant := time.Now().Unix()
	for i := 0; i < 30; i++ {
		ingere(t, s, envelope.Envelope{Timestamp: maintenant - 200 + int64(i), Sensor: "waf", SrcIP: "198.51.100.10", DstService: "git.gk2", Severity: 85, BehaviorTags: []string{"sqli", "high_value_probe"}})
	}
	ingere(t, s, envelope.Envelope{Timestamp: maintenant - 100, Sensor: "waf", SrcIP: "198.51.100.11", DstService: "git.gk2", Severity: 10})
	s.evT = tampon[[]envelope.Envelope]{}
	ms, err := s.recalculerMesures(maintenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(parIP(ms, "198.51.100.10")) == 0 {
		t.Fatalf("l'adresse qui a attaqué est sous mesure : %+v", ms)
	}
	for _, m := range ms {
		for _, ip := range m.IPs {
			if ip == "198.51.100.11" {
				t.Fatalf("l'adresse qui n'a rien fait n'est jamais sous mesure : %+v", m)
			}
		}
	}
}

func TestUnActeurDontAucuneAdresseEstHostileNAPasDeMesure(t *testing.T) {
	s := serveur(t)
	maintenant := time.Now().Unix()
	for i := 0; i < 30; i++ { // beaucoup d'événements, tous de gravité faible, étalés sur de nombreuses adresses : aucune n'atteint le seuil individuel
		ingere(t, s, envelope.Envelope{Timestamp: maintenant - 200 + int64(i), Sensor: "waf", SrcIP: fmt.Sprintf("198.51.100.%d", 100+i), DstService: "git.gk2", Severity: 45, BehaviorTags: []string{"scanners"}})
	}
	s.evT = tampon[[]envelope.Envelope]{}
	ms, _ := s.recalculerMesures(maintenant)
	for _, m := range ms {
		if len(m.IPs) == 0 {
			t.Fatalf("une mesure sans adresse n'existe pas : %+v", m)
		}
	}
}

func TestUnBanExigeUnePreuveIndividuelleBienPlusForteQueLeRalentissement(t *testing.T) {
	ips := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}
	h := map[string]int{"198.51.100.1": mesure.SeuilHostilesDeny, "198.51.100.2": mesure.SeuilHostilesDeny - 1, "198.51.100.3": mesure.SeuilHostilesIP}
	forts, faibles := repartirDeny(ips, h)
	if len(forts) != 1 || forts[0] != "198.51.100.1" || len(faibles) != 2 {
		t.Fatalf("forts=%v faibles=%v", forts, faibles)
	}
}

func TestUnActeurEnDenyDontCertainesAdressesSontFaiblesLesRalentitSeulement(t *testing.T) {
	s := serveur(t)
	maintenant := time.Now().Unix()
	pose := func(ip string, n int) {
		for i := 0; i < n; i++ {
			ingere(t, s, envelope.Envelope{Timestamp: maintenant - 300 + int64(i), Sensor: "waf", SrcIP: ip, DstService: "git.gk2", Severity: 85, BehaviorTags: []string{"sqli", "high_value_probe"}})
			ingere(t, s, envelope.Envelope{Timestamp: maintenant - 300 + int64(i), Sensor: "dpi", SrcIP: ip, Severity: 80, RuleID: "dpi.risk.malicious_fingerprint"})
		}
	}
	pose("198.51.100.20", 15) // beaucoup d'événements, deux capteurs
	pose("198.51.100.21", 3)  // quelques-uns seulement
	s.evT = tampon[[]envelope.Envelope]{}
	ms, _ := s.recalculerMesures(maintenant)
	fort, faible := niveauMax(parIP(ms, "198.51.100.20")), niveauMax(parIP(ms, "198.51.100.21"))
	if fort == mesure.Observe {
		t.Fatalf("l'adresse très active est sous mesure : %v", ms)
	}
	if faible == mesure.Deny || faible == mesure.Quarantine {
		t.Fatalf("une adresse qui n'a que %d événements n'est jamais bannie sur la réputation de l'acteur : %s", 3*2, faible)
	}
}
