// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package main

import (
	"encoding/json"
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
