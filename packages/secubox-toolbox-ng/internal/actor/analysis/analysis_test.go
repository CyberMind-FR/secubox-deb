// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package analysis

import (
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
)

const t0 = int64(1_800_000_000)

func ev(i int, dt int64, capteur, regle string, sev int, tags ...string) Event {
	return Event{ID: strings.Repeat("e", 1) + string(rune('a'+i%26)), TS: t0 + dt, Sensor: capteur, Rule: regle, Severity: sev, Tags: tags, SrcIP: "203.0.113.9", Action: "observe"}
}

func TestClasser_ParCapteurRegleEtEtiquette(t *testing.T) {
	cas := []struct {
		e    Event
		want Etape
	}{
		{ev(0, 0, "firewall", "fw.scan.vertical", 60, "port_scan"), EtapeReconnaissance},
		{ev(0, 0, "dns", "dns.dga", 55), EtapeCanalCache},
		{ev(0, 0, "dns", "dns.hijack.new_net", 60), EtapeCanalCache},
		{ev(0, 0, "dpi", "dpi.risk.probing_attempt", 40), EtapeSondage},
		{ev(0, 0, "dpi", "dpi.risk.malicious_fingerprint", 70), EtapeExploitation},
		{ev(0, 0, "waf", "", 50, "scanners"), EtapeSondage},
		{ev(0, 0, "waf", "", 50, "host_anomaly:unrouted"), EtapeSondage},
		{ev(0, 0, "waf", "", 80, "recon", "high_value_probe"), EtapeExploitation},
		{ev(0, 0, "waf", "", 80, "sqli"), EtapeExploitation},
		{ev(0, 0, "waf", "", 70, "leurre:marque-revenue"), EtapeExploitation},
		{ev(0, 0, "authwatch", "ssh_bruteforce/12", 70), EtapeExploitation},
		{ev(0, 0, "waf", "", 10), EtapeSondage}, // inconnu : au mieux un sondage, jamais une exploitation
	}
	for _, c := range cas {
		if got := Classer(c.e); got != c.want {
			t.Errorf("%s/%s %v → %q, attendu %q", c.e.Sensor, c.e.Rule, c.e.Tags, got, c.want)
		}
	}
}

func TestEvenementIsole_NeFaitQueObserver(t *testing.T) {
	r := Evaluer(Entree{Events: []Event{ev(0, 0, "waf", "", 40, "scanners")}, Maintenant: t0 + 10})
	if r.Decision.Niveau != "OBSERVE" || r.Capteurs[0] != "waf" || len(r.Capteurs) != 1 {
		t.Fatalf("un événement isolé reste en observation : %+v", r.Decision)
	}
	if r.Confiance.Valeur >= 50 {
		t.Fatalf("un seul événement ne donne pas une confiance forte : %d", r.Confiance.Valeur)
	}
}

func chaine() []Event {
	return []Event{
		ev(0, 0, "firewall", "fw.scan.vertical", 66, "port_scan"),
		ev(1, 60, "dns", "dns.listed", 80),
		ev(2, 120, "waf", "", 55, "scanners"), ev(3, 130, "waf", "", 55, "host_anomaly:unrouted"), ev(4, 140, "waf", "", 55, "recon_crawler"),
		ev(5, 200, "waf", "", 85, "sqli"), ev(6, 210, "waf", "", 85, "rce"), ev(7, 220, "dpi", "dpi.risk.malicious_fingerprint", 80),
		ev(8, 300, "waf", "", 80, "high_value_probe"), ev(9, 310, "waf", "", 80, "high_value_probe"), ev(10, 320, "waf", "", 80, "leurre:marque-revenue"),
	}
}

func TestChaineMultiCapteurs_ProduitUnScenarioUniqueEtUnBlocExplique(t *testing.T) {
	r := Evaluer(Entree{Events: chaine(), Vecteur: graph.Vector{Automation: 70, Confidence: 90, Persistence: 40}, Maintenant: t0 + 400})
	var ordre []string
	for _, e := range r.Scenario.Etapes {
		ordre = append(ordre, string(e.Etape))
	}
	if strings.Join(ordre, ">") != "reconnaissance>canal_cache>sondage>exploitation" || !r.Scenario.Complet {
		t.Fatalf("scénario ordonné par première apparition attendu : %v complet=%v", ordre, r.Scenario.Complet)
	}
	if r.Risque.Valeur < 75 || r.Confiance.Valeur < 80 || r.Decision.Niveau != "BLOCK" {
		t.Fatalf("BLOCK attendu (risque %d, confiance %d) : %+v", r.Risque.Valeur, r.Confiance.Valeur, r.Decision)
	}
	if len(r.Capteurs) < 3 {
		t.Fatalf("au moins trois capteurs distincts : %v", r.Capteurs)
	}
}

func TestLeRisqueEstLaSommeDeSesFacteurs(t *testing.T) {
	r := Evaluer(Entree{Events: chaine(), Vecteur: graph.Vector{Automation: 70, Confidence: 90}, Maintenant: t0 + 400})
	somme := 0
	for _, f := range r.Risque.Facteurs {
		somme += f.Points
		if f.Libelle == "" || len(f.Preuves) == 0 {
			t.Fatalf("chaque facteur porte un libellé et au moins une preuve : %+v", f)
		}
	}
	if somme < r.Risque.Valeur || (somme > 100 && r.Risque.Valeur != 100) || (somme <= 100 && somme != r.Risque.Valeur) {
		t.Fatalf("la valeur (%d) est la somme plafonnée des facteurs (%d)", r.Risque.Valeur, somme)
	}
}

func TestBlocRefuseSurUnSeulCapteur_MemeAvecUnRisqueEleve(t *testing.T) {
	var evs []Event
	for i := 0; i < 30; i++ {
		evs = append(evs, ev(i, int64(i*10), "waf", "", 90, "sqli", "rce"))
	}
	evs = append(evs, ev(30, 2*86400+10, "waf", "", 90, "sqli")) // la même campagne revient deux jours plus tard
	r := Evaluer(Entree{Events: evs, Vecteur: graph.Vector{Automation: 90, Confidence: 100}, Maintenant: t0 + 400})
	if r.Risque.Valeur < 75 {
		t.Fatalf("scénario conçu pour un risque élevé : %d", r.Risque.Valeur)
	}
	if r.Decision.Niveau == "BLOCK" {
		t.Fatalf("jamais de BLOCK sur un seul capteur : %+v", r.Decision)
	}
	if r.Decision.Niveau != "MITIGATE" || !contient(r.Decision.Refus, "capteur") {
		t.Fatalf("MITIGATE avec le motif du refus attendu : %+v", r.Decision)
	}
}

func TestPanneDeCapteurAbaisseLaConfiance(t *testing.T) {
	base := Evaluer(Entree{Events: chaine(), Vecteur: graph.Vector{Confidence: 90}, Maintenant: t0 + 400})
	muet := Evaluer(Entree{Events: chaine(), Vecteur: graph.Vector{Confidence: 90}, CapteursMuets: []string{"dpi", "dns"}, Maintenant: t0 + 400})
	if muet.Confiance.Valeur >= base.Confiance.Valeur {
		t.Fatalf("des capteurs muets abaissent la confiance : %d vs %d", muet.Confiance.Valeur, base.Confiance.Valeur)
	}
	if muet.Risque.Valeur != base.Risque.Valeur {
		t.Fatalf("la panne n'invente ni ne retire de risque : %d vs %d", muet.Risque.Valeur, base.Risque.Valeur)
	}
}

func TestPersistanceSurPlusieursJours(t *testing.T) {
	evs := []Event{ev(0, 0, "waf", "", 50, "scanners"), ev(1, 2*86400+5, "waf", "", 50, "scanners")}
	r := Evaluer(Entree{Events: evs, Maintenant: t0 + 3*86400})
	var persiste bool
	for _, e := range r.Scenario.Etapes {
		persiste = persiste || e.Etape == EtapePersistance
	}
	if !persiste {
		t.Fatalf("deux jours distincts : étape persistance attendue : %+v", r.Scenario)
	}
}

func TestComportementNormal_UnClientQuiLitUnePageNeLeveRien(t *testing.T) {
	r := Evaluer(Entree{Events: []Event{ev(0, 0, "waf", "", 5), ev(1, 5, "waf", "", 5)}, Maintenant: t0 + 60})
	if r.Risque.Valeur >= 42 || r.Decision.Niveau != "OBSERVE" {
		t.Fatalf("comportement normal : %d %+v", r.Risque.Valeur, r.Decision)
	}
}

func TestAucunEvenement_RienNInvente(t *testing.T) {
	r := Evaluer(Entree{Maintenant: t0})
	if r.Risque.Valeur != 0 || r.Confiance.Valeur != 0 || r.Decision.Niveau != "OBSERVE" || len(r.Scenario.Etapes) != 0 {
		t.Fatalf("sans événement : tout à zéro, jamais d'invention : %+v", r)
	}
}

func contient(l []string, sous string) bool {
	for _, s := range l {
		if strings.Contains(s, sous) {
			return true
		}
	}
	return false
}

func TestGraphe_ActeurIPsCiblesCapteursEtPairs(t *testing.T) {
	g := ConstruireGraphe(EntreeGraphe{ActeurID: "ACT-7", IPs: []string{"203.0.113.9", "192.168.1.60"}, ASNs: []string{"AS54113"}, Pays: []string{"US"},
		Cibles: []string{"git.gk2", "nc.gk2"}, Pairs: []string{"ACT-9"}, Events: chaine()})
	types := map[string]int{}
	for _, n := range g.Noeuds {
		types[n.Type]++
	}
	if types["acteur"] != 1 || types["ip"] != 1 || types["appareil"] != 1 || types["cible"] != 2 || types["asn"] != 1 || types["pays"] != 1 || types["autre_acteur"] != 1 || types["capteur"] != 4 {
		t.Fatalf("typage des nœuds : %v", types)
	}
	relations := map[string]bool{}
	ids := map[string]bool{}
	for _, n := range g.Noeuds {
		ids[n.ID] = true
	}
	for _, l := range g.Liens {
		relations[l.Relation] = true
		if !ids[l.De] || !ids[l.Vers] {
			t.Fatalf("lien vers un nœud inexistant : %+v", l)
		}
	}
	for _, r := range []string{"utilise", "vise", "vu par", "hébergé par", "même mode opératoire"} {
		if !relations[r] {
			t.Errorf("relation %q manquante : %v", r, relations)
		}
	}
}

func TestGraphe_PlafonneEtNeDuplique(t *testing.T) {
	var ips, cibles []string
	for i := 0; i < 500; i++ {
		ips = append(ips, "198.51.100."+string(rune('0'+i%10))+string(rune('a'+i%26)))
		cibles = append(cibles, "h"+string(rune('a'+i%26))+string(rune('a'+i/26%26)))
	}
	g := ConstruireGraphe(EntreeGraphe{ActeurID: "ACT-1", IPs: append(ips, ips...), Cibles: cibles})
	vus := map[string]bool{}
	for _, n := range g.Noeuds {
		if vus[n.ID] {
			t.Fatalf("nœud en double : %s", n.ID)
		}
		vus[n.ID] = true
	}
	if len(g.Noeuds) > 1+maxIPsGraphe+maxCiblesGraphe {
		t.Fatalf("graphe non plafonné : %d nœuds", len(g.Noeuds))
	}
}
