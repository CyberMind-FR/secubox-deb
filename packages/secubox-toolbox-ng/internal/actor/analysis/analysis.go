// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

// Package analysis : scénarios, risque, confiance et décision d'un acteur (Actor Intelligence 2.0, phase 3, #2240).
//
// Fonctions PURES : elles lisent les événements déjà reçus d'un acteur et rendent une évaluation EXPLICABLE. Rien n'est appliqué ici.
//
// Trois principes du brief :
//   - plusieurs signaux d'un même acteur forment UN scénario ordonné (balayage → sondage → exploitation…), pas six alertes ;
//   - le RISQUE (ce que l'acteur fait) et la CONFIANCE (ce que nous en savons) sont deux notes séparées, chacune somme de facteurs nommés, avec leurs preuves ;
//   - aucune décision sur un seul capteur : BLOCK exige au moins DEUX capteurs distincts, un risque élevé ET une confiance élevée ; sinon la décision est
//     rétrogradée en MITIGATE et le motif du refus est dit.
package analysis

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
)

// VersionPolitique est figée avec chaque évaluation : changer les poids ne falsifie jamais une ancienne.
const VersionPolitique = "v2"

const (
	SeuilMitigate        = 42
	SeuilConfianceMitige = 50
	SeuilBlockRisque     = 75
	SeuilBlockConfiance  = 80
	MinCapteursBlock     = 2
)

type Etape string

const (
	EtapeReconnaissance Etape = "reconnaissance"
	EtapeSondage        Etape = "sondage"
	EtapeExploitation   Etape = "exploitation"
	EtapeCanalCache     Etape = "canal_cache"
	EtapePersistance    Etape = "persistance"
)

var libelleEtape = map[Etape]string{EtapeReconnaissance: "balayage", EtapeSondage: "sondage", EtapeExploitation: "exploitation",
	EtapeCanalCache: "canal DNS suspect", EtapePersistance: "persistance"}

// Event est la projection légère d'une enveloppe : ce dont l'analyse a besoin, rien de plus.
type Event struct {
	ID       string   `json:"event_id"`
	TS       int64    `json:"ts"`
	Sensor   string   `json:"sensor"`
	Rule     string   `json:"rule_id,omitempty"`
	Action   string   `json:"action,omitempty"`
	Target   string   `json:"target,omitempty"`
	Severity int      `json:"severity"`
	Tags     []string `json:"tags,omitempty"`
	SrcIP    string   `json:"src_ip,omitempty"`
}

var categoriesExploitation = map[string]bool{"sqli": true, "xss": true, "rce": true, "lfi": true, "rfi": true, "traversal": true, "ssrf": true, "injection": true,
	"cmdi": true, "xxe": true, "deserialization": true, "shellshock": true, "log4j": true, "bruteforce": true, "auth_bruteforce": true, "credential_stuffing": true}

func aTag(e Event, f func(string) bool) bool {
	for _, t := range e.Tags {
		if f(t) {
			return true
		}
	}
	return false
}

// Classer rend l'étape d'un événement. Un événement inconnu est au mieux un SONDAGE, jamais une exploitation : on ne grossit pas ce qu'on ne comprend pas.
func Classer(e Event) Etape {
	regle := strings.ToLower(e.Rule)
	switch e.Sensor {
	case "firewall":
		return EtapeReconnaissance
	case "dns":
		return EtapeCanalCache
	case "dpi":
		if strings.Contains(regle, "exploit") || strings.Contains(regle, "malicious") || strings.Contains(regle, "malware") {
			return EtapeExploitation
		}
		return EtapeSondage
	}
	if strings.Contains(regle, "brute") || strings.Contains(regle, "cred") {
		return EtapeExploitation
	}
	if aTag(e, func(t string) bool {
		return categoriesExploitation[t] || t == "high_value_probe" || t == "leurre:marque-revenue"
	}) {
		return EtapeExploitation
	}
	return EtapeSondage
}

// Stage est une étape du scénario : quand, combien, par quels capteurs, avec quelles preuves.
type Stage struct {
	Etape      Etape    `json:"etape"`
	Libelle    string   `json:"libelle"`
	Debut      int64    `json:"debut"`
	Fin        int64    `json:"fin"`
	Evenements int      `json:"evenements"`
	Capteurs   []string `json:"capteurs"`
	Preuves    []string `json:"preuves"`
}

type Scenario struct {
	Etapes  []Stage `json:"etapes"`
	Libelle string  `json:"libelle"`
	Complet bool    `json:"complet"`
}

type Facteur struct {
	Libelle string   `json:"libelle"`
	Points  int      `json:"points"`
	Preuves []string `json:"preuves"`
}

type Score struct {
	Valeur   int       `json:"valeur"`
	Facteurs []Facteur `json:"facteurs"`
	Version  string    `json:"version"`
}

type Decision struct {
	Niveau  string   `json:"niveau"` // OBSERVE | MITIGATE | BLOCK
	Raisons []string `json:"raisons"`
	Refus   []string `json:"refus,omitempty"` // pourquoi un niveau plus dur n'est PAS retenu
	Action  string   `json:"action_proposee"`
}

type Evaluation struct {
	Risque     Score    `json:"risque"`
	Confiance  Score    `json:"confiance"`
	Decision   Decision `json:"decision"`
	Scenario   Scenario `json:"scenario"`
	Capteurs   []string `json:"capteurs"`
	Evenements int      `json:"evenements"`
}

type Entree struct {
	Events        []Event
	Vecteur       graph.Vector
	CapteursMuets []string // capteurs qui émettaient et se sont tus : ils abaissent la confiance, jamais le risque
	Maintenant    int64
}

func preuves(evs []Event, n int) []string {
	var out []string
	for _, e := range evs {
		if len(out) >= n {
			break
		}
		out = append(out, e.ID)
	}
	return out
}

func clampe(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func ensemble(evs []Event, f func(Event) string) []string {
	m := map[string]bool{}
	for _, e := range evs {
		if k := f(e); k != "" {
			m[k] = true
		}
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func jours(evs []Event) int {
	m := map[string]bool{}
	for _, e := range evs {
		m[time.Unix(e.TS, 0).UTC().Format("2006-01-02")] = true
	}
	return len(m)
}

// construireScenario ordonne les étapes par première apparition et ajoute la PERSISTANCE quand l'activité couvre au moins deux jours.
func construireScenario(evs []Event) Scenario {
	par := map[Etape][]Event{}
	for _, e := range evs {
		par[Classer(e)] = append(par[Classer(e)], e)
	}
	var etapes []Stage
	for et, l := range par {
		sort.Slice(l, func(i, j int) bool { return l[i].TS < l[j].TS })
		etapes = append(etapes, Stage{Etape: et, Libelle: libelleEtape[et], Debut: l[0].TS, Fin: l[len(l)-1].TS, Evenements: len(l),
			Capteurs: ensemble(l, func(e Event) string { return e.Sensor }), Preuves: preuves(l, 3)})
	}
	if len(evs) > 0 && jours(evs) >= 2 {
		deb, fin := evs[0].TS, evs[0].TS
		for _, e := range evs {
			if e.TS < deb {
				deb = e.TS
			}
			if e.TS > fin {
				fin = e.TS
			}
		}
		etapes = append(etapes, Stage{Etape: EtapePersistance, Libelle: libelleEtape[EtapePersistance], Debut: deb, Fin: fin, Evenements: len(evs),
			Capteurs: ensemble(evs, func(e Event) string { return e.Sensor }), Preuves: preuves(evs, 3)})
	}
	sort.SliceStable(etapes, func(i, j int) bool {
		if etapes[i].Debut != etapes[j].Debut {
			return etapes[i].Debut < etapes[j].Debut
		}
		return etapes[i].Etape < etapes[j].Etape
	})
	sc := Scenario{Etapes: etapes}
	var noms []string
	exploitation := false
	for _, s := range etapes {
		noms = append(noms, s.Libelle)
		exploitation = exploitation || s.Etape == EtapeExploitation
	}
	sc.Libelle = strings.Join(noms, " → ")
	sc.Complet = len(etapes) >= 3 && exploitation
	return sc
}

func filtre(evs []Event, f func(Event) bool) []Event {
	var out []Event
	for _, e := range evs {
		if f(e) {
			out = append(out, e)
		}
	}
	return out
}

func maxGravite(evs []Event) int {
	m := 0
	for _, e := range evs {
		if e.Severity > m {
			m = e.Severity
		}
	}
	return m
}

func ajoute(s *Score, libelle string, points int, preuve []string) {
	if points == 0 {
		return
	}
	s.Facteurs = append(s.Facteurs, Facteur{Libelle: libelle, Points: points, Preuves: preuve})
}

func somme(s *Score) {
	t := 0
	for _, f := range s.Facteurs {
		t += f.Points
	}
	s.Valeur = clampe(t)
	s.Version = VersionPolitique
}

// Evaluer calcule le scénario, le risque, la confiance et la décision. Sans événement : tout à zéro, OBSERVE, rien d'inventé.
func Evaluer(in Entree) Evaluation {
	evs := append([]Event(nil), in.Events...)
	sort.Slice(evs, func(i, j int) bool { return evs[i].TS < evs[j].TS })
	ev := Evaluation{Evenements: len(evs), Capteurs: ensemble(evs, func(e Event) string { return e.Sensor }),
		Risque: Score{Version: VersionPolitique}, Confiance: Score{Version: VersionPolitique}}
	if len(evs) == 0 {
		ev.Decision = Decision{Niveau: "OBSERVE", Raisons: []string{"aucun événement"}, Action: "aucune"}
		return ev
	}
	ev.Scenario = construireScenario(evs)
	n, nCapteurs, gmax := len(evs), len(ev.Capteurs), maxGravite(evs)

	scans := filtre(evs, func(e Event) bool { return e.Sensor == "firewall" })
	expl := filtre(evs, func(e Event) bool { return Classer(e) == EtapeExploitation })
	dns := filtre(evs, func(e Event) bool { return Classer(e) == EtapeCanalCache })
	sensibles := filtre(evs, func(e Event) bool {
		return aTag(e, func(t string) bool {
			return t == "high_value_probe" || t == "honeypot" || strings.HasPrefix(t, "leurre:")
		})
	})
	persiste := false
	for _, s := range ev.Scenario.Etapes {
		persiste = persiste || s.Etape == EtapePersistance
	}

	// ── RISQUE : ce que l'acteur FAIT ──
	r := &ev.Risque
	if len(scans) > 0 {
		ajoute(r, "balayage de ports", 20, preuves(scans, 3))
	}
	if n >= 10 {
		ajoute(r, "répétition", 15, preuves(evs, 3))
	}
	if len(sensibles) > 0 {
		ajoute(r, "service sensible ou leurre visé", 20, preuves(sensibles, 3))
	}
	if len(expl) > 0 {
		ajoute(r, "tentative d'exploitation", 20, preuves(expl, 3))
	}
	if len(expl) >= 5 {
		ajoute(r, "charges d'attaque répétées", 15, preuves(expl, 3))
	}
	if nCapteurs >= 2 {
		ajoute(r, "corrélation multi-capteurs", 15, preuves(evs, 3))
	}
	if in.Vecteur.Automation >= 60 {
		ajoute(r, "comportement automatisé", 10, preuves(evs, 2))
	}
	if persiste {
		ajoute(r, "historique sur plusieurs jours", 7, preuves(evs, 2))
	}
	if len(dns) > 0 {
		ajoute(r, "anomalie DNS (canal caché possible)", 10, preuves(dns, 3))
	}
	switch {
	case gmax >= 80:
		ajoute(r, "gravité maximale ≥ 80", 10, preuves(filtre(evs, func(e Event) bool { return e.Severity >= 80 }), 2))
	case gmax >= 60:
		ajoute(r, "gravité maximale ≥ 60", 5, preuves(filtre(evs, func(e Event) bool { return e.Severity >= 60 }), 2))
	}
	somme(r)

	// ── CONFIANCE : ce que nous en SAVONS ──
	c := &ev.Confiance
	ajoute(c, "événements observés", 25, preuves(evs, 2))
	if nCapteurs >= 2 {
		ajoute(c, "capteurs indépendants (≥ 2)", 20, ev.Capteurs)
	}
	if nCapteurs >= 3 {
		ajoute(c, "capteurs indépendants (≥ 3)", 10, ev.Capteurs)
	}
	if n >= 5 {
		ajoute(c, "volume d'événements (≥ 5)", 15, preuves(evs, 2))
	}
	if n >= 20 {
		ajoute(c, "volume d'événements (≥ 20)", 10, preuves(evs, 2))
	}
	if len(ev.Scenario.Etapes) >= 3 {
		ajoute(c, "scénario structuré (≥ 3 étapes)", 10, []string{ev.Scenario.Libelle})
	}
	if v := in.Vecteur.Confidence / 10; v > 0 {
		if v > 10 {
			v = 10
		}
		ajoute(c, "continuité du graphe d'acteurs", v, nil)
		c.Facteurs[len(c.Facteurs)-1].Preuves = []string{"vecteur.confidence"}
	}
	if n == 1 {
		ajoute(c, "un seul événement", -15, preuves(evs, 1))
	}
	if gmax < 30 {
		ajoute(c, "gravité faible partout", -10, preuves(evs, 1))
	}
	if m := len(in.CapteursMuets); m > 0 {
		if m > 2 {
			m = 2
		}
		ajoute(c, fmt.Sprintf("capteur(s) muet(s) : %s", strings.Join(in.CapteursMuets, ", ")), -10*m, in.CapteursMuets)
	}
	somme(c)

	// ── DÉCISION ──
	d := Decision{Niveau: "OBSERVE", Action: "aucune"}
	top := append([]Facteur(nil), r.Facteurs...)
	sort.Slice(top, func(i, j int) bool { return top[i].Points > top[j].Points })
	for i, f := range top {
		if i >= 3 {
			break
		}
		d.Raisons = append(d.Raisons, fmt.Sprintf("%s (+%d)", f.Libelle, f.Points))
	}
	switch {
	case r.Valeur >= SeuilBlockRisque && c.Valeur >= SeuilBlockConfiance && nCapteurs >= MinCapteursBlock:
		d.Niveau, d.Action = "BLOCK", "blocage temporaire réversible (ban 1 h, réévalué à l'échéance)"
	case r.Valeur >= SeuilMitigate && c.Valeur >= SeuilConfianceMitige:
		d.Niveau, d.Action = "MITIGATE", "mesure réversible : délai, défi ou limitation de débit"
		if r.Valeur >= SeuilBlockRisque {
			if nCapteurs < MinCapteursBlock {
				d.Refus = append(d.Refus, fmt.Sprintf("BLOCK refusé : un seul capteur (%d requis)", MinCapteursBlock))
			}
			if c.Valeur < SeuilBlockConfiance {
				d.Refus = append(d.Refus, fmt.Sprintf("BLOCK refusé : confiance %d < %d", c.Valeur, SeuilBlockConfiance))
			}
		}
	default:
		if r.Valeur >= SeuilMitigate {
			d.Refus = append(d.Refus, fmt.Sprintf("MITIGATE refusé : confiance %d < %d", c.Valeur, SeuilConfianceMitige))
		}
	}
	ev.Decision = d
	return ev
}
