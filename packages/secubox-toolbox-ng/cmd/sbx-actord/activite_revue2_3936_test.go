// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Seconde revue de #3936 : horloge, entrées en attente, taille de l'instantané.

// sauter décale l'horloge murale sans faire passer le temps.
func sauter(now *int64, d int64) { *now += d; decalageHorloge += d }

func heures24(s *Server, ip string, t *testing.T, now int64) []int {
	t.Helper()
	x := s.act.acteurs[acteurDeIP(t, s, ip).ID]
	out := []int{}
	for _, p := range s.act.serieDe(x, 3600, 24, now, x.heureEvts).Valeurs {
		out = append(out, val(p))
	}
	return out
}

// N1 : un seul événement stocké daté en avance ne suspend rien et n'avance aucun anneau.
func TestEvenementStockeEnAvanceNeSuspendRien(t *testing.T) {
	now := horloge(t, t36)
	s := serveur(t)
	s.actChemin = filepath.Join(t.TempDir(), "activite.json")
	s.rebuild()
	for i := int64(0); i < 3; i++ {
		e := evtDe(1, t36+i*3600, "203.0.113.1")
		_ = s.store.Ingest(e)
		*now = e.Timestamp
		s.observe(e)
	}
	s.sauverActivite()
	_ = s.store.Ingest(evtDe(1, *now+30*86400, "203.0.113.1")) // capteur à l'horloge folle
	*now += 60
	r := redemarrer(s, t)
	*now += 2 * 3600
	r.observe(evtDe(1, *now, "203.0.113.1"))
	if h := heures24(r, "203.0.113.1", t, *now); h[23] != 1 || h[22] != 0 || h[21] != 1 || h[20] != 1 || h[19] != 1 {
		t.Errorf("heures %v", h)
	}
	r.sauverActivite()
	r2 := redemarrer(r, t)
	if h := heures24(r2, "203.0.113.1", t, *now); h[21] != 1 || h[20] != 1 {
		t.Errorf("perte fixée dans l'instantané : %v", h)
	}
}

// N1 : un événement en avance ne cache pas l'arrêt du démon.
func TestEvenementEnAvanceNeCachePasUnTrou(t *testing.T) {
	now := horloge(t, t36)
	s := serveur(t)
	_ = s.store.Ingest(evtDe(1, t36-600, "203.0.113.1"))
	_ = s.store.Ingest(evtDe(1, t36+86400, "203.0.113.1"))
	*now = t36 + 5*3600 // cinq heures d'arrêt
	s.rebuild()
	*now += 60
	s.observe(evtDe(1, *now, "203.0.113.1"))
	if h := heures24(s, "203.0.113.1", t, *now); h[20] != -1 || h[23] != 1 {
		t.Errorf("faux zéros pendant l'arrêt : %v", h)
	}
}

// N1b : un instantané daté en avance ne suspend rien ; ce qui est compté ensuite se voit.
func TestInstantaneDateEnAvance(t *testing.T) {
	now := horloge(t, t36)
	s := serveur(t)
	s.actChemin = filepath.Join(t.TempDir(), "activite.json")
	s.rebuild()
	e := evtDe(1, *now, "203.0.113.1")
	_ = s.store.Ingest(e)
	s.observe(e)
	*now += 3600
	s.sauverActivite()
	b, _ := os.ReadFile(s.actChemin)
	var o instantane
	if err := json.Unmarshal(b, &o); err != nil {
		t.Fatal(err)
	}
	o.GenereLe += 6 * 3600
	b, _ = json.Marshal(o)
	_ = os.WriteFile(s.actChemin, b, 0o600)
	r := redemarrer(s, t)
	for i := 0; i < 8; i++ {
		*now += 3600
		r.observe(evtDe(1, *now, "203.0.113.1"))
	}
	if h := heures24(r, "203.0.113.1", t, *now); fmt.Sprint(h[14:]) != "[1 0 1 1 1 1 1 1 1 1]" {
		t.Errorf("heures %v", h)
	}
}

// Horloge en retard au démarrage, remise à l'heure en marche : le saut est un trou, pas des zéros.
func TestSautEnAvantEstUnTrou(t *testing.T) {
	now := horloge(t, t36)
	s := serveur(t)
	s.actChemin = filepath.Join(t.TempDir(), "activite.json")
	s.rebuild()
	e := evtDe(1, *now, "203.0.113.1")
	_ = s.store.Ingest(e)
	s.observe(e)
	*now += 3600
	s.sauverActivite()
	sauter(now, -2*3600) // sans pile : l'horloge repart avant l'arrêt
	r := redemarrer(s, t)
	*now += 60
	sauter(now, 7*3600)         // NTP
	r.act.verifierHorloge(*now) // une lecture ou un événement passe
	*now += 60
	r.observe(evtDe(1, *now, "203.0.113.1"))
	h := heures24(r, "203.0.113.1", t, *now)
	if h[23] != 1 || h[21] != -1 || h[20] != -1 || h[19] != -1 {
		t.Errorf("heures %v trous %v", h, r.act.trous)
	}
}

// N2 : après un aller-retour de l'horloge, un acteur inactif ne lit pas de faux zéros.
func TestAllerRetourHorlogeActeurInactif(t *testing.T) {
	now := horloge(t, t36)
	s := serveur(t)
	s.actChemin = filepath.Join(t.TempDir(), "activite.json")
	s.observe(evtDe(1, *now, "203.0.113.1"))
	s.observe(evtDe(2, *now, "203.0.113.2"))
	*now += 3600
	s.observe(evtDe(4, *now, "203.0.113.4"))
	sauter(now, 400*86400)
	s.observe(evtDe(1, *now, "203.0.113.1"))
	sauter(now, -400*86400)
	s.observe(evtDe(3, *now, "203.0.113.3"))
	*now += 2 * 3600
	for i, v := range heures24(s, "203.0.113.1", t, *now)[:21] {
		if v >= 0 { // ses anneaux sont partis : rien avant la remise à l'heure
			t.Fatalf("valeur %d à la tranche %d", v, i)
		}
	}
	// L'acteur que le saut n'a pas touché garde ce qu'il savait.
	if h := heures24(s, "203.0.113.2", t, *now); h[20] != 1 {
		t.Errorf("acteur intact : %v", h)
	}
	s.sauverActivite()
	b, _ := os.ReadFile(s.actChemin)
	var o instantane
	_ = json.Unmarshal(b, &o)
	for _, e := range o.Acteurs {
		for _, h := range e.Heures {
			if h[0] > *now/3600+1 {
				t.Errorf("heure future écrite : %v", h)
			}
		}
	}
}

// N3 : les entrées en attente sont bornées en adresses et purgées.
func TestAttenteBorneeEtPurgee(t *testing.T) {
	now := horloge(t, t36)
	s := serveur(t)
	ips := func(k, n int) []string {
		var l []string
		for i := 0; i < n; i++ {
			l = append(l, fmt.Sprintf("2001:db8:%x::%x", k, i))
		}
		return l
	}
	o := &instantane{Depuis: t36 - 10*86400, GenereLe: t36}
	for k := 0; k < 500; k++ {
		o.Acteurs = append(o.Acteurs, entreeInstantane{IPs: ips(k, 512), Jours: [][2]int64{{t36/86400 - int64(k%10), 1}}})
	}
	s.act.depuis, s.act.depuisGraphe = t36, t36
	s.fermerRejeu(o)
	if n := len(s.act.attente); n > 200000 || n < 190000 {
		t.Errorf("%d adresses en attente", n)
	}
	*now += 12 * 86400 // tout a plus de quinze jours, sauf les trois derniers jours
	s.purgerMemoire(*now - 15*86400)
	for _, e := range s.act.attente {
		if e.dernierJour() <= *now/86400-joursGardes {
			t.Fatalf("entrée périmée gardée : jour %d", e.dernierJour())
		}
	}
	if len(s.act.attente) == 0 {
		t.Error("les entrées récentes doivent rester")
	}
	*now += 10 * 86400
	s.purgerMemoire(*now - 15*86400)
	if len(s.act.attente) != 0 || s.act.nAttente != 0 {
		t.Errorf("reste %d adresses, %d entrées", len(s.act.attente), s.act.nAttente)
	}
}

// N4 : le fichier écrit se relit toujours ; les plus anciennes entrées partent d'abord.
func TestInstantaneNeDepassePasSaLimite(t *testing.T) {
	now := horloge(t, t36)
	s := serveur(t)
	s.actChemin = filepath.Join(t.TempDir(), "activite.json")
	s.act.depuis, s.act.depuisGraphe = t36-9*86400, t36-9*86400
	for i := 0; i < 200; i++ {
		*now = t36 - 5*86400 + int64(i)*2000
		s.observe(evtDe(i, *now, fmt.Sprintf("203.0.113.%d", i)))
	}
	defer func(v int) { instantaneMax = v }(instantaneMax)
	instantaneMax = 12000
	s.sauverActivite()
	fi, err := os.Stat(s.actChemin)
	if err != nil || fi.Size() > int64(instantaneMax) {
		t.Fatalf("%v %v", fi, err)
	}
	o := lireInstantane(s.actChemin, *now)
	if o == nil || len(o.Acteurs) < 10 || len(o.Acteurs) >= 200 {
		t.Fatalf("relu : %+v", o)
	}
	recent, plusVieux := false, int64(1<<60)
	for _, e := range o.Acteurs {
		recent = recent || e.IPs[0] == "203.0.113.199"
		plusVieux = min(plusVieux, e.dernierJour())
	}
	if !recent || plusVieux < t36/86400-3 {
		t.Errorf("les plus récentes d'abord : récente %v, plus vieux jour %d (aujourd'hui %d)", recent, plusVieux, *now/86400)
	}
}
