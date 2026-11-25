// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
)

// Constats de la revue de #3936 : couverture PAR ACTEUR, horloge, trous, instantané.

// evtDe : un événement d'un acteur distinct par `qui` (aucun axe commun).
func evtDe(qui int, ts int64, ip string) *envelope.Envelope {
	e := evt(ts, ip, fmt.Sprintf("s%d.exemple.test", qui), envelope.ActionBlock)
	e.CredentialTokenHash, e.UserAgentFamily = fmt.Sprintf("c%d", qui), fmt.Sprintf("o%d", qui)
	e.PathShape, e.GeoCountry = fmt.Sprintf("/p%d", qui), []string{"US", "GB", "FR", "DE"}[qui%4]
	return e
}

func acteurDeIP(t *testing.T, s *Server, ip string) *graph.Actor {
	t.Helper()
	for _, a := range s.graph.Actors() {
		for _, x := range a.IPs {
			if x == ip {
				return a
			}
		}
	}
	t.Fatalf("aucun acteur pour %s", ip)
	return nil
}

func redemarrer(s *Server, t *testing.T) *Server {
	t.Helper()
	r := serveur(t)
	r.store, r.actChemin, r.rebuildMax = s.store, s.actChemin, s.rebuildMax
	r.rebuild()
	return r
}

func jours(s *Server, a *graph.Actor, now int64) string {
	x := s.act.acteurs[a.ID]
	out := []int{}
	for _, p := range s.act.serieDe(x, 86400, joursGardes, now, x.jourEvts).Valeurs[10:] {
		out = append(out, val(p))
	}
	return fmt.Sprint(out)
}

// Un acteur vu il y a trois jours, sorti du rejeu, qui revient après le redémarrage.
func scenarioRevenant(t *testing.T) (*Server, *int64, int64) {
	now := horloge(t, t36)
	s := serveur(t)
	s.actChemin, s.rebuildMax = filepath.Join(t.TempDir(), "activite.json"), 5
	s.rebuild()
	mettre := func(e *envelope.Envelope) {
		if err := s.store.Ingest(e); err != nil {
			t.Fatal(err)
		}
		s.observe(e)
	}
	*now += 86400
	mettre(evtDe(1, *now, "203.0.113.1"))
	mettre(evtDe(1, *now, "203.0.113.2"))
	vu := *now
	*now += 3 * 86400
	for i := int64(0); i < 5; i++ {
		mettre(evtDe(2, *now-10+i, "198.51.100.7"))
	}
	s.sauverActivite()
	return redemarrer(s, t), now, vu
}

func TestRevenantParUneAdresseConnueRetrouveSaSerie(t *testing.T) {
	r, now, vu := scenarioRevenant(t)
	r.sauverActivite() // l'entrée en attente survit à un second redémarrage
	r = redemarrer(r, t)
	*now += 2 * 3600
	r.observe(evtDe(1, *now, "203.0.113.2"))
	a := acteurDeIP(t, r, "203.0.113.2")
	if got := jours(r, a, *now); got != "[0 2 0 0 1]" {
		t.Errorf("jours %s", got)
	}
	if r.premierVu(a) != vu {
		t.Errorf("premier %d, attendu %d", r.premierVu(a), vu)
	}
	if len(r.act.attente) != 0 {
		t.Errorf("entrée reprise encore en attente : %d adresses", len(r.act.attente))
	}
}

func TestRevenantInconnuNAJamaisDeFauxZero(t *testing.T) {
	r, now, _ := scenarioRevenant(t)
	*now += 2 * 3600
	r.observe(evtDe(1, *now, "203.0.113.250")) // même personne, adresse jamais relevée
	a := acteurDeIP(t, r, "203.0.113.250")
	if got := jours(r, a, *now); got != "[-1 -1 -1 -1 1]" {
		t.Errorf("faux zéros : %s", got)
	}
	d := r.calculerDetail(a.ID, true)
	if d.Tendance.Bans != nil || d.Tendance.Evenements != nil {
		t.Error("tendance annoncée sur des heures non observées pour cet acteur")
	}
	if d.CouvertureDepuis != r.act.depuisGraphe || d.TotauxDepuis != r.act.depuisGraphe {
		t.Errorf("couverture %d totaux %d, graphe %d", d.CouvertureDepuis, d.TotauxDepuis, r.act.depuisGraphe)
	}
	// L'acteur resté dans le rejeu garde toute sa couverture.
	b := acteurDeIP(t, r, "198.51.100.7")
	if got := jours(r, b, *now); got != "[0 0 0 0 5]" {
		t.Errorf("acteur suivi : %s", got)
	}
}

// Un acteur du rejeu que l'instantané ne connaît pas garde ses événements rejoués.
func TestActeurDuRejeuAbsentDeLInstantane(t *testing.T) {
	now := horloge(t, t36)
	s := serveur(t)
	s.actChemin = filepath.Join(t.TempDir(), "activite.json")
	s.rebuild()
	e := evtDe(1, *now, "203.0.113.1")
	_ = s.store.Ingest(e)
	s.observe(e)
	_ = s.store.Ingest(evtDe(2, *now, "203.0.113.2")) // stocké, pas dans l'instantané
	*now += 60
	s.sauverActivite()
	*now += 60
	e = evtDe(1, *now, "203.0.113.1")
	_ = s.store.Ingest(e)
	r := redemarrer(s, t)
	for ip, n := range map[string]uint32{"203.0.113.1": 2, "203.0.113.2": 1} {
		a := acteurDeIP(t, r, ip)
		x := r.act.acteurs[a.ID]
		if x.heureEvts(*now/3600) != n || x.modules[0] != n {
			t.Errorf("%s : %d événements, %d modules, attendu %d", ip, x.heureEvts(*now/3600), x.modules[0], n)
		}
	}
}

func TestFusionCouvertureIncertaineSansFauxZero(t *testing.T) {
	horloge(t, t36)
	s := serveur(t)
	s.act.depuis, s.act.depuisGraphe = t36-10*86400, t36-3600
	x := &activiteActeur{depuis: t36 - 10*86400, plein: t36 - 10*86400}
	x.ajouterJour(t36/86400-2, 4)
	x.verser(&activiteActeur{depuis: t36 - 3600, plein: t36 - 3600})
	v := s.act.serieDe(x, 86400, joursGardes, t36, x.jourEvts)
	if val(v.Valeurs[12]) != 4 || v.Valeurs[13] != nil || v.Valeurs[11] != nil || v.Valeurs[14] != nil || fmt.Sprint(v.Partielles) != "[12]" {
		t.Errorf("jours %v %v %v partielles %v", val(v.Valeurs[11]), val(v.Valeurs[12]), val(v.Valeurs[13]), v.Partielles)
	}
	if te := s.act.tendance(x, t36); te.Bans != nil {
		t.Error("tendance sur une couverture incertaine")
	}
}

func TestLotPartiellesParActeur(t *testing.T) {
	r, now, _ := scenarioRevenant(t)
	*now += 2 * 3600
	r.observe(evtDe(1, *now, "203.0.113.250"))
	a, b := acteurDeIP(t, r, "203.0.113.250"), acteurDeIP(t, r, "198.51.100.7")
	var o lotActivite
	w := appel(t, r, http.MethodGet, "/activite?ids="+a.ID+","+b.ID, nil, "")
	if err := json.Unmarshal(w.Body.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	if o.Acteurs[a.ID][0] != nil || val(o.Acteurs[b.ID][0]) != 0 {
		t.Errorf("lot : %s", w.Body.String())
	}
	if len(o.PartiellesActeurs[a.ID]) != 1 || o.PartiellesActeurs[b.ID] != nil {
		t.Errorf("partielles %v", o.PartiellesActeurs)
	}
}

func TestPlafondLibereCouvertureRepartDeMaintenant(t *testing.T) {
	now := horloge(t, t36)
	s := serveur(t)
	s.observe(evtDe(1, *now-3*86400, "203.0.113.1"))
	a := acteurDeIP(t, s, "203.0.113.1")
	delete(s.act.acteurs, a.ID) // plafond atteint à l'époque
	s.observe(evtDe(1, *now, "203.0.113.1"))
	if got := jours(s, a, *now); got != "[-1 -1 -1 -1 1]" {
		t.Errorf("jours %s", got)
	}
}

func TestHorlogeEnAvancePuisRemise(t *testing.T) {
	now := horloge(t, t36)
	s := serveur(t)
	s.observe(evtDe(1, *now, "203.0.113.1"))
	*now = t36 + 400*86400 // saut en avant
	s.observe(evtDe(1, *now, "203.0.113.1"))
	*now = t36 + 7200 // remise à l'heure
	s.observe(evtDe(1, *now, "203.0.113.1"))
	s.observe(evtDe(1, *now, "203.0.113.1"))
	a := acteurDeIP(t, s, "203.0.113.1")
	x := s.act.acteurs[a.ID]
	h := s.act.serieDe(x, 3600, 24, *now, x.heureEvts)
	if val(h.Valeurs[23]) != 2 || h.Valeurs[20] != nil || val(s.act.serieDe(x, 86400, joursGardes, *now, x.jourEvts).Valeurs[14]) != 2 {
		t.Errorf("anneaux figés : %d %d", val(h.Valeurs[23]), val(h.Valeurs[20]))
	}
	if g := s.act.serieDe(&s.act.global, 3600, 24, *now, s.act.global.heureEvts); val(g.Valeurs[23]) != 2 {
		t.Errorf("série d'ensemble figée : %d", val(g.Valeurs[23]))
	}
	// Couverture ouverte dans le futur (démarrage avec une horloge en avance).
	s2 := serveur(t)
	*now = t36 + 400*86400
	s2.rebuild()
	*now = t36
	s2.observe(evtDe(1, *now, "203.0.113.1"))
	a = acteurDeIP(t, s2, "203.0.113.1")
	x = s2.act.acteurs[a.ID]
	if n := val(s2.act.serieDe(x, 3600, 24, *now, x.heureEvts).Valeurs[23]); n != 1 {
		t.Errorf("après recalage : %d", n)
	}
}

func TestHorlogeEnRetardAuDemarrage(t *testing.T) {
	now := horloge(t, t36)
	s := serveur(t)
	s.actChemin = filepath.Join(t.TempDir(), "activite.json")
	*now = t36 - 600
	s.rebuild()
	*now = t36
	e := evtDe(1, *now, "203.0.113.1")
	_ = s.store.Ingest(e)
	s.observe(e)
	s.sauverActivite()
	*now = t36 - 200*86400 // pas d'horloge matérielle : démarrage dans le passé
	r := redemarrer(s, t)
	a := acteurDeIP(t, r, "203.0.113.1")
	if r.act.acteurs[a.ID].heureEvts(t36/3600) != 1 {
		t.Fatal("instantané ou rejeu perdu")
	}
	r.observe(evtDe(1, *now, "203.0.113.1")) // daté par une horloge fausse : pas compté
	*now = t36 + 5*3600                      // NTP
	r.observe(evtDe(1, *now, "203.0.113.1"))
	*now += 120
	x := r.act.acteurs[a.ID]
	h := r.act.serieDe(x, 3600, 24, *now, x.heureEvts)
	if val(h.Valeurs[18]) != 1 || h.Valeurs[20] != nil || val(h.Valeurs[23]) != 1 {
		t.Errorf("heures %d %d %d, trous %v", val(h.Valeurs[18]), val(h.Valeurs[20]), val(h.Valeurs[23]), r.act.trous)
	}
}

// Un instantané plus court que le rejeu est écarté, pas les trous qu'il connaît.
func TestTrousGardesQuandLeRejeuSuffit(t *testing.T) {
	now := horloge(t, t36)
	s := serveur(t)
	s.actChemin = filepath.Join(t.TempDir(), "activite.json")
	_ = s.store.Ingest(evtDe(1, t36-20*3600, "203.0.113.1"))
	_ = s.store.Ingest(evtDe(1, t36-60, "203.0.113.1"))
	o := instantane{Version: instantaneVersion, GenereLe: t36 - 60, Depuis: t36 - 10*3600, Trous: [][2]int64{{t36 - 9*3600, t36 - 5*3600}}}
	b, _ := json.Marshal(o)
	if err := os.WriteFile(s.actChemin, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s.rebuild()
	a := acteurDeIP(t, s, "203.0.113.1")
	x := s.act.acteurs[a.ID]
	h := s.act.serieDe(x, 3600, 24, *now, x.heureEvts)
	if s.act.depuis != t36-20*3600 || val(h.Valeurs[3]) != 1 || val(h.Valeurs[23]) != 1 {
		t.Errorf("rejeu : depuis %d, %d %d", s.act.depuis, val(h.Valeurs[3]), val(h.Valeurs[23]))
	}
	if h.Valeurs[16] != nil { // heure dans le trou
		t.Errorf("trou oublié : %d", *h.Valeurs[16])
	}
}

func TestMagasinIllisibleNEcrasePasLInstantane(t *testing.T) {
	horloge(t, t36)
	s := serveur(t)
	s.actChemin = filepath.Join(t.TempDir(), "activite.json")
	chemin := s.actChemin
	if err := os.WriteFile(chemin, []byte("PRECIEUX"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = s.store.Close()
	s.rebuild()
	s.observe(evtDe(1, t36, "203.0.113.1"))
	s.sauverActivite()
	if b, _ := os.ReadFile(chemin); string(b) != "PRECIEUX" {
		t.Errorf("instantané écrasé : %s", b)
	}
}

// Aucune entrée en attente ne sort de l'API.
func TestAttenteJamaisExposee(t *testing.T) {
	r, _, _ := scenarioRevenant(t)
	if len(r.act.attente) == 0 {
		t.Fatal("précondition : rien en attente")
	}
	for _, c := range []string{"/actors", "/activite?campagnes=1", "/actors/" + r.graph.Actors()[0].ID} {
		if strings.Contains(appel(t, r, http.MethodGet, c, nil, "").Body.String(), "203.0.113.") {
			t.Errorf("%s : adresse en attente exposée", c)
		}
	}
}
