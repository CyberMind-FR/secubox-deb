// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package mesure

import (
	"testing"
	"time"
)

const t0 = int64(1_800_000_000)

func e(risque, conf, capteurs, hostiles int) Entree {
	return Entree{Risque: risque, Confiance: conf, Capteurs: capteurs, Hostiles: hostiles}
}

func TestLEchelleSuitLeRisqueQuandLaConfianceLePermet(t *testing.T) {
	cas := []struct {
		r, c, k int
		veut    Niveau
	}{
		{10, 90, 3, Observe}, // peu de risque : on regarde
		{41, 90, 3, Observe}, // juste sous le seuil
		{42, 50, 1, Delay},   // premier cran
		{54, 70, 1, Delay},
		{55, 70, 1, Challenge},
		{64, 70, 1, Challenge},
		{65, 70, 1, Tarpit},
		{74, 70, 1, Tarpit},
		{82, 70, 1, Tarpit}, // risque BLOCK mais un seul capteur : on ne bloque pas, on ralentit
		{82, 79, 2, Tarpit}, // deux capteurs mais confiance < 80
		{82, 80, 2, Deny},   // BLOCK : risque ≥ 75, confiance ≥ 80, 2 capteurs
		{97, 89, 3, Deny},
		{90, 49, 3, Observe}, // la faible confiance n'escalade JAMAIS
	}
	for _, c := range cas {
		m, _ := Choisir(e(c.r, c.c, c.k, 0), nil, t0)
		if m.Niveau != c.veut {
			t.Errorf("risque %d confiance %d capteurs %d : %s, attendu %s", c.r, c.c, c.k, m.Niveau, c.veut)
		}
	}
}

func TestChaqueCranALaDureeDuMoteurDeReponse(t *testing.T) {
	for niv, ttl := range map[Niveau]time.Duration{Delay: 5 * time.Minute, Challenge: 15 * time.Minute, Tarpit: 30 * time.Minute, Deny: time.Hour, Quarantine: 6 * time.Hour} {
		if TTL(niv) != ttl {
			t.Errorf("%s : %s", niv, TTL(niv))
		}
	}
	if TTL(Observe) != 0 {
		t.Error("observer n'est pas une mesure : durée nulle")
	}
}

func TestUnLanNeRecoitJamaisDeMesureHTTPMaisLaQuarantaineQuandBlock(t *testing.T) {
	en := e(60, 90, 3, 0)
	en.LAN = true
	if m, _ := Choisir(en, nil, t0); m.Niveau != Observe {
		t.Fatalf("délai/défi/tarpit n'ont aucun sens pour un appareil du LAN : %s", m.Niveau)
	}
	en = e(82, 80, 2, 0)
	en.LAN = true
	if m, _ := Choisir(en, nil, t0); m.Niveau != Quarantine {
		t.Fatalf("niveau BLOCK sur un appareil du LAN = quarantaine : %s", m.Niveau)
	}
	en = e(82, 70, 1, 0)
	en.LAN = true
	if m, _ := Choisir(en, nil, t0); m.Niveau != Observe {
		t.Fatalf("un seul capteur ne suffit pas à isoler un appareil : %s", m.Niveau)
	}
}

func TestUneMesureEnCoursNeDescendPasAvantSonEcheance(t *testing.T) {
	_, st := Choisir(e(70, 70, 1, 0), nil, t0) // TARPIT
	m, _ := Choisir(e(45, 70, 1, 0), &st, t0+600)
	if m.Niveau != Tarpit {
		t.Fatalf("le risque retombe mais la mesure court encore 30 min : %s", m.Niveau)
	}
	m, _ = Choisir(e(45, 70, 1, 0), &st, t0+int64(31*60))
	if m.Niveau != Delay {
		t.Fatalf("après l'échéance on redescend au cran du moment : %s", m.Niveau)
	}
}

func TestInsisterSousUneMesureFaitMonterD_unCran(t *testing.T) {
	m, st := Choisir(e(50, 70, 1, 3), nil, t0) // DELAY, 3 événements hostiles au départ
	if m.Niveau != Delay {
		t.Fatal(m.Niveau)
	}
	m, st = Choisir(e(50, 70, 1, 3+SeuilInsistance-1), &st, t0+60)
	if m.Niveau != Delay {
		t.Fatalf("pas encore assez d'insistance : %s", m.Niveau)
	}
	m, st = Choisir(e(50, 70, 1, 3+SeuilInsistance), &st, t0+120)
	if m.Niveau != Challenge || m.Raison == "" {
		t.Fatalf("l'acteur continue sous délai : défi, avec sa raison : %+v", m)
	}
	// le compteur repart du nouveau cran
	m, _ = Choisir(e(50, 70, 1, 3+SeuilInsistance+SeuilInsistance-1), &st, t0+180)
	if m.Niveau != Challenge {
		t.Fatalf("un seul cran à la fois : %s", m.Niveau)
	}
}

func TestUnActeurQuiInsisteSousTarpitFinitBanniMemeAvecUnSeulCapteur(t *testing.T) {
	m, st := Choisir(e(70, 70, 1, 0), nil, t0) // TARPIT
	m, _ = Choisir(e(70, 70, 1, SeuilInsistance), &st, t0+300)
	if m.Niveau != Deny {
		t.Fatalf("c'est ainsi qu'un acteur vu par le seul WAF finit banni : %s", m.Niveau)
	}
	if m.Raison == "" {
		t.Fatal("la raison de l'escalade est écrite")
	}
}

func TestLInsistanceNeFaitJamaisEscaladerSousLeSeuilDeConfiance(t *testing.T) {
	_, st := Choisir(e(70, 70, 1, 0), nil, t0)
	m, _ := Choisir(e(70, 49, 1, 500), &st, t0+300)
	if m.Niveau == Deny || m.Niveau == Quarantine {
		t.Fatalf("confiance insuffisante : aucune escalade (%s)", m.Niveau)
	}
}

func TestUnLanNEscaladePasAuDelaDeLaQuarantaine(t *testing.T) {
	en := e(82, 80, 2, 0)
	en.LAN = true
	_, st := Choisir(en, nil, t0)
	en.Hostiles = 500
	if m, _ := Choisir(en, &st, t0+60); m.Niveau != Quarantine {
		t.Fatalf("%s", m.Niveau)
	}
}

func TestLaMesureRendSonEtatPourEtreRetenu(t *testing.T) {
	m, st := Choisir(e(60, 70, 1, 4), nil, t0)
	if st.Niveau != m.Niveau || st.Depuis != t0 || st.Expire != t0+int64(TTL(Challenge).Seconds()) || st.HostilesDepart != 4 {
		t.Fatalf("%+v", st)
	}
}
