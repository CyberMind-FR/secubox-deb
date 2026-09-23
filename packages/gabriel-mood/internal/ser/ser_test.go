// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package ser

import (
	"math"
	"strings"
	"testing"
)

// ordinaire : la voix « de tous les jours » d'un locuteur fictif.
func ordinaire() Traits {
	return Traits{
		F0Median: 130, F0Etendue: 4, Energie: 0.30, EnergieVar: 0.05,
		Debit: 150, Jitter: 0.8, Shimmer: 0.5, Centre: 1400, Pente: -8,
		PartVoisee: 0.6, TramesVoisees: 60,
	}
}

func etalonne(t *testing.T) (*Etalon, *Heuristique) {
	t.Helper()
	e := NouvelEtalon(600)
	base := ordinaire()
	// De la variation, sinon l'écart interquartile est nul et tous les écarts
	// se retrouvent à zéro — ce qui masquerait les bugs qu'on cherche.
	for i := 0; i < MinimumEtalon+40; i++ {
		v := base
		d := float64(i%20-10) / 10
		v.F0Median += d * 6
		v.Energie += d * 0.03
		v.Debit += d * 12
		v.Jitter += d * 0.15
		v.Centre += d * 120
		e.Observe(v)
	}
	if !e.Pret() {
		t.Fatal("étalon non prêt")
	}
	return e, NouvelleHeuristique(e)
}

// ── LA RÈGLE CARDINALE ─────────────────────────────────────────────────────
// « Ne jamais présenter les émotions comme des certitudes. » Ce test est le
// gardien de cette phrase : il doit échouer si quelqu'un relève un jour le
// plafond, ou laisse passer une lecture sans réserve.

func TestAucuneLectureNeDepasseLePlafondDeConfiance(t *testing.T) {
	_, h := etalonne(t)
	// On pousse des traits extrêmes dans tous les sens : rien ne doit
	// permettre d'atteindre la certitude.
	for _, f := range []float64{-4, -2, -1, 0, 1, 2, 4, 10} {
		v := ordinaire()
		v.F0Median *= 1 + f/4
		v.Energie *= 1 + f/4
		v.Debit *= 1 + f/4
		v.Jitter *= 1 + math.Abs(f)
		v.Shimmer *= 1 + math.Abs(f)
		v.Centre *= 1 + f/4
		l := h.Evalue(v)
		if l.Confiance > PlafondConfiance {
			t.Fatalf("confiance %.3f au-dessus du plafond %.2f", l.Confiance, PlafondConfiance)
		}
		if l.Confiance > 0 && l.Reserve == "" {
			t.Fatal("une lecture sort sans sa réserve")
		}
		somme := 0.0
		for _, v := range l.Indices {
			if v < 0 || v > 1 {
				t.Fatalf("indice hors [0,1] : %v", l.Indices)
			}
			somme += v
		}
		if math.Abs(somme-1) > 0.02 {
			t.Fatalf("les indices somment à %.3f", somme)
		}
	}
}

func TestSansEtalonOnNeRepondPas(t *testing.T) {
	h := NouvelleHeuristique(NouvelEtalon(600))
	l := h.Evalue(ordinaire())
	if l.Etat != Indetermine {
		t.Fatalf("état %q rendu sans étalon", l.Etat)
	}
	if l.Etalonne {
		t.Error("prétend être étalonné")
	}
	if !strings.Contains(strings.ToLower(strings.Join(l.Pourquoi, " ")), "étalonnage") {
		t.Errorf("le motif n'explique pas l'étalonnage : %v", l.Pourquoi)
	}
}

func TestSansAssezDeVoixOnNeRepondPas(t *testing.T) {
	_, h := etalonne(t)
	v := ordinaire()
	v.TramesVoisees = MinTramesVoisees - 1
	l := h.Evalue(v)
	if l.Etat != Indetermine {
		t.Fatalf("état %q rendu sur %d trames voisées", l.Etat, v.TramesVoisees)
	}
	if !l.Etalonne {
		t.Error("l'étalon existe : la lecture doit le dire, même en refusant")
	}
}

// L'INDÉTERMINÉ EST UN CAS NORMAL, pas une erreur : il doit rester lisible
// (indices présents, réserve présente) pour que l'interface l'affiche
// proprement au lieu d'un trou.
func TestLIndetermineResteLisible(t *testing.T) {
	l := LectureIndeterminee("motif", false)
	if len(l.Indices) != len(Etats) {
		t.Fatalf("%d indices, veut %d", len(l.Indices), len(Etats))
	}
	if l.Reserve == "" {
		t.Error("pas de réserve")
	}
	if l.Confiance != 0 {
		t.Errorf("confiance %v sur un indéterminé", l.Confiance)
	}
}

// ── LE SENS DES INDICES ────────────────────────────────────────────────────
// On ne teste pas « ce test détecte la colère » — ce serait prétendre que la
// vérité est connue. On teste que l'ORDRE est cohérent : plus de voix haute,
// forte et rapide doit faire MONTER l'activation, pas la faire descendre.

func TestUneVoixPlusHauteEtPlusForteMonteEnActivation(t *testing.T) {
	_, h := etalonne(t)
	bas := ordinaire()
	bas.F0Median, bas.Energie, bas.Debit = 105, 0.18, 110
	haut := ordinaire()
	haut.F0Median, haut.Energie, haut.Debit = 175, 0.50, 200

	lb, lh := h.Evalue(bas), h.Evalue(haut)
	if !(lh.Activation > lb.Activation) {
		t.Fatalf("activation : voix haute %.3f <= voix basse %.3f", lh.Activation, lb.Activation)
	}
	if lb.Activation >= 0 {
		t.Errorf("voix nettement sous l'ordinaire : activation %+.3f, attendue négative", lb.Activation)
	}
}

func TestUneVoixIrregulliereEtPeuActiveePencheVersLaFatigue(t *testing.T) {
	_, h := etalonne(t)
	v := ordinaire()
	v.F0Median, v.Energie, v.Debit = 108, 0.17, 105
	v.Jitter, v.Shimmer, v.F0Etendue, v.Pente = 2.4, 1.3, 1.8, -15
	l := h.Evalue(v)
	if l.Indices[Fatigue] <= l.Indices[Joie] {
		t.Errorf("fatigue %.3f <= joie %.3f sur une voix basse, plate et irrégulière",
			l.Indices[Fatigue], l.Indices[Joie])
	}
}

func TestUneVoixPoseeEtReguliereNePencheNiVersLaColereNiVersLaTension(t *testing.T) {
	_, h := etalonne(t)
	v := ordinaire()
	v.Jitter, v.Shimmer = 0.4, 0.25
	l := h.Evalue(v)
	if l.Indices[Colere] > l.Indices[Calme] {
		t.Errorf("colère %.3f > calme %.3f sur une voix ordinaire et régulière",
			l.Indices[Colere], l.Indices[Calme])
	}
}

// À ÉGALITÉ, LA RÉPONSE DOIT ÊTRE STABLE. L'ordre de parcours d'une map est
// aléatoire en Go : sans tri déterministe, l'état affiché clignoterait entre
// deux étiquettes équivalentes sans que la voix ait bougé.
func TestLaReponseNeClignotePasAEgalite(t *testing.T) {
	m := map[string]float64{Calme: 0.2, Joie: 0.2, Tension: 0.2, Colere: 0.2, Fatigue: 0.1, Concentre: 0.1}
	premier, _ := deuxPremiers(m)
	for i := 0; i < 200; i++ {
		if p, _ := deuxPremiers(m); p != premier {
			t.Fatalf("réponse instable : %q puis %q", premier, p)
		}
	}
}

func TestLEtalonIgnoreLeSilence(t *testing.T) {
	e := NouvelEtalon(600)
	muet := Traits{TramesVoisees: 0, F0Median: 0}
	for i := 0; i < 500; i++ {
		e.Observe(muet)
	}
	if e.Pret() {
		t.Fatal("l'étalon s'est constitué sur du silence")
	}
	if e.Progression() != 0 {
		t.Errorf("progression %.2f sur du silence", e.Progression())
	}
}

// L'étalon doit résister à quelques valeurs aberrantes — un saut d'octave, une
// porte qui claque — sinon l'ordinaire qu'il apprend n'est celui de personne.
func TestLEtalonResisteAUneAberration(t *testing.T) {
	e := NouvelEtalon(600)
	base := ordinaire()
	for i := 0; i < MinimumEtalon+40; i++ {
		v := base
		v.F0Median += float64(i%10) - 5
		e.Observe(v)
	}
	sain := e.Ecarts(base)["f0"]
	for i := 0; i < 5; i++ {
		v := base
		v.F0Median = 900 // aberration franche
		e.Observe(v)
	}
	if apres := e.Ecarts(base)["f0"]; math.Abs(apres-sain) > 0.5 {
		t.Fatalf("l'ordinaire a bougé de %.2f à %.2f à cause de cinq aberrations", sain, apres)
	}
}
