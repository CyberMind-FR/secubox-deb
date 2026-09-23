// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package vad

import (
	"math"
	"math/rand"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/fft"
)

const (
	fe    = 48000.0
	nfft  = 1024
	raies = nfft/2 + 1
)

// tramesDe fabrique le spectre de puissance d'un signal.
func spectreDe(plan *fft.Plan, x []float64) []float64 {
	mag := plan.Spectre(x, nil)
	p := make([]float64, len(mag))
	for i, m := range mag {
		p[i] = m * m
	}
	return p
}

func silence(rng *rand.Rand, niveau float64) []float64 {
	x := make([]float64, nfft)
	for i := range x {
		x[i] = rng.NormFloat64() * niveau
	}
	return x
}

func parole(f0 float64, ampli float64) []float64 {
	x := make([]float64, nfft)
	for i := range x {
		t := float64(i) / fe
		// fondamentale + formants vers 700 et 1200 Hz : de la voix, pas un sinus
		x[i] = ampli * (math.Sin(2*math.Pi*f0*t) +
			0.7*math.Sin(2*math.Pi*700*t) +
			0.5*math.Sin(2*math.Pi*1200*t) +
			0.3*math.Sin(2*math.Pi*2400*t))
	}
	return x
}

// LE PLANCHER S'APPREND, et tant qu'il n'est pas appris on ne décide pas.
// Annoncer « parole » sur les premières trames, avant d'avoir la moindre idée
// du bruit de la pièce, serait deviner.
func TestPasDeDecisionPendantLAmorcage(t *testing.T) {
	plan := fft.NouveauPlan(nfft)
	d := Nouveau(raies, fe, Normal, 5)
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < AmorcageTrames-1; i++ {
		v := d.Analyse(spectreDe(plan, parole(120, 0.3)))
		if v.Parole {
			t.Fatalf("trame %d : décision rendue pendant l'amorçage", i)
		}
		if !v.Amorcage {
			t.Fatalf("trame %d : l'amorçage n'est pas signalé", i)
		}
		_ = rng
	}
}

func amorce(d *Detecteur, plan *fft.Plan, rng *rand.Rand, niveau float64) {
	for i := 0; i < AmorcageTrames+40; i++ {
		d.Analyse(spectreDe(plan, silence(rng, niveau)))
	}
}

func TestLaParoleEstDetecteeEtPasLeSilence(t *testing.T) {
	plan := fft.NouveauPlan(nfft)
	d := Nouveau(raies, fe, Normal, 5)
	rng := rand.New(rand.NewSource(2))
	amorce(d, plan, rng, 0.001)

	if v := d.Analyse(spectreDe(plan, silence(rng, 0.001))); v.Parole {
		t.Error("silence déclaré parole")
	}
	var vu bool
	for i := 0; i < 5; i++ {
		if d.Analyse(spectreDe(plan, parole(120, 0.2))).Parole {
			vu = true
		}
	}
	if !vu {
		t.Error("parole non détectée")
	}
}

// LA RÉMANENCE EXISTE POUR LES FINS DE MOTS. Les consonnes finales sont
// faibles ; une décision trame par trame les coupe, et le débit mesuré devient
// faux. On vérifie qu'un trou bref ne casse pas la détection.
func TestLaRemanenceNeCoupePasLesFinsDeMots(t *testing.T) {
	plan := fft.NouveauPlan(nfft)
	d := Nouveau(raies, fe, Normal, 8)
	rng := rand.New(rand.NewSource(3))
	amorce(d, plan, rng, 0.001)
	for i := 0; i < 10; i++ {
		d.Analyse(spectreDe(plan, parole(120, 0.25)))
	}
	// Trois trames creuses, comme une occlusive : on doit rester en parole.
	for i := 0; i < 3; i++ {
		if !d.Analyse(spectreDe(plan, silence(rng, 0.001))).Parole {
			t.Fatalf("coupure au creux %d : la rémanence ne joue pas", i)
		}
	}
}

// UN SEUIL FIXE NE SURVIT PAS AU CHANGEMENT DE PIÈCE. Dans un bruit de fond
// fort et CONSTANT, le plancher doit monter et cesser de crier à la parole.
func TestUnBruitDeFondConstantFinitParSeTaire(t *testing.T) {
	plan := fft.NouveauPlan(nfft)
	d := Nouveau(raies, fe, Normal, 5)
	rng := rand.New(rand.NewSource(4))
	// Bruit fort, longuement : le plancher doit l'apprendre.
	for i := 0; i < 1500; i++ {
		d.Analyse(spectreDe(plan, silence(rng, 0.05)))
	}
	bavardages := 0
	for i := 0; i < 100; i++ {
		if d.Analyse(spectreDe(plan, silence(rng, 0.05))).Parole {
			bavardages++
		}
	}
	if bavardages > 10 {
		t.Fatalf("%d/100 trames de bruit constant prises pour de la parole", bavardages)
	}
}

func TestPlusPrudentNeDetectePasPlus(t *testing.T) {
	plan := fft.NouveauPlan(nfft)
	compte := func(a Agressivite) int {
		d := Nouveau(raies, fe, a, 0)
		rng := rand.New(rand.NewSource(5))
		amorce(d, plan, rng, 0.002)
		n := 0
		for i := 0; i < 60; i++ {
			// parole faible, juste au-dessus du bruit : c'est là que
			// l'agressivité départage
			if d.Analyse(spectreDe(plan, parole(140, 0.004))).Parole {
				n++
			}
		}
		return n
	}
	bavard, prudent := compte(Bavard), compte(TresPrudent)
	if prudent > bavard {
		t.Fatalf("« très prudent » détecte %d trames contre %d pour « bavard »", prudent, bavard)
	}
}

func TestLaReinitialisationOublieLaPiecePrecedente(t *testing.T) {
	plan := fft.NouveauPlan(nfft)
	d := Nouveau(raies, fe, Normal, 5)
	rng := rand.New(rand.NewSource(6))
	for i := 0; i < 1200; i++ {
		d.Analyse(spectreDe(plan, silence(rng, 0.05)))
	}
	d.Reinitialise()
	v := d.Analyse(spectreDe(plan, silence(rng, 0.05)))
	if !v.Amorcage {
		t.Error("après réinitialisation, l'amorçage doit recommencer")
	}
	for i := range v.Plancher {
		if v.Plancher[i] > -40 {
			t.Errorf("bande %d : plancher %.1f dB conservé malgré la réinitialisation", i, v.Plancher[i])
		}
	}
}
