// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package fft

import (
	"math"
	"testing"
)

// UNE FFT SE VÉRIFIE EXACTEMENT, c'est ce qui rend acceptable de l'écrire
// soi-même. Trois propriétés suffisent à la coincer : un Dirac doit donner un
// spectre plat, une sinusoïde pure une seule raie à la bonne place et à la
// bonne amplitude, et Parseval doit tenir au flottant près.

func TestDiracDonneUnSpectrePlat(t *testing.T) {
	p := NouveauPlan(64)
	re := make([]float64, 64)
	im := make([]float64, 64)
	re[0] = 1
	p.Transforme(re, im)
	for k := range re {
		if math.Abs(math.Hypot(re[k], im[k])-1) > 1e-12 {
			t.Fatalf("raie %d = %g, veut 1", k, math.Hypot(re[k], im[k]))
		}
	}
}

func TestParseval(t *testing.T) {
	const n = 256
	p := NouveauPlan(n)
	re := make([]float64, n)
	im := make([]float64, n)
	somme := 0.0
	for i := range re {
		re[i] = math.Sin(2*math.Pi*7*float64(i)/n) + 0.3*math.Cos(2*math.Pi*31*float64(i)/n)
		somme += re[i] * re[i]
	}
	p.Transforme(re, im)
	spectrale := 0.0
	for k := range re {
		spectrale += re[k]*re[k] + im[k]*im[k]
	}
	spectrale /= n
	if math.Abs(somme-spectrale)/somme > 1e-10 {
		t.Fatalf("Parseval violé : temps %g, fréquence %g", somme, spectrale)
	}
}

// L'AMPLITUDE DOIT ÊTRE LUE, PAS APPROCHÉE. Une sinusoïde d'amplitude 0,5 doit
// rendre 0,5 sur sa raie, fenêtre de Hann comprise : c'est tout l'objet de la
// correction de gain. Sans elle on afficherait la moitié, et le niveau
// dépendrait de la fenêtre plutôt que de la voix.
func TestUneSinusoidePureRendSonAmplitude(t *testing.T) {
	const (
		n     = 2048
		fe    = 48000.0
		f0    = 750.0 // multiple exact de fe/n : pas de fuite à compenser
		ampli = 0.5
	)
	p := NouveauPlan(n)
	x := make([]float64, n)
	for i := range x {
		x[i] = ampli * math.Sin(2*math.Pi*f0*float64(i)/fe)
	}
	sp := p.Spectre(x, nil)

	kmax, vmax := 0, 0.0
	for k, v := range sp {
		if v > vmax {
			kmax, vmax = k, v
		}
	}
	if f := p.Frequence(kmax, fe); math.Abs(f-f0) > fe/n {
		t.Errorf("raie à %.1f Hz, veut %.1f", f, f0)
	}
	if math.Abs(vmax-ampli)/ampli > 0.02 {
		t.Errorf("amplitude lue %.4f, veut %.2f (correction de fenêtre absente ?)", vmax, ampli)
	}
}

func TestLeSilenceNeProduitPasDeNaN(t *testing.T) {
	p := NouveauPlan(256)
	sp := p.Spectre(make([]float64, 256), nil)
	for k, v := range sp {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			t.Fatalf("raie %d = %v sur un signal muet", k, v)
		}
		if d := Decibels(v, -120); d != -120 {
			t.Fatalf("dB du silence = %v, veut le plancher -120", d)
		}
	}
}

func TestUneTailleQuiNEstPasUnePuissanceDeDeuxEstRefusee(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("une taille non radix-2 doit échouer bruyamment, pas rendre du faux")
		}
	}()
	NouveauPlan(1000)
}

func BenchmarkSpectre2048(b *testing.B) {
	p := NouveauPlan(2048)
	x := make([]float64, 2048)
	for i := range x {
		x[i] = math.Sin(float64(i) * 0.01)
	}
	var out []float64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = p.Spectre(x, out)
	}
}

func TestLaTransformeeInverseRendLeSignal(t *testing.T) {
	const n = 128
	p := NouveauPlan(n)
	re := make([]float64, n)
	im := make([]float64, n)
	orig := make([]float64, n)
	for i := range re {
		re[i] = math.Sin(float64(i)*0.3) + 0.4*math.Cos(float64(i)*1.1)
		orig[i] = re[i]
	}
	p.Transforme(re, im)
	p.TransformeInverse(re, im)
	for i := range re {
		if math.Abs(re[i]-orig[i]) > 1e-12 || math.Abs(im[i]) > 1e-12 {
			t.Fatalf("échantillon %d : %g+%gi, veut %g", i, re[i], im[i], orig[i])
		}
	}
}
