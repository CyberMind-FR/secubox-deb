// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package pitch

import (
	"math"
	"math/rand"
	"testing"
)

const fe = 48000.0

// voyelle fabrique un signal à la fois périodique et riche en harmoniques,
// c'est-à-dire ce qui piège l'autocorrélation nue : le pic de l'octave
// inférieure y rivalise avec le bon.
func voyelle(f0 float64, n int, harmoniques []float64) []float64 {
	x := make([]float64, n)
	for i := range x {
		t := float64(i) / fe
		for h, a := range harmoniques {
			x[i] += a * math.Sin(2*math.Pi*f0*float64(h+1)*t)
		}
	}
	return x
}

func TestHauteurDUneVoixSynthetique(t *testing.T) {
	e := NouvelEstimateur(2048, fe)
	for _, f0 := range []float64{85, 110, 147, 196, 262, 330, 440} {
		r := e.Estime(voyelle(f0, 2048, []float64{1, 0.5, 0.3, 0.2, 0.1}))
		if !r.Voise {
			t.Errorf("%.0f Hz : non voisé alors que le signal est périodique", f0)
			continue
		}
		// Un demi-ton vaut ~6 % ; on exige dix fois mieux.
		if ecart := math.Abs(r.Hz-f0) / f0; ecart > 0.006 {
			t.Errorf("%.0f Hz : lu %.2f Hz (écart %.2f %%)", f0, r.Hz, ecart*100)
		}
		if r.Clarte < 0.8 {
			t.Errorf("%.0f Hz : clarté %.2f, trop basse pour un signal pur", f0, r.Clarte)
		}
	}
}

// L'ERREUR D'OCTAVE EST LE DÉFAUT CLASSIQUE, et la raison d'être de YIN. Un
// signal dont la fondamentale est FAIBLE devant ses harmoniques fait chuter
// l'autocorrélation nue d'une octave. Le seuil absolu doit tenir.
func TestPasDErreurDOctaveQuandLaFondamentaleEstFaible(t *testing.T) {
	e := NouvelEstimateur(2048, fe)
	const f0 = 120.0
	x := voyelle(f0, 2048, []float64{0.1, 1.0, 0.8, 0.6, 0.4}) // H2 domine
	r := e.Estime(x)
	if !r.Voise {
		t.Fatal("non voisé")
	}
	if math.Abs(r.Hz-2*f0) < math.Abs(r.Hz-f0) {
		t.Fatalf("saut d'octave : %.1f Hz au lieu de %.1f", r.Hz, f0)
	}
	if math.Abs(r.Hz-f0)/f0 > 0.02 {
		t.Fatalf("lu %.1f Hz, veut %.1f", r.Hz, f0)
	}
}

func TestLeBruitBlancNEstPasVoise(t *testing.T) {
	e := NouvelEstimateur(2048, fe)
	rng := rand.New(rand.NewSource(1))
	x := make([]float64, 2048)
	for i := range x {
		x[i] = rng.NormFloat64() * 0.2
	}
	if r := e.Estime(x); r.Voise {
		t.Fatalf("bruit déclaré voisé à %.1f Hz (clarté %.2f)", r.Hz, r.Clarte)
	}
}

func TestLeSilenceNeProduitNiHauteurNiNaN(t *testing.T) {
	e := NouvelEstimateur(2048, fe)
	r := e.Estime(make([]float64, 2048))
	if r.Voise {
		t.Error("le silence est déclaré voisé")
	}
	if math.IsNaN(r.Hz) || math.IsNaN(r.Clarte) {
		t.Fatalf("NaN sur le silence : %+v", r)
	}
}

// Hors des bornes de la voix parlée, on ne rend RIEN plutôt qu'une valeur :
// une raie à 2 kHz dans une conversation est un sifflement ou une erreur, pas
// une hauteur de voix.
func TestHorsDesBornesDeLaVoixOnNeRendRien(t *testing.T) {
	e := NouvelEstimateur(2048, fe)
	if r := e.Estime(voyelle(1500, 2048, []float64{1})); r.Voise {
		t.Fatalf("1500 Hz accepté comme hauteur de voix (%.1f)", r.Hz)
	}
}

func TestUneTrameTropCourteEstRefusee(t *testing.T) {
	e := NouvelEstimateur(2048, fe)
	if r := e.Estime(make([]float64, 100)); r.Voise || r.Hz != 0 {
		t.Fatalf("une trame courte doit être refusée, pas complétée : %+v", r)
	}
}

func BenchmarkEstime2048(b *testing.B) {
	e := NouvelEstimateur(2048, fe)
	x := voyelle(147, 2048, []float64{1, 0.5, 0.3})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Estime(x)
	}
}
