// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package moteur

import (
	"math"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/audio"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/ser"
)

// nourrit pousse du signal dans l'analyseur sans passer par la boucle
// temps réel, pour que les tests durent des millisecondes.
func nourrit(a *Analyseur, x []float64) {
	a.anneau.Ecris(x, a.analyseTrame)
}

func voix(f0 float64, n int, ampli float64) []float64 {
	x := make([]float64, n)
	for i := range x {
		t := float64(i) / audio.Echantillonnage
		env := 0.5 + 0.5*math.Sin(2*math.Pi*4*t)
		x[i] = ampli * env * (math.Sin(2*math.Pi*f0*t) +
			0.6*math.Sin(2*math.Pi*2*f0*t) +
			0.3*math.Sin(2*math.Pi*820*t))
	}
	return x
}

func TestUneVoixEstEntenduePasLeSilence(t *testing.T) {
	a := Nouveau(audio.NouvelleSynthese(false))
	// Amorçage du VAD sur du quasi-silence.
	nourrit(a, make([]float64, audio.Echantillonnage))
	if a.Derniere().Voix {
		t.Error("voix détectée sur du silence")
	}
	nourrit(a, voix(130, audio.Echantillonnage, 0.3))
	if !a.Derniere().Voix {
		t.Error("voix non détectée sur une voyelle franche")
	}
	if p := a.Derniere().Pitch; p < 120 || p > 140 {
		t.Errorf("hauteur %.1f Hz pour une fondamentale à 130", p)
	}
}

// LA RÈGLE CARDINALE, VUE DEPUIS LA SORTIE. Quoi qu'on pousse dans la chaîne,
// aucune image ne doit sortir avec une confiance de certitude, ni sans sa
// réserve dès qu'elle affirme quelque chose.
func TestAucuneImageNAffirmeUneCertitude(t *testing.T) {
	a := Nouveau(audio.NouvelleSynthese(false))
	for i := 0; i < 20; i++ {
		nourrit(a, voix(90+float64(i)*12, audio.Echantillonnage/2, 0.1+float64(i)*0.04))
		img := a.Derniere()
		if img.Confiance > ser.PlafondConfiance {
			t.Fatalf("confiance %.3f au-dessus du plafond", img.Confiance)
		}
		if img.Etat != ser.Indetermine && img.Reserve == "" {
			t.Fatalf("l'image affirme %q sans réserve", img.Etat)
		}
	}
}

// AVANT L'ÉTALONNAGE, ON NE DIT PAS D'HUMEUR. C'est le cas NORMAL des
// premières minutes, pas une panne.
func TestAvantEtalonnageLEtatResteIndetermine(t *testing.T) {
	a := Nouveau(audio.NouvelleSynthese(false))
	nourrit(a, voix(130, audio.Echantillonnage*3, 0.3))
	img := a.Derniere()
	if img.Etat != ser.Indetermine {
		t.Fatalf("état %q rendu après trois secondes, sans étalon", img.Etat)
	}
	if img.Etalonnage <= 0 || img.Etalonnage > 1 {
		t.Errorf("progression d'étalonnage %.2f hors [0,1]", img.Etalonnage)
	}
}

// Le spectre envoyé doit tenir dans ce qu'un écran peut montrer, et rester
// lisible : pas de NaN, pas d'infini, des décibels bornés.
func TestLeSpectreEnvoyeEstBorneEtDeLaBonneTaille(t *testing.T) {
	a := Nouveau(audio.NouvelleSynthese(false))
	nourrit(a, voix(200, audio.Echantillonnage, 0.4))
	f := a.Derniere().FFT
	if len(f) != BandesAffichees {
		t.Fatalf("%d bandes, veut %d", len(f), BandesAffichees)
	}
	for i, v := range f {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			t.Fatalf("bande %d = %v", i, v)
		}
		if v < -100.01 || v > 6 {
			t.Fatalf("bande %d = %.1f dB, hors des bornes attendues", i, v)
		}
	}
}

// L'ÉCHELLE DOIT ÊTRE LOGARITHMIQUE : une voix à 200 Hz doit se voir dans le
// premier tiers des bandes, pas écrasée dans la première.
func TestLeSpectreEstEnEchelleLogarithmique(t *testing.T) {
	a := Nouveau(audio.NouvelleSynthese(false))
	nourrit(a, voix(200, audio.Echantillonnage, 0.4))
	f := a.Derniere().FFT
	crete, ou := -200.0, 0
	for i, v := range f {
		if v > crete {
			crete, ou = v, i
		}
	}
	// 200 Hz sur une échelle log de 50 à 8000 Hz : ln(200/50)/ln(8000/50) ≈ 0,27
	attendu := int(math.Log(200.0/50) / math.Log(8000.0/50) * BandesAffichees)
	if math.Abs(float64(ou-attendu)) > 8 {
		t.Fatalf("crête en bande %d, attendue vers %d", ou, attendu)
	}
}

func TestLeDebitADUnOrdreDeGrandeurPlausible(t *testing.T) {
	a := Nouveau(audio.NouvelleSynthese(false))
	// L'enveloppe de `voix` module à 4 Hz : ~240 « syllabes » par minute.
	nourrit(a, voix(130, audio.Echantillonnage*3, 0.35))
	d := a.Traits().Debit
	if d < 120 || d > 400 {
		t.Fatalf("débit %.0f syllabes/min pour une enveloppe à 4 Hz (attendu ~240)", d)
	}
}

// LA CHARGE ET LA LATENCE SONT MESURÉES. Un chiffre de latence qu'on
// n'instrumente pas est un chiffre qu'on invente.
func TestLaLatenceEtLaChargeSontRenseignees(t *testing.T) {
	a := Nouveau(audio.NouvelleSynthese(false))
	nourrit(a, voix(130, audio.Echantillonnage, 0.3))
	img := a.Derniere()
	// Le pas d'analyse vaut 512/48000 = 10,7 ms : c'est le plancher.
	if img.LatenceMs < 10 || img.LatenceMs > 60 {
		t.Errorf("latence %.1f ms hors du plausible", img.LatenceMs)
	}
	if img.ChargeCPU <= 0 {
		t.Error("charge processeur nulle : elle n'est pas mesurée")
	}
}

// UNE SOURCE FABRIQUÉE DOIT SE VOIR JUSQUE DANS L'IMAGE, sinon une
// démonstration finit par passer pour une mesure.
func TestUneSourceFabriqueeSeVoitDansLImage(t *testing.T) {
	a := Nouveau(audio.NouvelleSynthese(false))
	nourrit(a, voix(130, audio.Echantillonnage/2, 0.3))
	if a.Derniere().SourceReelle {
		t.Fatal("l'image prétend venir d'une vraie voix")
	}
}

// Le budget annoncé est « < 8 % d'un cœur ». Ce test ne prouve rien sur
// l'ARM64 de la board, mais il attrape une régression d'un facteur dix.
func TestLeCoutParTrameResteRaisonnable(t *testing.T) {
	a := Nouveau(audio.NouvelleSynthese(false))
	trame := voix(130, TailleTrame, 0.3)
	// Amorçage, pour que le VAD laisse passer le chemin coûteux (YIN).
	for i := 0; i < 80; i++ {
		a.analyseTrame(trame)
	}
	debut := time.Now()
	const n = 200
	for i := 0; i < n; i++ {
		a.analyseTrame(trame)
	}
	parTrame := time.Since(debut) / n
	// Une trame arrive toutes les 10,7 ms. À 8 % d'un cœur, on a 0,85 ms.
	budget := PasTrame * time.Second / audio.Echantillonnage * 8 / 100
	if parTrame > budget*4 {
		t.Fatalf("%v par trame, budget x4 = %v : la chaîne a nettement enflé", parTrame, budget*4)
	}
	t.Logf("coût mesuré : %v/trame (budget 8 %% d'un cœur = %v)", parTrame, budget)
}
