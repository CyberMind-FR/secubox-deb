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

// LA RÉFÉRENCE EST VIVANTE DÈS LES PREMIÈRES SECONDES, et la fiabilité dit à
// quel point on peut s'y fier. C'est ce qui remplace le pourcentage
// d'étalonnage : une pente, pas un mur — le module répond pendant la montée.
func TestLaChaineRepondTotEtSeDeclarePeuSure(t *testing.T) {
	a := Nouveau(audio.NouvelleSynthese(false))
	nourrit(a, voix(130, audio.Echantillonnage*3, 0.3))
	img := a.Derniere()
	if img.Fiabilite < 0 || img.Fiabilite > 1 {
		t.Errorf("fiabilité %.2f hors [0,1]", img.Fiabilite)
	}
	if img.Etat != ser.Indetermine {
		// Elle a répondu : alors elle doit se déclarer peu sûre.
		if img.Confiance > 0.45 {
			t.Errorf("confiance %.2f après trois secondes : trop assurée", img.Confiance)
		}
		if img.Fiabilite > 0.5 {
			t.Errorf("fiabilité %.2f après trois secondes : trop assurée", img.Fiabilite)
		}
	}
	if img.Observations < 1 {
		t.Error("aucune observation comptée après trois secondes de voix")
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

// ── LA FENÊTRE SE COMPTE EN VOIX, PAS EN SECONDES ──────────────────────────
//
// C'était le défaut de fond signalé — « vers 10-15 secondes on part dans les
// indéterminés ». La fenêtre valait une seconde d'HORLOGE, et personne ne
// parle cent pour cent du temps : dès qu'on marquait une pause pour respirer
// ou écouter, elle n'avait plus assez de trames voisées et la lecture
// disparaissait. Sur une conversation ordinaire, la moitié du temps.

func paroleAvecPauses(a *Analyseur, secondes int) {
	for s := 0; s < secondes; s++ {
		if s%4 == 2 || s%4 == 3 {
			nourrit(a, make([]float64, audio.Echantillonnage)) // pause
		} else {
			nourrit(a, voix(130, audio.Echantillonnage, 0.30))
		}
	}
}

func TestUneConversationAvecPausesNePerdPasSaLecture(t *testing.T) {
	a := Nouveau(audio.NouvelleSynthese(false))
	paroleAvecPauses(a, 8) // de quoi amorcer
	perdues := 0
	for s := 0; s < 24; s++ {
		if s%4 == 2 || s%4 == 3 {
			nourrit(a, make([]float64, audio.Echantillonnage))
		} else {
			nourrit(a, voix(130, audio.Echantillonnage, 0.30))
		}
		if a.Derniere().Etat == ser.Indetermine {
			perdues++
		}
	}
	if perdues > 2 {
		t.Fatalf("%d secondes sur 24 sans lecture : la respiration éteint encore la carte", perdues)
	}
}

// MAIS UNE LECTURE TENUE DIT SON ÂGE. Afficher indéfiniment la dernière humeur
// connue serait pire que de ne rien afficher : ça se lit comme une mesure en
// cours.
func TestUneLectureTenueVieillitPuisSEfface(t *testing.T) {
	a := Nouveau(audio.NouvelleSynthese(false))
	paroleAvecPauses(a, 12)
	if a.Derniere().Etat == ser.Indetermine {
		t.Skip("pas de lecture à tenir dans cette fixture")
	}
	// On triche sur l'horloge plutôt que d'attendre douze secondes.
	a.mu.Lock()
	a.bonneQuand = time.Now().Add(-PeremptionLecture - time.Second)
	a.derniereLec = ser.LectureIndeterminee(ser.MotifPeuDeVoix, "silence", true)
	a.mu.Unlock()
	lec, age := a.lectureTenue()
	if lec.Etat != ser.Indetermine {
		t.Errorf("une lecture périmée est encore servie (%s, %.1f s)", lec.Etat, age)
	}
}

// « BRUIT » ET « AMBIANCE » NE SE MASQUENT PAS. Ils disent que le signal est
// mauvais MAINTENANT : les cacher derrière une ancienne lecture empêcherait de
// comprendre pourquoi ça ne marche pas, et d'aller approcher le micro.
func TestUnDefautDeSignalNEstJamaisMasqueParUneAncienneLecture(t *testing.T) {
	a := Nouveau(audio.NouvelleSynthese(false))
	paroleAvecPauses(a, 12)
	a.mu.Lock()
	a.bonneLec = ser.Lecture{Etat: ser.Calme, Confiance: .5}
	a.bonneQuand = time.Now()
	a.derniereLec = ser.LectureIndeterminee(ser.MotifBruit, "spectre plat", true)
	a.mu.Unlock()
	if lec, _ := a.lectureTenue(); lec.Etat != ser.Indetermine || lec.Motif != ser.MotifBruit {
		t.Fatalf("le motif « bruit » est masqué : %s / %s", lec.Etat, lec.Motif)
	}
}

// ── LA STABILITÉ DE L'ÉTIQUETTE ────────────────────────────────────────────
//
// Une étiquette d'humeur ne doit pas changer toutes les deux secondes. Près de
// l'origine — là où se tient justement une voix ordinaire — trois étiquettes
// se disputent la tête, et le moindre frémissement de mesure faisait changer
// la gagnante. Ce n'est pas un changement d'humeur, c'est du bruit de mesure
// qui a l'air d'un changement d'humeur, ce qui est pire.
func TestLEtiquetteNeClignotePasSurUneVoixConstante(t *testing.T) {
	a := Nouveau(audio.NouvelleSynthese(false))
	nourrit(a, voix(130, audio.Echantillonnage*8, 0.30)) // amorçage
	var precedent string
	bascules := 0
	for s := 0; s < 24; s++ {
		nourrit(a, voix(130, audio.Echantillonnage, 0.30))
		e := a.Derniere().Etat
		if e == ser.Indetermine {
			continue
		}
		if precedent != "" && e != precedent {
			bascules++
		}
		precedent = e
	}
	// Sur une voix rigoureusement constante, au plus quelques bascules — et
	// celles qui restent sont légitimes : trois étiquettes voisines de
	// l'origine, ce que la confiance basse dit par ailleurs.
	if bascules > 6 {
		t.Fatalf("%d bascules d'étiquette sur 24 s de voix constante", bascules)
	}
}

// Le lissage ne sert pas à gagner de l'assurance : à distribution lissée, la
// confiance retenue est la plus PRUDENTE des deux.
func TestLeLissageNeGonflePasLaConfiance(t *testing.T) {
	a := Nouveau(audio.NouvelleSynthese(false))
	nourrit(a, voix(130, audio.Echantillonnage*10, 0.30))
	for s := 0; s < 12; s++ {
		nourrit(a, voix(130, audio.Echantillonnage, 0.30))
		if c := a.Derniere().Confiance; c > ser.PlafondConfiance {
			t.Fatalf("confiance %.3f au-dessus du plafond après lissage", c)
		}
	}
}
