// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package audio

import (
	"math"
	"math/rand"
	"time"
)

// Synthese : une voix FABRIQUÉE, pour la démonstration et les tests.
//
// ELLE SE DÉCLARE COMME TELLE (`Reelle: false`), et l'interface doit le
// montrer en grand. Un cockpit qui s'anime est très convaincant ; sans
// marquage, une démonstration se prend pour une mesure, et l'on finit par
// croire qu'on a écouté quelqu'un.
type Synthese struct {
	phase   float64
	t       int64
	rng     *rand.Rand
	horloge time.Time
	direct  bool
}

// NouvelleSynthese fabrique la source. `direct` = true respecte le temps réel
// (utile pour une démonstration) ; false rend les échantillons aussi vite que
// demandé (utile pour un test, qui ne doit pas durer dix secondes).
func NouvelleSynthese(direct bool) *Synthese {
	return &Synthese{rng: rand.New(rand.NewSource(1)), horloge: time.Now(), direct: direct}
}

// Lis fabrique une parole plausible : des groupes de syllabes séparés de
// pauses, une fondamentale qui module, deux formants, et un souffle de fond.
func (s *Synthese) Lis(dst []float64) (int, error) {
	if s.direct {
		// On ne rend pas les échantillons plus vite que le temps ne passe,
		// sinon la « latence » affichée serait celle d'un calcul, pas d'un flux.
		attendu := time.Duration(s.t) * time.Second / Echantillonnage
		if d := attendu - time.Since(s.horloge); d > 0 {
			time.Sleep(d)
		}
	}
	for i := range dst {
		t := float64(s.t) / Echantillonnage
		// Cycle de six secondes : quatre de parole, deux de silence.
		cycle := math.Mod(t, 6)
		if cycle > 4 {
			dst[i] = s.rng.NormFloat64() * 0.002 // bruit de pièce
			s.t++
			continue
		}
		// Enveloppe syllabique à ~4 Hz, comme une parole ordinaire.
		env := 0.5 + 0.5*math.Sin(2*math.Pi*4*t)
		env *= env
		f0 := 128 + 18*math.Sin(2*math.Pi*0.35*t) // intonation lente
		s.phase += 2 * math.Pi * f0 / Echantillonnage
		v := math.Sin(s.phase) + 0.55*math.Sin(2*s.phase) + 0.30*math.Sin(3*s.phase)
		v += 0.25 * math.Sin(2*math.Pi*780*t) // formant
		v += 0.15 * math.Sin(2*math.Pi*1240*t)
		dst[i] = 0.22*env*v + s.rng.NormFloat64()*0.003
		s.t++
	}
	return len(dst), nil
}

func (s *Synthese) Ferme() error { return nil }
func (s *Synthese) Decrit() Description {
	return Description{
		Genre: "synthese", Reelle: false, Perenne: true,
		Detail: "VOIX FABRIQUÉE — démonstration, aucune personne n'est écoutée",
	}
}
