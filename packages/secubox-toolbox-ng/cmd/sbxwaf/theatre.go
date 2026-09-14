// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

// THÉÂTRE — reconnaître, puis SIMULER pour voir la suite (#1290).
//
// LE LEURRE SANS MÉMOIRE S'ARRÊTE TROP TÔT. Servir un faux `/.env` apprend
// qu'on a sondé `/.env`. Mais un outil ne s'arrête pas là : il prend ce qu'il
// trouve et il l'ESSAIE. C'est cette deuxième étape qui distingue un balayage
// de masse d'un kit qui sait quoi faire d'un secret — et c'est elle qu'un
// leurre amnésique ne verra jamais, parce qu'il aura répondu à la tentative
// comme à une première visite.
//
// D'OÙ UNE MÉMOIRE COURTE. On retient, par visiteur, les étapes déjà
// traversées et les marques déjà semées. La réponse suivante en tient compte :
// qui revient avec une clé qu'on lui a donnée obtient ce que cette clé promet.
// Il avance, et en avançant il se décrit.
//
// CE QUI NE CHANGE PAS D'UN IOTA :
//   * on reste dans l'espace NON ROUTÉ — aucun service réel n'est en jeu ;
//   * les corps restent des constantes ; rien n'est exécuté, rien n'est lu sur
//     le disque. « Simuler » ne veut pas dire « implémenter » : on écrit une
//     réponse plausible, on ne construit pas un serveur ;
//   * apprentissage seul — la mémoire ne sert qu'à mieux observer, jamais à
//     sanctionner.
//
// LA MÉMOIRE EST BORNÉE, ET CE N'EST PAS UN DÉTAIL. La box tient ~1,8 Gio
// disponibles. Une carte indexée par adresse source est, telle quelle, un
// moyen offert à n'importe qui de la remplir : il suffit de varier l'IP. On
// plafonne donc le nombre de scènes ET leur durée de vie, et l'on jette les
// plus anciennes quand le plafond est atteint. Un leurre qui fait tomber la
// box qu'il protège serait le comble.

import (
	"sync"
	"time"
)

// Scene — ce qu'on a déjà joué avec un visiteur.
type Scene struct {
	Etapes  []string  // familles de sondes traversées, dans l'ordre
	Marques []string  // aléas semés à ce visiteur
	Vu      time.Time // dernier contact, pour l'expiration
}

// Theatre garde les scènes en cours. Sûr en concurrence.
type Theatre struct {
	mu     sync.Mutex
	scenes map[string]*Scene
	max    int
	ttl    time.Duration
}

// NewTheatre borne la mémoire dès la construction : pas de réglage implicite.
func NewTheatre(max int, ttl time.Duration) *Theatre {
	if max <= 0 {
		max = 2048
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &Theatre{scenes: make(map[string]*Scene, 64), max: max, ttl: ttl}
}

// Cle identifie un visiteur par son adresse ET la forme de ses requêtes.
//
// POURQUOI PAS L'ADRESSE SEULE. Derrière un même NAT, deux outils différents
// partageraient une scène et la rendraient incohérente. L'empreinte d'en-têtes
// les sépare — et comme elle vient de leur bibliothèque HTTP, elle reste
// stable sur toute la durée d'un kit.
func (t *Theatre) Cle(ip, empreinte string) string { return ip + "|" + empreinte }

// Avance enregistre une étape et rend le NUMÉRO d'étape (1 pour la première)
// ainsi que les marques déjà semées à ce visiteur.
func (t *Theatre) Avance(cle string, famille familleSonde, alea string) (int, []string) {
	if t == nil || cle == "" {
		return 1, nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.purgeSansVerrou()

	s := t.scenes[cle]
	if s == nil {
		if len(t.scenes) >= t.max {
			// Plafond atteint : on jette la plus ancienne plutôt que de
			// refuser d'apprendre. Une scène perdue coûte moins qu'une box
			// qui gonfle.
			t.jetteLaPlusAncienneSansVerrou()
		}
		s = &Scene{}
		t.scenes[cle] = s
	}
	s.Vu = time.Now()
	// On borne aussi la LONGUEUR d'une scène : un fuzzer qui tire dix mille
	// chemins ne doit pas faire grossir une entrée indéfiniment. Au-delà, on
	// sait déjà tout ce qu'on avait à savoir de lui.
	if len(s.Etapes) < 64 {
		s.Etapes = append(s.Etapes, string(famille))
	}
	if alea != "" && len(s.Marques) < 32 {
		s.Marques = append(s.Marques, alea)
	}
	return len(s.Etapes), append([]string(nil), s.Marques...)
}

// Connu dit si ce visiteur a déjà été servi, et combien d'étapes il a faites.
func (t *Theatre) Connu(cle string) (int, bool) {
	if t == nil {
		return 0, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if s := t.scenes[cle]; s != nil {
		return len(s.Etapes), true
	}
	return 0, false
}

// Sequence rend les étapes traversées — c'est ELLE, et non une requête isolée,
// qui décrit l'outil.
func (t *Theatre) Sequence(cle string) []string {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if s := t.scenes[cle]; s != nil {
		return append([]string(nil), s.Etapes...)
	}
	return nil
}

func (t *Theatre) purgeSansVerrou() {
	limite := time.Now().Add(-t.ttl)
	for k, s := range t.scenes {
		if s.Vu.Before(limite) {
			delete(t.scenes, k)
		}
	}
}

func (t *Theatre) jetteLaPlusAncienneSansVerrou() {
	var vieille string
	var quand time.Time
	for k, s := range t.scenes {
		if vieille == "" || s.Vu.Before(quand) {
			vieille, quand = k, s.Vu
		}
	}
	if vieille != "" {
		delete(t.scenes, vieille)
	}
}

// Taille — pour l'observabilité et les tests.
func (t *Theatre) Taille() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.scenes)
}
