// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package ser

import (
	"sort"
	"sync"
)

// L'ORDINAIRE DU GROUPE : une référence de secours, jamais un jugement.
//
// ── LE PROBLÈME QU'IL RÉSOUT ───────────────────────────────────────────────
//
// Une personne qui arrive n'a pas d'ordinaire connu. Pendant trois minutes de
// parole effective, le module ne pouvait rien dire — et se taire si longtemps
// ressemble à une panne. L'ordinaire du groupe donne un point de départ.
//
// ── POURQUOI C'EST DÉFENDABLE ICI, ET SEULEMENT ICI ────────────────────────
//
// Tout ce module répète qu'un seuil absolu sur la hauteur compare des gens
// entre eux, ce qui n'a pas de sens : une voix grave n'est pas une voix
// abattue. Un étalon partagé EST une comparaison entre personnes, et il faut
// donc dire précisément pourquoi celui-ci ne retombe pas dans le travers.
//
// Ce n'est pas une norme de population tirée d'un corpus : ce sont les
// ordinaires de gens qui parlent DANS LA MÊME PIÈCE, DEVANT DES MICROS
// COMPARABLES, sur la même board. Le placement du micro et l'acoustique de la
// pièce pèsent autant que n'importe quelle différence entre individus ; les
// tenir constants retire justement le plus gros des confusions. Ce qui reste
// — grave ou aigu, fort ou discret — est une vraie différence entre personnes,
// et c'est pour cela que cette référence est PROVISOIRE et ANNONCÉE comme
// telle, remplacée dès que l'ordinaire personnel existe.
//
// ── ET POURQUOI IL A LE MÊME SEUIL QUE LES STATISTIQUES PARTAGÉES ──────────
//
// La hauteur médiane d'une voix identifie assez bien quelqu'un. Un « ordinaire
// du groupe » constitué d'UN seul contributeur est donc la signature vocale de
// cette personne, sous un autre nom. À deux, celui qui connaît la sienne
// retrouve l'autre. Il en faut trois — la même arithmétique, la même règle.
const MinContributeurs = 3

// EtalonPartage : les ordinaires PERSONNELS mis en commun.
//
// On ne met pas en commun des mesures brutes : on met en commun, pour chaque
// personne, UN nombre par trait — son ordinaire à elle, une fois qu'il est
// établi. Le groupe est donc une distribution d'ordinaires, ce qui est
// exactement ce qu'on veut comparer, et ce qui limite d'autant ce qu'on
// accumule : rien qui ressemble à un enregistrement.
// resume : l'ordinaire d'UNE personne pour UN trait — son centre et sa
// dispersion propre. Deux nombres, pas une série.
//
// POURQUOI DEUX ET PAS UN. Avec une seule médiane par personne, trois
// contributeurs donnent trois nombres : de quoi situer un centre, pas de quoi
// mesurer une dispersion robuste (l'interquartile en demande huit). On
// obtenait donc des écarts nuls partout, c'est-à-dire une base commune qui ne
// distinguait rien. En transportant AUSSI la dispersion propre à chacun, trois
// personnes suffisent — et cela ne stocke toujours que deux nombres par tête,
// rien qui ressemble à un enregistrement.
type resume struct{ centre, dispersion float64 }

type EtalonPartage struct {
	mu      sync.RWMutex
	f0      map[string]resume // par session : son ordinaire à elle
	energie map[string]resume
	debit   map[string]resume
	jitter  map[string]resume
	centre  map[string]resume
}

func NouvelEtalonPartage() *EtalonPartage {
	return &EtalonPartage{
		f0: map[string]resume{}, energie: map[string]resume{},
		debit: map[string]resume{}, jitter: map[string]resume{},
		centre: map[string]resume{},
	}
}

// FiabiliteMinPartage : on ne met en commun qu'une référence déjà solide.
// Mettre en commun des à-peu-près donnerait un à-peu-près commun, et personne
// n'y gagnerait — surtout pas celui qui vient d'arriver et s'y fie.
const FiabiliteMinPartage = 0.70

// Contribue enregistre l'ordinaire d'une session.
func (p *EtalonPartage) Contribue(session string, r *Reference) {
	if p == nil || r == nil || r.Fiabilite() < FiabiliteMinPartage {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.f0[session] = resume{r.F0.Centre, r.F0.Disp}
	p.energie[session] = resume{r.Energie.Centre, r.Energie.Disp}
	p.debit[session] = resume{r.Debit.Centre, r.Debit.Disp}
	p.jitter[session] = resume{r.Jitter.Centre, r.Jitter.Disp}
	p.centre[session] = resume{r.Centre.Centre, r.Centre.Disp}
}

// Retire oublie une session. UN DÉPART EFFACE LA CONTRIBUTION : rien ne
// subsiste d'une personne qui a fermé son onglet, et surtout pas son
// empreinte vocale moyenne.
func (p *EtalonPartage) Retire(session string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.f0, session)
	delete(p.energie, session)
	delete(p.debit, session)
	delete(p.jitter, session)
	delete(p.centre, session)
}

// Contributeurs : combien d'ordinaires composent la référence.
func (p *EtalonPartage) Contributeurs() int {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.f0)
}

// Utilisable : y a-t-il assez de monde pour que la référence soit à la fois
// statistiquement utile et anonyme ?
func (p *EtalonPartage) Utilisable() bool { return p.Contributeurs() >= MinContributeurs }

// ecartGroupe : où se situe `v` dans l'ordinaire du groupe.
//
// LA DISPERSION RETENUE EST LA PLUS GRANDE DES DEUX, et c'est le point
// délicat. Deux choses varient : ce que CHACUN fait varier sa propre voix
// (dispersion interne, qu'on transporte), et ce qui SÉPARE les gens entre eux
// (l'étalement des centres). Ne retenir que la première déclarerait « très
// activé » quiconque parle simplement plus haut que la moyenne du groupe —
// exactement la confusion que tout ce module refuse. Ne retenir que la
// seconde, avec trois personnes, donnerait une échelle au hasard. On prend la
// plus large : c'est la lecture la plus PRUDENTE, celle qui crie le moins.
func ecartGroupe(m map[string]resume, v float64) float64 {
	if len(m) < MinContributeurs {
		return 0
	}
	centres := make([]float64, 0, len(m))
	disps := make([]float64, 0, len(m))
	for _, r := range m {
		centres = append(centres, r.centre)
		disps = append(disps, r.dispersion)
	}
	c := mediane(centres)
	sort.Float64s(centres)
	entre := (centres[len(centres)-1] - centres[0]) / 2
	d := mediane(disps)
	if entre > d {
		d = entre
	}
	if d <= 1e-9 {
		return 0
	}
	z := (v - c) / d
	// Même bornage que pour l'étalon personnel : au-delà de trois dispersions,
	// la magnitude exacte ne veut plus rien dire.
	if z > 3 {
		return 3
	}
	if z < -3 {
		return -3
	}
	return z
}

// Ecarts : la position des traits courants dans l'ordinaire DU GROUPE.
func (p *EtalonPartage) Ecarts(t Traits) map[string]float64 {
	if !p.Utilisable() {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return map[string]float64{
		"f0":      ecartGroupe(p.f0, t.F0Median),
		"energie": ecartGroupe(p.energie, t.Energie),
		"debit":   ecartGroupe(p.debit, t.Debit),
		"jitter":  ecartGroupe(p.jitter, t.Jitter),
		"centre":  ecartGroupe(p.centre, t.Centre),
	}
}

func mediane(s []float64) float64 {
	if len(s) == 0 {
		return 0
	}
	c := append([]float64(nil), s...)
	sort.Float64s(c)
	return c[len(c)/2]
}
