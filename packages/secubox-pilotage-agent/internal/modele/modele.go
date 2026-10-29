// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package modele porte le modèle de données TR-181 de l'agent : des sources
// fournissent des paramètres sous leur chemin complet, le modèle les assemble
// et répond aux requêtes Get (chemin exact ou préfixe terminé par un point).
package modele

import (
	"context"
	"sort"
	"strings"
)

// Source fournit un sous-ensemble de paramètres, chacun sous son chemin complet.
type Source interface {
	Nom() string
	Lire(ctx context.Context) (map[string]any, error)
}

// Declarant est facultatif : une source qui l'implémente annonce ses chemins
// (gabarits « {i} » pour les listes) pour GetSupportedDM.
type Declarant interface {
	Chemins() []string
}

// Resultat est la réponse à un chemin demandé.
type Resultat struct {
	Chemin string         `json:"path"`
	Params map[string]any `json:"params,omitempty"`
	Erreur string         `json:"err,omitempty"`
	// Echecs : noms (triés) des sources en échec quand une requête par préfixe a quand même trouvé des valeurs ;
	// le maître y voit un relevé dégradé (il n'efface rien).
	Echecs []string `json:"failed,omitempty"`
}

// Modele assemble les sources.
type Modele struct {
	sources []Source
}

// NouveauModele construit un modèle sur les sources données.
func NouveauModele(sources ...Source) *Modele {
	return &Modele{sources: sources}
}

// Get lit chaque source une seule fois puis répond à chaque chemin. Une source
// en échec n'empêche pas les autres ; si un chemin ne trouve rien alors qu'une
// source a échoué, l'erreur mentionne cette source plutôt que « chemin inconnu ».
func (m *Modele) Get(ctx context.Context, chemins []string) []Resultat {
	tout := map[string]any{}
	var echecs []string
	for _, s := range m.sources {
		p, err := s.Lire(ctx)
		if err != nil {
			echecs = append(echecs, s.Nom())
			continue
		}
		for k, v := range p {
			tout[k] = v
		}
	}
	res := make([]Resultat, 0, len(chemins))
	for _, c := range chemins {
		r := Resultat{Chemin: c, Params: map[string]any{}}
		for k, v := range tout {
			if k == c || (strings.HasSuffix(c, ".") && strings.HasPrefix(k, c)) {
				r.Params[k] = v
			}
		}
		if len(r.Params) > 0 && len(echecs) > 0 && strings.HasSuffix(c, ".") {
			r.Echecs = append([]string(nil), echecs...)
			sort.Strings(r.Echecs)
		}
		if len(r.Params) == 0 {
			r.Params = nil
			if len(echecs) > 0 {
				r.Erreur = "source indisponible : " + strings.Join(echecs, ", ")
			} else {
				r.Erreur = "chemin inconnu"
			}
		}
		res = append(res, r)
	}
	return res
}

// Supportes rend la liste triée des chemins connus (GetSupportedDM).
func (m *Modele) Supportes() []string {
	var l []string
	for _, s := range m.sources {
		if d, ok := s.(Declarant); ok {
			l = append(l, d.Chemins()...)
		}
	}
	sort.Strings(l)
	return l
}

// Aplatir fusionne les paramètres de plusieurs résultats en une table unique
// (chemin complet → valeur) ; un résultat en erreur n'apporte rien.
func Aplatir(res []Resultat) map[string]any {
	plat := map[string]any{}
	for _, r := range res {
		if r.Erreur != "" {
			continue
		}
		for k, v := range r.Params {
			plat[k] = v
		}
	}
	return plat
}
