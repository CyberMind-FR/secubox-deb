// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbx-authwatch — filtres de service declaratifs (#1223)
//
// POURQUOI DECLARATIF. Les motifs SSH, SMTP et IMAP sont dans le code parce
// qu'ils sont universels : tout postfix ecrit la meme ligne. Les services
// HEBERGES, non — gitea, nextcloud, mastodon, le panneau d'administration ont
// chacun leur formulation, leur emplacement de journal, et la liste s'allonge a
// chaque service ajoute. Les figer dans le binaire, c'est exiger une
// recompilation pour couvrir un service de plus.
//
// D'OU CE FICHIER. Un service = une entree declarative : ou lire, quoi
// reconnaitre, comment le nommer. Ajouter nextcloud ne demande pas une ligne de
// Go.
//
// DEUX SOURCES, PARCE QUE LES DEUX EXISTENT. gitea et mastodon ecrivent dans le
// journal de leur conteneur, lisible de l'hote par `journalctl --directory`.
// nextcloud ecrit dans un FICHIER, nextcloud.log. Une abstraction qui ne
// couvrirait que journald laisserait nextcloud dehors — c'est-a-dire le service
// qui porte les documents.
//
// PRUDENCE AU CHARGEMENT. Un motif invalide, un champ manquant, un fichier
// illisible : on refuse l'entree FAUTIVE en le disant, et on garde les autres.
// Abandonner tout le fichier pour une virgule priverait de couverture des
// services qui, eux, etaient bien declares.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// MotifService est un motif declare pour un service heberge.
type MotifService struct {
	Motif     string `json:"motif"`
	Categorie string `json:"categorie"`
	Severite  string `json:"severite"`
	Detail    string `json:"detail"`
	re        *regexp.Regexp
}

// ServiceFiltre declare ou lire et quoi reconnaitre pour un service.
type ServiceFiltre struct {
	ID      string         `json:"id"`
	Nom     string         `json:"nom"`
	Journal string         `json:"journal"` // repertoire journald, ou vide
	Fichier string         `json:"fichier"` // fichier texte, ou vide
	Actif   *bool          `json:"actif"`   // absent = actif
	Motifs  []MotifService `json:"motifs"`
}

type fichierServices struct {
	Services []ServiceFiltre `json:"services"`
}

// Filtres porte les services declares, compiles.
type Filtres struct {
	services []ServiceFiltre
	avertis  []string // ce qui a ete refuse, pour le dire au demarrage
}

// ChargerFiltres lit le fichier declaratif. Un chemin absent n'est pas une
// erreur : la couverture des services heberges est optionnelle.
func ChargerFiltres(chemin string) (*Filtres, error) {
	f := &Filtres{}
	if strings.TrimSpace(chemin) == "" {
		return f, nil
	}
	brut, err := os.ReadFile(chemin)
	if err != nil {
		if os.IsNotExist(err) {
			return f, nil
		}
		return nil, fmt.Errorf("%s : %w", chemin, err)
	}
	var doc fichierServices
	if err := json.Unmarshal(brut, &doc); err != nil {
		return nil, fmt.Errorf("%s : JSON illisible : %w", chemin, err)
	}

	for _, s := range doc.Services {
		if s.Actif != nil && !*s.Actif {
			continue
		}
		if strings.TrimSpace(s.ID) == "" {
			f.avertis = append(f.avertis, "service sans id — ignoré")
			continue
		}
		if s.Journal == "" && s.Fichier == "" {
			f.avertis = append(f.avertis,
				fmt.Sprintf("%s : ni journal ni fichier déclaré — ignoré", s.ID))
			continue
		}
		compiles := make([]MotifService, 0, len(s.Motifs))
		for i, m := range s.Motifs {
			if strings.TrimSpace(m.Motif) == "" {
				f.avertis = append(f.avertis,
					fmt.Sprintf("%s : motif %d vide — ignoré", s.ID, i+1))
				continue
			}
			re, err := regexp.Compile("(?i)" + m.Motif)
			if err != nil {
				// On refuse CE motif, pas le service entier : les autres
				// motifs du service restent utiles.
				f.avertis = append(f.avertis,
					fmt.Sprintf("%s : motif %d invalide (%v) — ignoré", s.ID, i+1, err))
				continue
			}
			if re.SubexpIndex("ip") < 0 {
				f.avertis = append(f.avertis,
					fmt.Sprintf("%s : motif %d ne capture pas (?P<ip>…) — ignoré", s.ID, i+1))
				continue
			}
			m.re = re
			if m.Categorie == "" {
				m.Categorie = "auth_" + s.ID + ":failed"
			}
			if m.Severite == "" {
				m.Severite = "medium"
			}
			compiles = append(compiles, m)
		}
		if len(compiles) == 0 {
			f.avertis = append(f.avertis,
				fmt.Sprintf("%s : aucun motif exploitable — service ignoré", s.ID))
			continue
		}
		s.Motifs = compiles
		if s.Nom == "" {
			s.Nom = s.ID
		}
		f.services = append(f.services, s)
	}
	return f, nil
}

// Sources rend les sources a suivre pour les services declares.
func (f *Filtres) Sources() []Source {
	if f == nil {
		return nil
	}
	var out []Source
	for _, s := range f.services {
		out = append(out, Source{Nom: s.ID, Repertoire: s.Journal, Fichier: s.Fichier})
	}
	return out
}

// Reconnaitre applique les motifs declares a une ligne.
//
// Rend le premier signal trouve. L'appelant essaie d'abord les motifs
// universels (SSH/SMTP/IMAP) : un service heberge ne doit pas masquer une
// ligne postfix qui aurait ete mieux classee.
func (f *Filtres) Reconnaitre(ligne string) (Signal, bool) {
	if f == nil || strings.TrimSpace(ligne) == "" {
		return Signal{}, false
	}
	for _, s := range f.services {
		for _, m := range s.Motifs {
			sm := m.re.FindStringSubmatch(ligne)
			if sm == nil {
				continue
			}
			idx := m.re.SubexpIndex("ip")
			if idx < 0 || idx >= len(sm) {
				continue
			}
			ip := strings.Trim(sm[idx], "[]")
			if !estAdresse(ip) {
				continue
			}
			return Signal{
				IP:        ip,
				Service:   s.ID,
				Categorie: m.Categorie,
				Severite:  m.Severite,
				Detail:    m.Detail,
				Cible:     cibleDeclaree(m.re, sm),
			}, true
		}
	}
	return Signal{}, false
}

// cibleDeclaree lit le groupe (?P<cible>…) quand le motif en declare un : le
// compte vise est ce qui rend une campagne lisible.
func cibleDeclaree(re *regexp.Regexp, sm []string) string {
	i := re.SubexpIndex("cible")
	if i < 0 || i >= len(sm) {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(sm[i]))
}

// Avertissements rend ce qui a ete refuse au chargement.
func (f *Filtres) Avertissements() []string {
	if f == nil {
		return nil
	}
	return f.avertis
}

// Nombre rend le nombre de services effectivement charges.
func (f *Filtres) Nombre() int {
	if f == nil {
		return 0
	}
	return len(f.services)
}
