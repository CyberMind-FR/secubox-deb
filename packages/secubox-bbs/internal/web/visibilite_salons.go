// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: BBS — CE QU'UN APPELANT NE VOIT PAS (#1608).
//
// UNE SEULE REGLE, POUR TOUTES LES PORTES. Les pages, l'API des membres, la
// carte du Hall, les compteurs de non-lus, les notifications : chacune demande
// ici quels salons son lecteur ne voit pas, et un fil d'un de ces salons
// n'existe pas pour lui — ni dans une liste, ni par son adresse, ni par un
// compteur. Pour qui n'y a pas acces, la reponse est 404, jamais 403 : un
// refus confirmerait que le fil existe.
package web

import (
	"log"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// masqueSalons : les salons qu'un appelant ne doit pas voir.
//
// `tout` vaut vrai quand on ne sait meme plus lesquels sont prives : alors rien
// ne passe. Une page vide se remarque et se signale ; un salon ferme montre a
// tort ne se rattrape pas.
type masqueSalons struct {
	caches map[int64]bool
	tout   bool
}

// voit : ce salon existe-t-il pour cet appelant ?
func (m masqueSalons) voit(cat int64) bool {
	return !m.tout && !m.caches[cat]
}

// construireMasque applique la regle de repli, separee de la lecture pour
// pouvoir l'eprouver sans casser une base.
//
// EN CAS D'ERREUR, ON FERME. Si la liste nominative est illisible, tout salon
// prive est cache, membre ou non ; si meme la liste des salons l'est, plus
// aucun fil ne sort. Jamais l'inverse : une erreur ne doit pas ouvrir un salon.
func construireMasque(caches map[int64]bool, err error,
	lireSalons func() ([]store.Category, error)) masqueSalons {
	if err == nil {
		if caches == nil {
			caches = map[int64]bool{}
		}
		return masqueSalons{caches: caches}
	}
	cats, errCats := lireSalons()
	if errCats != nil {
		return masqueSalons{tout: true}
	}
	m := masqueSalons{caches: map[int64]bool{}}
	for _, c := range cats {
		if c.Prive {
			m.caches[c.ID] = true
		}
	}
	return m
}

// masquePour rend le masque d'un compte du BBS. `uid` 0 = visiteur sans compte :
// il ne voit aucun salon prive.
func (s *Server) masquePour(uid int64, sysop bool) masqueSalons {
	caches, err := s.st.SalonsCachesPour(uid, sysop)
	if err != nil {
		log.Printf("bbs: salons caches pour %d illisibles (%v) : tout salon prive est cache", uid, err)
	}
	return construireMasque(caches, err, func() ([]store.Category, error) {
		return s.st.Categories(false)
	})
}

// masqueVisiteur : le masque du visiteur d'une page.
func (s *Server) masqueVisiteur(v visiteur) masqueSalons {
	if !v.Connecte {
		return s.masquePour(0, false)
	}
	return s.masquePour(v.ID, v.Sysop())
}

// masqueAnonyme : ce que voit quelqu'un dont on ne sait rien. C'est la regle
// de toute surface lue sans session — la carte du Hall, les pieces rendues
// publiques.
func (s *Server) masqueAnonyme() masqueSalons { return s.masquePour(0, false) }

// masqueCompte : le masque d'un compte resolu depuis un jeton. Le rang de
// sysop est relu dans la base du BBS ; s'il est illisible, le compte est traite
// en membre ordinaire.
func (s *Server) masqueCompte(uid int64) masqueSalons {
	sysop := false
	if uid > 0 {
		if u, err := s.st.UserInfo(uid); err == nil {
			sysop = u.Role == store.RoleSysop
		}
	}
	return s.masquePour(uid, sysop)
}

// filsRecents : les derniers fils que ce masque laisse voir.
func (s *Server) filsRecents(n int, pub bool, m masqueSalons) ([]store.Thread, error) {
	if m.tout {
		return nil, nil
	}
	return s.st.RecentHors(n, pub, m.caches)
}

// salonOuvertATous : un salon qu'un visiteur sans compte peut voir. C'est la
// condition pour qu'un contenu de ce salon devienne lisible hors session — une
// piece jointe rendue publique, par exemple.
func (s *Server) salonOuvertATous(cat int64) bool {
	return s.masqueAnonyme().voit(cat)
}
