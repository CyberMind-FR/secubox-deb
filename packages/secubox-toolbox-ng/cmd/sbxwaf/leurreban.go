// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import "time"

// Ban sur détection de leurre (#2238, décision du propriétaire du 2026-10-11).
//
// Un leurre n'est servi QUE dans l'espace non routé, à un client extérieur, pour un hôte qui n'est pas à nous (voir main.go : LAN et première
// partie ne sont jamais leurrés). Quelqu'un qui y arrive n'est donc pas un utilisateur de nos services. Reste le risque réel : un CGNAT partagé
// avec un scanner. D'où la durée GRADUÉE — un faux positif est débloqué en une heure —, qui monte à la récidive : 1 h, puis 24 h, puis 7 j.
// La récidive se lit dans le journal de bans (catégorie « leurre: »), fenêtre de 30 jours : la mémoire survit aux redémarrages.
const fenetreRecidiveLeurre = 30 * 24 * time.Hour

func dureeLeurre(recidives int) time.Duration {
	switch {
	case recidives <= 0:
		return time.Hour
	case recidives == 1:
		return 24 * time.Hour
	default:
		return 7 * 24 * time.Hour
	}
}

// recidivesLeurre compte les bans de leurre déjà posés sur cette adresse dans la fenêtre.
func (s *Server) recidivesLeurre(ip string) int {
	if s.nftBan == nil {
		return 0
	}
	return s.nftBan.store.CompteCategorie(ip, "leurre:", time.Now().Add(-fenetreRecidiveLeurre).Unix())
}
