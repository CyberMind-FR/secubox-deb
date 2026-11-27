// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"log"
	"net/http"
	"time"
)

// Ban sur détection de leurre (#2238, décision du propriétaire du 2026-10-11).
//
// Un leurre n'est servi QUE dans l'espace non routé, à un client extérieur, pour un hôte qui n'est pas à nous (voir main.go : LAN et première
// partie ne sont jamais leurrés). Quelqu'un qui y arrive n'est donc pas un utilisateur de nos services. Reste le risque réel : un CGNAT partagé
// avec un scanner. Le propriétaire a tranché (#3988, 2026-11-26) : un balayeur de service inexistant n'a aucune lecture innocente, il est traité en
// offensif — 24 h au premier contact, 7 j à la récidive (l'ancienne marche d'une heure laissait des centaines d'attaquants « non bannis »).
// La récidive se lit dans le journal de bans (catégorie « leurre: »), fenêtre de 30 jours : la mémoire survit aux redémarrages.
const fenetreRecidiveLeurre = 30 * 24 * time.Hour

func dureeLeurre(recidives int) time.Duration {
	switch {
	case recidives <= 0:
		return 24 * time.Hour
	default:
		return 7 * 24 * time.Hour
	}
}

// dureeMesure garde l'ancienne gradation 1 h / 24 h / 7 j pour les mesures
// (`mesure:`), qui l'empruntaient : #3988 ne change que les leurres.
func dureeMesure(recidives int) time.Duration {
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

// prefixeSondeCMS : catégorie des bans de sonde de CMS absent (#4019), « cms_sonde:wordpress ».
const prefixeSondeCMS = "cms_sonde:"

// recidivesSondeCMS compte les bans de sonde de CMS déjà posés sur cette adresse (même fenêtre que les leurres, #4019).
func (s *Server) recidivesSondeCMS(ip string) int {
	if s.nftBan == nil {
		return 0
	}
	return s.nftBan.store.CompteCategorie(ip, prefixeSondeCMS, time.Now().Add(-fenetreRecidiveLeurre).Unix())
}

// UN LEURRE N'A AUCUN AUTRE BUT QUE DE DÉTECTER (décision du propriétaire, 2026-10-11) : tout contact avec un service simulé est banni, où qu'il ait
// lieu — hôte non routé, chemin-appât d'un vrai vhost, marque rejouée. Les garde-fous restent : jamais le LAN, jamais une plage protégée (la box, la
// Freebox, le maillage), durée graduée à la récidive (24 h puis 7 j, #3988), journal de bans annulable.
//
// `minDuree` : plancher de durée. Une MARQUE REJOUÉE (une fausse clé servie par le leurre qui revient dans une requête) prouve que cette source a
// moissonné le leurre puis essaie ce qu'elle a pris : 24 h au minimum.
func (s *Server) banLeurre(ip, categorie, sev string, minDuree time.Duration) {
	if s == nil || !s.leurreBan || s.nftBan == nil || adresseProtegee(ip, s.protegees) {
		return
	}
	d := dureeLeurre(s.recidivesLeurre(ip))
	if d < minDuree {
		d = minDuree
	}
	log.Printf("sbxwaf: leurre-ban %s ← %s (%s)", ip, categorie, d)
	go s.nftBan.BanFor(ip, "leurre:"+categorie, sev, d)
}

// surMarqueRevenue : une marque semée par le leurre revient dans une requête vers un SERVICE RÉEL. Jamais pour le LAN.
func (s *Server) surMarqueRevenue(r *http.Request) {
	if s == nil || !s.leurreBan || s.leurre == nil || s.leurre.fil == nil {
		return
	}
	ip := clientIP(r)
	if privateCIDR(ip) || len(s.marquesRevenues(r)) == 0 {
		return
	}
	s.banLeurre(ip, "marque-revenue", "high", 24*time.Hour)
}
