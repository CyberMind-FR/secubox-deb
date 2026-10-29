// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"errors"
	"io/fs"
	"log"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/lecture"
)

// cheminReglages : fichier d'environnement facultatif, relatif à la racine. Il
// est lu par l'agent lui-même, plus par systemd (EnvironmentFile suivrait un
// lien posé dans /etc/secubox par le compte partagé secubox, R12/R36).
const (
	cheminReglages = "etc/secubox/pilotage-agent.env"
	reglagesMax    = 16 << 10
)

// clesReglages : les seules variables qu'un fichier de réglages peut poser.
var clesReglages = map[string]bool{
	"PILOTAGE_MAITRE":              true,
	"PILOTAGE_RELEVE_INTERVALLE_S": true,
	"PILOTAGE_MEMOIRE_SEUIL_MO":    true,
	"PILOTAGE_SWAP_SEUIL_PCT":      true,
	"PILOTAGE_BOUCLE_RELANCES":     true,
	"PILOTAGE_BOUCLE_FENETRE_S":    true,
}

// chargerReglages lit le fichier de réglages sous racine par descripteur, sans
// suivre de lien (lecture.LireDeConfiance) : il doit appartenir à p (root:root
// en production) et n'être inscriptible ni par le groupe ni par les autres ;
// sinon il est ignoré en entier, avec une ligne de journal. Absent : rien.
// Format KEY=VALEUR (guillemets simples ou doubles retirés) ; seules les clés
// de clesReglages sont posées par poser ; comme EnvironmentFile de systemd, le
// fichier l'emporte sur l'environnement de l'unité.
func chargerReglages(racine string, p lecture.Proprietaire, poser func(cle, valeur string) error) {
	b, err := lecture.LireDeConfiance(racine, cheminReglages, reglagesMax, p)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		log.Printf("fichier de réglages ignoré : %v (attendu : fichier régulier root:root, sans droit d'écriture groupe/autres)", err)
		return
	}
	for _, ligne := range strings.Split(string(b), "\n") {
		ligne = strings.TrimSpace(ligne)
		if ligne == "" || strings.HasPrefix(ligne, "#") {
			continue
		}
		cle, valeur, ok := strings.Cut(ligne, "=")
		cle, valeur = strings.TrimSpace(cle), strings.TrimSpace(valeur)
		if !ok || !clesReglages[cle] {
			log.Printf("réglages : %q non reconnu, ligne ignorée", tronquer(cle, 64))
			continue
		}
		if len(valeur) >= 2 && (valeur[0] == '"' || valeur[0] == '\'') && valeur[len(valeur)-1] == valeur[0] {
			valeur = valeur[1 : len(valeur)-1]
		}
		if err := poser(cle, valeur); err != nil {
			log.Printf("réglages : %s non posé : %v", cle, err)
		}
	}
}

// tronquer borne une chaîne venue d'un fichier avant de la journaliser.
func tronquer(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
