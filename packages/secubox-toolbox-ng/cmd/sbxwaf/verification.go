// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// VÉRIFICATION AVANT REDÉMARRAGE (#3932). Le postinst lance le NOUVEAU binaire avec la ligne de commande réellement effective
// (unité et surcharge locale) et `--verifier` : un drapeau inconnu, des règles ou des routes illisibles se voient pendant que
// l'ancien processus sert encore, au lieu de laisser le port fermé.

// VerifierConfiguration rend un bilan d'une ligne, ou ce qui empêcherait le WAF de servir. Profils illisibles : le WAF démarre
// quand même, plus strict (phase G désactivée) — dit, pas refusé.
func VerifierConfiguration(regles, routes, profils string, restants []string) (string, error) {
	if len(restants) > 0 {
		return "", fmt.Errorf("argument inattendu : %q (les drapeaux qui le suivent seraient ignorés)", restants[0])
	}
	var bilan []string
	// Un fichier ABSENT n'est pas un refus : le WAF démarre sans lui, comme aujourd'hui. Illisible, si.
	absent := func(quoi, chemin string) bool {
		_, err := os.Stat(chemin)
		if errors.Is(err, os.ErrNotExist) {
			bilan = append(bilan, quoi+" : "+chemin+" absent")
			return true
		}
		return false
	}
	if regles != "" && !absent("règles", regles) {
		if err := lireObjetJSON(regles); err != nil {
			return "", fmt.Errorf("règles : %w", err)
		}
		n := len(loadRulesJSON(regles).cats)
		if n == 0 {
			return "", fmt.Errorf("règles : %s ne donne aucune catégorie", regles)
		}
		bilan = append(bilan, fmt.Sprintf("%d catégorie(s) de règles", n))
	}
	if routes != "" && !absent("routes", routes) {
		if err := lireObjetJSON(routes); err != nil {
			return "", fmt.Errorf("routes : %w", err)
		}
		bilan = append(bilan, fmt.Sprintf("%d route(s)", len(loadRoutesJSON(routes))))
	}
	if profils != "" {
		if _, err := chargerVhostProfiles(profils); err != nil {
			bilan = append(bilan, fmt.Sprintf("profils illisibles (%v) : phase G désactivée", err))
		}
	}
	if len(bilan) == 0 {
		bilan = append(bilan, "drapeaux valides")
	}
	return strings.Join(bilan, ", "), nil
}

func lireObjetJSON(chemin string) error {
	brut, err := os.ReadFile(chemin)
	if err != nil {
		return err
	}
	var objet map[string]json.RawMessage
	if err := json.Unmarshal(brut, &objet); err != nil {
		return fmt.Errorf("%s : %w", chemin, err)
	}
	return nil
}
