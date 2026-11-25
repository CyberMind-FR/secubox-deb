// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// VÉRIFICATION AVANT REDÉMARRAGE (#3932). Le postinst lance le NOUVEAU binaire avec la ligne de commande réellement effective
// (unité et surcharge locale) et `--verifier` : un drapeau inconnu, des règles ou des routes illisibles se voient pendant que
// l'ancien processus sert encore, au lieu de laisser le port fermé.

// ConfigVerifiee : ce que la ligne de commande donne ; "" = non donné.
type ConfigVerifiee struct {
	Regles, Routes, Profils string
	Cookies, Menaces        string
	Protegees               string
	Restants                []string
}

// VerifierConfiguration rend un bilan d'une ligne, ou ce qui empêcherait le WAF de servir. Profils illisibles : le WAF démarre
// quand même, plus strict (phase G désactivée) — dit, pas refusé.
//
// Refusés aussi : une plage protégée trop large (analyserCIDRs), et un registre des cookies ou un journal des menaces que le
// compte du service ne peut pas ouvrir — sbxwaf PANIQUE sur le premier (503 partout, port déjà ouvert), perd ses détections sur
// le second. Rien n'est créé ni écrit.
func VerifierConfiguration(c ConfigVerifiee) (string, error) {
	regles, routes, profils, restants := c.Regles, c.Routes, c.Profils, c.Restants
	if len(restants) > 0 {
		return "", fmt.Errorf("argument inattendu : %q (les drapeaux qui le suivent seraient ignorés)", restants[0])
	}
	if _, larges, _ := analyserCIDRs(c.Protegees); len(larges) > 0 {
		return "", fmt.Errorf("plage protégée plus large que /%d (IPv4) ou /%d (IPv6) : %s (/etc/secubox/waf/protegees.env)",
			prefixeMinProtege4, prefixeMinProtege6, strings.Join(larges, ", "))
	}
	for _, j := range []struct{ quoi, chemin string }{{"registre des cookies", c.Cookies}, {"journal des menaces", c.Menaces}} {
		if j.chemin == "" {
			continue
		}
		if err := ouvrableEnAjout(j.chemin); err != nil {
			return "", fmt.Errorf("%s : %w", j.quoi, err)
		}
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

// ouvrableEnAjout : le fichier s'ouvre en ajout, ou peut être créé (dossier, existant ou le premier ancêtre, inscriptible).
func ouvrableEnAjout(chemin string) error {
	f, err := os.OpenFile(chemin, os.O_WRONLY|os.O_APPEND|syscall.O_NONBLOCK, 0)
	if err == nil {
		return f.Close()
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for d := filepath.Dir(chemin); ; d = filepath.Dir(d) {
		st, err := os.Stat(d)
		if errors.Is(err, os.ErrNotExist) && d != filepath.Dir(d) {
			continue
		}
		switch {
		case err != nil:
			return err
		case !st.IsDir():
			return fmt.Errorf("%s n'est pas un dossier", d)
		}
		if err := syscall.Access(d, 0x2|0x1); err != nil { // écriture et traversée
			return fmt.Errorf("%s ne peut pas être créé, %s : %w", chemin, d, err)
		}
		return nil
	}
}
