// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package sbxobj : l'objet SBX installable, et son paquet .sbx (#1391).
//
// PAS UN FORMAT DE PLUS. Un .sbx de métablog EST le .sbxsite que le
// metablogizer exporte et importe déjà (tar.gz : manifest.json + content.tar
// ou repo.bundle) — on lui AJOUTE ce qui lui manquait :
//
//   - la fiche de l'objet (auteur, licence, canal, rétribution…) ;
//   - l'intégrité : SHA-256 de chaque membre ;
//   - l'éditeur : son DID, sa clé, et son certificat SBX ;
//   - une signature Ed25519 de l'éditeur sur la forme canonique du manifeste.
//
// Le metablogizer l'importe toujours (il ignore les champs qu'il ne connaît
// pas) ; la fédération, elle, refuse d'installer ce qui n'est pas signé,
// intègre, et édité par une box que la CA a certifiée.
package sbxobj

import (
	"errors"
	"fmt"
	"regexp"
)

// Types d'objets du cahier des charges. P5a n'emballe que `metablog`.
var Types = []string{"app", "site", "metablog", "waf", "dataset", "archive", "config", "template"}

var reNom = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
var reVersion = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+~-]{0,31}$`)

// Objet : la fiche publique (le SBXObject de la spec, avec la rétribution).
type Objet struct {
	ID          string `json:"id"` // <type>.<nom>
	Name        string `json:"name"`
	Type        string `json:"type"`
	Version     string `json:"version"`
	Channel     string `json:"channel"`
	Author      string `json:"author"`
	License     string `json:"license"`
	Wallet      string `json:"wallet,omitempty"`
	SupportURL  string `json:"support_url,omitempty"`
	Description string `json:"description,omitempty"`
}

func (o *Objet) Valide() error {
	if !contient(Types, o.Type) {
		return fmt.Errorf("type inconnu : %q", o.Type)
	}
	if !reNom.MatchString(o.Name) {
		return fmt.Errorf("nom invalide : %q (minuscules, chiffres, tirets)", o.Name)
	}
	if o.ID != o.Type+"."+o.Name {
		return fmt.Errorf("id %q : %s.%s attendu", o.ID, o.Type, o.Name)
	}
	if !reVersion.MatchString(o.Version) {
		return fmt.Errorf("version invalide : %q", o.Version)
	}
	if !contient([]string{"stable", "beta", "alpha"}, o.Channel) {
		return fmt.Errorf("canal inconnu : %q", o.Channel)
	}
	if o.Author == "" || o.License == "" {
		return errors.New("author et license sont requis")
	}
	for _, s := range []string{o.Author, o.License, o.Wallet, o.SupportURL} {
		if len(s) > 200 {
			return errors.New("champ trop long (200 caractères au plus)")
		}
	}
	if len(o.Description) > 1000 {
		return errors.New("description trop longue (1000 caractères au plus)")
	}
	return nil
}

func (o *Objet) carte() map[string]any {
	m := map[string]any{"id": o.ID, "name": o.Name, "type": o.Type, "version": o.Version,
		"channel": o.Channel, "author": o.Author, "license": o.License}
	for k, v := range map[string]string{"wallet": o.Wallet, "support_url": o.SupportURL, "description": o.Description} {
		if v != "" {
			m[k] = v
		}
	}
	return m
}

func contient(l []string, s string) bool {
	for _, e := range l {
		if e == s {
			return true
		}
	}
	return false
}
