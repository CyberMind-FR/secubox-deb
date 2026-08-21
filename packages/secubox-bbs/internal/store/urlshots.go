// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// File d'attente + état des vignettes-snapshot d'URL (#1120).
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
	"time"
)

// CleUrlshot : clé de cache d'une URL. Normalise (schéma+hôte en minuscules,
// fragment retiré) puis sha256 tronqué en 32 hexa — sûr pour _safe_key côté
// Python (ni '/', ni '.', ni '\'). Vide si l'URL n'est pas une http(s) absolue.
func CleUrlshot(brut string) string {
	u, err := url.Parse(strings.TrimSpace(brut))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	sum := sha256.Sum256([]byte(u.String()))
	return hex.EncodeToString(sum[:])[:32]
}

// EnfileUrlshot insère une ligne pending si absente, et MONTE la visibilité à
// 'public' si cette citation est publique — jamais l'inverse (une fois public,
// reste public : le fichier a fuité, on ne le reprivatise pas — cf. /f/ #1114).
func (s *Store) EnfileUrlshot(cle, u, visibility string) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`
		INSERT INTO urlshots(cle,url,visibility,statut,maj) VALUES(?,?,?,'pending',?)
		ON CONFLICT(cle) DO UPDATE SET
		  visibility = CASE WHEN excluded.visibility='public' THEN 'public' ELSE urlshots.visibility END`,
		cle, u, visibility, now)
	return err
}

// StatutUrlshot lit l'état courant d'une clé (statut de capture + visibilité).
func (s *Store) StatutUrlshot(cle string) (statut, visibility string, ok bool) {
	err := s.db.QueryRow(`SELECT statut, visibility FROM urlshots WHERE cle=?`, cle).
		Scan(&statut, &visibility)
	return statut, visibility, err == nil
}
