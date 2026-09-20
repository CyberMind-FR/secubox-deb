// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package jeton verifie les JWT HS256 du parc.
//
// CE QU'IL REMPLACE. La v1 se contentait de « le jeton n'est pas vide ». Ce
// n'etait pas une simplification, c'etait un trou : n'importe quelle chaine
// ouvrait l'API d'un module qui commande une messagerie chiffree de bout en
// bout.
//
// AUCUN REPLI SUR UN SECRET PAR DEFAUT. La doctrine du parc est ecrite dans
// common/secubox_core/auth.py : « A missing secret is a provisioning failure
// and must stop the service, not degrade it. » Jusqu'a #942, un noeud non
// provisionne signait tous ses jetons avec une chaine publiee dans le depot.
// Ici, secret absent => AUCUN jeton n'est accepte, et le demon le dit.
//
// SANS DEPENDANCE. HS256 tient dans crypto/hmac et encoding/base64 ; importer
// une bibliotheque JWT pour cela ajouterait du code a auditer dans le module
// qui garde les cles d'un lien Signal.
package jeton

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
)

var (
	ErrPasDeSecret = errors.New("aucun secret JWT configure")
	ErrMalForme    = errors.New("jeton mal forme")
	ErrAlgo        = errors.New("algorithme refuse")
	ErrSignature   = errors.New("signature invalide")
	ErrExpire      = errors.New("jeton expire")
)

type Verificateur struct{ secret []byte }

// entete et charge : seuls les champs dont la verification depend.
type entete struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type charge struct {
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
	Nbf int64  `json:"nbf"`
}

// Nouveau resout le secret selon la meme chaine que le reste du parc :
// l'environnement d'abord (ce que pose l'unite), puis api.jwt_secret dans
// /etc/secubox/secubox.conf. Il ne CREE jamais de secret.
func Nouveau(cheminConf string) *Verificateur {
	s := os.Getenv("SECUBOX_JWT_SECRET")
	if s == "" {
		s = depuisConf(cheminConf)
	}
	if s == "" {
		return &Verificateur{}
	}
	return &Verificateur{secret: []byte(s)}
}

// Arme dit si un secret a ete trouve. Le demon s'en sert pour AVERTIR au
// demarrage plutot que de laisser decouvrir des 401 inexplicables.
func (v *Verificateur) Arme() bool { return len(v.secret) > 0 }

// depuisConf lit api.jwt_secret. Lecteur minimal : la cle est plate, et le
// module n'embarque pas de parseur TOML (cf. internal/config).
func depuisConf(chemin string) string {
	b, err := os.ReadFile(chemin)
	if err != nil {
		return ""
	}
	section := ""
	for _, ligne := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(ligne)
		if i := strings.Index(t, "#"); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.Trim(t, "[]")
			continue
		}
		cle, val, ok := strings.Cut(t, "=")
		if !ok || section != "api" || strings.TrimSpace(cle) != "jwt_secret" {
			continue
		}
		return strings.Trim(strings.TrimSpace(val), `"`)
	}
	return ""
}

// Valide verifie signature, algorithme et fenetre temporelle, puis rend le
// sujet. L'ordre compte : on ne LIT la charge qu'une fois la signature
// verifiee — analyser du JSON non authentifie, c'est offrir une surface.
func (v *Verificateur) Valide(brut string) (string, error) {
	if !v.Arme() {
		return "", ErrPasDeSecret
	}
	parties := strings.Split(brut, ".")
	if len(parties) != 3 {
		return "", ErrMalForme
	}

	var e entete
	bh, err := base64.RawURLEncoding.DecodeString(parties[0])
	if err != nil || json.Unmarshal(bh, &e) != nil {
		return "", ErrMalForme
	}
	// REFUSER `none` ET tout ce qui n'est pas HS256 : accepter l'algorithme
	// annonce par le jeton est la faille classique des implementations JWT.
	if e.Alg != "HS256" {
		return "", ErrAlgo
	}

	mac := hmac.New(sha256.New, v.secret)
	mac.Write([]byte(parties[0] + "." + parties[1]))
	attendue := mac.Sum(nil)
	fournie, err := base64.RawURLEncoding.DecodeString(parties[2])
	if err != nil {
		return "", ErrMalForme
	}
	// Comparaison a temps constant : une comparaison naive fuit la signature
	// octet par octet.
	if !hmac.Equal(attendue, fournie) {
		return "", ErrSignature
	}

	var c charge
	bc, err := base64.RawURLEncoding.DecodeString(parties[1])
	if err != nil || json.Unmarshal(bc, &c) != nil {
		return "", ErrMalForme
	}
	maintenant := time.Now().Unix()
	// Une petite tolerance couvre la derive d'horloge entre modules ; au-dela
	// elle rendrait `exp` decoratif.
	const glissement = 30
	if c.Exp != 0 && maintenant > c.Exp+glissement {
		return "", ErrExpire
	}
	if c.Nbf != 0 && maintenant+glissement < c.Nbf {
		return "", ErrExpire
	}
	return c.Sub, nil
}
