// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// verifierJeton valide un JWT HS256 signé avec le secret de flotte
// (api.jwt_secret, le même que lit le BBS). L'algorithme est IMPOSÉ (jamais lu
// du jeton), l'expiration exigée. Retourne les claims.
func verifierJeton(tok, secret string) (map[string]any, error) {
	if secret == "" {
		return nil, errors.New("secret JWT absent")
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("jeton malformé")
	}
	// En-tête : imposer alg=HS256, typ JWT.
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var hd struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(hb, &hd) != nil || hd.Alg != "HS256" {
		return nil, errors.New("alg non HS256")
	}
	// Signature.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	att := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(att), []byte(parts[2])) {
		return nil, errors.New("signature invalide")
	}
	// Claims + expiration exigée.
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(pb, &claims); err != nil {
		return nil, err
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, errors.New("exp manquant")
	}
	if int64(exp) < time.Now().Unix() {
		return nil, errors.New("jeton expiré")
	}
	return claims, nil
}

// signerJeton fabrique un JWT HS256 de service (pour appeler le BBS).
func signerJeton(secret, sub string, ttl time.Duration) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	now := time.Now()
	claims, _ := json.Marshal(map[string]any{
		"sub": sub, "iss": "metanews",
		"iat": now.Unix(), "exp": now.Add(ttl).Unix(),
	})
	pl := base64.RawURLEncoding.EncodeToString(claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(hdr + "." + pl))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return hdr + "." + pl + "." + sig
}
