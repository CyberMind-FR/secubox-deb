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

// verifierJeton valide un JWT HS256 signé avec le secret de flotte (imposé
// HS256, exp exigé).
func verifierJeton(tok, secret string) error {
	if secret == "" {
		return errors.New("secret absent")
	}
	parts := strings.Split(strings.TrimPrefix(tok, "Bearer "), ".")
	if len(parts) != 3 {
		return errors.New("malformé")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	var hd struct{ Alg string `json:"alg"` }
	if json.Unmarshal(hb, &hd) != nil || hd.Alg != "HS256" {
		return errors.New("alg")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal([]byte(base64.RawURLEncoding.EncodeToString(mac.Sum(nil))), []byte(parts[2])) {
		return errors.New("signature")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	var cl map[string]any
	if json.Unmarshal(pb, &cl) != nil {
		return errors.New("claims")
	}
	exp, ok := cl["exp"].(float64)
	if !ok || int64(exp) < time.Now().Unix() {
		return errors.New("exp")
	}
	return nil
}
