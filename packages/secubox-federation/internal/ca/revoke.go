// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package ca

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/canon"
	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/sbxcert"
	"gopkg.in/yaml.v3"
)

// Revocation : une entrée de la liste.
type Revocation struct {
	Serial string `yaml:"serial"`
	Date   string `yaml:"date"`
	Motif  string `yaml:"motif"`
}

// CRL : la liste de révocation, SIGNÉE par la CA. Une box qui la télécharge
// la vérifie avant de s'en servir : une liste falsifiée pourrait sinon
// « révoquer » tout le monde, ou blanchir une clé volée.
type CRL struct {
	Version   int          `yaml:"version"`
	Issuer    string       `yaml:"issuer"`
	Updated   string       `yaml:"updated"`
	Revoked   []Revocation `yaml:"revoked"`
	Signature string       `yaml:"signature,omitempty"`
}

func (l *CRL) Charge() map[string]any {
	rev := make([]any, 0, len(l.Revoked))
	for _, r := range l.Revoked {
		rev = append(rev, map[string]any{"serial": r.Serial, "date": r.Date, "motif": r.Motif})
	}
	return map[string]any{"version": l.Version, "issuer": l.Issuer, "updated": l.Updated, "revoked": rev}
}

// Series : l'ensemble des numéros révoqués.
func (l *CRL) Series() map[string]bool {
	m := make(map[string]bool, len(l.Revoked))
	for _, r := range l.Revoked {
		m[r.Serial] = true
	}
	return m
}

// VerifieCRL : signature par la CA attendue.
func VerifieCRL(b []byte, caPub ed25519.PublicKey) (*CRL, error) {
	var l CRL
	if err := yaml.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	if l.Issuer != sbxcert.DID(caPub) {
		return nil, errors.New("liste émise par une autre autorité")
	}
	msg, err := canon.Encode(l.Charge())
	if err != nil {
		return nil, err
	}
	if !sbxcert.Verifie(caPub, msg, l.Signature) {
		return nil, errors.New("liste de révocation : signature invalide")
	}
	return &l, nil
}

func (a *Autorite) cheminCRL() string { return filepath.Join(a.Dir, "crl.yaml") }

// CRL : la liste courante (vide et signée si aucune révocation).
func (a *Autorite) CRL() (*CRL, error) {
	b, err := os.ReadFile(a.cheminCRL())
	if errors.Is(err, os.ErrNotExist) {
		return a.signeCRL(&CRL{Version: 1, Issuer: a.DID, Revoked: []Revocation{}}, time.Now())
	}
	if err != nil {
		return nil, err
	}
	return VerifieCRL(b, a.Pub)
}

// Revoque ajoute un numéro de série (idempotent) et re-signe la liste.
func (a *Autorite) Revoque(serie, motif string, maintenant time.Time) (*CRL, error) {
	if _, err := a.Lit(serie); err != nil {
		return nil, errors.New("aucun certificat émis sous ce numéro : " + serie)
	}
	l, err := a.CRL()
	if err != nil {
		return nil, err
	}
	if l.Series()[serie] {
		return l, nil
	}
	motif = strings.TrimSpace(motif)
	if motif == "" {
		motif = "non précisé"
	}
	l.Revoked = append(l.Revoked, Revocation{Serial: serie, Date: maintenant.UTC().Format(time.RFC3339), Motif: motif})
	return a.signeCRL(l, maintenant)
}

func (a *Autorite) signeCRL(l *CRL, maintenant time.Time) (*CRL, error) {
	l.Updated = maintenant.UTC().Format(time.RFC3339)
	msg, err := canon.Encode(l.Charge())
	if err != nil {
		return nil, err
	}
	l.Signature = "ed25519:" + hex.EncodeToString(a.signe(msg))
	b, err := yaml.Marshal(l)
	if err != nil {
		return nil, err
	}
	return l, ecritAtomique(a.cheminCRL(), b, 0o644)
}

// YAMLCRL : la forme publiée.
func (l *CRL) YAML() ([]byte, error) { return yaml.Marshal(l) }
