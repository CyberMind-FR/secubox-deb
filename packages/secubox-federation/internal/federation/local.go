// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package federation

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/sbxcert"
)

// Chemins : un seul endroit, surchargeable pour les tests.
type Chemins struct {
	Config  string // /etc/secubox/federation.yaml
	NodeKey string // /etc/secubox/secrets/annuaire/node.key — l'identité annuaire de la box
	Etat    string // /var/lib/secubox/federation
	CAKey   string // /etc/secubox/secrets/federation/ca.key (autorité seulement)
	Sites   string // /srv/metablogizer/sites — où s'installent les métablogs
}

func CheminsParDefaut() Chemins {
	return Chemins{
		Config:  "/etc/secubox/federation.yaml",
		NodeKey: "/etc/secubox/secrets/annuaire/node.key",
		Etat:    "/var/lib/secubox/federation",
		CAKey:   "/etc/secubox/secrets/federation/ca.key",
		Sites:   "/srv/metablogizer/sites",
	}
}

func (c Chemins) Cert() string    { return filepath.Join(c.Etat, "cert.yaml") }
func (c Chemins) CAPub() string   { return filepath.Join(c.Etat, "ca.pub") }
func (c Chemins) CRL() string     { return filepath.Join(c.Etat, "crl.yaml") }
func (c Chemins) DirCA() string   { return filepath.Join(c.Etat, "ca") }
func (c Chemins) Demande() string { return filepath.Join(c.Etat, "demande.json") }
func (c Chemins) Objets() string  { return filepath.Join(c.Etat, "objets") }

// Confiance : la clé de CA qui fait foi ICI (la sienne pour l'autorité, celle
// épinglée pour un membre), la liste de révocation connue, et les canaux que
// le certificat VALIDE de cette box ouvre.
func (c Chemins) Confiance(cfg *Config, clesCA func() (ed25519.PublicKey, map[string]bool)) (ed25519.PublicKey, map[string]bool, []string) {
	caPub, rev := clesCA()
	var canaux []string
	if cert, err := c.CertLocal(); err == nil && cert != nil && caPub != nil {
		if cert.Verification(caPub, time.Now(), rev).Valide {
			canaux = cert.Channels
		}
	}
	return caPub, rev, canaux
}

// CertLocal : le certificat de CETTE box, s'il existe.
func (c Chemins) CertLocal() (*sbxcert.Certificat, error) {
	b, err := os.ReadFile(c.Cert())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sbxcert.Lit(b)
}

// CAEpinglee : la clé de la CA retenue lors de l'adhésion (confiance au
// premier usage, empreinte affichée à l'administrateur à ce moment-là).
func (c Chemins) CAEpinglee() (ed25519.PublicKey, error) {
	b, err := os.ReadFile(c.CAPub())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sbxcert.LitPub(strings.TrimSpace(string(b)))
}

// Statut : la réponse de GET /api/federation/status et de `sbxctl federation status`.
type Statut struct {
	Role string `json:"role"`
	Tier string `json:"tier"`
	// TierCertifie : faux tant qu'aucun certificat VALIDE ne porte ce tier —
	// le tier du fichier de config n'est alors qu'une demande.
	TierCertifie bool              `json:"tier_certifie"`
	URL          string            `json:"federation_url,omitempty"`
	Box          string            `json:"box_did,omitempty"`
	CA           string            `json:"ca_did,omitempty"`
	Certificat   *StatutCert       `json:"certificat"`
	Sync         map[string]string `json:"sync"`
	Demandes     *int              `json:"demandes_en_attente,omitempty"`
}

type StatutCert struct {
	Serial   string          `json:"serial"`
	Tier     string          `json:"tier"`
	Channels []string        `json:"channels"`
	Rights   map[string]bool `json:"rights"`
	Expires  string          `json:"expires"`
	Etat     sbxcert.Etat    `json:"etat"`
}

// Construit : l'état MESURÉ — certificat vérifié contre la CA épinglée et la
// liste de révocation connue, pas simplement relu.
func Construit(cfg *Config, ch Chemins, caPub ed25519.PublicKey, boxDID string, revoques map[string]bool, maintenant time.Time) Statut {
	s := Statut{Role: cfg.Role, Tier: cfg.Tier, URL: cfg.Federation.URL, Box: boxDID, Sync: map[string]string{}}
	if caPub != nil {
		s.CA = sbxcert.DID(caPub)
	}
	tier := cfg.Tier
	if c, err := ch.CertLocal(); err == nil && c != nil {
		sc := &StatutCert{Serial: c.Serial, Tier: c.Tier, Channels: c.Channels, Rights: c.Rights, Expires: c.Expires}
		if caPub == nil {
			sc.Etat = sbxcert.Etat{Motif: "aucune CA épinglée : certificat non vérifiable"}
		} else {
			sc.Etat = c.Verification(caPub, maintenant, revoques)
		}
		// C'EST LE CERTIFICAT QUI FAIT LE TIER, pas le fichier de config :
		// réclamer « premium » dans federation.yaml n'ouvre rien.
		if sc.Etat.Valide {
			tier = c.Tier
			s.Tier = c.Tier
			s.TierCertifie = true
		}
		s.Certificat = sc
	}
	for _, quoi := range []string{"waf", "appstore", "metapack"} {
		s.Sync[quoi] = cfg.Intervalle(tier, quoi).String()
	}
	return s
}
