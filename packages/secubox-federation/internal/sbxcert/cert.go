// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package sbxcert : le certificat SBX v2 (#1389).
//
// UNE SEULE AUTORITÉ DE CONFIANCE. Le sujet d'un certificat est l'IDENTITÉ
// ANNUAIRE de la box — did:plc:<sha256(clé publique)[:32]>, la clé de
// /etc/secubox/secrets/annuaire/node.key — et la signature porte sur
// canonical_bytes(charge utile sans « signature »), exactement comme tout objet
// de secubox-annuaire. Un certificat émis ici se vérifie donc aussi en Python,
// avec annuaire.crypto.verify, sans rien réinventer.
//
// Le YAML n'est qu'une PRÉSENTATION : lisible, diffable. Ce qui est signé est
// la forme canonique JSON des mêmes champs.
package sbxcert

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/canon"
	"gopkg.in/yaml.v3"
)

const Version = 2

// Droits connus. Un droit inconnu est refusé à l'émission : une faute de frappe
// ne doit pas produire un certificat qui « accorde » quelque chose que rien ne lit.
var DroitsConnus = []string{"appstore", "metapack", "waf_pro", "mesh", "support"}

// Canaux de dépôt, du plus stable au plus neuf.
var CanauxConnus = []string{"stable", "beta", "alpha"}

var reDID = regexp.MustCompile(`^did:plc:[0-9a-f]{32}$`)
var reSerie = regexp.MustCompile(`^SBX-[0-9]{4}-[0-9]{4,}$`)
var reJour = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

// Certificat : le format du cahier des charges, avec deux champs de plus —
// `issued` (daté) et `issuer` (le DID de la CA, pour savoir QUELLE clé vérifie).
type Certificat struct {
	Version   int             `yaml:"version"`
	Serial    string          `yaml:"serial"`
	BoxID     string          `yaml:"box_id"`
	Owner     string          `yaml:"owner"`
	Tier      string          `yaml:"tier"`
	Channels  []string        `yaml:"channels"`
	Rights    map[string]bool `yaml:"rights"`
	Issued    string          `yaml:"issued"`
	Expires   string          `yaml:"expires"`
	Issuer    string          `yaml:"issuer"`
	Pubkey    string          `yaml:"pubkey"`
	Signature string          `yaml:"signature,omitempty"`
}

// Charge : ce qui est signé — tous les champs sauf la signature.
func (c *Certificat) Charge() map[string]any {
	ch := append([]string{}, c.Channels...)
	return map[string]any{
		"version":  c.Version,
		"serial":   c.Serial,
		"box_id":   c.BoxID,
		"owner":    c.Owner,
		"tier":     c.Tier,
		"channels": ch,
		"rights":   c.Rights,
		"issued":   c.Issued,
		"expires":  c.Expires,
		"issuer":   c.Issuer,
		"pubkey":   c.Pubkey,
	}
}

// Octets : la forme canonique à signer.
func (c *Certificat) Octets() ([]byte, error) { return canon.Encode(c.Charge()) }

// ── Clés et DID ─────────────────────────────────────────────────────────────

// DID d'une clé publique, à la manière de annuaire.crypto.did_from_pubkey.
func DID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "did:plc:" + hex.EncodeToString(h[:])[:32]
}

// FormatPub / LitPub : « ed25519:<hex> ».
func FormatPub(pub ed25519.PublicKey) string { return "ed25519:" + hex.EncodeToString(pub) }

func LitPub(s string) (ed25519.PublicKey, error) {
	h, ok := strings.CutPrefix(s, "ed25519:")
	if !ok {
		return nil, errors.New("clé publique : préfixe ed25519: attendu")
	}
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("clé publique : 32 octets hexadécimaux attendus")
	}
	return ed25519.PublicKey(b), nil
}

// Signe / Verifie : « ed25519:<hex> » sur des octets canoniques.
func Signe(priv ed25519.PrivateKey, msg []byte) string {
	return "ed25519:" + hex.EncodeToString(ed25519.Sign(priv, msg))
}

func Verifie(pub ed25519.PublicKey, msg []byte, sig string) bool {
	h, ok := strings.CutPrefix(sig, "ed25519:")
	if !ok {
		return false
	}
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, msg, b)
}

// ── Validation ──────────────────────────────────────────────────────────────

// Valide contrôle la FORME : champs présents, sujet auto-certifiant (le DID
// est bien l'empreinte de la clé), droits et canaux connus.
func (c *Certificat) Valide() error {
	if c.Version != Version {
		return fmt.Errorf("version %d : seule la %d est comprise", c.Version, Version)
	}
	if !reSerie.MatchString(c.Serial) {
		return fmt.Errorf("numéro de série invalide : %q", c.Serial)
	}
	if !reDID.MatchString(c.BoxID) || !reDID.MatchString(c.Issuer) {
		return errors.New("box_id et issuer doivent être des did:plc")
	}
	pub, err := LitPub(c.Pubkey)
	if err != nil {
		return err
	}
	// LE SUJET EST LA CLÉ. Un box_id qui ne serait pas l'empreinte de pubkey
	// permettrait de présenter la clé d'une box sous le nom d'une autre.
	if DID(pub) != c.BoxID {
		return errors.New("box_id n'est pas l'empreinte de pubkey — sujet non auto-certifiant")
	}
	if strings.TrimSpace(c.Owner) == "" || strings.TrimSpace(c.Tier) == "" {
		return errors.New("owner et tier sont requis")
	}
	if !reJour.MatchString(c.Expires) {
		return fmt.Errorf("expires : AAAA-MM-JJ attendu, pas %q", c.Expires)
	}
	if _, err := time.Parse(time.RFC3339, c.Issued); err != nil {
		return fmt.Errorf("issued : RFC 3339 attendu (%v)", err)
	}
	for _, ch := range c.Channels {
		if !contient(CanauxConnus, ch) {
			return fmt.Errorf("canal inconnu : %q", ch)
		}
	}
	for d := range c.Rights {
		if !contient(DroitsConnus, d) {
			return fmt.Errorf("droit inconnu : %q", d)
		}
	}
	return nil
}

// Etat : la vérification COMPLÈTE face à la clé de la CA et à une date.
type Etat struct {
	Valide  bool   `json:"valide"`
	Motif   string `json:"motif,omitempty"`
	Expire  bool   `json:"expire"`
	Revoque bool   `json:"revoque"`
}

// Verification : forme, émetteur attendu, signature, échéance, révocation.
func (c *Certificat) Verification(caPub ed25519.PublicKey, maintenant time.Time, revoques map[string]bool) Etat {
	if err := c.Valide(); err != nil {
		return Etat{Motif: err.Error()}
	}
	if c.Issuer != DID(caPub) {
		return Etat{Motif: "émis par " + c.Issuer + ", pas par cette CA"}
	}
	msg, err := c.Octets()
	if err != nil {
		return Etat{Motif: err.Error()}
	}
	if !Verifie(caPub, msg, c.Signature) {
		return Etat{Motif: "signature invalide"}
	}
	if revoques[c.Serial] {
		return Etat{Revoque: true, Motif: "certificat révoqué"}
	}
	fin, _ := time.Parse("2006-01-02", c.Expires)
	// Valable JUSQU'À la fin du jour d'échéance (UTC).
	if !maintenant.Before(fin.Add(24 * time.Hour)) {
		return Etat{Expire: true, Motif: "certificat expiré le " + c.Expires}
	}
	return Etat{Valide: true}
}

// ── YAML ────────────────────────────────────────────────────────────────────

// YAML ne réordonne RIEN : la signature porte sur l'ordre des canaux tel
// qu'émis (la CA le normalise, voir TrieCanaux). Relu, un certificat doit
// redonner exactement les octets signés.
func (c *Certificat) YAML() ([]byte, error) { return yaml.Marshal(c) }

// TrieCanaux : stable, beta, alpha — l'ordre fixé à l'émission.
func TrieCanaux(l []string) []string {
	out := append([]string{}, l...)
	sort.SliceStable(out, func(i, j int) bool { return indice(CanauxConnus, out[i]) < indice(CanauxConnus, out[j]) })
	return out
}

func Lit(b []byte) (*Certificat, error) {
	var c Certificat
	d := yaml.NewDecoder(strings.NewReader(string(b)))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return nil, fmt.Errorf("certificat illisible : %w", err)
	}
	return &c, nil
}

func contient(l []string, s string) bool { return indice(l, s) >= 0 }

func indice(l []string, s string) int {
	for i, e := range l {
		if e == s {
			return i
		}
	}
	return -1
}
