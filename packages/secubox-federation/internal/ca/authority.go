// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package ca : l'autorité de certification de la fédération GK2 (#1389).
//
// LA CLÉ DE LA CA N'EST QU'UNE CLÉ ANNUAIRE DE PLUS : graine Ed25519 en
// hexadécimal, DID = empreinte de la clé publique. Aujourd'hui un fichier 0600
// (/etc/secubox/secrets/federation/ca.key) ; demain scellée dans le Coffre
// (#1367) — rien ici ne suppose qu'elle reste sur le disque.
//
// LA CA NE GÉNÈRE JAMAIS SA CLÉ D'ELLE-MÊME. Une clé absente est une erreur
// (Init est un geste explicite : `sbxctl ca init`). Sans cette règle, un
// fichier perdu produirait en silence une NOUVELLE autorité, et toutes les
// boxes rejetteraient ses certificats — ou pire, une restauration partielle
// ferait coexister deux autorités.
package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Autorite : la clé et le répertoire d'état de la CA.
type Autorite struct {
	priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
	DID  string
	Dir  string // /var/lib/secubox/federation/ca
}

// LitGraine lit une graine Ed25519 hexadécimale (format annuaire node.key).
func LitGraine(chemin string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(chemin)
	if err != nil {
		return nil, err
	}
	g, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(g) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s : graine Ed25519 hexadécimale de 32 octets attendue", chemin)
	}
	return ed25519.NewKeyFromSeed(g), nil
}

// Charge ouvre une CA existante.
func Charge(cle, dir string, didDe func(ed25519.PublicKey) string) (*Autorite, error) {
	priv, err := LitGraine(cle)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("aucune clé de CA en %s — `sbxctl ca init` la crée, explicitement", cle)
	}
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	a := &Autorite{priv: priv, Pub: pub, DID: didDe(pub), Dir: dir}
	for _, d := range []string{"emis", "demandes"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o750); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// Init crée la clé de la CA — et refuse d'écraser une clé existante.
func Init(cle string) error {
	if _, err := os.Stat(cle); err == nil {
		return fmt.Errorf("%s existe déjà : une CA ne se recrée pas par-dessus elle-même", cle)
	}
	if err := os.MkdirAll(filepath.Dir(cle), 0o700); err != nil {
		return err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(cle, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(hex.EncodeToString(priv.Seed()) + "\n")
	return err
}

// signe : réservé au paquet — la clé privée ne sort jamais de l'Autorite.
func (a *Autorite) signe(msg []byte) []byte { return ed25519.Sign(a.priv, msg) }

// ecritAtomique : temporaire + rename, même répertoire.
func ecritAtomique(chemin string, b []byte, mode os.FileMode) error {
	tmp := chemin + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, chemin)
}
