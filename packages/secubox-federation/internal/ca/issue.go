// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package ca

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/canon"
	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/sbxcert"
)

// ── Demande d'adhésion ──────────────────────────────────────────────────────
//
// LA BOX PROUVE QU'ELLE TIENT SA CLÉ. La demande est signée par la clé de
// nœud dont box_id est l'empreinte : personne ne peut demander un certificat
// au nom d'une box qu'il ne contrôle pas. L'horodatage borne le rejeu.

type Demande struct {
	BoxID      string `json:"box_id"`
	Pubkey     string `json:"pubkey"`
	Owner      string `json:"owner"`
	Tier       string `json:"tier"`
	Horodatage string `json:"horodatage"`
	Signature  string `json:"signature,omitempty"`
	// Recue : posé par la CA à l'arrivée, hors signature.
	Recue string `json:"recue,omitempty"`
}

func (d *Demande) Charge() map[string]any {
	return map[string]any{"action": "join", "box_id": d.BoxID, "pubkey": d.Pubkey,
		"owner": d.Owner, "tier": d.Tier, "horodatage": d.Horodatage}
}

// FenetreRejeu : une demande plus vieille (ou plus « future ») est refusée.
const FenetreRejeu = 15 * time.Minute

// VerifiePreuve : sujet auto-certifiant, signature de la box, fraîcheur.
func VerifiePreuve(boxID, pubkey, horodatage, signature string, charge map[string]any, maintenant time.Time) (ed25519.PublicKey, error) {
	pub, err := sbxcert.LitPub(pubkey)
	if err != nil {
		return nil, err
	}
	if sbxcert.DID(pub) != boxID {
		return nil, errors.New("box_id n'est pas l'empreinte de la clé présentée")
	}
	t, err := time.Parse(time.RFC3339, horodatage)
	if err != nil {
		return nil, errors.New("horodatage : RFC 3339 attendu")
	}
	if d := maintenant.Sub(t); d > FenetreRejeu || d < -FenetreRejeu {
		return nil, errors.New("horodatage hors fenêtre (±15 min) : horloge ou rejeu")
	}
	msg, err := canon.Encode(charge)
	if err != nil {
		return nil, err
	}
	if !sbxcert.Verifie(pub, msg, signature) {
		return nil, errors.New("signature de la box invalide")
	}
	return pub, nil
}

// MaxDemandes : borne la file — une route ouverte ne doit pas remplir un disque.
const MaxDemandes = 200

// Recoit enregistre une demande VÉRIFIÉE (en attente de décision).
func (a *Autorite) Recoit(d *Demande, maintenant time.Time) error {
	if _, err := VerifiePreuve(d.BoxID, d.Pubkey, d.Horodatage, d.Signature, d.Charge(), maintenant); err != nil {
		return err
	}
	if len(d.Owner) > 120 || strings.ContainsAny(d.Owner, "\n\r") {
		return errors.New("owner : 120 caractères au plus, sur une ligne")
	}
	dir := filepath.Join(a.Dir, "demandes")
	chemin := filepath.Join(dir, fichierDe(d.BoxID)+".json")
	if _, err := os.Stat(chemin); err != nil {
		if n, _ := os.ReadDir(dir); len(n) >= MaxDemandes {
			return errors.New("file des demandes pleine")
		}
	}
	d.Recue = maintenant.UTC().Format(time.RFC3339)
	b, _ := json.MarshalIndent(d, "", "  ")
	return ecritAtomique(chemin, b, 0o640)
}

// Demandes : la file en attente.
func (a *Autorite) Demandes() ([]Demande, error) {
	es, err := os.ReadDir(filepath.Join(a.Dir, "demandes"))
	if err != nil {
		return nil, err
	}
	var out []Demande
	for _, e := range es {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(a.Dir, "demandes", e.Name()))
		if err != nil {
			continue
		}
		var d Demande
		if json.Unmarshal(b, &d) == nil {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Recue < out[j].Recue })
	return out, nil
}

func (a *Autorite) Demande(boxID string) (*Demande, error) {
	b, err := os.ReadFile(filepath.Join(a.Dir, "demandes", fichierDe(boxID)+".json"))
	if err != nil {
		return nil, fmt.Errorf("aucune demande pour %s", boxID)
	}
	var d Demande
	return &d, json.Unmarshal(b, &d)
}

// ── Émission ────────────────────────────────────────────────────────────────

// Politique : ce qu'un tier ouvre, fourni par l'appelant (federation.Config).
type Politique struct {
	Channels []string
	Rights   map[string]bool
}

// Emet signe un certificat pour une clé de box.
func (a *Autorite) Emet(pubkey, owner, tier string, p Politique, jours int, maintenant time.Time) (*sbxcert.Certificat, error) {
	pub, err := sbxcert.LitPub(pubkey)
	if err != nil {
		return nil, err
	}
	serie, err := a.prochaineSerie(maintenant)
	if err != nil {
		return nil, err
	}
	droits := map[string]bool{}
	for k, v := range p.Rights {
		droits[k] = v
	}
	c := &sbxcert.Certificat{
		Version: sbxcert.Version, Serial: serie, BoxID: sbxcert.DID(pub),
		Owner: owner, Tier: tier, Channels: sbxcert.TrieCanaux(p.Channels), Rights: droits,
		Issued:  maintenant.UTC().Format(time.RFC3339),
		Expires: maintenant.UTC().AddDate(0, 0, jours).Format("2006-01-02"),
		Issuer:  a.DID, Pubkey: sbxcert.FormatPub(pub),
	}
	if err := c.Valide(); err != nil {
		return nil, err
	}
	msg, err := c.Octets()
	if err != nil {
		return nil, err
	}
	c.Signature = "ed25519:" + hex.EncodeToString(a.signe(msg))
	y, err := c.YAML()
	if err != nil {
		return nil, err
	}
	if err := ecritAtomique(filepath.Join(a.Dir, "emis", serie+".yaml"), y, 0o644); err != nil {
		return nil, err
	}
	// Le DERNIER certificat de chaque box, pour qu'elle vienne le chercher.
	if err := ecritAtomique(filepath.Join(a.Dir, "emis", fichierDe(c.BoxID)+".courant"), []byte(serie), 0o644); err != nil {
		return nil, err
	}
	// Émise, la demande quitte la file.
	os.Remove(filepath.Join(a.Dir, "demandes", fichierDe(c.BoxID)+".json"))
	return c, nil
}

// Courant : le dernier certificat émis pour une box (nil, nil s'il n'y en a pas).
func (a *Autorite) Courant(boxID string) (*sbxcert.Certificat, error) {
	s, err := os.ReadFile(filepath.Join(a.Dir, "emis", fichierDe(boxID)+".courant"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return a.Lit(strings.TrimSpace(string(s)))
}

// Lit un certificat émis par son numéro de série.
func (a *Autorite) Lit(serie string) (*sbxcert.Certificat, error) {
	if strings.ContainsAny(serie, "/.") {
		return nil, errors.New("numéro de série invalide")
	}
	b, err := os.ReadFile(filepath.Join(a.Dir, "emis", serie+".yaml"))
	if err != nil {
		return nil, err
	}
	return sbxcert.Lit(b)
}

// prochaineSerie : SBX-<année>-<n°>, compteur par année, jamais réutilisé.
func (a *Autorite) prochaineSerie(maintenant time.Time) (string, error) {
	an := maintenant.UTC().Year()
	f := filepath.Join(a.Dir, fmt.Sprintf("serie-%d", an))
	n := 0
	if b, err := os.ReadFile(f); err == nil {
		n, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	n++
	if err := ecritAtomique(f, []byte(strconv.Itoa(n)), 0o640); err != nil {
		return "", err
	}
	return fmt.Sprintf("SBX-%d-%04d", an, n), nil
}

// fichierDe : le suffixe hexadécimal d'un did:plc (nom de fichier sûr).
func fichierDe(did string) string { return strings.TrimPrefix(did, "did:plc:") }
