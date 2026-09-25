// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sbxobj

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/sbxcert"
)

// Entree : une ligne du catalogue — ce que l'App Store affiche.
type Entree struct {
	Objet
	Editeur  string `json:"editeur"`
	Certifie bool   `json:"certifie"`
	Motif    string `json:"motif,omitempty"`
	Fichier  string `json:"fichier"`
	Taille   int64  `json:"taille"`
	SHA256   string `json:"sha256"`
	Publie   string `json:"publie_le"`
	Apercus  int    `json:"apercus"` // rangés à côté : <Fichier sans .sbx>.apercu-N.jpg
	// certificat : gardé pour re-vérifier l'éditeur à chaque lecture (une
	// révocation survenue depuis la publication doit se voir).
	Certificat string `json:"certificat,omitempty"`
	// Verrouille : le canal de l'objet n'est pas ouvert par le certificat de
	// la box qui consulte (posé à la lecture).
	Verrouille bool `json:"verrouille"`
}

// Catalogue : /var/lib/secubox/federation/objets.
type Catalogue struct{ Dir string }

func (c Catalogue) index() string { return filepath.Join(c.Dir, "catalogue.json") }

func (c Catalogue) lit() ([]Entree, error) {
	b, err := os.ReadFile(c.index())
	if errors.Is(err, os.ErrNotExist) {
		return []Entree{}, nil
	}
	if err != nil {
		return nil, err
	}
	var es []Entree
	return es, json.Unmarshal(b, &es)
}

// Ajoute range un paquet VÉRIFIÉ dans le catalogue (une version remplace
// la même version ; les autres versions restent).
func (c Catalogue) Ajoute(chemin string, p *Paquet, maintenant time.Time) (*Entree, error) {
	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		return nil, err
	}
	nom := fmt.Sprintf("%s@%s.sbx", p.Objet.ID, p.Objet.Version)
	dest := filepath.Join(c.Dir, nom)
	if err := copie(chemin, dest+".tmp"); err != nil {
		return nil, err
	}
	if err := os.Rename(dest+".tmp", dest); err != nil {
		return nil, err
	}
	// Aperçus : extraits À CÔTÉ du paquet, pour être servis sans le rouvrir.
	// Ceux d'une publication précédente de la même version partent d'abord.
	base := strings.TrimSuffix(dest, ".sbx")
	for i := 1; i <= ApercusMax; i++ {
		os.Remove(base + "." + membreApercu(i))
	}
	for i, src := range p.Apercus {
		if err := copie(src, base+"."+membreApercu(i+1)); err != nil {
			return nil, err
		}
	}
	somme, _ := sha256Fichier(dest)
	st, _ := os.Stat(dest)
	ed, _ := p.Manifeste["editeur"].(map[string]any)
	cy, _ := ed["certificat"].(string)
	e := Entree{Objet: p.Objet, Editeur: p.Editeur, Certifie: p.Certifie, Motif: p.Motif,
		Fichier: nom, Taille: st.Size(), SHA256: somme, Publie: maintenant.UTC().Format(time.RFC3339),
		Certificat: cy, Apercus: len(p.Apercus)}
	es, err := c.lit()
	if err != nil {
		return nil, err
	}
	garde := es[:0]
	for _, x := range es {
		if !(x.ID == e.ID && x.Version == e.Version) {
			garde = append(garde, x)
		}
	}
	garde = append(garde, e)
	sort.Slice(garde, func(i, j int) bool {
		if garde[i].ID != garde[j].ID {
			return garde[i].ID < garde[j].ID
		}
		return garde[i].Publie > garde[j].Publie
	})
	b, _ := json.MarshalIndent(garde, "", "  ")
	tmp := c.index() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return nil, err
	}
	return &e, os.Rename(tmp, c.index())
}

// Liste : la DERNIÈRE version de chaque objet, filtrée par type, avec
// l'éditeur re-vérifié et le canal comparé au certificat de la box.
func (c Catalogue) Liste(typ string, caPub ed25519.PublicKey, revoques map[string]bool, canauxOuverts []string, maintenant time.Time) ([]Entree, error) {
	es, err := c.lit()
	if err != nil {
		return nil, err
	}
	vu := map[string]bool{}
	out := []Entree{}
	for _, e := range es {
		if typ != "" && e.Type != typ {
			continue
		}
		if vu[e.ID] { // index trié : la plus récente d'abord
			continue
		}
		vu[e.ID] = true
		e.Certifie, e.Motif = recertifie(e, caPub, revoques, maintenant)
		e.Verrouille = !contient(canauxOuverts, e.Channel)
		e.Certificat = ""
		out = append(out, e)
	}
	return out, nil
}

// Contient : cette version de cet objet est-elle déjà au catalogue ?
func (c Catalogue) Contient(id, version string) bool {
	es, _ := c.lit()
	for _, e := range es {
		if e.ID == id && e.Version == version {
			return true
		}
	}
	return false
}

// Apercu : le chemin du n-ième aperçu de la dernière version d'un objet.
func (c Catalogue) Apercu(id string, n int) (string, error) {
	e, chemin, err := c.Trouve(id)
	if err != nil {
		return "", err
	}
	if n < 1 || n > e.Apercus {
		return "", errors.New("pas d'aperçu")
	}
	return strings.TrimSuffix(chemin, ".sbx") + "." + membreApercu(n), nil
}

// Trouve l'entrée courante d'un id (dernière version).
func (c Catalogue) Trouve(id string) (*Entree, string, error) {
	es, err := c.lit()
	if err != nil {
		return nil, "", err
	}
	for _, e := range es {
		if e.ID == id {
			if strings.ContainsAny(e.Fichier, "/\\") {
				return nil, "", errors.New("entrée corrompue")
			}
			return &e, filepath.Join(c.Dir, e.Fichier), nil
		}
	}
	return nil, "", fmt.Errorf("objet inconnu : %s", id)
}

func recertifie(e Entree, caPub ed25519.PublicKey, revoques map[string]bool, maintenant time.Time) (bool, string) {
	if caPub == nil {
		return false, "aucune CA pour vérifier l'éditeur"
	}
	if e.Certificat == "" {
		return false, "éditeur sans certificat SBX"
	}
	c, err := sbxcert.Lit([]byte(e.Certificat))
	if err != nil || c.BoxID != e.Editeur {
		return false, "certificat de l'éditeur invalide"
	}
	if v := c.Verification(caPub, maintenant, revoques); !v.Valide {
		return false, "certificat de l'éditeur : " + v.Motif
	}
	return true, ""
}

func copie(src, dst string) error {
	r, err := os.Open(src)
	if err != nil {
		return err
	}
	defer r.Close()
	w, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, r); err != nil {
		w.Close()
		return err
	}
	return w.Close()
}
