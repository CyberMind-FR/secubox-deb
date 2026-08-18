// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package gateway

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Capacités qu'un connecteur peut déclarer.
const (
	CapResoudre = "resoudre"
	CapTirer    = "tirer"
	CapPousser  = "pousser"
	CapAuth     = "auth"
)

// Nature de l'authentification exigée par la plateforme.
const (
	AuthAucune  = "aucune"
	AuthOAuth2  = "oauth2"
	AuthJeton   = "jeton"
	AuthCookies = "cookies"
)

// Modes de réplique.
const (
	ModeMiroir  = "miroir"
	ModePousse  = "pousse"
	ModeArchive = "archive"
)

// États de santé d'un connecteur.
const (
	EtatSain    = "sain"
	EtatDegrade = "degrade"
	EtatEteint  = "eteint"
)

var (
	// ErrProprieteTiers : on ne republie pas le travail d'autrui.
	ErrProprieteTiers = errors.New("contenu de tiers : republication refusée")
	// ErrPasDePublication : ce connecteur ne sait que lire.
	ErrPasDePublication = errors.New("ce connecteur ne publie pas")
	// ErrConnecteurInconnu : nom absent du registre.
	ErrConnecteurInconnu = errors.New("connecteur inconnu")
)

// Sante décrit l'état d'un connecteur.
//
// Une plateforme qui change ses règles du jour au lendemain ne doit pas faire
// perdre ce qui est déjà entré : le connecteur passe `degrade`, les contenus
// gardent leur adresse, leurs métadonnées et leur provenance. Seul le
// rafraîchissement s'arrête.
type Sante struct {
	Etat  string `json:"etat"`
	Motif string `json:"motif,omitempty"`
}

// Utilisable dit si l'on peut encore demander quelque chose au connecteur.
func (s Sante) Utilisable() bool { return s.Etat == EtatSain }

// Manifeste décrit ce qu'un connecteur sait faire.
type Manifeste struct {
	Nom       string   `json:"nom"`
	Version   string   `json:"version"`
	Capacites []string `json:"capacites"`
	AuthKind  string   `json:"auth"`
	MotifsURL []string `json:"motifs_url,omitempty"`
}

var capacites = map[string]bool{
	CapResoudre: true, CapTirer: true, CapPousser: true, CapAuth: true,
}

var auths = map[string]bool{
	AuthAucune: true, AuthOAuth2: true, AuthJeton: true, AuthCookies: true,
}

// SaitFaire dit si la capacité est déclarée.
func (m Manifeste) SaitFaire(cap string) bool {
	for _, c := range m.Capacites {
		if c == cap {
			return true
		}
	}
	return false
}

// Valider contrôle le manifeste AU CHARGEMENT.
//
// Un motif d'URL cassé ou une capacité fantaisiste se manifesteraient sinon à
// l'exécution, loin de leur cause — au pire pendant une collecte nocturne.
func (m Manifeste) Valider() error {
	if strings.TrimSpace(m.Nom) == "" {
		return errors.New("manifeste sans nom")
	}
	if strings.TrimSpace(m.Version) == "" {
		return fmt.Errorf("connecteur %q : version absente", m.Nom)
	}
	if !auths[m.AuthKind] {
		return fmt.Errorf("connecteur %q : authentification inconnue %q", m.Nom, m.AuthKind)
	}
	for _, c := range m.Capacites {
		if !capacites[c] {
			return fmt.Errorf("connecteur %q : capacité inconnue %q", m.Nom, c)
		}
	}
	for _, motif := range m.MotifsURL {
		if _, err := regexp.Compile(motif); err != nil {
			return fmt.Errorf("connecteur %q : motif d'URL illisible %q : %w", m.Nom, motif, err)
		}
	}
	// Publier chez un tiers suppose de s'y être authentifié. La contradiction
	// vaut mieux d'être vue au chargement qu'au premier envoi.
	if m.SaitFaire(CapPousser) && m.AuthKind == AuthAucune {
		return fmt.Errorf("connecteur %q : publication déclarée sans authentification", m.Nom)
	}
	return nil
}

// Publieur est l'envoi réel, appelé UNIQUEMENT après contrôle de propriété.
type Publieur interface {
	PublierAutorise(c Contenu) (Replique, error)
}

// Connecteur est le contrat de tout connecteur.
//
// La méthode `scelle` n'est pas exportée : seul Base peut la fournir. Un
// connecteur qui n'embarque pas Base ne satisfait donc PAS cette interface et
// ne compile pas — c'est ainsi que la garde de propriété devient impossible à
// contourner par oubli.
type Connecteur interface {
	Manifeste() Manifeste
	Resoudre(url string) (Contenu, error)
	RecupererMedias(c Contenu) ([]Media, error)
	Tirer(depuis int64) ([]Contenu, error)
	Publier(c Contenu) (Replique, error)
	Sante() Sante
	scelle()
}

// Base porte la garde de propriété. Tout connecteur l'embarque.
type Base struct {
	// Sortie reste nil pour un connecteur qui ne sait que lire.
	Sortie Publieur
}

func (Base) scelle() {}

// Publier contrôle le droit de republier AVANT de solliciter la plateforme.
//
// La règle vit ici, une seule fois. La placer dans chaque connecteur
// reviendrait à parier que personne ne l'oubliera jamais — et il suffirait
// d'un oubli pour republier le travail de quelqu'un d'autre sous le nom de
// l'utilisateur.
func (b Base) Publier(c Contenu) (Replique, error) {
	if !c.EstRepubliable() {
		return Replique{}, fmt.Errorf("%w (propriété : %q)", ErrProprieteTiers, c.Propriete)
	}
	if b.Sortie == nil {
		return Replique{}, ErrPasDePublication
	}
	return b.Sortie.PublierAutorise(c)
}

// Registre tient les connecteurs disponibles.
type Registre struct {
	parNom map[string]Connecteur
}

// NouveauRegistre rend un registre vide.
func NouveauRegistre() *Registre {
	return &Registre{parNom: map[string]Connecteur{}}
}

// Enregistrer ajoute un connecteur, après validation de son manifeste.
func (r *Registre) Enregistrer(c Connecteur) error {
	m := c.Manifeste()
	if err := m.Valider(); err != nil {
		return err
	}
	if _, deja := r.parNom[m.Nom]; deja {
		// Deux connecteurs du même nom rendraient le résolveur imprévisible :
		// le même lien irait tantôt à l'un, tantôt à l'autre.
		return fmt.Errorf("connecteur %q déjà enregistré", m.Nom)
	}
	r.parNom[m.Nom] = c
	return nil
}

// Ouvrir rend le connecteur nommé.
func (r *Registre) Ouvrir(nom string) (Connecteur, error) {
	c, ok := r.parNom[nom]
	if !ok {
		return nil, fmt.Errorf("%w : %q", ErrConnecteurInconnu, nom)
	}
	return c, nil
}

// Noms rend les connecteurs enregistrés, dans un ordre stable — une liste qui
// change d'ordre à chaque affichage se lit mal.
func (r *Registre) Noms() []string {
	noms := make([]string, 0, len(r.parNom))
	for n := range r.parNom {
		noms = append(noms, n)
	}
	sort.Strings(noms)
	return noms
}

// Tous rend les connecteurs, dans l'ordre de leurs noms.
func (r *Registre) Tous() []Connecteur {
	out := make([]Connecteur, 0, len(r.parNom))
	for _, n := range r.Noms() {
		out = append(out, r.parNom[n])
	}
	return out
}
