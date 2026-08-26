// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbx-authwatch — liste blanche (#1220)
//
// Sans liste blanche, ce programme est un piege pour son proprietaire : le
// premier mot de passe rate depuis un hotel bannit l'administrateur de sa
// propre box, et un leurre sur un port courant bannit un outil de supervision
// legitime. La liste blanche est donc une PIECE DE SECURITE, pas une commodite.
//
// Le prive est TOUJOURS exempte, sans avoir a l'ecrire : c'est le meme
// garde-fou qu'au niveau du banneur, mais applique plus tot pour que le
// journal ne se remplisse pas d'evenements qui n'auront jamais de suite.
package main

import (
	"fmt"
	"net"
	"os"
	"strings"
)

type ListeBlanche struct {
	reseaux []*net.IPNet
	exactes map[string]bool
}

// NewListeBlanche accepte des adresses et des prefixes, separes par virgules
// ou retours a la ligne : « 203.0.113.7, 198.51.100.0/24 ».
func NewListeBlanche(spec string) (*ListeBlanche, error) {
	lb := &ListeBlanche{exactes: make(map[string]bool)}
	// Le commentaire se retire LIGNE PAR LIGNE, avant tout decoupage : couper
	// d'abord en champs ferait survivre le texte qui suit le « # » — « # bureau »
	// laissait passer « bureau », refuse ensuite comme adresse invalide.
	var champs []string
	for _, ligne := range strings.Split(spec, "\n") {
		if i := strings.IndexByte(ligne, '#'); i >= 0 {
			ligne = ligne[:i]
		}
		champs = append(champs, strings.FieldsFunc(ligne, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\r'
		})...)
	}
	for _, c := range champs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if strings.Contains(c, "/") {
			_, reseau, err := net.ParseCIDR(c)
			if err != nil {
				return nil, fmt.Errorf("prefixe invalide dans la liste blanche : %q", c)
			}
			lb.reseaux = append(lb.reseaux, reseau)
			continue
		}
		if net.ParseIP(c) == nil {
			return nil, fmt.Errorf("adresse invalide dans la liste blanche : %q", c)
		}
		lb.exactes[c] = true
	}
	return lb, nil
}

// ChargeFichier ajoute le contenu d'un fichier, s'il existe. Un fichier absent
// n'est PAS une erreur : la liste blanche est optionnelle, et l'operateur doit
// pouvoir la creer apres coup sans redemarrer autre chose.
func (lb *ListeBlanche) ChargeFichier(chemin string) error {
	if chemin == "" {
		return nil
	}
	data, err := os.ReadFile(chemin)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	autre, err := NewListeBlanche(string(data))
	if err != nil {
		return fmt.Errorf("%s : %w", chemin, err)
	}
	lb.reseaux = append(lb.reseaux, autre.reseaux...)
	for ip := range autre.exactes {
		lb.exactes[ip] = true
	}
	return nil
}

// Contient dit si l'adresse est exemptee. Le prive et le loopback le sont
// toujours, qu'ils figurent ou non dans la liste.
func (lb *ListeBlanche) Contient(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false // une adresse illisible n'est pas exemptee, elle est ignoree ailleurs
	}
	if p.IsLoopback() || p.IsPrivate() || p.IsLinkLocalUnicast() {
		return true
	}
	if lb == nil {
		return false
	}
	if lb.exactes[ip] {
		return true
	}
	for _, r := range lb.reseaux {
		if r.Contains(p) {
			return true
		}
	}
	return false
}

// Taille rend le nombre d'entrees declarees, pour le journal de demarrage :
// « liste blanche : 0 entree » doit sauter aux yeux si c'est une erreur.
func (lb *ListeBlanche) Taille() int {
	if lb == nil {
		return 0
	}
	return len(lb.exactes) + len(lb.reseaux)
}
