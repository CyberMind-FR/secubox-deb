// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package reseau porte les contrôles communs aux sorties réseau du BBS.
//
// Ce garde vivait dans le connecteur Mastodon. Il est remonté ici parce que
// chaque connecteur en a besoin — le résolveur de liens et le collecteur de
// flux prennent eux aussi des adresses saisies par un membre. Un contrôle de
// sécurité recopié dans plusieurs paquets finit toujours par diverger : on ne
// corrige que l'un des exemplaires.
package reseau

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ErrHoteRefuse : l'adresse ne doit pas être appelée.
var ErrHoteRefuse = errors.New("hôte refusé")

// VerifieHote decide si le serveur a le droit d'appeler cet hote.
//
// LE PROBLEME EST REEL ET SPECIFIQUE A CETTE FONCTIONNALITE : l'instance est
// TAPEE PAR LE MEMBRE. Sans controle, n'importe qui obtiendrait du BBS qu'il
// emette des requetes vers le reseau interne — les services d'administration,
// les sockets d'autres modules, les adresses de metadonnees. C'est la faille
// classique dite SSRF, et elle est ici a portee de formulaire.
//
// MAIS LE REFLEXE « INTERDIRE TOUTE ADRESSE PRIVEE » CASSERAIT LE CAS PRINCIPAL :
// l'instance de la maison est justement sur le reseau local. On distingue donc
// deux situations au lieu d'appliquer une regle unique qui aurait l'air plus
// stricte tout en rendant la fonction inutilisable :
//
//   - l'instance CONFIGUREE par le sysop est jointe telle quelle. Elle n'est pas
//     choisie par le membre, elle est le reglage de la maison ;
//   - toute AUTRE instance doit resoudre vers des adresses publiques, et
//     seulement vers elles.
func VerifieHote(instance, interne string) error {
	h := strings.ToLower(strings.TrimSpace(instance))
	if h == "" {
		return fmt.Errorf("%w : adresse vide", ErrHoteRefuse)
	}
	if strings.ContainsAny(h, "/\\ @:") {
		return fmt.Errorf("%w : %q n'est pas un nom d'hote", ErrHoteRefuse, instance)
	}
	// L'instance de la maison : c'est un reglage, pas une saisie de membre.
	if interne != "" && h == strings.ToLower(strings.TrimSpace(interne)) {
		return nil
	}
	adrs, err := net.LookupIP(h)
	if err != nil {
		return fmt.Errorf("%w : %s introuvable", ErrHoteRefuse, h)
	}
	if len(adrs) == 0 {
		return fmt.Errorf("%w : %s ne resout vers rien", ErrHoteRefuse, h)
	}
	for _, ip := range adrs {
		if !estPublique(ip) {
			// ON NE DIT PAS VERS QUOI ELLE RESOUT. Le message renseignerait sur
			// la topologie interne qui que ce soit ayant un compte.
			return fmt.Errorf("%w : %s designe une adresse du reseau interne",
				ErrHoteRefuse, h)
		}
	}
	return nil
}

// estPublique : tout ce qui n'est pas routable sur internet est refuse.
func estPublique(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	// 100.64.0.0/10 (CGNAT, dont Tailscale) n'est pas couvert par IsPrivate.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return false
	}
	return true
}
