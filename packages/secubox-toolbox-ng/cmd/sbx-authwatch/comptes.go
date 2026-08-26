// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbx-authwatch — comptes reels (#1220)
//
// LE SIGNAL LE PLUS SUR DONT ON DISPOSE. La box de gk2 heberge UNE boite :
// gk2@secubox.in. Les campagnes, elles, visent gerald@gk2.net, gerard@gk2.net,
// gege, s4wlume — aucune n'existe ici. Un echec d'authentification sur une
// boite INEXISTANTE ne peut pas etre un utilisateur qui se trompe : il n'y a
// personne a tromper. C'est le meme raisonnement que « invalid user » en SSH,
// et que le vhost non routé en HTTP.
//
// CE QUE CELA CHANGE. Le compteur a fenetre glissante suppose que l'attaquant
// revienne ; les mesures disent qu'il ne revient pas (339 sources sur 388 vues
// une seule fois en sept jours). Contre un compte inexistant, on n'a plus
// besoin d'attendre : la premiere tentative suffit, et les 339 sont prises.
//
// LA PRUDENCE RESTE DU BON COTE. Si la liste ne peut pas etre lue, ou si elle
// est vide, ce module rend « je ne sais pas » et le comportement patient
// s'applique. Une liste tronquee ferait bannir un utilisateur reel : on
// n'active donc la certitude que sur une liste EFFECTIVEMENT chargee.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type Comptes struct {
	connus map[string]bool
	charge bool
}

// NewComptes lit une liste de comptes. Deux formats acceptes, parce que les
// deux existent sur la box :
//
//	gk2@secubox.in                       (une adresse par ligne)
//	gk2@secubox.in  secubox.in/gk2/      (table postfix vmailbox : 1er champ)
//	gk2@secubox.in:{SHA512-CRYPT}$6$…    (passwd-file dovecot : avant le 1er « : »)
//
// Le troisieme est celui qui compte sur gk2 : dovecot y lit ses comptes
// (passdb passwd-file, /etc/mail-config/users) et c'est LUI qui porte
// l'authentification SASL de postfix. Sans decoupage sur « : », on prendrait
// l'empreinte du mot de passe pour un nom de compte.
//
// Les commentaires et les lignes vides sont ignores.
func NewComptes(chemins []string) (*Comptes, error) {
	c := &Comptes{connus: make(map[string]bool)}
	for _, chemin := range chemins {
		chemin = strings.TrimSpace(chemin)
		if chemin == "" {
			continue
		}
		f, err := os.Open(chemin)
		if err != nil {
			if os.IsNotExist(err) {
				continue // un chemin absent n'est pas une erreur : on cumule ce qu'on trouve
			}
			return nil, fmt.Errorf("%s : %w", chemin, err)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			ligne := sc.Text()
			if i := strings.IndexByte(ligne, '#'); i >= 0 {
				ligne = ligne[:i]
			}
			champs := strings.Fields(ligne)
			if len(champs) == 0 {
				continue
			}
			nom := champs[0]
			if i := strings.IndexByte(nom, ':'); i > 0 {
				nom = nom[:i]
			}
			c.ajoute(nom)
		}
		_ = f.Close()
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("%s : %w", chemin, err)
		}
	}
	c.charge = len(c.connus) > 0
	return c, nil
}

// ajoute enregistre l'adresse ET sa partie locale : les journaux montrent les
// deux formes — « sasl_username=gerald@gk2.net » comme « sasl_username=gerald ».
func (c *Comptes) ajoute(nom string) {
	nom = strings.ToLower(strings.TrimSpace(nom))
	if nom == "" {
		return
	}
	c.connus[nom] = true
	if i := strings.IndexByte(nom, '@'); i > 0 {
		c.connus[nom[:i]] = true
	}
}

// Charge dit si une liste exploitable a ete lue. Sans elle, aucune certitude
// n'est tiree : mieux vaut rester patient que bannir un utilisateur reel.
func (c *Comptes) Charge() bool { return c != nil && c.charge }

// Inexistant dit si la cible n'est PAS un compte de la box.
//
// Rend false quand la liste n'est pas chargee ou quand la ligne ne portait
// aucune cible : dans le doute, on ne conclut rien.
func (c *Comptes) Inexistant(cible string) bool {
	if !c.Charge() || strings.TrimSpace(cible) == "" {
		return false
	}
	return !c.connus[strings.ToLower(strings.TrimSpace(cible))]
}

// Taille rend le nombre d'entrees, formes locales comprises.
func (c *Comptes) Taille() int {
	if c == nil {
		return 0
	}
	return len(c.connus)
}
