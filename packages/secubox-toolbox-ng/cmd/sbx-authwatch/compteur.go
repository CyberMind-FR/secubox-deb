// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbx-authwatch — compteur a fenetre glissante (#1220)
//
// Un echec isole n'est pas une attaque : c'est un doigt qui glisse, un client
// mal configure, un mot de passe change hier. Ce qui distingue l'attaque, c'est
// la REPETITION dans un temps court. Le compteur ci-dessous ne retient donc que
// les evenements de la fenetre courante et bannit au franchissement du seuil.
//
// La fenetre est GLISSANTE et non fixe : avec des tranches fixes, un attaquant
// qui repartit ses tentatives a cheval sur deux tranches passe indefiniment
// sous le seuil.
package main

import (
	"sync"
	"time"
)

// Compteur accumule le poids des echecs par adresse sur une fenetre glissante.
type Compteur struct {
	fenetre time.Duration
	seuil   int

	mu         sync.Mutex
	evenements map[string][]evenement
	bannies    map[string]time.Time // anti-tempete : une IP deja bannie ne re-declenche pas
	repit      time.Duration
}

type evenement struct {
	quand time.Time
	poids int
}

func NewCompteur(fenetre time.Duration, seuil int, repit time.Duration) *Compteur {
	return &Compteur{
		fenetre:    fenetre,
		seuil:      seuil,
		evenements: make(map[string][]evenement),
		bannies:    make(map[string]time.Time),
		repit:      repit,
	}
}

// Ajoute enregistre un echec et dit s'il faut bannir MAINTENANT.
//
// Rend aussi le total courant, pour que l'appelant puisse le journaliser : une
// decision de bannissement dont on ne sait pas sur quoi elle repose n'est pas
// auditable.
func (c *Compteur) Ajoute(ip string, poids int, maintenant time.Time) (total int, bannir bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Deja bannie et toujours dans son repit : on compte sans re-declencher.
	if t, ok := c.bannies[ip]; ok {
		if maintenant.Sub(t) < c.repit {
			return c.totalSansVerrou(ip, maintenant), false
		}
		delete(c.bannies, ip)
	}

	c.evenements[ip] = append(c.evenements[ip], evenement{quand: maintenant, poids: poids})
	total = c.totalSansVerrou(ip, maintenant)
	if total >= c.seuil {
		c.bannies[ip] = maintenant
		// On repart de zero pour cette adresse : les evenements ont servi,
		// les garder ferait re-franchir le seuil au premier echec suivant.
		delete(c.evenements, ip)
		return total, true
	}
	return total, false
}

// totalSansVerrou elague la fenetre et somme ce qui reste. L'elagage se fait
// ici plutot que dans une tache periodique : sans trafic d'une adresse, ses
// evenements n'ont aucune raison d'etre revisites.
func (c *Compteur) totalSansVerrou(ip string, maintenant time.Time) int {
	limite := maintenant.Add(-c.fenetre)
	garde := c.evenements[ip][:0]
	total := 0
	for _, e := range c.evenements[ip] {
		if e.quand.After(limite) {
			garde = append(garde, e)
			total += e.poids
		}
	}
	if len(garde) == 0 {
		delete(c.evenements, ip)
	} else {
		c.evenements[ip] = garde
	}
	return total
}

// Elague retire les adresses devenues inutiles. Appele periodiquement : sans
// lui, une longue campagne visant des milliers d'adresses distinctes ferait
// croitre les cartes sans borne.
func (c *Compteur) Elague(maintenant time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	retires := 0
	for ip := range c.evenements {
		if c.totalSansVerrou(ip, maintenant) == 0 {
			retires++
		}
	}
	for ip, t := range c.bannies {
		if maintenant.Sub(t) >= c.repit {
			delete(c.bannies, ip)
			retires++
		}
	}
	return retires
}

// Suivies rend le nombre d'adresses actuellement en observation, pour le
// journal de demarrage et le diagnostic.
func (c *Compteur) Suivies() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.evenements)
}
