// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package sentinel relaie les alertes de sbx-sentinel vers Signal.
//
// POURQUOI UNE SOCKET D'ABONNEMENT. Trois voies avaient ete pesees (RFC §8) :
// suivre un fichier journal, s'abonner a une socket, ou faire appeler signal
// par sentinel. La derniere INVERSE la dependance — le detecteur connaitrait
// son notificateur — et la premiere paie la rotation et l'analyse fragile.
// L'abonnement est la seule qui laisse sentinel ignorer qui l'ecoute.
//
// SOCKET ABSENTE => RELAIS INACTIF, et le module reste utilisable comme
// messagerie. On ne fait pas dependre la messagerie du detecteur.
package sentinel

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Envoyeur est ce dont le relais a besoin — rien de plus. L'interface est
// etroite pour que les tests n'aient pas a simuler un client Signal entier.
type Envoyeur interface {
	Envoyer(ctx context.Context, dest, corps string) error
}

type Relay struct {
	socket   string
	dest     string
	maxHeure int
	env      Envoyeur

	mu       sync.Mutex
	fenetre  []time.Time
	retenues int // alertes agregees pendant la suppression
}

type alerte struct {
	Niveau  string `json:"level"`
	Source  string `json:"source"`
	Message string `json:"message"`
}

func New(socket, dest string, maxHeure int, env Envoyeur) *Relay {
	return &Relay{socket: socket, dest: dest, maxHeure: maxHeure, env: env}
}

// Run lit la socket jusqu'a annulation. Une socket absente n'est PAS une
// erreur fatale : on le dit une fois et le module continue sans relais.
func (r *Relay) Run(ctx context.Context) {
	if r.dest == "" {
		log.Printf("[sentinel] aucune destination configuree — relais inactif")
		return
	}
	for {
		if ctx.Err() != nil {
			return
		}
		conn, err := net.Dial("unix", r.socket)
		if err != nil {
			log.Printf("[sentinel] socket indisponible (%v) — nouvelle tentative dans 30 s", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
			continue
		}
		r.consommer(ctx, conn)
		_ = conn.Close()
	}
}

func (r *Relay) consommer(ctx context.Context, conn net.Conn) {
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		if ctx.Err() != nil {
			return
		}
		var a alerte
		if json.Unmarshal(sc.Bytes(), &a) != nil {
			continue
		}
		r.traiter(ctx, a)
	}
}

// traiter applique le GARDE-FOU ANTI-AVALANCHE. Au-dela du seuil horaire, les
// alertes sont comptees mais pas emises ; la premiere alerte de la fenetre
// suivante porte la synthese. Une tempete d'evenements ne doit devenir ni une
// tempete de notifications, ni un epuisement du quota du compte lie.
func (r *Relay) traiter(ctx context.Context, a alerte) {
	r.mu.Lock()
	maintenant := time.Now()
	garde := maintenant.Add(-time.Hour)
	vif := r.fenetre[:0]
	for _, t := range r.fenetre {
		if t.After(garde) {
			vif = append(vif, t)
		}
	}
	r.fenetre = vif

	if len(r.fenetre) >= r.maxHeure {
		r.retenues++
		r.mu.Unlock()
		return
	}
	r.fenetre = append(r.fenetre, maintenant)
	retenues := r.retenues
	r.retenues = 0
	r.mu.Unlock()

	corps := fmt.Sprintf("[%s] %s — %s", a.Niveau, a.Source, a.Message)
	if retenues > 0 {
		corps = fmt.Sprintf("%s\n(+%d alerte(s) agregee(s) pendant la suppression)", corps, retenues)
	}
	if err := r.env.Envoyer(ctx, r.dest, corps); err != nil {
		log.Printf("[sentinel] envoi echoue : %v", err)
	}
}
