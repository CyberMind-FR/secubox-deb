// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package emit est le client d'émission des Event Envelopes vers sbx-actord
// (RFC-0013 §1/§15). Il est conçu pour le HOT PATH d'un capteur (sbxwaf, sbxdpi,
// sbx-authwatch, sbx-sentinel) : Emit ne bloque JAMAIS le producteur — il dépose
// l'enveloppe dans une file bornée qu'un goroutine d'arrière-plan écoule vers le
// socket unix d'actord, en se reconnectant au besoin. Si actord est absent, lent
// ou tombé, les enveloppes sont simplement déposées (comptées) : le capteur
// continue de protéger. Aucune dépendance externe.
package emit

import (
	"encoding/json"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
)

// Emitter émet des enveloppes vers actord sans bloquer le producteur.
type Emitter struct {
	path string
	ch   chan []byte
	quit chan struct{}
	wg   sync.WaitGroup

	dropped atomic.Uint64
	sent    atomic.Uint64

	mu   sync.Mutex
	conn net.Conn
}

// New crée un Emitter vers `path` avec une file de profondeur `queue` (>=1) et
// démarre son goroutine d'envoi.
func New(path string, queue int) *Emitter {
	if queue < 1 {
		queue = 1024
	}
	e := &Emitter{path: path, ch: make(chan []byte, queue), quit: make(chan struct{})}
	e.wg.Add(1)
	go e.loop()
	return e
}

// Emit met une enveloppe en file. NON BLOQUANT : si la file est pleine ou le
// marshalling échoue, l'enveloppe est déposée (comptée) et Emit retourne
// immédiatement. Retourne true si mise en file.
func (e *Emitter) Emit(env *envelope.Envelope) bool {
	blob, err := json.Marshal(env)
	if err != nil {
		e.dropped.Add(1)
		return false
	}
	blob = append(blob, '\n')
	select {
	case e.ch <- blob:
		return true
	default:
		e.dropped.Add(1)
		return false
	}
}

// Dropped/Sent : compteurs d'observabilité.
func (e *Emitter) Dropped() uint64 { return e.dropped.Load() }
func (e *Emitter) Sent() uint64    { return e.sent.Load() }

func (e *Emitter) loop() {
	defer e.wg.Done()
	for {
		select {
		case <-e.quit:
			e.closeConn()
			return
		case blob := <-e.ch:
			e.write(blob)
		}
	}
}

func (e *Emitter) write(blob []byte) {
	c := e.ensure()
	if c == nil {
		e.dropped.Add(1)
		return
	}
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(blob); err != nil {
		// connexion cassée : on la ferme, on dépose cette enveloppe (la suivante
		// reconnectera). On ne bloque ni ne réessaie en boucle sur le hot path.
		e.closeConn()
		e.dropped.Add(1)
		return
	}
	e.sent.Add(1)
}

// ensure renvoie une connexion établie, en se (re)connectant au besoin.
func (e *Emitter) ensure() net.Conn {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn != nil {
		return e.conn
	}
	c, err := net.DialTimeout("unix", e.path, 2*time.Second)
	if err != nil {
		return nil
	}
	e.conn = c
	return c
}

func (e *Emitter) closeConn() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn != nil {
		_ = e.conn.Close()
		e.conn = nil
	}
}

// Close arrête proprement l'Emitter (vide au mieux la file en cours puis ferme).
func (e *Emitter) Close() {
	close(e.quit)
	e.wg.Wait()
}
