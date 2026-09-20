// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package ws implemente le strict necessaire de RFC 6455, cote serveur.
//
// POURQUOI PAS UNE BIBLIOTHEQUE. Le module n'emet que des trames TEXTE, ne
// recoit rien d'autre que des pings, et sert un seul type d'enveloppe JSON.
// Importer un framework WebSocket pour cela ajouterait plus de code a auditer
// que la centaine de lignes ci-dessous — dans un module dont la posture est
// la dependance minimale.
//
// CE QUI EST VOLONTAIREMENT ABSENT : la fragmentation (nos trames sont
// courtes), la compression per-message (inutile sur du JSON de quelques
// centaines d'octets), et le masquage cote serveur — que la RFC INTERDIT.
package ws

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

const magie = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type Hub struct {
	mu      sync.Mutex
	clients map[*client]struct{}
}

type client struct {
	conn interface {
		Write([]byte) (int, error)
		Close() error
	}
	mu sync.Mutex
}

type Enveloppe struct {
	Type string `json:"type"`
	TS   string `json:"ts"`
	Data any    `json:"data,omitempty"`
}

func NewHub() *Hub { return &Hub{clients: map[*client]struct{}{}} }

// Upgrade realise la poignee de main puis enregistre le client.
func (h *Hub) Upgrade(w http.ResponseWriter, r *http.Request) error {
	if r.Header.Get("Upgrade") != "websocket" {
		return errors.New("pas une demande de bascule websocket")
	}
	cle := r.Header.Get("Sec-WebSocket-Key")
	if cle == "" {
		return errors.New("Sec-WebSocket-Key absent")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return errors.New("ResponseWriter ne sait pas etre detourne")
	}
	somme := sha1.Sum([]byte(cle + magie))
	accept := base64.StdEncoding.EncodeToString(somme[:])

	conn, brw, err := hj.Hijack()
	if err != nil {
		return err
	}
	_, err = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n")
	if err != nil {
		conn.Close()
		return err
	}
	if err := brw.Flush(); err != nil {
		conn.Close()
		return err
	}

	c := &client{conn: conn}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	return nil
}

// Diffuser emet une enveloppe a tous les clients. Un client en erreur est
// retire : une diffusion ne doit jamais dependre du plus lent.
func (h *Hub) Diffuser(typ string, data any) {
	env := Enveloppe{Type: typ, TS: time.Now().UTC().Format(time.RFC3339), Data: data}
	charge, err := json.Marshal(env)
	if err != nil {
		return
	}
	trame := encoder(charge)

	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		c.mu.Lock()
		_, err := c.conn.Write(trame)
		c.mu.Unlock()
		if err != nil {
			_ = c.conn.Close()
			delete(h.clients, c)
		}
	}
}

func (h *Hub) Nombre() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// encoder produit une trame texte non masquee, finale.
func encoder(charge []byte) []byte {
	n := len(charge)
	var tete []byte
	switch {
	case n < 126:
		tete = []byte{0x81, byte(n)}
	case n < 65536:
		tete = []byte{0x81, 126, 0, 0}
		binary.BigEndian.PutUint16(tete[2:], uint16(n))
	default:
		tete = make([]byte, 10)
		tete[0], tete[1] = 0x81, 127
		binary.BigEndian.PutUint64(tete[2:], uint64(n))
	}
	return append(tete, charge...)
}
