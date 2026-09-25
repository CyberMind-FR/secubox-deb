// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package signalcli pilote signal-cli en JSON-RPC sur stdio.
//
// POURQUOI STDIO ET PAS LE MODE HTTP. signal-cli sait exposer du JSON-RPC sur
// un port ; l'utiliser voudrait dire ouvrir un port de plus sur la box, avec
// une authentification que signal-cli ne fournit pas. Sur stdio, le canal est
// le processus enfant lui-meme : rien a filtrer, rien a bannir, et le bac a
// sable de l'unite systemd couvre les deux d'un seul tenant.
//
// POURQUOI UN PROCESSUS PERSISTANT. Chaque invocation de signal-cli demarre
// une JVM — plusieurs secondes sur arm64. Un envoi par invocation rendrait le
// module inutilisable pour du temps reel. Le client maintient donc UN daemon
// et lui parle.
package signalcli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

var ErrNonLie = errors.New("aucun compte Signal lie")

type Client struct {
	chemin   string
	stateDir string
	timeout  time.Duration

	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader

	seq      atomic.Int64
	attentes sync.Map // id -> chan json.RawMessage

	// Evenements entrants (messages recus). Le demon s'y abonne ; un
	// consommateur absent ne doit PAS bloquer la lecture, d'ou le non-bloquant
	// a l'emission.
	Events chan Event
}

type Event struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type requete struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
	ID      int64  `json:"id"`
}

type reponse struct {
	ID     int64           `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

func New(chemin, stateDir string, timeout time.Duration) *Client {
	return &Client{
		chemin:   chemin,
		stateDir: stateDir,
		timeout:  timeout,
		Events:   make(chan Event, 64),
	}
}

// Start lance le daemon signal-cli et la boucle de lecture.
func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmd != nil {
		return nil
	}
	cmd := exec.CommandContext(ctx, c.chemin,
		"--config", c.stateDir,
		"--output=json",
		"daemon", "--no-receive-stdout")
	// Son stderr rejoint le journal de l'unite : c'est la que la JVM dit
	// POURQUOI elle meurt (bibliotheque native absente, par exemple).
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("signal-cli introuvable ou non executable (%s) : %w", c.chemin, err)
	}
	c.cmd, c.stdin, c.stdout = cmd, in, bufio.NewReader(out)
	go c.lire()
	return nil
}

// lire demultiplexe les reponses et les notifications.
func (c *Client) lire() {
	for {
		ligne, err := c.stdout.ReadBytes('\n')
		if err != nil {
			c.fin()
			return
		}
		var r reponse
		if json.Unmarshal(ligne, &r) != nil {
			continue // une ligne illisible ne doit pas tuer la boucle
		}
		if r.ID != 0 {
			if ch, ok := c.attentes.LoadAndDelete(r.ID); ok {
				ch.(chan reponse) <- r
			}
			continue
		}
		if r.Method != "" {
			select {
			case c.Events <- Event{Type: r.Method, Data: r.Params}:
			default: // consommateur absent ou lent : on jette, on ne bloque pas
			}
		}
	}
}

// fin : signal-cli s'est arrete (ou a ete arrete). On RECUEILLE le processus
// — sans Wait il restait zombie — on le journalise, et le client revient a
// l'etat « non demarre » : les appels le disent au lieu d'attendre le delai.
func (c *Client) fin() {
	c.mu.Lock()
	cmd := c.cmd
	c.cmd, c.stdin, c.stdout = nil, nil, nil
	c.mu.Unlock()
	if cmd == nil {
		return
	}
	log.Printf("signal-cli s'est arrete : %v", cmd.Wait())
	// Les appels en vol n'auront jamais de reponse : on les libere.
	c.attentes.Range(func(id, ch any) bool {
		c.attentes.Delete(id)
		ch.(chan reponse) <- reponse{Error: &struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}{-1, "backend signal-cli arrete"}}
		return true
	})
}

// Call emet une requete et attend sa reponse.
func (c *Client) Call(ctx context.Context, methode string, params any) (json.RawMessage, error) {
	c.mu.Lock()
	stdin := c.stdin
	c.mu.Unlock()
	if stdin == nil {
		return nil, errors.New("backend signal-cli non demarre")
	}

	id := c.seq.Add(1)
	ch := make(chan reponse, 1)
	c.attentes.Store(id, ch)
	defer c.attentes.Delete(id)

	brut, err := json.Marshal(requete{JSONRPC: "2.0", Method: methode, Params: params, ID: id})
	if err != nil {
		return nil, err
	}
	if _, err := stdin.Write(append(brut, '\n')); err != nil {
		return nil, err
	}

	ctx, annule := context.WithTimeout(ctx, c.timeout)
	defer annule()
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("signal-cli n'a pas repondu en %s : %w", c.timeout, ctx.Err())
	case r := <-ch:
		if r.Error != nil {
			return nil, fmt.Errorf("signal-cli: %s (code %d)", r.Error.Message, r.Error.Code)
		}
		return r.Result, nil
	}
}

func (c *Client) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmd == nil || c.cmd.Process == nil {
		return nil
	}
	_ = c.stdin.Close()
	return c.cmd.Process.Kill()
}
