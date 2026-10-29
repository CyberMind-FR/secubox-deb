// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

const (
	cheminSystemctl    = "/usr/bin/systemctl"
	delaiSystemctl     = 5 * time.Second
	maxSortieSystemctl = 1 << 20
	attenteFermeture   = time.Second // après le tir, délai laissé aux tubes avant de les fermer
)

// plafond garde au plus max octets et jette le reste sans erreur : le
// processus n'est jamais bloqué sur une sortie que personne ne lit.
type plafond struct {
	buf bytes.Buffer
	max int
}

func (p *plafond) Write(b []byte) (int, error) {
	if r := p.max - p.buf.Len(); r > 0 {
		if len(b) < r {
			r = len(b)
		}
		p.buf.Write(b[:r])
	}
	return len(b), nil
}

// lanceurSystemctl lance l'exécutable donné (systemctl en production) avec les
// arguments reçus. Au délai ou à l'annulation, tout le groupe du processus est
// tué (SIGKILL) : ni processus ni goroutine ne s'accumule. Environnement vide.
func lanceurSystemctl(chemin string, delai time.Duration) func(ctx context.Context, args ...string) ([]byte, error) {
	return func(ctx context.Context, args ...string) ([]byte, error) {
		ctx, annule := context.WithTimeout(ctx, delai)
		defer annule()
		cmd := exec.CommandContext(ctx, chemin, args...)
		cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error {
			if cmd.Process == nil {
				return nil
			}
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		cmd.WaitDelay = attenteFermeture
		sortie := &plafond{max: maxSortieSystemctl}
		cmd.Stdout = sortie
		if err := cmd.Run(); err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("systemctl interrompu : %w", ctx.Err())
			}
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return nil, fmt.Errorf("systemctl : code %d", ee.ExitCode())
			}
			return nil, err
		}
		return sortie.buf.Bytes(), nil
	}
}
