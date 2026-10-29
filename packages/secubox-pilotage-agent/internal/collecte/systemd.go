// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package collecte

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
)

const (
	racineServices = "Device.X_SECUBOX_Services."
	maxUnites      = 200
	delaiSystemctl = 5 * time.Second
)

// unitesAdmises : hors préfixe « secubox- », seules ces unités sont publiées.
var unitesAdmises = map[string]bool{
	"nginx.service": true, "unbound.service": true, "ssh.service": true, "nftables.service": true,
}

type systemd struct {
	lanceur func(ctx context.Context, args ...string) ([]byte, error)
}

// NouvelleSourceSystemd interroge systemctl par le lanceur injecté (un seul
// appel, 5 s). C'est la seule source autorisée à lancer un processus.
func NouvelleSourceSystemd(lanceur func(ctx context.Context, args ...string) ([]byte, error)) modele.Source {
	return &systemd{lanceur: lanceur}
}

func (s *systemd) Nom() string { return "systemd" }

func (s *systemd) Chemins() []string {
	l := []string{racineServices + "FailedNumberOfEntries"}
	for _, f := range []string{"Name", "ActiveState", "SubState", "NRestarts", "Result"} {
		l = append(l, racineServices+"{i}."+f)
	}
	return l
}

type reponseLanceur struct {
	sortie []byte
	err    error
}

func (s *systemd) Lire(ctx context.Context) (map[string]any, error) {
	ctx, annule := context.WithTimeout(ctx, delaiSystemctl)
	defer annule()
	// Le lanceur tourne à part : même s'il ignore le contexte, Lire rend la main
	// au délai (canal tamponné, la goroutine n'est jamais bloquée).
	ch := make(chan reponseLanceur, 1)
	go func() {
		b, err := s.lanceur(ctx, "show", "--property=Id,ActiveState,SubState,NRestarts,Result",
			"secubox-*", "nginx.service", "unbound.service", "ssh.service", "nftables.service")
		ch <- reponseLanceur{b, err}
	}()
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("systemctl : %w", ctx.Err())
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("systemctl : %w", r.err)
		}
		return analyserSystemctl(r.sortie)
	}
}

// analyserSystemctl lit les blocs « Clé=valeur » séparés par une ligne vide.
func analyserSystemctl(sortie []byte) (map[string]any, error) {
	p := map[string]any{}
	n, echecs := 0, 0
	bloc := map[string]string{}
	clore := func() {
		id := bloc["Id"]
		defer func() { bloc = map[string]string{} }()
		if id == "" || !(strings.HasPrefix(id, "secubox-") || unitesAdmises[id]) {
			return
		}
		if bloc["ActiveState"] == "failed" {
			echecs++
		}
		if n >= maxUnites {
			return
		}
		n++
		base := fmt.Sprintf("%s%d.", racineServices, n)
		p[base+"Name"] = id
		p[base+"ActiveState"] = bloc["ActiveState"]
		p[base+"SubState"] = bloc["SubState"]
		p[base+"Result"] = bloc["Result"]
		r, _ := strconv.ParseUint(bloc["NRestarts"], 10, 64)
		p[base+"NRestarts"] = r
	}
	sc := bufio.NewScanner(bytes.NewReader(sortie))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" {
			clore()
			continue
		}
		if k, v, ok := strings.Cut(l, "="); ok {
			bloc[k] = v
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	clore()
	if n == 0 && echecs == 0 && len(sortie) == 0 {
		return nil, errors.New("systemctl : sortie vide")
	}
	p[racineServices+"FailedNumberOfEntries"] = echecs
	return p, nil
}
