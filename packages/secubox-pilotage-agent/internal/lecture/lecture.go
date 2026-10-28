// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package lecture : lecture bornée et non bloquante de fichiers (/proc, /sys, …).
package lecture

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
)

var errNonRegulier = errors.New("pas un fichier régulier")

// Borne rend au plus restant octets, puis sonde un octet de plus pour
// savoir si le fichier a été coupé par le plafond.
type Borne struct {
	f       *os.File
	restant int64
	coupe   bool
}

func (l *Borne) Read(p []byte) (int, error) {
	if l.restant <= 0 {
		var un [1]byte
		if n, _ := l.f.Read(un[:]); n > 0 {
			l.coupe = true
		}
		return 0, io.EOF
	}
	if int64(len(p)) > l.restant {
		p = p[:l.restant]
	}
	n, err := l.f.Read(p)
	l.restant -= int64(n)
	return n, err
}

func (l *Borne) Close() error { return l.f.Close() }

// Tronque dit si le plafond a coupé le fichier (valable une fois la fin atteinte).
func (l *Borne) Tronque() bool { return l.coupe }

// Ouvrir ouvre sans bloquer (une FIFO ne retient pas l'agent), exige un
// fichier régulier et ne rend jamais plus de max octets. Les liens sont suivis.
func Ouvrir(chemin string, max int64) (*Borne, error) {
	f, err := os.OpenFile(chemin, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, errNonRegulier
	}
	return &Borne{f: f, restant: max}, nil
}

// Lignes appelle fn pour chaque ligne complète. Si le plafond a coupé
// le fichier, la dernière ligne (sans fin de ligne) est ignorée : elle peut
// s'arrêter au milieu d'un nom ou d'une version. Les erreurs de lecture et
// l'annulation du contexte sont remontées.
func Lignes(ctx context.Context, r *Borne, fn func(ligne string)) error {
	br := bufio.NewReader(r)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ligne, err := br.ReadString('\n')
		if err == nil {
			fn(strings.TrimRight(ligne, "\r\n"))
			continue
		}
		if err != io.EOF {
			return err
		}
		if ligne != "" && !r.Tronque() {
			fn(ligne)
		}
		return nil
	}
}

// Lire lit au plus max octets d'un fichier régulier.
func Lire(chemin string, max int64) ([]byte, error) {
	r, err := Ouvrir(chemin, max)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
