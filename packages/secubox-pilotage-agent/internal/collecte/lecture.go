// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
package collecte

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
)

// Plafonds de lecture : l'agent est borné en mémoire et lit des arbres que
// d'autres processus peuvent modifier (FIFO, liens vers de gros fichiers).
const (
	plafondPetit   = 64 << 10  // fichiers d'une ligne ou presque
	plafondProc    = 1 << 20   // /proc, /sys
	plafondVhost   = 256 << 10 // un fichier de sites-enabled
	plafondReseau  = 4 << 20   // /proc/net/tcp*
	plafondDpkg    = 16 << 20  // /var/lib/dpkg/status
	maxFichiersVhs = 256
)

var errNonRegulier = errors.New("pas un fichier régulier")

// lecteurBorne rend au plus restant octets, puis sonde un octet de plus pour
// savoir si le fichier a été coupé par le plafond.
type lecteurBorne struct {
	f       *os.File
	restant int64
	coupe   bool
}

func (l *lecteurBorne) Read(p []byte) (int, error) {
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

func (l *lecteurBorne) Close() error { return l.f.Close() }

// Tronque dit si le plafond a coupé le fichier (valable une fois la fin atteinte).
func (l *lecteurBorne) Tronque() bool { return l.coupe }

// ouvrirBorne ouvre sans bloquer (une FIFO ne retient pas l'agent), exige un
// fichier régulier et ne rend jamais plus de max octets. Les liens sont suivis.
func ouvrirBorne(chemin string, max int64) (*lecteurBorne, error) {
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
	return &lecteurBorne{f: f, restant: max}, nil
}

// parcourirLignes appelle fn pour chaque ligne complète. Si le plafond a coupé
// le fichier, la dernière ligne (sans fin de ligne) est ignorée : elle peut
// s'arrêter au milieu d'un nom ou d'une version. Les erreurs de lecture et
// l'annulation du contexte sont remontées.
func parcourirLignes(ctx context.Context, r *lecteurBorne, fn func(ligne string)) error {
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

// lireBorne lit au plus max octets d'un fichier régulier.
func lireBorne(chemin string, max int64) ([]byte, error) {
	r, err := ouvrirBorne(chemin, max)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
