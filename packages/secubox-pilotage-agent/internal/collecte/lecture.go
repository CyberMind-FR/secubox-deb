// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
package collecte

import (
	"errors"
	"io"
	"os"
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

type lecteurBorne struct {
	io.Reader
	f *os.File
}

func (l lecteurBorne) Close() error { return l.f.Close() }

// ouvrirBorne ouvre sans bloquer (une FIFO ne retient pas l'agent), exige un
// fichier régulier et ne rend jamais plus de max octets. Les liens sont suivis.
func ouvrirBorne(chemin string, max int64) (io.ReadCloser, error) {
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
	return lecteurBorne{io.LimitReader(f, max), f}, nil
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
