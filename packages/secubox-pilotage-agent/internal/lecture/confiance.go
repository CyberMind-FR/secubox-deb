// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package lecture

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// oPath : O_PATH de Linux (même valeur sur amd64, 386, arm et arm64) ; le paquet
// syscall ne le définit que pour arm64. Une ouverture O_PATH ne lit rien.
const oPath = 0x200000

// Proprietaire : compte exigé d'un fichier de réglage lu par l'agent.
type Proprietaire struct{ UID, GID uint32 }

// Root : le propriétaire exigé en production (R36).
var Root = Proprietaire{UID: 0, GID: 0}

// ouvrirDeConfiance ouvre rel sous racine sans suivre AUCUN lien : chaque
// dossier intermédiaire par descripteur (O_PATH|O_DIRECTORY|O_NOFOLLOW), le
// fichier en O_NOFOLLOW|O_NONBLOCK (une FIFO ne retient pas l'agent). Le
// fichier doit être régulier, appartenir à p, n'être inscriptible ni par le
// groupe ni par les autres et n'avoir qu'un lien physique. /etc/secubox
// appartient au compte partagé secubox : un lien ou un fichier qu'il y dépose
// n'est jamais pris pour un réglage de root.
func ouvrirDeConfiance(racine, rel string, p Proprietaire) (*os.File, error) {
	comps := strings.Split(rel, "/")
	for _, c := range comps {
		if c == "" || c == "." || c == ".." {
			return nil, fmt.Errorf("chemin %q invalide", rel)
		}
	}
	dir, err := syscall.Open(racine, oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: racine, Err: err}
	}
	for _, c := range comps[:len(comps)-1] {
		fd, err := syscall.Openat(dir, c, oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(dir)
		if err != nil {
			return nil, &os.PathError{Op: "openat", Path: c, Err: err}
		}
		dir = fd
	}
	chemin := filepath.Join(racine, rel)
	fd, err := syscall.Openat(dir, comps[len(comps)-1], syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	syscall.Close(dir)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: chemin, Err: err}
	}
	f := os.NewFile(uintptr(fd), chemin)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, &os.PathError{Op: "fstat", Path: chemin, Err: err}
	}
	var refus string
	switch {
	case st.Mode&syscall.S_IFMT != syscall.S_IFREG:
		refus = "pas un fichier régulier"
	case st.Uid != p.UID || st.Gid != p.GID:
		refus = fmt.Sprintf("propriétaire %d:%d, attendu %d:%d", st.Uid, st.Gid, p.UID, p.GID)
	case st.Mode&0o022 != 0:
		refus = fmt.Sprintf("mode %04o : inscriptible par le groupe ou les autres", st.Mode&0o7777)
	case st.Nlink != 1:
		refus = fmt.Sprintf("%d liens physiques", st.Nlink)
	}
	if refus != "" {
		f.Close()
		return nil, fmt.Errorf("%s : %s", chemin, refus)
	}
	return f, nil
}

// PresentDeConfiance rend nil si rel existe sous racine et passe les contrôles
// d'ouvrirDeConfiance ; absent : une erreur telle que errors.Is(err, fs.ErrNotExist).
func PresentDeConfiance(racine, rel string, p Proprietaire) error {
	f, err := ouvrirDeConfiance(racine, rel, p)
	if err != nil {
		return err
	}
	return f.Close()
}

// LireDeConfiance lit un fichier de réglage digne de confiance (voir
// ouvrirDeConfiance). Plus long que max : refusé, jamais coupé au milieu
// d'une valeur.
func LireDeConfiance(racine, rel string, max int64, p Proprietaire) ([]byte, error) {
	f, err := ouvrirDeConfiance(racine, rel, p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New(f.Name() + " : plus long que " + fmt.Sprint(max) + " octets")
	}
	return b, nil
}
