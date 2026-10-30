// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package relais

// Drapeaux root projetés par secubox-pilotagectl dans /etc/secubox-pilotage (dossier root 0755) : `mains-liees`
// (présence), `support-ouvert` et `proprietaire` (contenu : échéance en secondes epoch). Lus par le relais et par
// l'agent à CHAQUE message, sans privilège ni sudo, avec une seule vérification (lireDrapeau) : dossier
// O_DIRECTORY|O_NOFOLLOW, fichier par dir_fd O_NOFOLLOW, l'un et l'autre au compte uidRoot, sans écriture pour le
// groupe ni les autres, fichier régulier. Tout doute va vers le défaut sûr : mains liées, pas d'échéance.

import (
	"errors"
	"log"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type etatDrapeau int

const (
	drapeauAbsent  etatDrapeau = iota // dossier de confiance, fichier absent
	drapeauPresent                    // fichier de confiance (contenu lu)
	drapeauDouteux                    // dossier ou fichier douteux, illisible
)

const contenuDrapeauMax = 32

func lireDrapeau(dossier, nom string, uidRoot uint32) (etatDrapeau, string) {
	dir, err := syscall.Open(dossier, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return drapeauDouteux, ""
	}
	defer syscall.Close(dir)
	var st syscall.Stat_t
	if syscall.Fstat(dir, &st) != nil || st.Uid != uidRoot || st.Mode&0o022 != 0 {
		return drapeauDouteux, ""
	}
	fd, err := syscall.Openat(dir, nom, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) {
		return drapeauAbsent, ""
	}
	if err != nil {
		return drapeauDouteux, ""
	}
	defer syscall.Close(fd)
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != uidRoot || st.Mode&0o022 != 0 {
		return drapeauDouteux, ""
	}
	b := make([]byte, contenuDrapeauMax+1)
	n, err := syscall.Read(fd, b)
	if err != nil || n > contenuDrapeauMax {
		return drapeauDouteux, ""
	}
	return drapeauPresent, string(b[:n])
}

// MainsLieesDans : mains LIBRES seulement si le dossier est de confiance et le drapeau absent ; tout le reste
// (dossier absent ou douteux, drapeau présent ou douteux) vaut « mains liées » (R-L5-19).
func MainsLieesDans(dossier string, uidRoot uint32, journal *log.Logger) bool {
	e, _ := lireDrapeau(dossier, "mains-liees", uidRoot)
	if e == drapeauDouteux && journal != nil {
		journal.Printf("drapeau des mains liées douteux dans %s : traité comme posé", dossier)
	}
	return e != drapeauAbsent
}

// EcheanceDans : vrai seulement si le drapeau `nom` est de confiance et porte une échéance (entier décimal,
// secondes epoch) postérieure à maintenant (R-L5-21). Absent, douteux, illisible ou échu : faux.
func EcheanceDans(dossier, nom string, uidRoot uint32, maintenant time.Time) bool {
	e, contenu := lireDrapeau(dossier, nom, uidRoot)
	if e != drapeauPresent {
		return false
	}
	fin, err := strconv.ParseInt(strings.TrimSpace(contenu), 10, 64)
	return err == nil && fin > maintenant.Unix()
}
