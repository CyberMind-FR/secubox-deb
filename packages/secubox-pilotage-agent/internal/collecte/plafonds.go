// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
// Package lecture : lecture bornée et non bloquante de fichiers (/proc, /sys, …).
package collecte

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
