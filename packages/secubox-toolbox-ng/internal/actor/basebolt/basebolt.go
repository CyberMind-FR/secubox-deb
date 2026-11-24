// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package basebolt ouvre et ferme les bases bbolt d'actord (magasin d'événements
// et registre de preuves).
//
// POURQUOI UN ARRÊT PARTICULIER. Les bases tournent avec NoFreelistSync (#3320) :
// la liste des pages libres n'est plus réécrite à chaque transaction. En
// contrepartie, bbolt la RECONSTRUIT à l'ouverture en parcourant toutes les pages
// de tous les seaux, trois fois (pages, ordre des clés, sous-seaux), en lecture
// aléatoire (MADV_RANDOM, une faute de page de 4 Ko à la fois). Sur gk2 :
// 1,28 Go de bases, 3 Go lus, API fermée 10 minutes. Écrire cette liste UNE fois,
// à l'arrêt propre, suffit à rendre l'ouverture suivante immédiate ; la première
// transaction la retire. Après un arrêt brutal, le parcours complet reste.
package basebolt

import (
	"errors"
	"time"

	"go.etcd.io/bbolt"
)

// Options : options d'ouverture communes (#3320). FreelistMapType : allocation en
// O(1) au lieu d'un tableau trié.
func Options() *bbolt.Options {
	return &bbolt.Options{Timeout: 5 * time.Second, NoFreelistSync: true, FreelistType: bbolt.FreelistMapType}
}

// Fermer écrit la liste des pages libres puis ferme la base. Un échec d'écriture
// (disque plein, base en lecture seule) n'empêche pas la fermeture. Sans effet
// sur une base déjà fermée.
func Fermer(db *bbolt.DB) error {
	err := db.Update(func(*bbolt.Tx) error {
		// Sous le verrou d'écriture : Commit, qui lit ce champ, est dans la même
		// transaction, et aucune autre écriture ne court.
		db.NoFreelistSync = false
		return nil
	})
	if errors.Is(err, bbolt.ErrDatabaseNotOpen) || errors.Is(err, bbolt.ErrDatabaseReadOnly) {
		err = nil
	}
	return errors.Join(err, db.Close())
}
