// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"sync"
	"time"
)

// tampon est un cache À DOUBLE TAMPON : on sert TOUJOURS le dernier instantané complet, tout de suite, et le recalcul
// d'un instantané périmé se fait en arrière-plan (un seul à la fois). Un appel ne calcule jamais sur le chemin de la
// requête, sauf le tout premier (démarrage à froid), où il n'existe encore rien à servir.
//
// Pourquoi : /stats et /overview relisent des milliers d'événements. Avec un simple cache à durée de vie, l'appel qui
// tombait sur l'expiration payait le calcul (jusqu'à plusieurs minutes sur une box dont la RAM est saturée) et tous les
// autres attendaient derrière lui.
type tampon[T any] struct {
	mu      sync.Mutex
	val     T
	at      time.Time
	ok      bool
	enCours bool
}

// lire rend l'instantané courant ; s'il a plus de ttl, lance son renouvellement en arrière-plan.
func (b *tampon[T]) lire(ttl time.Duration, calcule func() (T, error)) (T, error) {
	b.mu.Lock()
	if b.ok {
		v := b.val
		if time.Since(b.at) >= ttl && !b.enCours {
			b.enCours = true
			go b.renouvelle(calcule)
		}
		b.mu.Unlock()
		return v, nil
	}
	// Démarrage à froid : rien à servir, un seul calcul (les autres attendent son résultat).
	defer b.mu.Unlock()
	v, err := calcule()
	if err != nil {
		var zero T
		return zero, err
	}
	b.val, b.at, b.ok = v, time.Now(), true
	return v, nil
}

func (b *tampon[T]) renouvelle(calcule func() (T, error)) {
	v, err := calcule()
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		b.val, b.at = v, time.Now()
	}
	b.enCours = false
}

// perime marque l'instantané comme périmé (tests).
func (b *tampon[T]) perime() {
	b.mu.Lock()
	b.at = time.Time{}
	b.mu.Unlock()
}
