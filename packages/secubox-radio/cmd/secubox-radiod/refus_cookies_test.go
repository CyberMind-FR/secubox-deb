// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package main

import "testing"

// #4055 : une proposition refusee faute de cookies n'est plus redemandee tant
// que le coffre n'a pas change ; un nouveau depot la remet en jeu une fois.
func TestRefusCookies(t *testing.T) {
	r := refusCookies{}
	if r.bloque(151, 1000) {
		t.Fatal("aucun refus note : la demande doit partir")
	}
	r.note(151, 1000)
	for i := 0; i < 3; i++ {
		if !r.bloque(151, 1000) {
			t.Fatal("coffre inchange : la proposition ne doit pas etre redemandee")
		}
	}
	if r.bloque(152, 1000) {
		t.Fatal("le refus d'une proposition ne bloque pas les autres")
	}
	if r.bloque(151, 2000) {
		t.Fatal("nouveaux cookies : la proposition doit etre retentee")
	}
	if r.bloque(151, 2000) {
		t.Fatal("refus leve : plus de blocage tant qu'un nouveau refus n'est pas note")
	}
}
