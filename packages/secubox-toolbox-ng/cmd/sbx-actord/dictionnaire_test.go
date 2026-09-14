// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package main

import "testing"

func inex(noms ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range noms {
		m[n] = true
	}
	return m
}

func TestDictionnaire_DeuxTranchesDuMemeSeRejoignent(t *testing.T) {
	// LE CAS OBSERVÉ EN PRODUCTION : un énumérateur tire sa liste dans l'ordre
	// et la répartit entre ses adresses. Deux tranches consécutives ne
	// partagent AUCUN nom — et se retrouvaient donc dans deux campagnes.
	ix := inex("tencent.secubox.in", "tw.secubox.in", "user.secubox.in",
		"wanted.secubox.in", "wazuh.secubox.in")
	s := &Server{inexistants: ix}

	a := s.signatureActeur([]string{"tencent.secubox.in", "tw.secubox.in", "user.secubox.in"})
	b := s.signatureActeur([]string{"wanted.secubox.in", "wazuh.secubox.in"})
	if a != b {
		t.Fatalf("deux tranches du même dictionnaire restent séparées : %s vs %s", a, b)
	}
}

func TestDictionnaire_DeuxDomainesNeSeMelangentPas(t *testing.T) {
	ix := inex("a.secubox.in", "b.secubox.in", "a.ganimed.fr", "b.ganimed.fr")
	s := &Server{inexistants: ix}
	if s.signatureActeur([]string{"a.secubox.in", "b.secubox.in"}) ==
		s.signatureActeur([]string{"a.ganimed.fr", "b.ganimed.fr"}) {
		t.Fatal("deux domaines différents ont été regroupés")
	}
}

func TestDictionnaire_UneSeuleCibleREELLESepareTout(t *testing.T) {
	// LA CONDITION EST STRICTE, ET C'EST VOULU. Qui vise un hôte qui EXISTE
	// cherche quelque chose de précis — pas la même chose que celui qui récite.
	// Le doute doit profiter à la séparation.
	ix := inex("x.secubox.in", "y.secubox.in")
	s := &Server{inexistants: ix}
	recite := s.signatureActeur([]string{"x.secubox.in", "y.secubox.in"})
	cible := s.signatureActeur([]string{"x.secubox.in", "hall.gk2.secubox.in"})
	if recite == cible {
		t.Fatal("un acteur visant un hôte réel a été pris pour un récitant")
	}
}

func TestDictionnaire_SousDomainesDeNiveauxDifferents(t *testing.T) {
	// `a.gk2.secubox.in` et `b.secubox.in` ne récitent PAS le même dictionnaire :
	// l'un énumère sous gk2, l'autre sous l'apex. Les confondre effacerait une
	// distinction qui compte — l'apex est là où rien n'est publié.
	ix := inex("a.gk2.secubox.in", "b.gk2.secubox.in", "c.secubox.in")
	s := &Server{inexistants: ix}
	if s.signatureActeur([]string{"a.gk2.secubox.in", "b.gk2.secubox.in"}) ==
		s.signatureActeur([]string{"c.secubox.in"}) {
		t.Fatal("deux niveaux de sous-domaine ont été regroupés")
	}
}

func TestDictionnaire_RefusDesSuffixesTropCourts(t *testing.T) {
	// « in » ou « fr » seuls regrouperaient la moitié de l'internet.
	ix := inex("secubox.in", "ganimed.fr")
	if _, ok := suffixeDictionnaire([]string{"secubox.in"}, ix); ok {
		t.Error("un suffixe de premier niveau a été accepté")
	}
	if _, ok := suffixeDictionnaire([]string{"localhost"}, inex("localhost")); ok {
		t.Error("un nom sans domaine parent a été accepté")
	}
}

func TestDictionnaire_LePortNeSepareDeRien(t *testing.T) {
	// `lldh.ganimed.fr` et `lldh.ganimed.fr:443` sont le même nom : un port
	// dans la cible ne doit pas fabriquer deux dictionnaires.
	ix := inex("lldh.ganimed.fr", "oracle.ganimed.fr:443")
	s := &Server{inexistants: ix}
	if s.signatureActeur([]string{"lldh.ganimed.fr"}) !=
		s.signatureActeur([]string{"oracle.ganimed.fr:443"}) {
		t.Fatal("le port a séparé deux tranches du même dictionnaire")
	}
}

func TestDictionnaire_SansCibleInexistanteRienNeChange(t *testing.T) {
	// Les campagnes « classiques » (plusieurs acteurs visant les mêmes hôtes
	// RÉELS) doivent garder exactement leur comportement d'avant.
	s := &Server{inexistants: map[string]bool{}}
	cibles := []string{"git.gk2.secubox.in", "gitea.gk2.secubox.in"}
	if s.signatureActeur(cibles) != signatureCampagne(cibles) {
		t.Fatal("le regroupement classique a été altéré")
	}
}
