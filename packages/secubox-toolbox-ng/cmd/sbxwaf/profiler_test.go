// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"strings"
	"testing"
)

// ligne fabrique une ligne NDJSON du journal.
func ligne(ip, path, cat, action, tool string) string {
	return `{"timestamp":"2026-08-20T10:00:00Z","client_ip":"` + ip +
		`","host":"x","method":"GET","path":"` + path +
		`","category":"` + cat + `","action":"` + action +
		`","user_agent":"ua","tool":"` + tool + `"}`
}

func TestConstruireProfils_AgregeParIP(t *testing.T) {
	log := strings.Join([]string{
		ligne("1.2.3.4", "/wp-login.php", "product_absent", "detect", "nuclei"),
		ligne("1.2.3.4", "/user/12", "scanners", "warning", ""),
		ligne("1.2.3.4", "/user/98", "scanners", "banned", ""),
	}, "\n")
	profs := construireProfils(strings.NewReader(log))
	if len(profs) != 1 {
		t.Fatalf("attendu 1 attaquant, obtenu %d", len(profs))
	}
	p := profs["1.2.3.4"]
	if p.Sondes != 3 {
		t.Errorf("sondes=%d ; attendu 3", p.Sondes)
	}
	if p.Verdict != "banned" {
		t.Errorf("verdict=%q ; attendu banned (le pire l'emporte)", p.Verdict)
	}
	// /user/12 et /user/98 → même forme normalisée /user/#
	last2 := p.Sequence[len(p.Sequence)-2:]
	if last2[0] != "/user/#" || last2[1] != "/user/#" {
		t.Errorf("normalisation attendue /user/# ; obtenu %v", last2)
	}
	if len(p.Outils) != 1 || p.Outils[0] != "nuclei" {
		t.Errorf("outils=%v ; attendu [nuclei]", p.Outils)
	}
}

func TestClusteriser_MemeWorkflowMemeCampagne(t *testing.T) {
	// Deux IP différentes menant EXACTEMENT le même balayage (mêmes chemins,
	// même outil) → une seule campagne.
	mk := func(ip string) []string {
		return []string{
			ligne(ip, "/wp-login.php", "product_absent", "banned", "nuclei"),
			ligne(ip, "/.git/config", "scanners", "banned", "nuclei"),
			ligne(ip, "/actuator/env", "scanners", "banned", "nuclei"),
		}
	}
	var all []string
	all = append(all, mk("1.1.1.1")...)
	all = append(all, mk("2.2.2.2")...)
	// Un troisième attaquant au workflow DIFFÉRENT.
	all = append(all,
		ligne("3.3.3.3", "/xmlrpc.php", "scanners", "warning", ""),
		ligne("3.3.3.3", "/vendor/phpunit", "scanners", "warning", ""),
	)

	profs := construireProfils(strings.NewReader(strings.Join(all, "\n")))
	camps := clusteriser(profs)

	if len(camps) != 2 {
		t.Fatalf("attendu 2 campagnes (1 partagée + 1 isolée), obtenu %d", len(camps))
	}
	// La plus grosse : 1.1.1.1 + 2.2.2.2, outil nuclei.
	top := camps[0]
	if len(top.Attaquants) != 2 || top.Attaquants[0] != "1.1.1.1" || top.Attaquants[1] != "2.2.2.2" {
		t.Errorf("campagne partagée attendue [1.1.1.1 2.2.2.2], obtenu %v", top.Attaquants)
	}
	if top.Outil != "nuclei" {
		t.Errorf("outil de campagne=%q ; attendu nuclei", top.Outil)
	}
	if top.Sondes != 6 {
		t.Errorf("sondes de campagne=%d ; attendu 6", top.Sondes)
	}
}

func TestConstruireProfils_IgnoreLignesCorrompues(t *testing.T) {
	log := "pas du json\n" + ligne("9.9.9.9", "/", "scanners", "detect", "") + "\n{bad"
	profs := construireProfils(strings.NewReader(log))
	if len(profs) != 1 || profs["9.9.9.9"] == nil {
		t.Fatalf("les lignes corrompues doivent être ignorées sans casser la relecture ; profs=%v", profs)
	}
}
