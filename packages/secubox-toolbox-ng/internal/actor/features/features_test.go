// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package features

import (
	"strings"
	"testing"
)

func TestPathShape(t *testing.T) {
	cas := []struct{ in, out string }{
		{"", "/"},
		{"/", "/"},
		{"/files/42", "/files/:id"},
		{"/files/1337?token=x", "/files/:id"},
		{"/API/Users/42/Files", "/api/users/:id/files"},
		{"/u/550e8400-e29b-41d4-a716-446655440000/p", "/u/:uuid/p"},
		{"/dl/deadbeefcafebabe1234", "/dl/:hex"},
		{"/s/AbCdEf0123456789_supersession-token", "/s/:tok"},
		{"index.php", "/index.php"}, // préfixe / ajouté
	}
	for _, c := range cas {
		if got := PathShape(c.in); got != c.out {
			t.Errorf("PathShape(%q) = %q, attendu %q", c.in, got, c.out)
		}
	}
	// Deux chemins de même grammaire produisent la même forme (pivot de corrélation).
	if PathShape("/files/1") != PathShape("/files/999999") {
		t.Error("deux ids devraient produire la même forme")
	}
	// Borne de longueur respectée.
	long := "/" + strings.Repeat("a", 400)
	if len(PathShape(long)) > MaxPathShape {
		t.Error("path_shape dépasse MaxPathShape")
	}
}

func TestUAFamily(t *testing.T) {
	cas := []struct{ in, out string }{
		{"", ""},
		{"Nuclei - Open-source project (github.com/projectdiscovery/nuclei)", "nuclei"},
		{"sqlmap/1.7", "sqlmap"},
		{"curl/8.5.0", "curl"},
		{"python-requests/2.31.0", "python"},
		{"Go-http-client/1.1", "go"},
		{"Mozilla/5.0 (X11; Linux x86_64) ... Chrome/128.0 Safari/537.36", "chrome"},
		{"Mozilla/5.0 ... Firefox/128.0", "firefox"},
		{"Mozilla/5.0 (compatible; Googlebot/2.1)", "crawler"},
		{"Mozilla/5.0 (unknown vendor build)", "browser-generic"},
		{"SomethingWeirdCustom/9", "other"},
	}
	for _, c := range cas {
		if got := UAFamily(c.in); got != c.out {
			t.Errorf("UAFamily(%q) = %q, attendu %q", c.in, got, c.out)
		}
	}
	// L'outil offensif prime sur le marqueur navigateur d'un UA usurpé.
	if UAFamily("Mozilla/5.0 sqlmap/1.7 Chrome/128") != "sqlmap" {
		t.Error("l'outil offensif devrait primer sur le navigateur")
	}
}
