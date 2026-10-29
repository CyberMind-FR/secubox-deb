// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package operations

import (
	"reflect"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/notifs"
)

// TestLireEtat : sortie du verbe de lecture `etat` du ctl. Fermé par défaut : toute forme inattendue est une erreur
// (aucune notification) ; un consentement ou un support aux champs hors motif aussi.
func TestLireEtat(t *testing.T) {
	ok := `{"ok": true, "box": "gk5", "mains_liees": true, "canal": "wg-mesh",
	  "consentements": [{"id": "0123456789abcdef", "action": "reboot", "etat": "accepte", "cree": 1, "expire": 2}],
	  "support": {"id": "s-01", "etat": "ouvert", "duree_min": 30, "cree": 1, "expire": 2, "ouvert": 3, "fin": 4}}`
	e, err := LireEtat([]byte(ok + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := notifs.EtatLocal{MainsLiees: true, Consentements: []notifs.Consentement{{ID: "0123456789abcdef", Etat: "accepte"}},
		Support: &notifs.Support{ID: "s-01", Etat: "ouvert"}}
	if !reflect.DeepEqual(e, want) {
		t.Fatalf("%+v, attendu %+v", e, want)
	}
	if e, err := LireEtat([]byte(`{"ok": true, "mains_liees": false, "consentements": [], "support": null}`)); err != nil ||
		e.Support != nil || e.MainsLiees {
		t.Fatalf("%+v %v", e, err)
	}
	for _, mauvais := range []string{
		``,
		`{"ok": false, "erreur": "état non fiable"}`,
		`{"ok": true}`,
		`{"ok": true, "mains_liees": "oui", "consentements": [], "support": null}`,
		`{"ok": true, "mains_liees": false, "consentements": [{"id": "../x", "etat": "accepte"}], "support": null}`,
		`{"ok": true, "mains_liees": false, "consentements": [{"id": "0123456789abcdef", "etat": "peut-etre"}], "support": null}`,
		`{"ok": true, "mains_liees": false, "consentements": [], "support": {"id": "S 1", "etat": "ouvert"}}`,
		`{"ok": true, "mains_liees": false, "consentements": [], "support": {"id": "s-1", "etat": "grand-ouvert"}}`,
		`{"ok": true, "mains_liees": false, "consentements": [], "support": null} {"ok": true}`,
	} {
		if _, err := LireEtat([]byte(mauvais)); err == nil {
			t.Errorf("%q : erreur attendue", mauvais)
		}
	}
}
