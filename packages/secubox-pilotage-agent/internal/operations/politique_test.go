// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package operations

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// TestPolitiqueAdmin : `sudo -n secubox-pilotagectl politique pilotage-admin` ; admin seulement sur un
// {"autorise": true} net, tout le reste (erreur, sortie bancale, refus) vaut lecture.
func TestPolitiqueAdmin(t *testing.T) {
	for _, cas := range []struct {
		sortie string
		err    error
		admin  bool
	}{
		{`{"autorise": true, "consentement": false, "raison": "box du propriétaire"}`, nil, true},
		{`{"autorise": false, "consentement": false, "raison": "box cliente : support non ouvert"}`, nil, false},
		{`{"autorise": "true"}`, nil, false},
		{`{"autorise": true} {"autorise": true}`, nil, false},
		{`pas du json`, nil, false},
		{`{"autorise": true}`, errors.New("rc 1"), false},
	} {
		var argv []string
		ctl := func(_ context.Context, a ...string) ([]byte, error) {
			argv = a
			return []byte(cas.sortie + "\n"), cas.err
		}
		if got := PolitiqueAdmin(ctl)(context.Background()); got != cas.admin {
			t.Fatalf("%q : admin=%v attendu", cas.sortie, cas.admin)
		}
		if want := []string{"-n", CheminCtl, "politique", "pilotage-admin"}; !reflect.DeepEqual(argv, want) {
			t.Fatalf("argv %v, attendu %v", argv, want)
		}
	}
}
