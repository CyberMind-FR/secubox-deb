// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

// HALLS DU PARC (#1672) : les Halls des nœuds relayés par cette box
// (hall.gk3.secubox.in…) peuvent encadrer ce service, comme le Hall de la box
// elle-même. La liste est tenue par `secubox-halls-parc` ; relue au plus toutes
// les 30 s. Une ligne qui n'est pas une origine https stricte est ignorée : un
// espace ou un `;` couperait la politique en deux. Jamais de joker.

import (
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var fichierHallsParc = "/var/lib/secubox/halls-parc/origines.txt"

var origineHall = regexp.MustCompile(`^https://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

var hallsParc struct {
	sync.Mutex
	lu  time.Time
	val string
}

// hallsDuParc rend « ␠origine1␠origine2 » (espace en tête), ou "".
func hallsDuParc() string {
	hallsParc.Lock()
	defer hallsParc.Unlock()
	if time.Since(hallsParc.lu) < 30*time.Second && !hallsParc.lu.IsZero() {
		return hallsParc.val
	}
	hallsParc.lu = time.Now()
	b, err := os.ReadFile(fichierHallsParc)
	if err != nil {
		hallsParc.val = ""
		return ""
	}
	var out strings.Builder
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if origineHall.MatchString(l) {
			out.WriteString(" " + l)
		}
	}
	hallsParc.val = out.String()
	return hallsParc.val
}
