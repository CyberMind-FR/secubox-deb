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

// LE HALL DE CETTE BOX (#1725). Les politiques figeaient hall.gk2 : sur gk3,
// radio.gk3 refusait d'être encadrée par hall.gk3, son propre Hall. Le domaine
// suit secubox_core.auth.domaine_box() : [global] domain, sinon
// [api] sso_cookie_domain (gk2 n'a que celui-ci) — /etc/secubox/secubox.conf,
// relu au plus toutes les 30 s ; inconnu ou invalide = rien (jamais de joker).
var fichierConfBox = "/etc/secubox/secubox.conf"

var nomDomaine = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

var confBox struct {
	sync.Mutex
	lu  time.Time
	dom string
}

// domaineBox rend le domaine de la box (« gk3.secubox.in »), ou "".
func domaineBox() string {
	confBox.Lock()
	defer confBox.Unlock()
	if time.Since(confBox.lu) < 30*time.Second && !confBox.lu.IsZero() {
		return confBox.dom
	}
	confBox.lu = time.Now()
	confBox.dom = ""
	b, err := os.ReadFile(fichierConfBox)
	if err != nil {
		return ""
	}
	global, cookie := "", ""
	section := ""
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "[") {
			section = strings.Trim(l, "[] ")
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		if i := strings.Index(v, "#"); i >= 0 {
			v = v[:i]
		}
		v = strings.ToLower(strings.TrimLeft(strings.Trim(strings.TrimSpace(v), `"'`), "."))
		switch {
		case section == "global" && strings.TrimSpace(k) == "domain" && global == "":
			global = v
		case section == "api" && strings.TrimSpace(k) == "sso_cookie_domain" && cookie == "":
			cookie = v
		}
	}
	for _, v := range []string{global, cookie} {
		if nomDomaine.MatchString(v) {
			confBox.dom = v
			break
		}
	}
	return confBox.dom
}

// origineBox rend « https://<prefixe>.<domaine de la box> », ou "".
func origineBox(prefixe string) string {
	if d := domaineBox(); d != "" {
		return "https://" + prefixe + "." + d
	}
	return ""
}

// hallDeLaBox rend « ␠https://hall.<domaine> » (espace en tête), ou "" — et
// rien quand c'est hall.gk2.secubox.in, déjà nommé en tête des politiques.
func hallDeLaBox() string {
	o := origineBox("hall")
	if o == "" || o == "https://hall.gk2.secubox.in" {
		return ""
	}
	return " " + o
}
