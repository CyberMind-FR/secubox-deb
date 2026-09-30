// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

// LES SERVICES DU PARC (#1727). L'unité figeait radio, billets, peertube,
// podcaster, socialrelay et metanews de gk2 : sur gk3, le BBS ignorait les
// siens. Avec --parc, chaque service consommé que l'unité ne précise pas
// devient celui de CETTE box si son paquet y est installé, sinon celui du nœud
// de référence du maillage — la règle de secubox_core.auth.hote_parc. Les
// listes d'origines autorisées gardent EN PLUS la référence : un fil fédéré
// de gk2 peut porter ses médias.

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/web"
)

const reference = "gk2.secubox.in"

var (
	dpkgInfo   = "/var/lib/dpkg/info"
	origineBox = web.OrigineBox // substituable par les tests
)

type service struct{ prefixe, paquet string }

var (
	sPeertube    = service{"peertube", "secubox-peertube"}
	sRadio       = service{"radio", "secubox-radio"}
	sPodcaster   = service{"podcaster", "secubox-podcaster"}
	sBillets     = service{"billets", "secubox-billets"}
	sSocialrelay = service{"socialrelay", "secubox-socialrelay"}
	sMetanews    = service{"metanews", "secubox-metanews"}
)

func (s service) reference() string { return "https://" + s.prefixe + "." + reference }

// origine : le service de CETTE box si son paquet y est installé, sinon la référence.
func (s service) origine() string {
	if _, err := os.Stat(filepath.Join(dpkgInfo, s.paquet+".list")); err == nil {
		if o := origineBox(s.prefixe); o != "" {
			return o
		}
	}
	return s.reference()
}

// liste : l'origine retenue de chaque service, plus sa référence si elle diffère.
func liste(services ...service) string {
	var out []string
	vu := map[string]bool{}
	for _, s := range services {
		for _, o := range []string{s.origine(), s.reference()} {
			if !vu[o] {
				vu[o] = true
				out = append(out, o)
			}
		}
	}
	return strings.Join(out, ",")
}

// appliquerParc remplit les options de services consommés que la ligne de
// commande n'a PAS données (`donnees`) ; une option explicite prime toujours.
func appliquerParc(donnees map[string]bool, opts map[string]*string) {
	valeurs := map[string]func() string{
		"peertube-origine": sPeertube.origine,
		"radio-base":       sRadio.origine,
		"billets-base":     sBillets.origine,
		"metanews-base":    sMetanews.origine,
		"media-origines": func() string {
			return liste(sPeertube, sRadio, sPodcaster, sBillets, sSocialrelay)
		},
		"frame-origines": func() string { return liste(sRadio, sPodcaster) },
	}
	for nom, v := range valeurs {
		if p, ok := opts[nom]; ok && p != nil && !donnees[nom] {
			*p = v()
		}
	}
}
