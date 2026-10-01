// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

// UNE SIGNATURE VALIDE NE SUFFIT PAS (#1814). Vérifier seulement signature et
// expiration laissait une session DÉCONNECTÉE ou RÉVOQUÉE valable ici jusqu'à
// son terme (jusqu'à 7 jours), et un jeton d'INTENTION (second facteur en
// cours) passait pour une session. Même règle que secubox_core.sessions :
//   - jeton avec `jti` → vivant dans le registre de secubox-auth ;
//   - jeton sans `jti` → seulement un jeton de SERVICE de la flotte (`iss`
//     connu), de courte durée ;
//   - `scope` présent → refusé.
// Le registre est relu seulement quand il change (mtime + taille) ; illisible
// ou absent, plus aucune session ne passe (échec fermé).

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// serviceTTLMax : durée de vie maximale d'un jeton de service sans session.
const serviceTTLMax = 10 * 60

var (
	registreMu    sync.Mutex
	registreStamp string
	registreIDs   map[string]bool
)

func cheminRegistre() string {
	if p := os.Getenv("SECUBOX_AUTH_SESSIONS"); p != "" {
		return p
	}
	return "/var/lib/secubox/auth/sessions.json"
}

func jtiVivant(jti string) bool {
	p := cheminRegistre()
	st, err := os.Stat(p)
	if err != nil {
		return false
	}
	stamp := fmt.Sprintf("%s|%d|%d", p, st.ModTime().UnixNano(), st.Size())
	registreMu.Lock()
	defer registreMu.Unlock()
	if stamp != registreStamp {
		ids := map[string]bool{}
		if brut, err := os.ReadFile(p); err == nil {
			var lignes []map[string]any
			if json.Unmarshal(brut, &lignes) == nil {
				for _, l := range lignes {
					if id, ok := l["id"].(string); ok && id != "" {
						ids[id] = true
					}
				}
			}
		}
		registreStamp, registreIDs = stamp, ids
	}
	return registreIDs[jti]
}

// controleSession applique la règle ci-dessus aux revendications d'un jeton
// dont la signature et l'expiration sont DÉJÀ vérifiées.
func controleSession(cl map[string]any, emetteurs map[string]bool) error {
	if sc, ok := cl["scope"]; ok && sc != nil && sc != "" {
		return errors.New("jeton d'intention, pas une session")
	}
	if jti, _ := cl["jti"].(string); jti != "" {
		if !jtiVivant(jti) {
			return errors.New("session terminée")
		}
		return nil
	}
	iss, _ := cl["iss"].(string)
	iat, _ := cl["iat"].(float64)
	exp, _ := cl["exp"].(float64)
	if emetteurs[iss] && iat > 0 && exp-iat > 0 && exp-iat <= serviceTTLMax {
		return nil
	}
	return errors.New("jeton sans session")
}
