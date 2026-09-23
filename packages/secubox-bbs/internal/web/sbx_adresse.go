// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: BBS — L'ADRESSE SE CONSULTE, ELLE NE SE COPIE PAS (#1361).
//
// L'adresse d'un membre venu de SBX OS est celle qu'il a déclarée à
// l'admission. Elle vit dans le registre des appareils, qui appartient au
// module d'accès.
//
// ON NE LA RECOPIE PAS DANS LA BASE DU BBS, et c'est la décision centrale.
// Copier créerait deux versions d'un même fait :
//
//   - elles divergent — quelqu'un corrige son adresse côté accès, le BBS
//     continue d'écrire à l'ancienne ;
//   - révoquer un appareil ne couperait plus rien : le BBS garderait sa copie
//     et continuerait de notifier quelqu'un qu'on vient d'écarter ;
//   - et l'adresse existerait à deux endroits à effacer le jour où il faut
//     l'effacer.
//
// En la RELISANT au moment d'envoyer, il n'y a qu'un propriétaire. Un appareil
// révoqué cesse d'être notifié sans qu'on ait rien à propager — l'absence de
// copie fait le travail que la propagation aurait mal fait.
//
// LE PRIX EST UNE LECTURE DE FICHIER PAR ENVOI. C'est un fichier local de
// quelques kilo-octets, lu au moment où l'on s'apprête à ouvrir une connexion
// SMTP : le coût est invisible à côté.
//
// POURQUOI UN FICHIER ET PAS UNE API. Le registre a été mis dans un fichier
// précisément pour que tout processus de la box puisse le lire (#1351) — un
// crochet en mémoire n'aurait servi qu'au processus qui l'installe. Le lire
// ici est l'usage prévu, pas un contournement.
package web

import (
	"encoding/json"
	"os"
	"strings"
)

// Le registre des appareils. Même chemin que `secubox_core.appareils`.
const registreAppareils = "/etc/secubox/appareils.json"

type appareilSbx struct {
	Compte string `json:"compte"`
	Nom    string `json:"nom"`
	Profil string `json:"profil"`
	Email  string `json:"email"`
	Actif  bool   `json:"actif"`
}

type registreSbx struct {
	Appareils []appareilSbx `json:"appareils"`
}

// adresseSbx rend l'adresse déclarée par ce compte, ou "" — inconnu, révoqué,
// ou simplement sans adresse (elle est facultative à l'admission).
//
// UN APPAREIL RÉVOQUÉ NE REND RIEN. C'est ici que la révocation prend effet
// pour les notifications, sans qu'aucun message n'ait eu à circuler.
func (s *Server) adresseSbx(compte string) string {
	compte = strings.ToLower(strings.TrimSpace(compte))
	if !strings.HasPrefix(compte, "sbx-") {
		// Les comptes qui ne viennent pas d'un appareil ne sont pas dans ce
		// registre : on ne cherche même pas.
		return ""
	}
	brut, err := os.ReadFile(registreAppareils)
	if err != nil {
		// Registre absent ou illisible : aucune adresse. Une notification qui
		// ne part pas vaut mieux qu'une qui part au mauvais endroit.
		return ""
	}
	var r registreSbx
	if json.Unmarshal(brut, &r) != nil {
		return ""
	}
	for _, a := range r.Appareils {
		if a.Compte == compte && a.Actif {
			return strings.TrimSpace(a.Email)
		}
	}
	return ""
}
