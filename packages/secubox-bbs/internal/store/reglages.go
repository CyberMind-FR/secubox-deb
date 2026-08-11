// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Reglages cle/valeur poses par le sysop depuis l'interface (#1008).
//
// POURQUOI PAS DANS LE TOML. Le lien d'invitation Mastodon change au gre des
// invitations creees dans Mastodon. Un conffile le ferait ressortir a chaque
// mise a jour du paquet comme une modification locale a arbitrer, et obligerait
// a passer par un shell root pour une valeur que le sysop doit pouvoir coller
// depuis son navigateur.
package store

import (
	"net/url"
	"strings"
)

// Cles connues. Declarees ici plutot qu'en litteral disperse : une faute de
// frappe dans un appel rendrait une valeur vide sans rien signaler.
const (
	CleMastodonInvite   = "mastodon.invitation"
	CleMastodonInstance = "mastodon.instance"
)

// Reglage lit une valeur. Une cle absente rend la chaine vide sans erreur :
// l'appelant affiche alors l'etat « non configure », qui n'est pas une panne.
func (s *Store) Reglage(cle string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT valeur FROM reglages WHERE cle = ?`, cle).Scan(&v)
	if err != nil && err.Error() == "sql: no rows in result set" {
		return "", nil
	}
	return v, err
}

// PoseReglage ecrit une valeur, ou l'efface si elle est vide.
//
// Effacer plutot que stocker une chaine vide : sans cela, « retirer le lien »
// laisserait une ligne que `Reglage` rendrait comme une valeur posee, et
// l'interface afficherait un lien vide au lieu de l'etat « non configure ».
func (s *Store) PoseReglage(cle, valeur string) error {
	valeur = strings.TrimSpace(valeur)
	if valeur == "" {
		_, err := s.db.Exec(`DELETE FROM reglages WHERE cle = ?`, cle)
		return err
	}
	_, err := s.db.Exec(
		`INSERT INTO reglages(cle, valeur, maj_at) VALUES(?,?,unixepoch())
		 ON CONFLICT(cle) DO UPDATE SET valeur = excluded.valeur, maj_at = excluded.maj_at`,
		cle, valeur)
	return err
}

// LienExterneValide n'accepte que http(s) et exige un hote.
//
// Le lien est colle par le sysop puis rendu dans un href affiche a tous les
// membres. Sans ce filtre, un `javascript:` colle par erreur — ou par quelqu'un
// ayant obtenu une session sysop — deviendrait un lien actif sur chaque page du
// module. Le refus est pose au STOCKAGE et pas seulement au rendu : une valeur
// invalide ne doit jamais atteindre la base.
func LienExterneValide(brut string) bool {
	brut = strings.TrimSpace(brut)
	if brut == "" {
		return false
	}
	u, err := url.Parse(brut)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return u.Host != ""
}
