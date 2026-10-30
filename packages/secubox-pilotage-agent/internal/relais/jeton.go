// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Paquet relais : relais local `sbx-pilotage-relais` d'une box légère (#3126 L5, tâche 2).
//
// L'agent de pilotage lui remet, par la socket /run/secubox/pilotage-relais.sock, un appel
// `/api/v1/<module>/…` venu d'une page servie par le maître. Le relais frappe un jeton DÉLÉGUÉ
// Ed25519 de 30 s (R-L5-9) et appelle la socket du module, comme nginx ou l'agrégateur. Le
// vérificateur est `secubox_core.auth` (`_porteur_pilotage`, `_forme_pilotage`) : ce fichier
// en suit le contrat à la lettre.
package relais

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"time"
)

// DureeJeton : exp - iat (le vérificateur accepte ≤ 60 s).
const DureeJeton = 30 * time.Second

// enteteJeton : fixe, jamais de kid/jku/jwk (le vérificateur lit la clé à un chemin fixe).
const enteteJeton = `{"alg":"EdDSA","typ":"JWT"}`

// Motifs de secubox_core.auth (_RE_NOM_BOX, _RE_MODULE, _RE_ACTEUR, _RE_MAITRE), en fullmatch.
var (
	reNomBox = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	reModule = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	reActeur = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
	reMaitre = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)
	// Avant normalisation : mêmes classes, majuscules ASCII admises (rien d'autre n'est converti).
	reActeurBrut = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	reMaitreBrut = regexp.MustCompile(`^[A-Za-z0-9-]{1,63}$`)
)

// nomDeBox : même règle que nom_box_locale() de secubox_core.auth —
// gethostname().split(".")[0].strip().lower(), puis motif d'un nom d'hôte ; "" sinon.
func nomDeBox(hote string) string {
	nom := strings.ToLower(strings.TrimSpace(strings.SplitN(hote, ".", 2)[0]))
	if !reNomBox.MatchString(nom) {
		return ""
	}
	return nom
}

// NomBoxLocale : le nom de cette box, relu à chaque appel (secubox-renommer change l'hôte sans
// redémarrer le relais). os.Hostname lit /proc/sys/kernel/hostname, comme gethostname().
func NomBoxLocale() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return nomDeBox(h)
}

// minusculesASCII : seules A-Z sont converties (jamais un caractère Unicode qui « deviendrait » ASCII).
func minusculesASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// Normaliser : acteur et maître mis en minuscules (ASCII), puis REFUSÉS — jamais convertis — s'ils
// sortent des motifs du vérificateur (R-L5-14). Le maître suit la même règle (nom d'hôte, la casse
// n'y porte aucun sens).
func Normaliser(acteur, maitre string) (string, string, error) {
	if !reActeurBrut.MatchString(acteur) {
		return "", "", errors.New("acteur invalide")
	}
	if !reMaitreBrut.MatchString(maitre) {
		return "", "", errors.New("maitre invalide")
	}
	return minusculesASCII(acteur), minusculesASCII(maitre), nil
}

type reclamation struct {
	Acteur string `json:"acteur"`
	Maitre string `json:"maitre"`
	Portee string `json:"portee"`
}

// charge : exactement les réclamations du jeton délégué ; ni scope, ni plafond, ni délégation, ni jti.
type charge struct {
	Sub      string      `json:"sub"`
	Aud      string      `json:"aud"`
	Iat      int64       `json:"iat"`
	Exp      int64       `json:"exp"`
	Cible    string      `json:"cible"`
	Pilotage reclamation `json:"pilotage"`
}

// Frapper rend le jeton délégué compact (JWS EdDSA). Les valeurs sont revalidées ici : un appelant
// ne peut pas frapper un jeton que le vérificateur refuserait pour sa forme.
func Frapper(cle ed25519.PrivateKey, box, cible, acteur, maitre, portee string, maintenant time.Time) (string, error) {
	switch {
	case len(cle) != ed25519.PrivateKeySize:
		return "", errors.New("cle invalide")
	case !reNomBox.MatchString(box):
		return "", errors.New("nom de box invalide")
	case !reModule.MatchString(cible):
		return "", errors.New("cible invalide")
	case !reActeur.MatchString(acteur):
		return "", errors.New("acteur invalide")
	case !reMaitre.MatchString(maitre):
		return "", errors.New("maitre invalide")
	case portee != "lecture" && portee != "admin":
		return "", errors.New("portee invalide")
	}
	iat := maintenant.Unix()
	c := charge{
		Sub: "pilotage:" + acteur + "@" + maitre, Aud: box, Iat: iat, Exp: iat + int64(DureeJeton/time.Second),
		Cible: cible, Pilotage: reclamation{Acteur: acteur, Maitre: maitre, Portee: portee},
	}
	p, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signe := base64.RawURLEncoding.EncodeToString([]byte(enteteJeton)) + "." + base64.RawURLEncoding.EncodeToString(p)
	return signe + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(cle, []byte(signe))), nil
}
