// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package main

import "strings"

// corpsBinaire dit si le corps d'une requete est un flux d'octets sur lequel
// les regles TEXTUELLES du WAF n'ont aucun sens.
//
// POURQUOI S'ABSTENIR PLUTOT QUE JUGER. Les regles cherchent des motifs de
// texte — une commande shell, une injection SQL, un chemin traverse. Appliquees
// aux octets d'un JPEG, elles trouvent ces motifs par pur hasard : une photo de
// quelques megaoctets contient statistiquement n'importe quelle courte suite.
//
// Le 2026-08-17, l'envoi d'une image depuis l'application Mastodon d'un
// telephone a ete classe « rce / critical » et bloque, alors que le meme envoi
// depuis un navigateur passait — le navigateur retravaille l'image et poste sur
// une autre route, l'application poste le fichier brut de l'appareil photo.
// C'etait un faux positif sur des donnees binaires, pas une attaque.
//
// Le defaut est aggrave par la troncature : l'inspection s'arrete a 1 Mio et
// juge sur un fragment coupe au milieu du binaire. sbxwaf le SAIT — il
// journalise « body-inspect-truncated » — et devrait en tirer la consequence.
//
// CE QUI RESTE INSPECTE. Tout le reste : methode, chemin, parametres,
// user-agent, origine, debit, reputation de l'adresse. On ne retire pas l'hote
// du WAF, on cesse seulement de chercher du texte dans une image.
func corpsBinaire(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if ct == "" {
		return false
	}
	// Un envoi de fichier : le corps est domine par les octets du fichier.
	if ct == "multipart/form-data" {
		return true
	}
	// Les familles binaires. `application/*` n'est PAS inclus en bloc : il
	// couvre aussi json, xml et x-www-form-urlencoded, qui sont du texte et
	// doivent rester inspectes.
	for _, p := range []string{"image/", "video/", "audio/", "font/"} {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	switch ct {
	case "application/octet-stream", "application/pdf", "application/zip",
		"application/gzip", "application/x-tar", "application/x-7z-compressed":
		return true
	}
	return false
}
