// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package billets

import (
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// AdresseLocale rend l'adresse publique d'un billet en LISANT sa base.
//
// POURQUOI PAS L'API. La surface admin de billets exige un jeton porteur d'un
// `jti` adosse a une session enregistree : un outil en ligne de commande ne
// peut pas en forger un, et c'est voulu — un secret de signature ne doit pas
// suffire a se faire passer pour une session ouverte. Une premiere version
// forgeait un JWT et se faisait refuser, ce qui etait le comportement CORRECT
// de billets.
//
// La lecture directe suit un chemin deja etabli ici : le BBS lit de la meme
// facon la base du podcaster. LECTURE SEULE, mode `ro` dans l'URI — un outil
// de rattrapage n'a aucune raison de pouvoir ecrire chez le voisin, et
// l'ouverture en lecture seule le garantit plutot que de le promettre.
func AdresseLocale(cheminDB, base, billetID string) (string, error) {
	db, err := sql.Open("sqlite", "file:"+cheminDB+"?mode=ro")
	if err != nil {
		return "", err
	}
	defer db.Close()

	var slug string
	err = db.QueryRow(`SELECT slug FROM billet WHERE id = ?`, billetID).Scan(&slug)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("billet %s absent de %s", billetID, cheminDB)
	}
	if err != nil {
		return "", err
	}
	if slug == "" {
		return "", fmt.Errorf("billet %s sans slug", billetID)
	}

	// ON NE FABRIQUE PAS D'HOTE. Sans base publique connue, un chemin relatif
	// est vrai ; un `https://quelque-chose/b/slug` invente serait un lien mort
	// presente comme bon, et la page Billets sait deja dire « adresse
	// manquante », ce qui est plus honnete.
	b := strings.TrimRight(base, "/")
	if b == "" {
		return "/b/" + slug, nil
	}
	return b + "/b/" + slug, nil
}
