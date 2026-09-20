// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — repliage de chemin pour COMPARAISON
//
// NE PAS CONFONDRE avec `normaliserChemin` de profiler.go, qui réduit un chemin
// à sa FORME pour REGROUPER des sondes (chiffres → #, query jetée). Celui-ci
// replie un chemin pour le COMPARER aux motifs. Deux buts opposés : le premier
// perd volontairement de l'information pour rapprocher, le second en préserve
// le plus possible pour accuser. Les fusionner casserait les deux.
//
// POURQUOI CE FICHIER EXISTE
//
// `unquotePlus` décode UNE fois. Cela suffit pour l'écrasante majorité du
// trafic observé : `/%2eenv` devient `/.env`, que les motifs attrapent. Le
// journal de gk2 le confirme — les quatre seuls chemins pourcent-encodés
// observés étaient DÉJÀ attrapés après ce décodage unique.
//
// Un décodage unique laisse pourtant une famille ouverte, par construction :
//
//	%252e      → un tour donne "%2e", pas "." — le motif `\.env` ne voit rien
//	%25252e    → deux tours, même histoire
//	%c0%ae     → UTF-8 sur-long : deux octets bruts, pas un point
//
// Rien de tout cela n'a été MESURÉ sur gk2. Ce fichier est donc de la défense
// en profondeur, pas une réponse à une attaque constatée — et il est écrit
// avec la prudence que cela impose.
//
// LA RÈGLE QUI GOUVERNE TOUT CE FICHIER
//
// On normalise pour COMPARER, jamais pour TRANSMETTRE. Le chemin envoyé au
// backend reste celui qu'a demandé le client, octet pour octet. Confondre les
// deux changerait la sémantique des requêtes légitimes — `%2f` dans un
// identifiant de dépôt gitea n'est pas un séparateur, et le replier casserait
// l'URL. Aucune fonction d'ici ne touche à la requête transmise.
//
// COMMENT LE RISQUE DE RÉGRESSION EST ANNULÉ
//
// La variante normalisée est AJOUTÉE au texte scanné, elle ne remplace pas le
// décodage existant. Une correspondance qui passait hier passe encore
// aujourd'hui : on ne peut qu'ajouter des prises. C'est délibéré — le coût est
// quelques octets de plus à scanner, le bénéfice est qu'aucun réglage patiemment
// mesuré ne peut être cassé par ce fichier.

package main

import (
	"net/url"
	"strings"
)

// profondeurDecodage borne le nombre de passes de décodage.
//
// POURQUOI UNE BORNE. Décoder jusqu'au point fixe sans limite est une primitive
// de déni de service : `%25%32%35...` répété fabrique une chaîne qui redonne du
// travail à chaque tour, et l'attaquant choisit la longueur. La borne rend le
// coût constant et connu.
//
// POURQUOI TROIS. Un tour est le comportement actuel. Deux couvrent `%252e`,
// le seul encodage double qu'on rencontre réellement dans les outils de scan.
// Trois donnent une marge sans ouvrir la porte. Au-delà, on ne défend plus
// contre un attaquant : on lui prête du calcul.
const profondeurDecodage = 3

// replierChemin replie un chemin vers la forme sur laquelle les motifs
// doivent raisonner. Décodage répété borné, puis repliage des séparateurs.
//
// Elle est volontairement TOLÉRANTE : un encodage malformé n'est pas une erreur
// à signaler, c'est le cas normal quand on inspecte du trafic hostile. On garde
// alors le meilleur résultat obtenu jusque-là.
func replierChemin(s string) string {
	if s == "" {
		return s
	}

	courant := strings.ReplaceAll(s, "+", " ")

	// Décodage jusqu'au point fixe, borné. On s'arrête dès qu'un tour ne change
	// plus rien : c'est le cas de la quasi-totalité du trafic, qui ne paie donc
	// qu'une seule passe.
	for i := 0; i < profondeurDecodage; i++ {
		suivant, err := url.PathUnescape(courant)
		if err != nil {
			// Pourcent-encodage malformé — `%zz`, `%` en fin de chaîne. C'est
			// fréquent et souvent délibéré. On garde ce qu'on a.
			break
		}
		if suivant == courant {
			break
		}
		courant = suivant
	}

	return replierSeparateurs(courant)
}

// replierSeparateurs réduit `//` à `/` et supprime les segments `/./`.
//
// POURQUOI SÉPARÉMENT DU DÉCODAGE. Le repliage doit venir APRÈS, parce que
// c'est le décodage qui fait apparaître les séparateurs cachés : `/%2f/` ne
// devient `//` qu'une fois décodé.
//
// CE QUE CETTE FONCTION NE FAIT PAS. Elle ne résout pas `..`. Remonter les
// segments parents est le travail d'un routeur, et le faire ici DÉTRUIRAIT de
// l'information : `/a/../../etc/passwd` se replierait en `/etc/passwd` et on
// perdrait la trace du `..` — or c'est précisément le `..` qui signe la
// traversée que les motifs cherchent. On replie ce qui masque, on garde ce qui
// accuse.
func replierSeparateurs(s string) string {
	// Sortie rapide : le trafic ordinaire n'a rien à replier et ne doit pas
	// payer la boucle. Les trois formes doivent y figurer — `/admin/.` vaut
	// `/admin/` et se replie, même sans `//` ni `/./` dans la chaîne.
	if !strings.Contains(s, "//") && !strings.Contains(s, "/./") && !strings.HasSuffix(s, "/.") {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '/' {
			// Absorbe la suite de séparateurs et les segments « . » qu'ils
			// encadrent, en n'émettant qu'un seul '/'.
			for i+1 < len(s) {
				if s[i+1] == '/' {
					i++
					continue
				}
				// « /./ » — et « /. » en fin de chaîne.
				if s[i+1] == '.' && (i+2 == len(s) || s[i+2] == '/') {
					i += 2
					continue
				}
				break
			}
		}
		b.WriteByte(c)
	}

	return b.String()
}

// varianteNormalisee rend la forme normalisée de s, ou "" si elle n'apporte
// rien de neuf.
//
// Le "" est le cas NORMAL : le trafic légitime n'est ni doublement encodé ni
// truffé de séparateurs superflus, donc il ne produit aucune variante et ne
// coûte rien au scan. Seules les requêtes qui se cachent paient le supplément —
// ce qui est l'ordre des choses souhaitable.
func varianteNormalisee(s, dejaDecode string) string {
	n := replierChemin(s)
	if n == dejaDecode || n == "" {
		return ""
	}
	return n
}
