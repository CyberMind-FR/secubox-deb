// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package cluster : regroupement heuristique d'articles en ÉVÉNEMENTS. Sans
// LLM : similarité de titres + entités partagées + fraîcheur. Un seuil décide
// si un article rejoint un sujet existant ou en ouvre un nouveau.
package cluster

import (
	"sort"
	"strings"
)

// Seuil : au-dessus, l'article rejoint le sujet ; en dessous, nouveau sujet.
// Les titres du même événement partagent souvent PEU de mots (formulations
// différentes) ; ce sont les ENTITÉS partagées qui portent le signal — d'où un
// poids fort sur elles (§Score) et un seuil bas mais discriminant.
const Seuil = 0.30

// FenetreSec : deux articles à plus de 36 h l'un de l'autre ne sont pas le même
// événement (garde temporelle du blocage).
const FenetreSec = 36 * 3600

var motsVides = map[string]bool{
	// FR
	"le": true, "la": true, "les": true, "un": true, "une": true, "des": true, "de": true, "du": true,
	"et": true, "ou": true, "à": true, "au": true, "aux": true, "en": true, "dans": true, "sur": true,
	"pour": true, "par": true, "avec": true, "sans": true, "sous": true, "ce": true, "cet": true, "cette": true,
	"ces": true, "son": true, "sa": true, "ses": true, "que": true, "qui": true, "quoi": true, "dont": true,
	"est": true, "sont": true, "a": true, "ont": true, "plus": true, "moins": true, "ne": true, "pas": true,
	// EN
	"the": true, "a2": true, "an": true, "of": true, "and": true, "or": true, "to": true, "in": true,
	"on": true, "for": true, "by": true, "with": true, "is": true, "are": true, "as": true, "at": true,
	"from": true, "that": true, "this": true, "it": true, "its": true, "be": true, "has": true, "have": true,
}

// Tokens : minuscule, découpe, mots vides et tokens courts retirés.
func Tokens(s string) []string {
	champs := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r >= 0x00C0 && r <= 0x024F)
	})
	var out []string
	for _, m := range champs {
		if len(m) < 3 || motsVides[m] {
			continue
		}
		out = append(out, m)
	}
	return out
}

// toutEnCapitales : un acronyme — au moins deux lettres, toutes majuscules.
func toutEnCapitales(s string) bool {
	n := 0
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 0x00E0 && r <= 0x00FF {
			return false
		}
		if r >= 'A' && r <= 'Z' || r >= 0x00C0 && r <= 0x00DE {
			n++
		}
	}
	return n >= 2
}

func ensemble(toks []string) map[string]bool {
	m := make(map[string]bool, len(toks))
	for _, t := range toks {
		m[t] = true
	}
	return m
}

// Jaccard : intersection / union de deux ensembles.
func Jaccard(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter := 0
	for k := range a {
		if b[k] {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

// SimTitres : similarité de deux titres (Jaccard des tokens + petit apport
// trigramme pour rattraper les variations morphologiques).
func SimTitres(a, b string) float64 {
	ja := Jaccard(ensemble(Tokens(a)), ensemble(Tokens(b)))
	tri := Jaccard(trigrammes(a), trigrammes(b))
	return 0.75*ja + 0.25*tri
}

func trigrammes(s string) map[string]bool {
	s = strings.ToLower(strings.Join(Tokens(s), " "))
	m := map[string]bool{}
	r := []rune(s)
	for i := 0; i+3 <= len(r); i++ {
		m[string(r[i:i+3])] = true
	}
	return m
}

// Entites : noms propres candidats — suites de mots Capitalisés (len ≥ 3),
// le premier mot du texte exclu (souvent capitalisé par convention). Rendues
// en minuscules pour la comparaison.
func Entites(s string) []string {
	mots := strings.Fields(s)
	vus := map[string]bool{}
	var out []string
	for i, m := range mots {
		net := strings.TrimFunc(m, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= 0x00C0 && r <= 0x024F)
		})
		if len([]rune(net)) < 3 {
			continue
		}
		r0 := []rune(net)[0]
		capital := r0 >= 'A' && r0 <= 'Z' || r0 >= 0x00C0 && r0 <= 0x00DE
		if !capital {
			continue
		}
		// LE PREMIER MOT N'EST PLUS EXCLU AVEUGLÉMENT (#1194d). On l'écartait
		// parce qu'un titre commence souvent par un mot capitalisé par
		// convention (« Nouvelle », « Selon »). Mais c'est aussi là que se
		// trouve l'entité qui PORTE le sujet — « BCE : … », « PSG : … » — et la
		// perdre faisait rater le regroupement d'articles pourtant identiques.
		// On ne garde en tête que les ACRONYMES (tout en capitales) : ce sont
		// presque toujours de vraies entités (BCE, PSG, NASA, OTAN), jamais un
		// « Le » ou un « Nouvelle » de début de phrase.
		if i == 0 && !toutEnCapitales(net) {
			continue
		}
		k := strings.ToLower(net)
		if motsVides[k] || vus[k] {
			continue
		}
		vus[k] = true
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Recence : 1 quand les dates sont proches, décroît linéairement jusqu'à 0 à
// FenetreSec.
func Recence(deltaSec int64) float64 {
	if deltaSec < 0 {
		deltaSec = -deltaSec
	}
	if deltaSec >= FenetreSec {
		return 0
	}
	return 1 - float64(deltaSec)/float64(FenetreSec)
}

// Score : proximité d'un article (titre, entités, date) avec un sujet (titre,
// entités, date de MAJ). Combine titre, entités, tags et fraîcheur.
func Score(titreA string, entA []string, pubA int64, titreT string, entT []string, majT int64) float64 {
	sTitre := SimTitres(titreA, titreT)
	sEnt := Jaccard(ensemble(entA), ensemble(entT))
	sRec := Recence(pubA - majT)

	// HORS FENÊTRE, JAMAIS LE MÊME ÉVÉNEMENT (#1194d).
	if sRec <= 0 {
		return 0
	}

	// GARDE DE CONTENU — la correction du mélange « tornade + préservatif ».
	//
	// Le même événement partage forcément quelque chose de CONCRET : une entité
	// (un lieu, une personne, une organisation) ou un titre très proche. Deux
	// articles aux entités DISJOINTES et aux titres éloignés ne sont pas le même
	// événement, même publiés à la même minute. Sans cette garde, deux sujets
	// sans aucun rapport se rejoignaient sur une coïncidence de vocabulaire.
	if sEnt == 0 && sTitre < 0.55 {
		return 0
	}

	// LA FRAÎCHEUR MODULE, ELLE NE CRÉE PAS. C'était le défaut de fond : elle
	// était ADDITIVE (0.20 acquis dès que deux articles étaient récents), si
	// bien qu'une similarité de contenu quasi nulle démarrait déjà à 0.20 et
	// qu'un seul token commun suffisait à franchir le seuil. Un événement récent
	// ET partagé le reste ; un événement récent SANS fond commun ne l'est pas.
	// On la passe donc en MULTIPLICATEUR : elle ne peut que réduire un score
	// déjà porté par le contenu (0.75 à 1.0 sur la fenêtre), jamais l'inventer.
	contenu := 0.35*sTitre + 0.65*sEnt
	return contenu * (0.75 + 0.25*sRec)
}

// Fusion : union triée de deux listes d'entités/tags.
func Fusion(a, b []string) []string {
	m := ensemble(a)
	for _, x := range b {
		m[x] = true
	}
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
