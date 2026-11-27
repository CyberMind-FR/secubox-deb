// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — bibliothèque figée de motifs (#4020)
//
// La bibliothèque (motifs tirés d'OWASP CRS et des modèles Nuclei, construits
// et rejoués côté dépôt, livrés figés dans secubox-waf-ng) arrive dans
// waf-rules.json comme des catégories `bib_<famille>` marquées
// `"bibliotheque": true`, en mode detect par défaut (identifier seulement).
// Ce fichier porte ce que le moteur en fait :
//
//   - un motif lit un CHAMP (chemin, requete, ua, corps) au lieu du texte
//     joint, ce qui rend ses ancres « ^…$ » exactes ;
//   - un motif « ^littéral$ » sur le chemin est rangé dans une table
//     (littéral → motif) : des milliers de chemins exacts coûtent une
//     consultation de table, pas des milliers de regex ;
//   - une touche est ÉTIQUETÉE `bib:<famille>:<techno>` dans waf-threats.log ;
//   - jamais appliquée sur un vhost qui héberge la techno visée
//     (hebergeTechno).
//
// Aucun moteur tiers : ce ne sont que des motifs RE2 évalués par sbxwaf.

package main

import (
	"net/http"
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
)

const (
	champTout uint8 = iota // texte joint historique (chemin requête corps ua)
	champChemin
	champRequete
	champUA
	champCorps
)

// champsMotif : valeurs admises de "champ" ; absent ou "" = texte joint.
var champsMotif = map[string]uint8{
	"":        champTout,
	"chemin":  champChemin,
	"requete": champRequete,
	"ua":      champUA,
	"corps":   champCorps,
}

// champsRequete : les champs d'une requête, décodés et en minuscules, et les
// variantes normalisées du chemin et de la requête ("" si aucune).
type champsRequete struct {
	chemin, cheminV, requete, requeteV, corps, ua string
	// donnees : règles courantes (mémo des UA) ; masque : verdicts des
	// motifs d'UA pour cette requête, lus une fois.
	donnees  *rulesData
	masque   uint64
	masqueOK bool
}

// touche évalue un motif lié à un champ.
func (c *champsRequete) touche(p compiledPattern) bool {
	switch p.champ {
	case champChemin:
		return p.re.MatchString(c.chemin) || (c.cheminV != "" && p.re.MatchString(c.cheminV))
	case champRequete:
		return (c.requete != "" && p.re.MatchString(c.requete)) || (c.requeteV != "" && p.re.MatchString(c.requeteV))
	case champUA:
		if p.uaBit >= 0 && c.donnees != nil {
			if !c.masqueOK {
				c.masque, c.masqueOK = c.donnees.memo.verdicts(c.ua, c.donnees.uaMotifs), true
			}
			return c.masque&(1<<uint(p.uaBit)) != 0
		}
		return p.re.MatchString(c.ua)
	case champCorps:
		return c.corps != "" && p.re.MatchString(c.corps)
	}
	return false
}

// litteralExact rend le littéral (minuscules) d'un motif de la forme
// « ^littéral$ » (regex échappée comprise), sinon ok=false. Seul un littéral
// complet entre les deux ancres de texte est retenu : la moindre classe,
// alternative ou répétition renvoie la regex à la boucle ordinaire.
func litteralExact(motif string) (string, bool) {
	re, err := syntax.Parse("(?i)"+motif, syntax.Perl)
	if err != nil {
		return "", false
	}
	re = re.Simplify()
	if re.Op != syntax.OpConcat || len(re.Sub) != 3 {
		return "", false
	}
	debut, lit, fin := re.Sub[0], re.Sub[1], re.Sub[2]
	if debut.Op != syntax.OpBeginText || fin.Op != syntax.OpEndText || lit.Op != syntax.OpLiteral {
		return "", false
	}
	return strings.ToLower(string(lit.Rune)), true
}

// infoBib : ce qu'un motif de la bibliothèque dit de lui-même.
type infoBib struct {
	famille, techno string
}

// nomBib : forme admise d'une famille ou d'une techno dans une étiquette.
func nomBib(s, defaut string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > 48 {
		return defaut
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return defaut
		}
	}
	return s
}

func (c *compiledCategory) bibInfo(id, famille, techno string) {
	if c.infos == nil {
		c.infos = map[string]infoBib{}
	}
	c.infos[id] = infoBib{famille: nomBib(famille, "autre"), techno: nomBib(techno, "generique")}
}

// InfoBibliotheque rend l'étiquette `bib:<famille>:<techno>` et la techno du
// motif touché, si (cat, id) est un motif de la bibliothèque.
func (r *Rules) InfoBibliotheque(cat, id string) (etiquette, techno string, ok bool) {
	if r == nil {
		return "", "", false
	}
	r.mu.RLock()
	cur := r.current
	r.mu.RUnlock()
	if cur == nil {
		return "", "", false
	}
	for _, c := range cur.cats {
		if c.id != cat {
			continue
		}
		if !c.data.bib {
			return "", "", false
		}
		i, trouve := c.data.infos[id]
		if !trouve {
			return "", "", false
		}
		return "bib:" + i.famille + ":" + i.techno, i.techno, true
	}
	return "", "", false
}

// hebergeTechno dit si ce vhost héberge la techno visée par un motif de la
// bibliothèque : une sonde WordPress sur un vrai WordPress n'est pas une
// sonde. Source d'abord : la déclaration par vhost des CMS hébergés
// (cms_vhosts de vhost_profiles.json, #4019). Repli : le service du vhost
// (vhosts : hôte → gitea, nextcloud…) comparé au nom de la techno. Aucun vhost
// déclaré → false (la règle s'applique, en identification seulement par
// défaut). « generique » n'est jamais hébergée. Récepteur nil-safe.
func (v *VhostProfiles) hebergeTechno(host, techno string) bool {
	if v == nil || techno == "" || techno == "generique" {
		return false
	}
	if v.hebergeCMS(host, techno) {
		return true
	}
	v.mu.RLock()
	service := v.hoteService[normaliserHote(host)]
	v.mu.RUnlock()
	return service != "" && strings.EqualFold(service, techno)
}

// bibliothequeEssaisMax borne les ré-évaluations quand plusieurs catégories
// de la bibliothèque visent une techno hébergée par ce vhost.
const bibliothequeEssaisMax = 4

// filtrerBibliotheque applique la règle de contexte de la bibliothèque à une
// touche : si le motif touché vient de la bibliothèque et vise une techno que
// ce vhost héberge, la requête est ré-évaluée sans cette catégorie (une autre
// règle, d'injection par exemple, garde sa prise). Rend la touche finale et
// son libellé de journal (bib:<famille>:<techno>, ou la catégorie).
func (s *Server) filtrerBibliotheque(r *http.Request, rawPath, body string, includeBlock bool,
	cat, sev, mode, motif string) (string, string, string, string, string, bool) {
	var exclure map[string]bool
	for essai := 0; essai < bibliothequeEssaisMax; essai++ {
		etiquette, techno, ok := s.rules.InfoBibliotheque(cat, motif)
		if !ok {
			return cat, sev, mode, motif, cat, true
		}
		if !s.vhostProfiles.hebergeTechno(r.Host, techno) {
			return cat, sev, mode, motif, etiquette, true
		}
		if exclure == nil {
			exclure = map[string]bool{}
			// Chemin légitime du service : la garde de Phase G a déjà
			// écarté les catégories supprimables, elles le restent.
			if s.vhostProfiles.estLegitime(r.Host, rawPath) {
				for c := range s.vhostProfiles.categoriesSupprimablesPour(r.Host) {
					exclure[c] = true
				}
			}
		}
		exclure[cat] = true
		var hit bool
		cat, sev, mode, motif, hit = s.rules.MatchDetail(r.Method, rawPath, r.URL.RawQuery, body,
			r.Header.Get("User-Agent"), includeBlock, exclure)
		if !hit {
			return "", "", "", "", "", false
		}
	}
	return "", "", "", "", "", false
}

// memoUABits : motifs d'UA mémoïsés au plus (un bit chacun) ; au-delà, ils
// sont évalués à chaque requête. memoUAMax : UA distinctes retenues ; la
// table pleine est VIDÉE (jamais de croissance sans fin sous une rafale d'UA
// forgées : on retombe alors au coût d'une regex, jamais pire).
const (
	memoUABits = 64
	memoUAMax  = 4096
)

// memoUA : UA (minuscules) → verdicts de tous les motifs d'UA. Les UA se
// répètent énormément ; la grande alternative de CRS 913100 coûte ~10–20 µs
// par évaluation au banc, une consultation de table quelques dizaines de ns.
type memoUA struct {
	mu sync.RWMutex
	m  map[string]uint64
}

func nouveauMemoUA() *memoUA { return &memoUA{m: map[string]uint64{}} }

func (m *memoUA) verdicts(ua string, motifs []*regexp.Regexp) uint64 {
	if len(motifs) == 0 {
		return 0
	}
	m.mu.RLock()
	v, ok := m.m[ua]
	m.mu.RUnlock()
	if ok {
		return v
	}
	for i, re := range motifs {
		if re.MatchString(ua) {
			v |= 1 << uint(i)
		}
	}
	if len(ua) <= 512 {
		m.mu.Lock()
		if len(m.m) >= memoUAMax {
			m.m = map[string]uint64{}
		}
		m.m[ua] = v
		m.mu.Unlock()
	}
	return v
}
