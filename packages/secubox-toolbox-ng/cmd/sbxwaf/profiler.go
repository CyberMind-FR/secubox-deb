// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Corrélateur d'attaquants / campagnes (#1070, phase D).
//
// Le journal `waf-threats.log` (NDJSON) est de la matière première : une ligne
// par événement, sans regroupement. On le relit pour :
//   1. bâtir un PROFIL par attaquant (clé IP pour l'instant, JA4 en phase E) :
//      séquence ordonnée des chemins sondés, outils identifiés, verdict, fenêtre.
//   2. calculer une SIGNATURE de workflow (empreinte de l'ensemble des chemins
//      normalisés + outil dominant) : deux attaquants qui sondent le même jeu de
//      chemins partagent la même signature.
//   3. CLUSTERISER par signature → campagnes = « même workflow depuis plusieurs
//      tentatives / plusieurs IP ».

var reChiffres = regexp.MustCompile(`\d+`)

// normaliserChemin réduit un chemin à sa FORME (minuscule, sans query, chiffres
// → #) pour que /user/12 et /user/98 comptent comme la même sonde.
func normaliserChemin(p string) string {
	p = strings.ToLower(p)
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	return reChiffres.ReplaceAllString(p, "#")
}

var rangVerdict = map[string]int{"detect": 0, "warning": 1, "banned": 2}

// AttackerProfile — profil agrégé d'un attaquant.
type AttackerProfile struct {
	Key        string   `json:"key"`
	Premier    string   `json:"premier"`
	Dernier    string   `json:"dernier"`
	Sondes     int      `json:"sondes"`
	Outils     []string `json:"outils,omitempty"`
	Categories []string `json:"categories"`
	Sequence   []string `json:"sequence"`
	Verdict    string   `json:"verdict"`
	Signature  string   `json:"signature"`
	// #1240 P0-A : intensité « negative space » de l'attaquant — combien de ses
	// sondes visent des ressources qui n'existent sur aucune conf normale
	// (Recon), dont combien de secrets/exécution/admin (HauteValeur). C'est
	// l'évidence qui fait passer « 185.x GET /.env » à « reconnaissance
	// automatisée ciblant des secrets exposés » (brief §21).
	Recon       int `json:"recon"`
	HauteValeur int `json:"haute_valeur"`
}

// Campaign — attaquants partageant la même signature de workflow.
type Campaign struct {
	Signature  string   `json:"signature"`
	Outil      string   `json:"outil,omitempty"`
	Attaquants []string `json:"attaquants"`
	Sondes     int      `json:"sondes"`
	Exemple    []string `json:"exemple_sequence"`
	// #1240 : sondes haute-valeur cumulées de la campagne — sépare un balayage
	// bruyant d'une campagne ciblant secrets/exécution.
	HauteValeur int `json:"haute_valeur"`
}

// CorrelationSummary — vue d'ensemble, campagnes triées par volume.
type CorrelationSummary struct {
	Attaquants int        `json:"attaquants"`
	Campagnes  []Campaign `json:"campagnes"`
}

const maxSequence = 60 // plafond de chemins mémorisés par attaquant

// construireProfils agrège les lignes du journal (dans l'ordre chronologique du
// fichier) en profils par IP.
func construireProfils(r io.Reader) map[string]*AttackerProfile {
	profs := map[string]*AttackerProfile{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var e logEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.ClientIP == "" {
			continue
		}
		// Clé = JA4 quand il est présent (#1070 phase E) : l'empreinte TLS
		// survit à la rotation d'IP, donc regroupe mieux un même attaquant que
		// l'IP seule. Repli sur l'IP sinon.
		clé := e.ClientIP
		if e.JA4 != "" {
			clé = e.JA4
		}
		p := profs[clé]
		if p == nil {
			p = &AttackerProfile{Key: clé, Premier: e.Timestamp}
			profs[clé] = p
		}
		p.Sondes++
		p.Dernier = e.Timestamp
		if rangVerdict[e.Action] > rangVerdict[p.Verdict] {
			p.Verdict = e.Action
		}
		ajouterDistinct(&p.Categories, e.Category)
		if e.Tool != "" {
			ajouterDistinct(&p.Outils, e.Tool)
		}
		// Intensité « negative space » (#1240) : l'étiquette est posée par le
		// journal (threatlog.go) uniquement sur les sondes de reconnaissance.
		if e.NegativeSpace != "" {
			p.Recon++
			if e.NegativeSpace == pathHighValueProbe {
				p.HauteValeur++
			}
		}
		if len(p.Sequence) < maxSequence {
			p.Sequence = append(p.Sequence, normaliserChemin(e.Path))
		}
	}
	for _, p := range profs {
		p.Signature = signatureWorkflow(p.Sequence, p.Outils)
	}
	return profs
}

func ajouterDistinct(liste *[]string, v string) {
	for _, x := range *liste {
		if x == v {
			return
		}
	}
	*liste = append(*liste, v)
}

// signatureWorkflow : empreinte stable de l'ENSEMBLE des chemins normalisés
// (ordre indifférent, robuste aux réordonnancements) + outil dominant. Deux
// attaquants menant le même balayage obtiennent la même signature.
func signatureWorkflow(sequence, outils []string) string {
	ens := map[string]bool{}
	for _, c := range sequence {
		ens[c] = true
	}
	chemins := make([]string, 0, len(ens))
	for c := range ens {
		chemins = append(chemins, c)
	}
	sort.Strings(chemins)
	h := sha1.Sum([]byte(strings.Join(chemins, "\n") + "\x00" + strings.Join(outils, ",")))
	return hex.EncodeToString(h[:8])
}

// clusteriser regroupe les profils par signature en campagnes (≥1 attaquant),
// triées par nombre de sondes décroissant.
func clusteriser(profs map[string]*AttackerProfile) []Campaign {
	parSig := map[string]*Campaign{}
	for _, p := range profs {
		c := parSig[p.Signature]
		if c == nil {
			c = &Campaign{Signature: p.Signature, Exemple: p.Sequence}
			if len(p.Outils) > 0 {
				c.Outil = p.Outils[0]
			}
			parSig[p.Signature] = c
		}
		c.Attaquants = append(c.Attaquants, p.Key)
		c.Sondes += p.Sondes
		c.HauteValeur += p.HauteValeur
		if c.Outil == "" && len(p.Outils) > 0 {
			c.Outil = p.Outils[0]
		}
	}
	out := make([]Campaign, 0, len(parSig))
	for _, c := range parSig {
		sort.Strings(c.Attaquants)
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Sondes != out[j].Sondes {
			return out[i].Sondes > out[j].Sondes
		}
		return out[i].Signature < out[j].Signature
	})
	return out
}

// CorrélerMenaces lit le journal et renvoie la synthèse des campagnes.
func CorrélerMenaces(chemin string) (CorrelationSummary, error) {
	f, err := os.Open(chemin)
	if err != nil {
		return CorrelationSummary{}, err
	}
	defer f.Close()
	profs := construireProfils(f)
	return CorrelationSummary{
		Attaquants: len(profs),
		Campagnes:  clusteriser(profs),
	}, nil
}
