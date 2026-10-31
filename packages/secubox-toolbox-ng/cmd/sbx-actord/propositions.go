// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"crypto/sha256"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/response"
)

// Propositions de blocage (RFC-0013 §8, phase 2).
//
// actord ne bloque RIEN lui-même (aucune capacité, shadow) : il PUBLIE, pour les seuls acteurs que son moteur de réponse range à DENY ou
// QUARANTINE, la liste des adresses à bloquer, avec la raison et la durée. Un consommateur qui a le droit d'agir (sbxwaf, qui a déjà le
// ban nft) les relit et décide, avec ses propres garde-fous. Une faible confiance ne produit JAMAIS de proposition (voir response.Recommend).

// Proposition est un acteur dont la réponse recommandée est un blocage temporaire.
type Proposition struct {
	Actor      string   `json:"actor"`
	Mode       string   `json:"mode"`
	Raison     string   `json:"raison"`
	TTLs       int64    `json:"ttl_s"`
	IPs        []string `json:"ips"`
	Bans       int      `json:"bans"`
	Confiance  int      `json:"confiance"`
	Priorite   int      `json:"priorite"`
	Reversible bool     `json:"reversible"`
}

// FichierPropositions est ce que lit le consommateur : daté, pour qu'il ignore un fichier périmé.
type FichierPropositions struct {
	GenereLe     int64         `json:"genere_le"`
	Shadow       bool          `json:"shadow"`
	Propositions []Proposition `json:"propositions"`
}

func propositionsDepuis(acteurs []*graph.Actor, shadow bool) []Proposition {
	out := []Proposition{}
	for _, a := range acteurs {
		v := a.Vector
		rec := response.Recommend(v.Severity, v.Knowledge, v.Intent, v.Confidence, nil, shadow)
		if rec.Mode != response.ModeDeny && rec.Mode != response.ModeQuarantine {
			continue
		}
		out = append(out, Proposition{
			Actor: a.ID, Mode: string(rec.Mode), Raison: rec.Reason, TTLs: int64(rec.TTL.Seconds()),
			IPs: append([]string(nil), a.IPs...), Bans: a.Bans, Confiance: v.Confidence, Priorite: a.Priority, Reversible: rec.Rollbackable,
		})
	}
	return out
}

// ecrirePropositions écrit le fichier de façon atomique (le lecteur ne voit jamais un fichier à moitié écrit) en 0640, puis le met au groupe
// `actord-ingest` (celui de sbxwaf) quand il existe : un membre d'un groupe peut y remettre son fichier sans capacité.
func ecrirePropositions(chemin string, p []Proposition, shadow bool, now time.Time) error {
	b, err := json.Marshal(FichierPropositions{GenereLe: now.Unix(), Shadow: shadow, Propositions: p})
	if err != nil {
		return err
	}
	tmp := chemin + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	if g, err := user.LookupGroup("actord-ingest"); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil {
			_ = os.Chown(tmp, -1, gid)
		}
	}
	_ = os.Chmod(tmp, 0o640)
	return os.Rename(tmp, filepath.Clean(chemin))
}

func (s *Server) propositions() []Proposition {
	s.mu.Lock()
	defer s.mu.Unlock()
	return propositionsDepuis(s.graph.Actors(), s.shadow)
}

// publierPropositions réécrit le fichier à intervalle régulier (vide quand rien n'atteint DENY : le consommateur ne voit alors rien à faire).
// #3320 : le fichier n'est reecrit que si les propositions changent, ou pour
// rester frais (sbxwaf ignore un fichier de plus de 10 min).
func (s *Server) publierPropositions(chemin string, pas time.Duration) {
	var e etatEcriture
	for {
		p := s.propositions()
		corps, _ := json.Marshal(p)
		if now := time.Now(); e.doitEcrire(corps, now, propositionsRafraichir) {
			if err := ecrirePropositions(chemin, p, s.shadow, now); err != nil {
				log.Printf("actord: propositions: %v", err)
				e = etatEcriture{} // retente au prochain tour
			}
		}
		time.Sleep(pas)
	}
}

// propositionsRafraichir : la moitie de la fraicheur exigee par sbxwaf (10 min).
const propositionsRafraichir = 5 * time.Minute

// etatEcriture retient le dernier contenu ecrit (empreinte) et sa date.
type etatEcriture struct {
	empreinte [32]byte
	le        time.Time
}

// doitEcrire dit s'il faut reecrire : premier passage, contenu change, ou
// contenu identique mais plus vieux que maxAge. Met a jour l'etat si oui.
func (e *etatEcriture) doitEcrire(corps []byte, now time.Time, maxAge time.Duration) bool {
	h := sha256.Sum256(corps)
	if !e.le.IsZero() && h == e.empreinte && now.Sub(e.le) < maxAge {
		return false
	}
	e.empreinte, e.le = h, now
	return true
}

func (s *Server) handlePropositions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, FichierPropositions{GenereLe: time.Now().Unix(), Shadow: s.shadow, Propositions: s.propositions()})
}
