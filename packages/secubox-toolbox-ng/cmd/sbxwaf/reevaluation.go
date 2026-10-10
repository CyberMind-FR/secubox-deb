// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// KILL SWITCH LOGIQUE (Actor Intelligence 2.0, phase 4, #2240).
//
//	ACTEUR BANNI → TIMER → RÉÉVALUATION À L'ÉCHÉANCE → RELEASE ou EXTEND
//
// Un ban ne se prolonge pas « par défaut » et ne devient jamais permanent par accident. Quelques instants avant l'échéance, on regarde ce que l'adresse a FAIT
// pendant son ban : les compteurs par élément de l'ensemble nft disent combien de paquets elle a encore envoyés (la chaîne les rejette avant tout journal : sans
// eux, une adresse qui insiste et une adresse qui s'est tue sont indiscernables).
//   - elle insiste (≥ seuil de paquets)  → EXTEND, avec la durée GRADUÉE suivante (leurre 1 h/24 h/7 j, campagne 4 h/24 h/7 j) ;
//   - elle s'est tue                     → RELEASE : le timeout nft fait le travail, rien n'est posé ;
//   - pas de compteur (ensemble ancien)  → RELEASE : jamais de prolongation à l'aveugle ;
//   - chaîne de bans de 30 jours         → RELEASE quoi qu'il arrive : jamais de ban permanent accidentel ; une prolongation ne dépasse jamais ce plafond.
//
// Chaque transition laisse une ligne de preuve (reevaluations.jsonl, append-only) et une ligne d'audit (/var/log/secubox/waf/audit.log : le répertoire que le service peut écrire ; le journal central est secubox:secubox 0640, fermé à secubox-waf). Mode `off` | `propose` (écrit ce qu'il ferait, n'applique
// rien) | `auto`. Seuls les bans du journal de sbxwaf sont réévalués : un ban posé à la main (wafctl) n'y figure pas et n'est jamais touché.
const (
	plafondChaine     = 30 * 24 * time.Hour
	plafondProlonge   = 7 * 24 * time.Hour
	fenetreReeval     = 90 * time.Second
	seuilReevalDefaut = 10
)

type ReevalDecision struct {
	Action string // RELEASE | EXTEND
	Duree  time.Duration
	Raison string
}

func dureeGraduee(categorie string, n int) time.Duration {
	switch {
	case strings.HasPrefix(categorie, "leurre:"):
		return dureeLeurre(n)
	default:
		return dureeCampagne(n) // 4 h, 24 h, 7 j : aussi la gradation par défaut
	}
}

func famille(categorie string) string {
	if i := strings.Index(categorie, ":"); i >= 0 {
		return categorie[:i+1]
	}
	return categorie
}

// Reevaluer décide. Pure : tout ce qu'elle lit est passé en argument.
func Reevaluer(categorie string, paquets uint64, avecCompteur bool, recidives int, depuisChaine time.Duration, seuil uint64) ReevalDecision {
	switch {
	case !avecCompteur:
		return ReevalDecision{"RELEASE", 0, "aucun compteur : pas de preuve de persistance, jamais de prolongation à l'aveugle"}
	case depuisChaine >= plafondChaine:
		return ReevalDecision{"RELEASE", 0, "chaîne de bans de 30 jours atteinte : jamais de ban permanent accidentel"}
	case paquets < seuil:
		return ReevalDecision{"RELEASE", 0, "n'a pas insisté pendant son ban"}
	}
	d := dureeGraduee(categorie, recidives+1) // `recidives` = bans déjà posés AVANT celui qui expire ; la prolongation est l'échelon suivant
	if d > plafondProlonge {
		d = plafondProlonge
	}
	if reste := plafondChaine - depuisChaine; d > reste {
		d = reste
	}
	if d <= 0 {
		return ReevalDecision{"RELEASE", 0, "plafond de 30 jours atteint"}
	}
	return ReevalDecision{"EXTEND", d, "a continué d'envoyer des paquets pendant son ban"}
}

type Reeval struct {
	banneur *NftBanner
	store   *BanStore
	mode    string // off | propose | auto
	preuves string
	audit   string
	seuil   uint64
	now     func() time.Time

	mu       sync.Mutex
	deja     map[string]int64 // ip|échéance → échéance (pour purger)
	erreurLu bool
}

func NewReeval(b *NftBanner, store *BanStore, mode, preuves string) *Reeval {
	return &Reeval{banneur: b, store: store, mode: mode, preuves: preuves, audit: "/var/log/secubox/waf/audit.log", seuil: seuilReevalDefaut,
		now: time.Now, deja: map[string]int64{}}
}

func (r *Reeval) ecrire(chemin string, v any) {
	if chemin == "" {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(chemin), 0o755)
	f, err := os.OpenFile(chemin, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		log.Printf("sbxwaf: réévaluation — écriture %s impossible : %v", chemin, err)
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

// Tick réévalue les bans qui arrivent à échéance dans la fenêtre.
func contexteCourt() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 8*time.Second)
}

func (r *Reeval) Tick() {
	if r.mode != "propose" && r.mode != "auto" {
		return
	}
	now := r.now()
	ctx, cancel := contexteCourt()
	defer cancel()
	elems, err := r.banneur.ElementsAvecCompteurs(ctx)
	if err != nil {
		r.mu.Lock()
		premiere := !r.erreurLu
		r.erreurLu = true
		r.mu.Unlock()
		if premiere {
			log.Printf("sbxwaf: réévaluation des bans impossible : %v", err)
		}
		return
	}
	r.mu.Lock()
	for k, exp := range r.deja {
		if exp < now.Unix()-3600 {
			delete(r.deja, k)
		}
	}
	r.mu.Unlock()
	for _, rec := range r.store.ActiveBans(now.Unix()) {
		reste := rec.Expires - now.Unix()
		if rec.Expires == 0 || reste <= 0 || reste > int64(fenetreReeval.Seconds()) {
			continue
		}
		cle := rec.IP + "|" + time.Unix(rec.Expires, 0).Format(time.RFC3339)
		r.mu.Lock()
		vu := r.deja[cle] != 0
		r.deja[cle] = rec.Expires
		r.mu.Unlock()
		el, ok := elems[rec.IP]
		if vu || !ok {
			continue // déjà traité, ou plus dans nft (levé entre-temps : rien à décider)
		}
		recid := r.store.CompteCategorie(rec.IP, famille(rec.Category), now.Add(-plafondChaine).Unix())
		d := Reevaluer(rec.Category, el.Paquets, el.AvecCompteur, max(recid-1, 0), r.store.DepuisChaine(rec.IP, now.Unix()), r.seuil)
		applique := r.mode == "auto" && d.Action == "EXTEND"
		r.ecrire(r.preuves, map[string]any{"ts": now.Unix(), "ip": rec.IP, "categorie": rec.Category, "paquets": el.Paquets, "compteur": el.AvecCompteur,
			"recidives": recid, "decision": d.Action, "duree_s": int64(d.Duree.Seconds()), "raison": d.Raison, "mode": r.mode, "applique": applique, "version": "v1"})
		r.ecrire(r.audit, map[string]any{"ts": now.UTC().Format("2006-01-02T15:04:05Z"), "module": "waf", "action": "reevaluation",
			"detail": rec.IP + " " + rec.Category + " → " + d.Action + " (" + d.Raison + ")"})
		log.Printf("sbxwaf: réévaluation %s ← %s : %s (%d paquets, %s) mode=%s", rec.IP, rec.Category, d.Action, el.Paquets, d.Raison, r.mode)
		if applique {
			r.banneur.Prolonger(rec.IP, strings.TrimSuffix(rec.Category, "|prolonge")+"|prolonge", rec.Severity, d.Duree, now)
		}
	}
}

// Veiller relance Tick toutes les 30 s.
func (r *Reeval) Veiller(pas time.Duration) {
	for {
		r.Tick()
		time.Sleep(pas)
	}
}
