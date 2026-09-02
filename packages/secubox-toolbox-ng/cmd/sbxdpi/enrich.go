// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxdpi :: enrichissement sémantique (DPI usage)
//
// Passe de « protocole détecté » à « usage compris ». Un jeu de RÈGLES externes
// versionnées (JSON), rechargées à chaud via internal/reload (le même standard
// que filter.go et sbxwaf/rules.go), mappe un flux → application / famille
// d'usage / type de contenu / infrastructure + rôle, avec une CONFIANCE et une
// liste d'EVIDENCE (jamais présentée comme une certitude).
//
// Convention de format reprise du _meta versionné de waf-rules.json ; les champs
// de matcher (domain_suffix / ndpi / port) viennent du brief DPI. Aucune règle
// n'est inventée dans le code : tout vit dans le fichier de règles, rechargeable
// sans recompilation. Fichier absent/corrompu → ensemble vide (fail-safe).
package main

import (
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reload"
)

// enrichRule : une règle d'enrichissement. Elle s'applique si TOUS les groupes
// de matcher renseignés matchent (ET entre groupes, OU dans un groupe).
type enrichRule struct {
	ID          string `json:"id"`
	Application string `json:"application,omitempty"`
	Usage       string `json:"usage,omitempty"`
	Content     string `json:"content,omitempty"`
	Infra       string `json:"infra,omitempty"`
	InfraRole   string `json:"infra_role,omitempty"`
	Confidence  int    `json:"confidence"` // 0..100
	Match       struct {
		DomainSuffix []string `json:"domain_suffix,omitempty"`
		NDPI         []string `json:"ndpi,omitempty"` // app nDPI ("YouTube") ou master ("TLS")
		Port         []int    `json:"port,omitempty"`
	} `json:"match"`
}

// ruleSet est le document de règles sur disque (mirroir du _meta de waf-rules.json).
type ruleSet struct {
	Meta  map[string]any `json:"_meta"`
	Rules []enrichRule   `json:"rules"`
}

// enrichment est le verdict pour un flux/hôte. Confidence + evidence obligatoires.
type enrichment struct {
	RuleID      string   `json:"rule_id,omitempty"`
	Application string   `json:"application,omitempty"`
	Usage       string   `json:"usage,omitempty"`
	Content     string   `json:"content,omitempty"`
	Infra       string   `json:"infra,omitempty"`
	InfraRole   string   `json:"infra_role,omitempty"`
	Confidence  int      `json:"confidence"`
	Evidence    []string `json:"evidence"`
}

type enricher struct {
	mu      sync.RWMutex
	rules   []enrichRule
	watcher *reload.Watcher
}

// loadRules lit le fichier de règles JSON, fail-safe (absent/corrompu → vide).
func loadRules(path string) any {
	buf, err := os.ReadFile(path)
	if err != nil {
		return []enrichRule{}
	}
	var rs ruleSet
	if err := json.Unmarshal(buf, &rs); err != nil {
		return []enrichRule{}
	}
	return rs.Rules
}

// newEnricher charge les règles et arme le hot-reload mtime (même standard que
// filter.go). Fichier absent → ensemble vide, jamais d'erreur.
func newEnricher(path string, reloadEvery time.Duration) *enricher {
	e := &enricher{rules: loadRules(path).([]enrichRule)}
	e.watcher = reload.NewWatcher(reloadEvery,
		reload.Target{
			Path: path, LastMtime: reload.StatMtime(path),
			Load:  loadRules,
			Apply: func(v any) { e.mu.Lock(); e.rules = v.([]enrichRule); e.mu.Unlock() },
		},
	)
	return e
}

// maybeReload : à appeler sur le hot-path (par requête d'API) — recharge les
// règles si le fichier a changé, throttlé.
func (e *enricher) maybeReload() {
	if e.watcher != nil {
		e.watcher.Maybe()
	}
}

// hostHasSuffix : host == suffix, ou host se termine par ".suffix".
func hostHasSuffix(host, suffix string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	suffix = strings.ToLower(strings.TrimSpace(suffix))
	if host == "" || suffix == "" {
		return false
	}
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}

// Classify applique les règles à un flux (host + app nDPI + master + port). La
// première règle qui matche avec la meilleure confiance gagne. Aucun match →
// enrichment vide de confiance 0 (unknown-first : à qualifier).
func (e *enricher) Classify(host, ndpiApp, ndpiMaster string, port int) enrichment {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	best := enrichment{Evidence: []string{}}
	for i := range rules {
		r := &rules[i]
		// Une règle sans aucun matcher ne s'applique jamais (garde-fou).
		if len(r.Match.DomainSuffix) == 0 && len(r.Match.NDPI) == 0 && len(r.Match.Port) == 0 {
			continue
		}
		// OU entre groupes : un signal disponible suffit à classer (le domaine
		// seul identifie YouTube même sans nDPI/port). Chaque hit devient une
		// evidence ; combiner plusieurs indices renforce simplement la preuve.
		var ev []string
		for _, s := range r.Match.DomainSuffix {
			if hostHasSuffix(host, s) {
				ev = append(ev, "domaine "+s)
				break
			}
		}
		for _, n := range r.Match.NDPI {
			if (ndpiApp != "" && strings.EqualFold(n, ndpiApp)) ||
				(ndpiMaster != "" && strings.EqualFold(n, ndpiMaster)) {
				ev = append(ev, "nDPI "+n)
				break
			}
		}
		if port != 0 {
			for _, p := range r.Match.Port {
				if p == port {
					ev = append(ev, "port "+strconv.Itoa(port))
					break
				}
			}
		}
		if len(ev) > 0 && r.Confidence >= best.Confidence {
			best = enrichment{
				RuleID: r.ID, Application: r.Application, Usage: r.Usage,
				Content: r.Content, Infra: r.Infra, InfraRole: r.InfraRole,
				Confidence: r.Confidence, Evidence: ev,
			}
		}
	}
	return best
}

// --- vue usage agrégée (endpoint /usage) -----------------------------------

// usageBucket : une entrée classée, part du volume classifié.
type usageBucket struct {
	Name       string  `json:"name"`
	Flows      uint64  `json:"flows"`
	Bytes      uint64  `json:"bytes"`
	Pct        float64 `json:"pct"`
	Confidence int     `json:"confidence,omitempty"`
}

// usageReport : la vue « usage » dérivée des destinations SNI déjà agrégées.
// Unknown-first : les hôtes non classifiés sont un produit, pas un déchet.
type usageReport struct {
	Usages       []usageBucket `json:"usages"`
	Providers    []usageBucket `json:"providers"`
	Applications []usageBucket `json:"applications"`
	Unknown      []kv          `json:"unknown"`
}

type acc struct {
	flows, bytes uint64
	conf         int
}

func sortBucketsDesc(b []usageBucket) {
	sort.Slice(b, func(i, j int) bool {
		if b[i].Bytes != b[j].Bytes {
			return b[i].Bytes > b[j].Bytes
		}
		return b[i].Flows > b[j].Flows
	})
}

func toBuckets(m map[string]*acc, total uint64) []usageBucket {
	out := make([]usageBucket, 0, len(m))
	for name, a := range m {
		var pct float64
		if total > 0 {
			pct = float64(a.bytes) / float64(total) * 100
		}
		out = append(out, usageBucket{Name: name, Flows: a.flows, Bytes: a.bytes, Pct: pct, Confidence: a.conf})
	}
	sortBucketsDesc(out)
	return out
}

func bumpAcc(m map[string]*acc, key string, flows, bytes uint64, conf int) {
	if key == "" {
		return
	}
	a := m[key]
	if a == nil {
		a = &acc{}
		m[key] = a
	}
	a.flows += flows
	a.bytes += bytes
	if conf > a.conf {
		a.conf = conf
	}
}

// report classe chaque destination SNI (hosts[] du snapshot) et agrège le
// volume par famille d'usage, infrastructure et application. Recharge d'abord
// les règles (hot-path). Le domaine est le seul signal disponible ici ; les
// signaux nDPI/port serviront la classification per-flow (L3).
func (e *enricher) report(hosts []kv) usageReport {
	e.maybeReload()
	usages := map[string]*acc{}
	providers := map[string]*acc{}
	apps := map[string]*acc{}
	unknown := []kv{}
	var total uint64
	for _, h := range hosts {
		total += h.Bytes
	}
	for _, h := range hosts {
		en := e.Classify(h.Name, "", "", 0)
		if en.Confidence == 0 {
			unknown = append(unknown, h)
			continue
		}
		bumpAcc(usages, en.Usage, h.Flows, h.Bytes, en.Confidence)
		bumpAcc(providers, en.Infra, h.Flows, h.Bytes, en.Confidence)
		bumpAcc(apps, en.Application, h.Flows, h.Bytes, en.Confidence)
	}
	return usageReport{
		Usages:       toBuckets(usages, total),
		Providers:    toBuckets(providers, total),
		Applications: toBuckets(apps, total),
		Unknown:      unknown,
	}
}
