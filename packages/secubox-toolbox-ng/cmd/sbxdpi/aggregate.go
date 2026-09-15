// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxdpi :: in-memory stats aggregator
//
// Mirrors sbxwaf/visitstats.go: a mutex-guarded set of capped counter maps on
// the hot path (O(1) increments under a short lock), a periodic atomic
// snapshot flush (temp file + rename so a reader never sees a half-written
// file), and bounded memory (each map capped so a flood of unique keys cannot
// grow the daemon without limit).
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// mapCap bounds every counter map. Past the cap, new keys are dropped (existing
// keys keep counting) — the top talkers/protocols are what the dashboard shows,
// and the long tail is noise.
const mapCap = 5000

// counter holds the two metrics we track per key.
type counter struct {
	Flows uint64
	Bytes uint64
}

type aggregator struct {
	mu         sync.Mutex
	protocols  map[string]*counter // master proto: "TLS"
	apps       map[string]*counter // full proto: "TLS.Google"
	categories map[string]*counter // "Web", "Cloud"
	talkers    map[string]*counter // "src->dst"
	hosts      map[string]*counter // SNI/DNS hostname (pivot des règles usage/CDN)
	ports      map[string]*counter // port destinataire (service)
	fps        map[string]*counter // empreinte JA4 (fingerprint device/learner)
	risks      map[string]*riskCounter
	firstParty map[string]bool // apps seen as first-party (our own vhosts)

	// nom donne un NOM aux adresses des talkers. Facultatif : un agrégateur
	// sans nommeur rend les adresses brutes, comme avant (#1342).
	nom *nommeur

	totalFlows uint64
	totalBytes uint64
	outBytes   uint64 // trafic sortant (source locale → destination publique)
	inBytes    uint64 // trafic entrant
	filtered   uint64

	connected atomic.Bool
}

type riskCounter struct {
	Count    uint64
	Severity string
}

func newAggregator() *aggregator {
	return &aggregator{
		protocols:  map[string]*counter{},
		apps:       map[string]*counter{},
		categories: map[string]*counter{},
		talkers:    map[string]*counter{},
		hosts:      map[string]*counter{},
		ports:      map[string]*counter{},
		fps:        map[string]*counter{},
		risks:      map[string]*riskCounter{},
		firstParty: map[string]bool{},
	}
}

// LA CLÉ TALKER PORTE DEUX ADRESSES, et le séparateur est une flèche entourée
// d'espaces insécables logiques. On la coupe ici, en un seul endroit : la
// dupliquer serait s'exposer à ce qu'un appelant coupe sur « → » sans espaces
// et rende des adresses avec une espace collée.
const sepTalker = " → "

func coupeTalker(k string) (src, dst string, ok bool) {
	i := strings.Index(k, sepTalker)
	if i < 0 {
		return "", "", false
	}
	return k[:i], k[i+len(sepTalker):], true
}

func (a *aggregator) setConnected(v bool) { a.connected.Store(v) }

// bump increments a capped map's counter, creating the key only if the map is
// under cap. Caller holds a.mu.
func bump(m map[string]*counter, key string, flows, bytes uint64) {
	c := m[key]
	if c == nil {
		if len(m) >= mapCap {
			return
		}
		c = &counter{}
		m[key] = c
	}
	c.Flows += flows
	c.Bytes += bytes
}

func (a *aggregator) recordFlow(ev *dpiEvent, firstParty bool) {
	a.mu.Lock()
	a.totalFlows++
	bump(a.protocols, ev.master(), 1, 0)
	bump(a.apps, ev.app(), 1, 0)
	bump(a.categories, ev.category(), 1, 0)
	bump(a.talkers, ev.SrcIP+sepTalker+ev.DstIP, 1, 0)
	if h := ev.host(); h != "" {
		bump(a.hosts, h, 1, 0)
		// LE NOM EST CAPTÉ ICI, pas redécouvert plus tard : c'est le seul
		// instant où l'on tient ENSEMBLE l'adresse jointe et le nom demandé.
		// La clé talker, elle, ne garde que les adresses.
		if a.nom != nil {
			a.nom.Observe(ev.DstIP, h)
		}
	}
	if j := ev.ja4(); j != "" {
		bump(a.fps, j, 1, 0)
	}
	if ev.DstPort > 0 {
		bump(a.ports, strconv.Itoa(ev.DstPort), 1, 0)
	}
	if firstParty {
		if len(a.firstParty) < mapCap {
			a.firstParty[ev.app()] = true
		}
	}
	a.mu.Unlock()
}

func (a *aggregator) recordBytes(ev *dpiEvent) {
	b := ev.bytes()
	if b == 0 {
		return
	}
	a.mu.Lock()
	a.totalBytes += b
	bump(a.protocols, ev.master(), 0, b)
	bump(a.apps, ev.app(), 0, b)
	bump(a.categories, ev.category(), 0, b)
	bump(a.talkers, ev.SrcIP+sepTalker+ev.DstIP, 0, b)
	if h := ev.host(); h != "" {
		bump(a.hosts, h, 0, b)
	}
	if j := ev.ja4(); j != "" {
		bump(a.fps, j, 0, b)
	}
	if ev.DstPort > 0 {
		bump(a.ports, strconv.Itoa(ev.DstPort), 0, b)
	}
	if ev.outbound() {
		a.outBytes += b
	} else {
		a.inBytes += b
	}
	a.mu.Unlock()
}

func (a *aggregator) recordRisks(ev *dpiEvent, filt *filter) {
	if len(ev.NDPI.FlowRisk) == 0 {
		return
	}
	a.mu.Lock()
	for _, r := range ev.NDPI.FlowRisk {
		if r.Risk == "" || filt.riskMuted(r.Risk) {
			continue
		}
		rc := a.risks[r.Risk]
		if rc == nil {
			if len(a.risks) >= mapCap {
				continue
			}
			rc = &riskCounter{}
			a.risks[r.Risk] = rc
		}
		rc.Count++
		if r.Severity != "" {
			rc.Severity = r.Severity
		}
	}
	a.mu.Unlock()
}

func (a *aggregator) countFiltered() {
	a.mu.Lock()
	a.filtered++
	a.mu.Unlock()
}

// --- snapshot / serialization ---------------------------------------------

// kv is one ranked entry in the API/snapshot output.
type kv struct {
	Name  string  `json:"name"`
	Flows uint64  `json:"flows"`
	Bytes uint64  `json:"bytes"`
	Pct   float64 `json:"pct"` // share of totalBytes (or totalFlows if no bytes)
}

// talkerKV : une conversation, avec l'identité de chaque bout. `kv` est
// EMBARQUÉ, donc ses champs restent à plat dans le JSON — un snapshot écrit
// avant #1342 se relit sans transition, les deux identités valant simplement
// vide.
type talkerKV struct {
	kv
	Src identite `json:"src"`
	Dst identite `json:"dst"`
}

type riskKV struct {
	Name     string `json:"name"`
	Count    uint64 `json:"count"`
	Severity string `json:"severity"`
}

// snapshot is the full on-disk / API-root document.
type snapshot struct {
	UpdatedAt    int64      `json:"updated_at"`
	Connected    bool       `json:"connected"`
	TotalFlows   uint64     `json:"total_flows"`
	TotalBytes   uint64     `json:"total_bytes"`
	OutBytes     uint64     `json:"out_bytes"` // direction (#DPI-sémantique, additif)
	InBytes      uint64     `json:"in_bytes"`
	Filtered     uint64     `json:"filtered"`
	FirstPartyN  int        `json:"first_party_apps"`
	Protocols    []kv       `json:"protocols"`
	Apps         []kv       `json:"apps"`
	Categories   []kv       `json:"categories"`
	Talkers      []talkerKV `json:"talkers"`
	Hosts        []kv       `json:"hosts"`        // SNI/DNS destinations (#DPI-sémantique, additif)
	Ports        []kv       `json:"ports"`        // ports destinataires (services)
	Fingerprints []kv       `json:"fingerprints"` // empreintes JA4
	Risks        []riskKV   `json:"risks"`
}

// rank sorts a counter map into a bytes-desc (flows-desc tiebreak) slice, with
// each entry's Pct as its share of the total. Caller holds a.mu.
func rank(m map[string]*counter, totalBytes, totalFlows uint64) []kv {
	out := make([]kv, 0, len(m))
	for name, c := range m {
		var pct float64
		if totalBytes > 0 {
			pct = float64(c.Bytes) / float64(totalBytes) * 100
		} else if totalFlows > 0 {
			pct = float64(c.Flows) / float64(totalFlows) * 100
		}
		out = append(out, kv{Name: name, Flows: c.Flows, Bytes: c.Bytes, Pct: pct})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Flows > out[j].Flows
	})
	return out
}

// rankTalkers classe les conversations et nomme leurs deux bouts. Le nommage
// se fait AU SNAPSHOT, jamais à l'enregistrement du flux : résoudre pendant le
// comptage mettrait une recherche de nom sur le chemin chaud, et figerait le
// nom au premier flux — alors qu'une adresse encore anonyme peut être nommée
// une minute plus tard. Appelant : a.mu tenu.
func (a *aggregator) rankTalkers(tb, tf uint64) []talkerKV {
	base := rank(a.talkers, tb, tf)
	out := make([]talkerKV, 0, len(base))
	for _, e := range base {
		t := talkerKV{kv: e}
		if src, dst, ok := coupeTalker(e.Name); ok && a.nom != nil {
			t.Src, t.Dst = a.nom.Nomme(src), a.nom.Nomme(dst)
		}
		out = append(out, t)
	}
	return out
}

// snapshot builds a consistent document under one lock hold.
func (a *aggregator) snapshot() snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	tb, tf := a.totalBytes, a.totalFlows
	risks := make([]riskKV, 0, len(a.risks))
	for name, r := range a.risks {
		risks = append(risks, riskKV{Name: name, Count: r.Count, Severity: r.Severity})
	}
	sort.Slice(risks, func(i, j int) bool { return risks[i].Count > risks[j].Count })
	return snapshot{
		UpdatedAt:    time.Now().Unix(),
		Connected:    a.connected.Load(),
		TotalFlows:   tf,
		TotalBytes:   tb,
		OutBytes:     a.outBytes,
		InBytes:      a.inBytes,
		Filtered:     a.filtered,
		FirstPartyN:  len(a.firstParty),
		Protocols:    rank(a.protocols, tb, tf),
		Apps:         rank(a.apps, tb, tf),
		Categories:   rank(a.categories, tb, tf),
		Talkers:      a.rankTalkers(tb, tf),
		Hosts:        rank(a.hosts, tb, tf),
		Ports:        rank(a.ports, tb, tf),
		Fingerprints: rank(a.fps, tb, tf),
		Risks:        risks,
	}
}

// writeSnapshot atomically rewrites the cache JSON (temp + rename).
func (a *aggregator) writeSnapshot(path string) {
	if path == "" {
		return
	}
	snap := a.snapshot()
	buf, err := json.Marshal(snap)
	if err != nil {
		log.Printf("sbxdpi: snapshot marshal: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		log.Printf("sbxdpi: snapshot mkdir: %v", err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o640); err != nil {
		log.Printf("sbxdpi: snapshot write: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("sbxdpi: snapshot rename: %v", err)
	}
}

// loadSnapshot warm-starts the counters from a prior snapshot so the API is
// non-empty immediately after a restart. Fail-safe: unreadable/corrupt → no-op.
func (a *aggregator) loadSnapshot(path string) {
	if path == "" {
		return
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var snap snapshot
	if err := json.Unmarshal(buf, &snap); err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.totalFlows = snap.TotalFlows
	a.totalBytes = snap.TotalBytes
	a.filtered = snap.Filtered
	restore := func(dst map[string]*counter, src []kv) {
		for _, e := range src {
			if len(dst) >= mapCap {
				break
			}
			dst[e.Name] = &counter{Flows: e.Flows, Bytes: e.Bytes}
		}
	}
	// LA MOITIÉ DES COMPTEURS ÉTAIT JETÉE ICI (#1342). Le snapshot ÉCRIT hosts,
	// ports, fingerprints et les octets directionnels ; le chargement ne les
	// relisait pas. À chaque redémarrage du démon, ils repartaient de zéro alors
	// que la donnée était sur le disque, juste à côté de celle qu'on restaurait.
	//
	// Ce n'était pas une perte cosmétique : `hosts` est le PIVOT des règles
	// d'enrichissement — sans lui, Usages, Infrastructure et Non-classifié
	// repartaient vides —, et `fingerprints` (JA4) est le signal d'identité des
	// appareils. Les détails d'appareils disparaissaient à chaque relance.
	a.outBytes = snap.OutBytes
	a.inBytes = snap.InBytes
	restore(a.protocols, snap.Protocols)
	restore(a.apps, snap.Apps)
	restore(a.categories, snap.Categories)
	restore(a.hosts, snap.Hosts)
	restore(a.ports, snap.Ports)
	restore(a.fps, snap.Fingerprints)
	for _, t := range snap.Talkers {
		if len(a.talkers) >= mapCap {
			break
		}
		a.talkers[t.Name] = &counter{Flows: t.Flows, Bytes: t.Bytes}
	}
	// Les noms déjà observés sont repris avec les hôtes : sans eux, un talker
	// resterait anonyme jusqu'à ce que le même flux repasse.
	if a.nom != nil {
		for _, h := range snap.Talkers {
			if h.Dst.Source == "observé" && h.Dst.Nom != "" {
				if _, dst, ok := coupeTalker(h.Name); ok {
					a.nom.Observe(dst, h.Dst.Nom)
				}
			}
		}
	}
	for _, r := range snap.Risks {
		if len(a.risks) >= mapCap {
			break
		}
		a.risks[r.Name] = &riskCounter{Count: r.Count, Severity: r.Severity}
	}
}

// flushLoop rewrites the snapshot every FlushInterval until ctx is cancelled.
func flushLoop(ctx context.Context, cfg Config, agg *aggregator) {
	t := time.NewTicker(cfg.FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			agg.writeSnapshot(cfg.CachePath)
		}
	}
}
