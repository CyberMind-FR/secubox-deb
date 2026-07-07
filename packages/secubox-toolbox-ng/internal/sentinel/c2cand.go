// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

// C2 auto-learn candidate lifecycle (#823): a beaconing host that passed the FP
// gate and carries >=1 corroborating signal becomes a candidate. It is promoted
// only when sustained across c2MinWindows separate beacon reports spanning at
// least c2MinSpanSec — never on a single burst.

import (
	"encoding/json"
	"os"
	"sync"
)

const (
	c2MaxEntries        = 2000
	c2MinWindows        = 3
	c2MaxDevicesPerHost = 256
)

var c2MinSpanSec int64 = 1800 // 30 min; var so tests/config can adjust

type C2Candidate struct {
	Host      string          `json:"host"`
	FirstSeen int64           `json:"first_seen"`
	LastSeen  int64           `json:"last_seen"`
	Windows   int             `json:"windows"`
	Devices   map[string]bool `json:"devices"`
	Signals   map[string]bool `json:"signals"`
	IntervalS float64         `json:"interval_s"`
	Promoted  bool            `json:"promoted"`
}

type C2Cand struct {
	path string
	mu   sync.Mutex
	m    map[string]*C2Candidate
}

// cloneCandidate returns a deep value copy of cd, including independent
// Devices/Signals map allocations, so callers holding the returned value can
// never race a concurrent Record() mutating the live candidate's maps.
func cloneCandidate(cd *C2Candidate) C2Candidate {
	out := *cd
	out.Devices = make(map[string]bool, len(cd.Devices))
	for k, v := range cd.Devices {
		out.Devices[k] = v
	}
	out.Signals = make(map[string]bool, len(cd.Signals))
	for k, v := range cd.Signals {
		out.Signals[k] = v
	}
	return out
}

// NewC2Cand loads persisted candidates from path (fail-safe: missing/corrupt →
// empty).
func NewC2Cand(path string) *C2Cand {
	c := &C2Cand{path: path, m: make(map[string]*C2Candidate)}
	if b, err := os.ReadFile(path); err == nil {
		var list []*C2Candidate
		if json.Unmarshal(b, &list) == nil {
			for _, cd := range list {
				if cd != nil && cd.Host != "" {
					if cd.Devices == nil {
						cd.Devices = map[string]bool{}
					}
					if cd.Signals == nil {
						cd.Signals = map[string]bool{}
					}
					c.m[cd.Host] = cd
				}
			}
		}
	}
	return c
}

// Record folds one beacon observation into host's candidate and reports whether
// this call is the FIRST to satisfy the promotion criteria (sustained across
// >=c2MinWindows spanning >=c2MinSpanSec). Latched: returns true at most once.
func (c *C2Cand) Record(host, mac string, ts int64, intervalS float64, signals []string) (bool, C2Candidate) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cd := c.m[host]
	isNew := cd == nil
	if isNew {
		cd = &C2Candidate{Host: host, FirstSeen: ts, Devices: map[string]bool{}, Signals: map[string]bool{}}
		c.m[host] = cd
	}
	cd.LastSeen = ts
	cd.Windows++
	cd.IntervalS = intervalS
	if mac != "" {
		if _, ok := cd.Devices[mac]; ok || len(cd.Devices) < c2MaxDevicesPerHost {
			cd.Devices[mac] = true
		}
	}
	for _, s := range signals {
		cd.Signals[s] = true
	}

	promote := false
	if !cd.Promoted &&
		cd.Windows >= c2MinWindows &&
		(cd.LastSeen-cd.FirstSeen) >= c2MinSpanSec &&
		len(cd.Signals) >= 1 {
		cd.Promoted = true
		promote = true
	}
	if isNew {
		// Evict only after cd.LastSeen is set to a real timestamp, so the
		// just-inserted entry can never be mistaken for the oldest (LastSeen
		// == 0) candidate and evict itself.
		c.evictLocked()
	}
	return promote, cloneCandidate(cd)
}

// evictLocked keeps the map under c2MaxEntries by dropping the oldest-seen
// non-promoted candidate. Caller holds the lock.
func (c *C2Cand) evictLocked() {
	if len(c.m) <= c2MaxEntries {
		return
	}
	var victim string
	var oldest int64
	for h, cd := range c.m {
		if cd.Promoted {
			continue
		}
		if victim == "" || cd.LastSeen < oldest {
			victim, oldest = h, cd.LastSeen
		}
	}
	if victim != "" {
		delete(c.m, victim)
	}
}

func (c *C2Cand) Snapshot() []C2Candidate {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]C2Candidate, 0, len(c.m))
	for _, cd := range c.m {
		out = append(out, cloneCandidate(cd))
	}
	return out
}

func (c *C2Cand) Remove(host string) {
	c.mu.Lock()
	delete(c.m, host)
	c.mu.Unlock()
}

// Persist atomically writes the candidate set to path.
func (c *C2Cand) Persist() error {
	c.mu.Lock()
	list := make([]C2Candidate, 0, len(c.m))
	for _, cd := range c.m {
		list = append(list, cloneCandidate(cd))
	}
	c.mu.Unlock()
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	if c.path == "" {
		return nil
	}
	return atomicWriteFile(c.path, b, 0o640)
}
