// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: WG persona identity (mac_hash) (#662 Phase 6 prep)
//
// Byte-exact port of the Python WG-peer identity resolver
// (packages/secubox-toolbox/mitmproxy_addons/_common.py: _wg_hash_of /
// mac_hash_of). Python is the source of truth; this mirrors it exactly, proven
// by the cross-engine parity harness (testdata/wg-peers-fixture.json +
// testdata/machash-fixtures.json + machash_test.go ↔ tests/test_machash_parity.py).
//
// R3 clients reach this transparent engine over WireGuard on 10.99.1.0/24 and
// have NO ARP entry on the captive subnet, so they are identified by their WG
// public key (one peer → one IP, deterministic): ip → sha256(pubkey)[:16].
//
// Pure standard library — no external modules, no go.sum.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"sync"
)

// wgPeersPath is the on-disk WG peer DB, mirroring _common._WG_PEERS_DB. It is a
// package-level var (not a const) so tests can repoint it at a fixture.
var wgPeersPath = "/var/lib/secubox/toolbox/wg-peers.json"

// wgPeer mirrors the per-pubkey metadata object in wg-peers.json. Only "ip" is
// consumed here (other fields are ignored, like the Python meta.get("ip")).
type wgPeer struct {
	IP string `json:"ip"`
}

// wgPeersDB mirrors the file shape: {"peers": {"<pubkey>": {"ip": "..."}}}.
type wgPeersDB struct {
	Peers map[string]wgPeer `json:"peers"`
}

// WG peer cache, mtime-keyed and reloaded only on mtime change — exactly like
// the Python _WG_PEERS_CACHE / _WG_PEERS_MTIME globals. Guarded by a mutex: the
// Go proxy is genuinely concurrent (Python relied on the GIL), so the cache map
// and mtime MUST NOT be read/written without holding wgMu.
var (
	wgMu    sync.Mutex
	wgCache map[string]string // ip → sha256(pubkey)[:16]
	wgMtime int64             // last loaded file mtime (UnixNano), 0 = unloaded
)

// resetWGCache clears the in-process WG cache so the next wgHashOf reload reads
// wgPeersPath afresh. Used by tests after repointing wgPeersPath; mirrors the
// Python parity test resetting _WG_PEERS_CACHE/_WG_PEERS_MTIME.
func resetWGCache() {
	wgMu.Lock()
	wgCache = nil
	wgMtime = 0
	wgMu.Unlock()
}

// wgHashOf maps a WG peer IP (10.99.1.X) to sha256(peer_pubkey)[:16]. Mirrors
// _common._wg_hash_of EXACTLY: mtime-cached, reloaded only when the file mtime
// changes (or the cache is empty); ANY error (missing file, bad JSON, stat
// failure) → "" (best-effort, fail-open to empty, never panics). Returns "" for
// an IP not present in the DB. The cache is mutex-guarded for concurrency.
func wgHashOf(ip string) string {
	wgMu.Lock()
	defer wgMu.Unlock()

	fi, err := os.Stat(wgPeersPath)
	if err != nil {
		return "" // missing file / unreadable → fail-open (Python: not exists → None)
	}
	mtime := fi.ModTime().UnixNano()
	if mtime != wgMtime || wgCache == nil {
		raw, err := os.ReadFile(wgPeersPath)
		if err != nil {
			return ""
		}
		var db wgPeersDB
		if err := json.Unmarshal(raw, &db); err != nil {
			return "" // bad JSON → fail-open (Python: except → None)
		}
		fresh := make(map[string]string, len(db.Peers))
		for pubkey, meta := range db.Peers {
			if meta.IP != "" {
				sum := sha256.Sum256([]byte(pubkey))
				fresh[meta.IP] = hex.EncodeToString(sum[:])[:16]
			}
		}
		wgCache = fresh
		wgMtime = mtime
	}
	return wgCache[ip] // missing key → "" (Python: cache.get(ip) → None)
}

// macHashOf resolves an IP to a stable per-client persona identity hash.
// Mirrors _common.mac_hash_of, but scoped to the R3 transparent engine:
//
//   - empty ip                → ""
//   - 10.99.1.0/24 (WG peer)  → wgHashOf(ip)  = sha256(peer_pubkey)[:16]
//   - else                    → ""
//
// The Python mac_hash_of has a third branch for the captive subnet
// (R0/R1/R2): hash_mac(mac_of(ip)) = HMAC(salt, ARP MAC). That ARP/HMAC path is
// INTENTIONALLY out of scope here — R3 clients arrive over WireGuard and have no
// ARP entry on the captive subnet, so this engine is WG-only. Off-subnet IPs
// therefore resolve to "" (the caller falls back to the raw peer IP).
func macHashOf(ip string) string {
	if ip == "" {
		return ""
	}
	if strings.HasPrefix(ip, "10.99.1.") {
		return wgHashOf(ip)
	}
	return "" // R0-R2 ARP/HMAC path out of scope for the R3 transparent engine
}
