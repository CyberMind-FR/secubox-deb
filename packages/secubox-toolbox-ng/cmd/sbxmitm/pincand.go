// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: certificate-pinning auto-learn (#740)
//
// Some clients PIN their server's certificate: a native/mobile app (ChatGPT et
// al.) or an own-infra API ships the expected leaf/CA and REFUSES our forged
// MITM cert, aborting the TLS handshake with a fatal alert. Under interception
// the app hard-fails ("connection error") and the user must cut the tunnel.
//
// The operator splice whitelist (policy.go spliceWl) fixes a KNOWN pinned host;
// this file makes the engine LEARN unknown ones. When tls.Server.Handshake()
// fails with a CLIENT cert-rejection alert (bad_certificate / unknown_ca /
// certificate_required / …) AND we have an SNI that is NOT already spliced, we
// tally the SNI as a pinning CANDIDATE. Candidates ride the existing ad-event
// flush to the portal, which surfaces them in the splice-whitelist WebUI as
// "auto-learned proposals" the operator can promote (→ force-splice) or ignore.
//
// We deliberately count ONLY explicit client TLS alerts — a plain RST / EOF /
// timeout is ambiguous (network blip, scanner, QUIC race) and would mislearn, so
// those are excluded. Same lock-guarded, capped, snapshot-and-clear shape as
// adCandidates; pure standard library.
package main

import (
	"strings"
	"sync"
)

// pinCandMapCap bounds the candidate buffer (mirrors adCandMapCap): NEW SNIs past
// the cap are dropped until the next flush clears it, so a dead portal can never
// grow memory unbounded. Pinning failures are rare, so this is generous.
const pinCandMapCap = 4096

// pinCandidateRow is one auto-learned pinning candidate (an SNI whose client
// rejected our forged cert), with how many times it was observed since the last
// flush. The portal persists these as splice proposals.
type pinCandidateRow struct {
	Host string `json:"host"`
	Hits int64  `json:"hits"`
}

// pinCandidates is the lock-guarded SNI→hits candidate aggregator, drained by the
// ad-stats flusher into the ad-event payload's "pinning_candidates" list.
type pinCandidates struct {
	mu  sync.Mutex
	hit map[string]int64
}

func newPinCandidates() *pinCandidates { return &pinCandidates{hit: map[string]int64{}} }

// record tallies one pinning candidate for sni. O(1); the cap drops only NEW
// keys (existing keys keep accumulating). Empty / dotless SNIs are ignored (an
// SNI-less or IP handshake carries no host to propose).
func (a *pinCandidates) record(sni string) {
	if a == nil {
		return
	}
	s := strings.Trim(strings.ToLower(sni), ".")
	if s == "" || !strings.Contains(s, ".") {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.hit[s]; ok {
		a.hit[s]++
	} else if len(a.hit) < pinCandMapCap {
		a.hit[s] = 1
	}
}

// snapshot atomically reads-and-clears the buffer, returning the candidate rows
// (nil when empty, so the caller can cheaply skip).
func (a *pinCandidates) snapshot() []pinCandidateRow {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.hit) == 0 {
		return nil
	}
	rows := make([]pinCandidateRow, 0, len(a.hit))
	for h, n := range a.hit {
		rows = append(rows, pinCandidateRow{Host: h, Hits: n})
	}
	a.hit = map[string]int64{}
	return rows
}

// isClientCertRejection reports whether a tls.Server.Handshake() error is a
// CLIENT-sent fatal alert that signals certificate PINNING (the client refused
// our forged leaf), as opposed to an ambiguous transport failure (RST/EOF/
// timeout) or our own server-side error. Go surfaces a received alert as an
// error whose text is "remote error: tls: <description>"; we match the
// cert-rejection descriptions only, so a network blip never mislearns.
func isClientCertRejection(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "remote error: tls:") {
		return false // not a client-sent alert (e.g. raw connection reset)
	}
	for _, sig := range pinAlertSignatures {
		if strings.Contains(msg, sig) {
			return true
		}
	}
	return false
}

// pinAlertSignatures are the TLS alert descriptions a pinning client sends when
// it rejects our cert. "bad certificate" / "unknown ca" / "certificate unknown"
// are the classic pinning alerts; "certificate required" / "decrypt error" /
// "handshake failure" cover stricter stacks that abort once the chain mismatches.
var pinAlertSignatures = []string{
	"bad certificate",
	"unknown certificate authority",
	"unknown ca",
	"certificate unknown",
	"certificate required",
	"unknown certificate",
	"decrypt error",
	"handshake failure",
}
