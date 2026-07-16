// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf :: crowdsec — CrowdSec LAPI alert bridge
//
// Task 4.1: implements CrowdSecClient, which satisfies the CrowdSecReporter
// interface declared in main.go.  On a ban event the handler calls
// crowdsec.Report(ip, cat, sev) in a goroutine; this client builds the LAPI
// alert JSON (ported faithfully from secubox_waf.py _ban_via_crowdsec) and
// POSTs it to {lapiURL}/v1/alerts with a 2 s timeout.
//
// Best-effort: network errors are logged and swallowed — the WAF never blocks
// on LAPI availability.  SSRF hygiene: redirect-following is disabled.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// CrowdSecClient implements CrowdSecReporter by POSTing alert objects to the
// CrowdSec LAPI /v1/alerts endpoint.
type CrowdSecClient struct {
	lapiURL  string
	jwt      string
	duration string
	client   *http.Client
}

// NewCrowdSecClient builds a CrowdSecClient with a 2 s timeout and no redirect
// following (SSRF hygiene).
//
//   - lapiURL:  base URL of the CrowdSec LAPI, e.g. "http://10.100.0.1:8080"
//   - jwt:      Bearer token (read from --crowdsec-jwt-file by main())
//   - duration: ban duration string forwarded in the decision, e.g. "4h"
func NewCrowdSecClient(lapiURL, jwt, duration string) *CrowdSecClient {
	return &CrowdSecClient{
		lapiURL:  strings.TrimRight(lapiURL, "/"),
		jwt:      jwt,
		duration: duration,
		client: &http.Client{
			Timeout: 2 * time.Second,
			// Disable redirect following — prevents SSRF via 3xx to internal hosts.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Report satisfies CrowdSecReporter.  It builds the LAPI alert payload and
// POSTs it.  Errors are logged only (best-effort, never panics).
// The caller already wraps this in a goroutine (see main.go ban branch).
func (c *CrowdSecClient) Report(ip, cat, sev string) {
	if err := c.postAlert(ip, cat, sev); err != nil {
		log.Printf("sbxwaf: crowdsec bridge error for %s (%s/%s): %v", ip, cat, sev, err)
	}
}

// csAlertSource mirrors the source object expected by the CrowdSec LAPI.
type csAlertSource struct {
	Scope     string  `json:"scope"`
	Value     string  `json:"value"`
	IP        string  `json:"ip"`
	AsNumber  string  `json:"as_number"`
	AsName    string  `json:"as_name"`
	Cn        string  `json:"cn"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// csDecision mirrors the decision object inside the LAPI alert.
type csDecision struct {
	Duration  string `json:"duration"`
	Scenario  string `json:"scenario"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Scope     string `json:"scope"`
	Origin    string `json:"origin"`
	Simulated bool   `json:"simulated"`
}

// csEventMeta is one key/value pair inside an event's meta list.
type csEventMeta struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// csEvent is a single event in the events array.
type csEvent struct {
	Timestamp string        `json:"timestamp"`
	Meta      []csEventMeta `json:"meta"`
}

// csAlert is the full alert object (one element of the POST body array).
type csAlert struct {
	Scenario        string        `json:"scenario"`
	ScenarioHash    string        `json:"scenario_hash"`
	ScenarioVersion string        `json:"scenario_version"`
	Message         string        `json:"message"`
	EventsCount     int           `json:"events_count"`
	StartAt         string        `json:"start_at"`
	StopAt          string        `json:"stop_at"`
	Capacity        int           `json:"capacity"`
	Leakspeed       string        `json:"leakspeed"`
	Simulated       bool          `json:"simulated"`
	Source          csAlertSource `json:"source"`
	Decisions       []csDecision  `json:"decisions"`
	Events          []csEvent     `json:"events"`
}

// postAlert builds and POSTs the alert; returns an error for logging.
func (c *CrowdSecClient) postAlert(ip, cat, sev string) error {
	// Python uses "%Y-%m-%dT%H:%M:%S.000000Z" — reproduce the same format so
	// existing CrowdSec consumers that parse that literal suffix are compatible.
	nowISO := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
	scenario := fmt.Sprintf("secubox-waf/%s", cat)

	alert := csAlert{
		Scenario:        scenario,
		ScenarioHash:    "",
		ScenarioVersion: "1",
		Message:         fmt.Sprintf("WAF threshold crossed for %s (%s)", ip, cat),
		EventsCount:     1,
		StartAt:         nowISO,
		StopAt:          nowISO,
		Capacity:        0,
		Leakspeed:       "0s",
		Simulated:       false,
		Source: csAlertSource{
			Scope:     "Ip",
			Value:     ip,
			IP:        ip,
			AsNumber:  "0",
			AsName:    "?",
			Cn:        "?",
			Latitude:  0.0,
			Longitude: 0.0,
		},
		Decisions: []csDecision{{
			Duration:  c.duration,
			Scenario:  scenario,
			Type:      "ban",
			Value:     ip,
			Scope:     "Ip",
			Origin:    "secubox-waf",
			Simulated: false,
		}},
		Events: []csEvent{{
			Timestamp: nowISO,
			Meta: []csEventMeta{
				{Key: "source_ip", Value: ip},
				{Key: "scenario", Value: cat},
			},
		}},
	}

	body, err := json.Marshal([]csAlert{alert})
	if err != nil {
		return fmt.Errorf("marshal alert: %w", err)
	}

	endpoint := c.lapiURL + "/v1/alerts"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.jwt)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("LAPI returned %d for %s (%s)", resp.StatusCode, ip, cat)
	}

	log.Printf("sbxwaf: crowdsec bridge BAN %s ← %s (sev=%s, dur=%s)",
		ip, cat, sev, c.duration)
	return nil
}

// CscliReporter implements CrowdSecReporter by shelling out to `cscli decisions
// add`, the SAME path the WAF dashboard's manual "ban" button uses (and the only
// one proven to create a real, bouncer-enforced nft drop on this platform).
//
// Why not the LAPI /v1/alerts POST above: that path requires a machine JWT that
// expires hourly (fragile as a static file) AND our alert schema is rejected by
// the LAPI with a 500 on this CrowdSec build. cscli reads the local API creds
// directly and always works when sbxwaf runs as root. Report is invoked from a
// goroutine (see main.go), so the ~sub-second exec never touches the hot path.
type CscliReporter struct {
	cscliPath string
	duration  string
	cooldown  time.Duration

	mu     sync.Mutex
	recent map[string]time.Time // ip → last ban-reported time (dedup)
}

// NewCscliReporter builds a reporter that runs `cscliPath decisions add …`.
// A per-IP cooldown collapses the storm caused by the graduated ban firing
// Report on EVERY banned request (not just the threshold transition): a rapid
// attacker would otherwise spawn dozens of concurrent cscli processes for the
// same IP before its nft drop takes effect, contending until they time out.
func NewCscliReporter(cscliPath, duration string) *CscliReporter {
	return &CscliReporter{
		cscliPath: cscliPath,
		duration:  duration,
		cooldown:  5 * time.Minute,
		recent:    make(map[string]time.Time),
	}
}

// Report adds a ban decision for ip via cscli, at most once per cooldown per IP.
// ip/cat are passed as discrete argv elements (never a shell string) so an
// attacker-influenced value cannot inject arguments; ip is already a validated
// client address.
func (r *CscliReporter) Report(ip, cat, sev string) {
	now := time.Now()
	r.mu.Lock()
	if last, ok := r.recent[ip]; ok && now.Sub(last) < r.cooldown {
		r.mu.Unlock()
		return // already reported this IP recently — skip the storm
	}
	r.recent[ip] = now
	if len(r.recent) > 4096 { // opportunistic GC of expired entries
		for k, t := range r.recent {
			if now.Sub(t) > r.cooldown {
				delete(r.recent, k)
			}
		}
	}
	r.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reason := fmt.Sprintf("secubox-waf/%s", cat)
	cmd := exec.CommandContext(ctx, r.cscliPath, "decisions", "add",
		"--ip", ip, "--duration", r.duration, "--reason", reason, "--type", "ban")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("sbxwaf: crowdsec cscli ban failed for %s (%s): %v: %s",
			ip, cat, err, strings.TrimSpace(string(out)))
		// let the next hit past the cooldown retry rather than pinning a failure
		r.mu.Lock()
		delete(r.recent, ip)
		r.mu.Unlock()
		return
	}
	log.Printf("sbxwaf: crowdsec cscli BAN %s ← %s (sev=%s, dur=%s)",
		ip, cat, sev, r.duration)
}
