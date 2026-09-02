// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxdpi :: emancipated DPI aggregator daemon
//
// sbxdpi is the Go-level layer over nDPId (the FOSS C capture engine). nDPId
// classifies flows on the wire and ships newline-framed JSON to nDPIsrvd (its
// C distributor); sbxdpi *dials* nDPIsrvd's distributor unix socket as a
// read-only consumer, applies our go-level filtering (first-party exemption,
// deny/allow lists, risk muting — the same declarative *.txt conffile pattern
// as sbxwaf/sbx-sentinel), aggregates protocol/app/category/talker/risk stats
// in memory, flushes an atomic JSON snapshot to /var/cache/secubox/dpi, and
// serves a read-only /api/v1/dpi/ HTTP surface over /run/secubox/dpi-live.sock
// for the Hall DPI cardlet (fronted by nginx + FastAPI JWT, per project model).
//
// Fail-safe by construction, mirroring sbx-sentinel:
//   - the distributor connection is dial-with-backoff and auto-reconnects; a
//     down/absent nDPIsrvd just means "no fresh flows", never a daemon exit;
//   - a malformed framed message is logged and skipped — the stream keeps
//     serving the remaining messages;
//   - context cancellation closes the API listener, stops the flusher, and
//     drops the distributor reader, returning cleanly with no goroutine leak.
//
// This is a capture-consumer only: it never writes to the wire, never needs
// CAP_NET_ADMIN, and holds no PII — aggregate counters keyed by protocol and
// by ip-pair only.
package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Default tuning, overridable via Config for production and tests alike.
const (
	defaultFlushInterval = 30 * time.Second
	defaultDialBackoff   = 3 * time.Second
	defaultReloadEvery = 15 * time.Second
	// 0666: the socket serves read-only, non-PII aggregate counters and is
	// fronted by nginx (JWT) on the same box; a world-readable local socket
	// avoids a cross-group chown the unprivileged daemon user cannot perform.
	defaultAPISockMode = 0o666
)

// Config configures one run of the sbxdpi daemon. Every field is injectable so
// run is testable end-to-end with a temp distributor socket, a temp API
// socket, and a temp cache file.
type Config struct {
	// DistributorSock is the nDPIsrvd distributor unix socket sbxdpi DIALS to
	// receive the framed flow-event JSON stream. Absent/down is tolerated
	// (dial-with-backoff).
	DistributorSock string
	// APISock is the unix socket sbxdpi LISTENS on to serve the read-only
	// /api/v1/dpi/ HTTP surface. Chmod'd to APISockMode after listen so the
	// nginx/portal user (a shared group) can reach it without world access.
	APISock     string
	APISockMode os.FileMode
	// CachePath is the atomic JSON snapshot the flusher rewrites every
	// FlushInterval — the warm-start/last-known source the API falls back to.
	CachePath     string
	FlushInterval time.Duration
	// DialBackoff is the reconnect delay between distributor dial attempts.
	DialBackoff time.Duration

	// Filter file paths (go-level filtering, hot-reloaded on mtime change).
	AllowFile   string // apps/hosts to always keep even when otherwise muted
	DenyFile    string // apps/hosts/protocols to drop from the stats entirely
	RiskMute    string // nDPI risk ids/names to not surface (noise reduction)
	BoxDomains  string // haproxy-routes.json — first-party (our own vhosts)
	RulesFile   string // règles d'enrichissement usage/app/infra (DPI sémantique)
	ReloadEvery time.Duration

	// onReady, if set, is called once the API listener is up (test hook).
	onReady func()
}

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDurationDefault(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Printf("sbxdpi: bad %s=%q (%v), using default %s", key, v, err, def)
		return def
	}
	return d
}

// defaultConfig assembles the production Config from the environment (DPI_* —
// a single /etc/secubox/dpi.env conffile drives the daemon).
func defaultConfig() Config {
	return Config{
		DistributorSock: getenvDefault("DPI_DISTRIBUTOR_SOCK", "/run/secubox/ndpi/distributor.sock"),
		APISock:         getenvDefault("DPI_API_SOCK", "/run/secubox/dpi-live.sock"),
		APISockMode:     defaultAPISockMode,
		CachePath:       getenvDefault("DPI_STATS_CACHE", "/data/secubox/sbxdpi/stats.json"),
		FlushInterval:   envDurationDefault("DPI_FLUSH_INTERVAL", defaultFlushInterval),
		DialBackoff:     envDurationDefault("DPI_DIAL_BACKOFF", defaultDialBackoff),
		AllowFile:       getenvDefault("DPI_ALLOW_FILE", "/etc/secubox/dpi/app-allow.txt"),
		DenyFile:        getenvDefault("DPI_DENY_FILE", "/etc/secubox/dpi/app-deny.txt"),
		RiskMute:        getenvDefault("DPI_RISK_MUTE", "/etc/secubox/dpi/risk-mute.txt"),
		BoxDomains:      getenvDefault("DPI_BOX_DOMAINS", "/etc/secubox/waf/haproxy-routes.json"),
		RulesFile:       getenvDefault("DPI_RULES_FILE", "/etc/secubox/dpi/rules.json"),
		ReloadEvery:     envDurationDefault("DPI_RELOAD_EVERY", defaultReloadEvery),
	}
}

func withDefaults(cfg Config) Config {
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaultFlushInterval
	}
	if cfg.DialBackoff <= 0 {
		cfg.DialBackoff = defaultDialBackoff
	}
	if cfg.ReloadEvery <= 0 {
		cfg.ReloadEvery = defaultReloadEvery
	}
	if cfg.APISockMode == 0 {
		cfg.APISockMode = defaultAPISockMode
	}
	return cfg
}

// run starts the daemon and blocks until ctx is cancelled. On a clean
// context-cancel shutdown it returns nil after the API server, flusher, and
// distributor reader have all exited (no goroutine leak).
func run(ctx context.Context, cfg Config) error {
	cfg = withDefaults(cfg)

	agg := newAggregator()
	// Warm-start from the last snapshot so the API is non-empty across a
	// restart before the first flush (fail-safe: unreadable → empty agg).
	agg.loadSnapshot(cfg.CachePath)

	filt := newFilter(cfg)
	enr := newEnricher(cfg.RulesFile, cfg.ReloadEvery)
	sess := newSessionTracker(enr)

	var wg sync.WaitGroup

	// 1) Distributor reader — dial-with-backoff, reconnecting, framed JSON.
	wg.Add(1)
	go func() {
		defer wg.Done()
		consumeDistributor(ctx, cfg, agg, filt, sess)
	}()

	// 2) Periodic atomic snapshot flush.
	wg.Add(1)
	go func() {
		defer wg.Done()
		flushLoop(ctx, cfg, agg)
	}()

	// 3) Read-only /api/v1/dpi/ HTTP surface over the aggregator unix socket.
	_ = os.Remove(cfg.APISock) // clear a stale socket from an unclean exit
	ln, err := net.Listen("unix", cfg.APISock)
	if err != nil {
		return err
	}
	if err := os.Chmod(cfg.APISock, cfg.APISockMode); err != nil {
		log.Printf("sbxdpi: chmod %q: %v (continuing)", cfg.APISock, err)
	}
	srv := &http.Server{
		Handler:           newDPIMux(agg, filt, enr, sess),
		ReadHeaderTimeout: 5 * time.Second,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		sdCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sdCtx)
	}()

	if cfg.onReady != nil {
		cfg.onReady()
	}

	err = srv.Serve(ln)
	if err == http.ErrServerClosed {
		err = nil
	}
	// A final snapshot on the way out so a restart warm-starts from fresh data.
	agg.writeSnapshot(cfg.CachePath)
	wg.Wait()
	return err
}

func main() {
	cfg := defaultConfig()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg); err != nil {
		log.Fatalf("sbxdpi: %v", err)
	}
}
