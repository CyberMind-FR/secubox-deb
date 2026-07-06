// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbx-sentinel :: async analyzer daemon (#823)
//
// sbx-sentinel is the async counterpart to sbxmitm's inline IOC gate: it
// listens on the local unix socket sbxmitm's Mirror ships flow observations
// to (newline-delimited JSON internal/sentinel.MirrorMsg), runs every
// configured Analyzer against each decoded message, finalizes each returned
// Verdict through sentinel.FinalizeAction (defense in depth — an analyzer
// that mis-declares a block action on a heuristic still gets downgraded),
// and records the result in the bbolt-backed Store. A periodic ticker prunes
// the store to its configured TTL.
//
// Tasks 9/10/11 (YARA, behavioral, spyware) plug their engines in as
// Analyzers — this file only owns the daemon: socket handling, the
// per-message pipeline, and store/prune wiring. This scaffold ships with no
// analyzers configured (an empty slice is a valid, inert daemon).
//
// Fail-safe by construction:
//   - a malformed JSON line on a connection is logged and skipped — the
//     connection keeps serving the remaining lines, other connections are
//     unaffected;
//   - a panicking Analyzer is recovered per-message — one bad analyzer never
//     takes down the daemon or blocks other analyzers/messages;
//   - context cancellation closes the listener and drains in-flight
//     connections/goroutines before returning, so the daemon shuts down
//     cleanly with no goroutine leak.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/sentinel"
)

// Analyzer is the extension point for the async detection engines (Tasks
// 9/10/11: YARA, behavioral, spyware). Each Analyzer inspects one mirrored
// flow observation and returns zero or more Verdicts. The daemon treats
// every Analyzer as untrusted: Analyze is always called under recover (see
// safeAnalyze), so a panicking analyzer degrades to "no verdicts for this
// message" rather than taking the daemon down.
type Analyzer interface {
	Analyze(sentinel.MirrorMsg) []*sentinel.Verdict
}

// Default tuning, overridable via Config for production and tests alike.
const (
	defaultTTL           = 72 * time.Hour
	defaultPruneInterval = 5 * time.Minute
	scannerMaxLine       = 1 << 20 // 1 MiB — generous headroom over the Mirror's bodyCap
)

// Config configures one run of the sbx-sentinel daemon. Every field is
// injectable so run is testable end-to-end with a temp socket, a temp bbolt
// db, and a stub Analyzer.
type Config struct {
	// SocketPath is the unix socket to listen on — the same path sbxmitm's
	// Mirror is configured to dial.
	SocketPath string
	// DBPath is the bbolt verdict store file.
	DBPath string
	// TTL is how long a verdict is retained; PruneInterval controls how
	// often the background Prune sweep runs. Zero values fall back to
	// defaultTTL / defaultPruneInterval.
	TTL           time.Duration
	PruneInterval time.Duration
	// Analyzers is the detection pipeline run against every decoded
	// MirrorMsg, in order. Nil/empty is a valid scaffold — no verdicts are
	// produced, but the socket/store/prune plumbing still runs.
	Analyzers []Analyzer

	// HTTPAddr, when non-empty, stands up a read-only status HTTP server
	// (see http.go: /stats and /verdicts) bound to this address. Empty (the
	// default) means no HTTP surface — the daemon is socket-only. Exposed
	// solely for a local operator/portal read; carries no PII beyond
	// mac_hash and never accepts writes.
	HTTPAddr string

	// onStoreOpen, if set, is called once with the daemon's own *Store
	// handle right after it is opened (before the listener is stood up).
	// It exists solely so tests can query the live store (bbolt takes an
	// exclusive file lock, so a second OpenStore on the same DBPath would
	// deadlock/timeout) — production callers leave it nil.
	onStoreOpen func(*sentinel.Store)
}

func withDefaults(cfg Config) Config {
	if cfg.TTL <= 0 {
		cfg.TTL = defaultTTL
	}
	if cfg.PruneInterval <= 0 {
		cfg.PruneInterval = defaultPruneInterval
	}
	return cfg
}

// run starts the daemon and blocks until ctx is cancelled or an
// unrecoverable setup/accept error occurs. On a clean context-cancel
// shutdown it returns nil after every accepted connection and background
// goroutine has exited (no goroutine leak).
func run(ctx context.Context, cfg Config) error {
	cfg = withDefaults(cfg)

	store, err := sentinel.OpenStore(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("sbx-sentinel: open store: %w", err)
	}
	defer store.Close()

	if cfg.onStoreOpen != nil {
		cfg.onStoreOpen(store)
	}

	// A stale socket file from a prior unclean shutdown must not block
	// Listen.
	_ = os.Remove(cfg.SocketPath)

	ln, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("sbx-sentinel: listen %q: %w", cfg.SocketPath, err)
	}

	var wg sync.WaitGroup

	// Closing the listener on ctx-cancel is what unblocks Accept below for
	// a clean shutdown.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		ln.Close()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		prunLoop(ctx, store, cfg.PruneInterval, cfg.TTL)
	}()

	// Optional read-only status HTTP surface (off unless HTTPAddr is set).
	if cfg.HTTPAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			serveStatus(ctx, cfg.HTTPAddr, store)
		}()
	}

	var connWG sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			connWG.Wait()
			wg.Wait()
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("sbx-sentinel: accept: %w", err)
			}
		}
		connWG.Add(1)
		go func() {
			defer connWG.Done()
			handleConn(ctx, conn, store, cfg.Analyzers)
		}()
	}
}

// prunLoop runs Store.Prune(ttl) every interval until ctx is cancelled.
func prunLoop(ctx context.Context, store *sentinel.Store, interval, ttl time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := store.Prune(ttl); err != nil {
				log.Printf("sbx-sentinel: prune failed: %v", err)
			}
		}
	}
}

// handleConn decodes newline-delimited JSON MirrorMsg values off conn until
// EOF, a read error, or ctx cancellation, running the analyzer pipeline for
// each successfully decoded message. A malformed line is logged and
// skipped — it never terminates the connection.
func handleConn(ctx context.Context, conn net.Conn, store *sentinel.Store, analyzers []Analyzer) {
	defer conn.Close()

	// Ensure a ctx-cancel unblocks a connection that is idle mid-read.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stop:
		}
	}()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), scannerMaxLine)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var msg sentinel.MirrorMsg
		if err := json.Unmarshal(line, &msg); err != nil {
			log.Printf("sbx-sentinel: skipping malformed line: %v", err)
			continue
		}

		processMsg(store, analyzers, msg)
	}

	if err := scanner.Err(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("sbx-sentinel: connection read error: %v", err)
	}
}

// processMsg runs every analyzer against msg, finalizes each returned
// Verdict's Action (defense in depth against a misbehaving analyzer — see
// sentinel.FinalizeAction), and records it to store.
func processMsg(store *sentinel.Store, analyzers []Analyzer, msg sentinel.MirrorMsg) {
	for _, a := range analyzers {
		for _, v := range safeAnalyze(a, msg) {
			if v == nil {
				continue
			}
			v.Action = sentinel.FinalizeAction(v)
			if err := store.Record(v); err != nil {
				log.Printf("sbx-sentinel: record verdict failed: %v", err)
			}
		}
	}
}

// safeAnalyze calls a.Analyze(msg) under recover: a panicking Analyzer
// yields no verdicts for this message instead of taking the daemon down.
func safeAnalyze(a Analyzer, msg sentinel.MirrorMsg) (verdicts []*sentinel.Verdict) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("sbx-sentinel: analyzer panicked (recovered, fail-safe): %v", r)
			verdicts = nil
		}
	}()
	return a.Analyze(msg)
}

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envDurationDefault parses key as a Go duration (e.g. "72h"), falling back to
// def on an unset/empty/unparsable value.
func envDurationDefault(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Printf("sbx-sentinel: bad %s=%q (%v), using default %s", key, v, err, def)
		return def
	}
	return d
}

// splitPaths splits an os-path-list-style value (":"-separated) into a clean
// slice, dropping empty entries. Used for SENTINEL_YARA_RULES.
func splitPaths(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ":") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// buildAnalyzers constructs the production detection pipeline: the
// commercial-spyware IOC correlator (backed by a pack Loader over
// packDir/overlayDir), the behavioral heuristic engine, and the YARA engine
// (the no-cgo stub in the default build; the libyara-backed engine under
// `-tags yara`). It is resilient: a failure to build the pack loader or the
// YARA engine is returned (joined) but does NOT drop the analyzers that could
// be built — a bad base pack must not silently disable the behavioral engine,
// which needs no pack. The happy path (readable/empty dirs) returns all three.
func buildAnalyzers(packDir, overlayDir string, yaraRules []string) ([]Analyzer, error) {
	var analyzers []Analyzer
	var errs []error

	loader, err := sentinel.NewLoader(packDir, overlayDir)
	if err != nil {
		errs = append(errs, fmt.Errorf("pack loader (spyware analyzer disabled): %w", err))
	} else {
		analyzers = append(analyzers, sentinel.NewSpyware(loader))
	}

	analyzers = append(analyzers, sentinel.NewBehavioral())

	yara, err := sentinel.NewYaraEngine(yaraRules)
	if err != nil {
		errs = append(errs, fmt.Errorf("yara engine (yara analyzer disabled): %w", err))
	} else {
		analyzers = append(analyzers, yara)
	}

	return analyzers, errors.Join(errs...)
}

// defaultConfig assembles the production Config from the environment
// (SENTINEL_* — same names sbxmitm's gate reads, so a single env file
// configures both binaries) and constructs the real analyzer pipeline. An
// analyzer-construction error is logged (fail-safe) but never aborts the
// daemon: the socket/store/prune plumbing plus whatever analyzers were built
// still run.
func defaultConfig() Config {
	packDir := getenvDefault("SENTINEL_PACK_DIR", "/usr/share/secubox/sentinel/packs/base")
	overlayDir := getenvDefault("SENTINEL_OVERLAY_DIR", "/var/lib/secubox/sentinel/overlay")
	yaraRules := splitPaths(os.Getenv("SENTINEL_YARA_RULES"))

	analyzers, err := buildAnalyzers(packDir, overlayDir, yaraRules)
	if err != nil {
		log.Printf("sbx-sentinel: analyzer construction degraded (fail-safe, daemon continues): %v", err)
	}

	return Config{
		SocketPath:    getenvDefault("SENTINEL_MIRROR_SOCK", "/run/secubox/sentinel-mirror.sock"),
		DBPath:        getenvDefault("SENTINEL_STORE_DB", "/var/lib/secubox/sentinel/verdicts.db"),
		TTL:           envDurationDefault("SENTINEL_TTL", defaultTTL),
		PruneInterval: defaultPruneInterval,
		Analyzers:     analyzers,
		HTTPAddr:      os.Getenv("SENTINEL_HTTP_ADDR"),
	}
}

func main() {
	cfg := defaultConfig()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		log.Fatalf("sbx-sentinel: %v", err)
	}
}
