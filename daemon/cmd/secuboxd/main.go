// SecuBox Mesh Daemon
// CyberMind — SecuBox-Deb — 2026
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cybermind/secubox-deb/internal/control"
	"github.com/cybermind/secubox-deb/internal/discovery"
	"github.com/cybermind/secubox-deb/internal/identity"
	"github.com/cybermind/secubox-deb/internal/telemetry"
	"github.com/cybermind/secubox-deb/internal/topology"
	"github.com/cybermind/secubox-deb/pkg/config"
)

var (
	configPath = flag.String("config", "/etc/secubox/secuboxd.yaml", "Path to config file")
	debug      = flag.Bool("debug", false, "Enable debug logging")
)

func main() {
	flag.Parse()

	// Setup logging
	logLevel := slog.LevelInfo
	if *debug {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	slog.Info("secuboxd starting", "version", "0.1.0", "config", *configPath)

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize modules
	ident, err := identity.New(cfg.Node.Keypair, cfg.Node.DID)
	if err != nil {
		slog.Error("failed to initialize identity", "error", err)
		os.Exit(1)
	}

	disco, err := discovery.New(cfg.Mesh.MDNSService, cfg.Mesh.BeaconInterval)
	if err != nil {
		slog.Error("failed to initialize discovery", "error", err)
		os.Exit(1)
	}

	topo, err := topology.New(cfg.Mesh.Subnet, cfg.Node.Role)
	if err != nil {
		slog.Error("failed to initialize topology", "error", err)
		os.Exit(1)
	}

	telem, err := telemetry.New(cfg.Telemetry.DB, cfg.Telemetry.Interval)
	if err != nil {
		slog.Error("failed to initialize telemetry", "error", err)
		os.Exit(1)
	}

	// Start modules
	if err := ident.Start(ctx); err != nil {
		slog.Error("failed to start identity", "error", err)
		os.Exit(1)
	}

	if err := disco.Start(ctx); err != nil {
		slog.Error("failed to start discovery", "error", err)
		os.Exit(1)
	}

	if err := topo.Start(ctx); err != nil {
		slog.Error("failed to start topology", "error", err)
		os.Exit(1)
	}

	if err := telem.Start(ctx); err != nil {
		slog.Error("failed to start telemetry", "error", err)
		os.Exit(1)
	}

	// Start control server
	ctrlSock := "/run/secuboxd/topo.sock"
	ctrl := control.New(ctrlSock, ident, disco, topo, telem)
	if err := ctrl.Start(ctx); err != nil {
		slog.Error("failed to start control server", "error", err)
		os.Exit(1)
	}

	slog.Info("secuboxd started", "role", cfg.Node.Role, "did", cfg.Node.DID)

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-sigCh
		switch sig {
		case syscall.SIGHUP:
			slog.Info("reloading configuration")
			newCfg, err := config.Load(*configPath)
			if err != nil {
				slog.Error("failed to reload config", "error", err)
				continue
			}
			cfg = newCfg
			// TODO: propagate config changes to modules
		case syscall.SIGINT, syscall.SIGTERM:
			slog.Info("shutting down")
			cancel()
			// Graceful shutdown
			ctrl.Stop()
			telem.Stop()
			topo.Stop()
			disco.Stop()
			ident.Stop()
			slog.Info("secuboxd stopped")
			os.Exit(0)
		}
	}
}
