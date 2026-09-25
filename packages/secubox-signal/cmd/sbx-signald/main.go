// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// sbx-signald — point d'entree de la passerelle Signal (#1309).
//
// RECONSTRUIT (#1385). Le main.go d'origine n'a jamais ete commite : le
// .gitignore ignorait « sbx-signald » sans ancrage, donc aussi ce dossier.
// Cette version est refaite depuis les paquets internal/, l'essai
// d'integration (tests/integration/smoke.sh, qui en est la specification) et
// le binaire 0.1.6 deploye sur gk2 : memes fermetures (purge, arret du
// serveur, relais sentinelle), memes messages de journal, meme notification
// systemd, meme socket en 0660.
//
// Ce que fait ce fichier, et rien d'autre : lire la configuration, ouvrir la
// base, lancer signal-cli, servir l'API sur la socket Unix, relayer les
// alertes sentinelle, purger selon la retention, s'arreter proprement.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-signal/internal/api"
	"github.com/CyberMind-FR/secubox-deb/secubox-signal/internal/config"
	"github.com/CyberMind-FR/secubox-deb/secubox-signal/internal/jeton"
	"github.com/CyberMind-FR/secubox-deb/secubox-signal/internal/sentinel"
	"github.com/CyberMind-FR/secubox-deb/secubox-signal/internal/signalcli"
	"github.com/CyberMind-FR/secubox-deb/secubox-signal/internal/store"
	"github.com/CyberMind-FR/secubox-deb/secubox-signal/internal/ws"
)

// La chaine du secret JWT est celle du parc : SECUBOX_JWT_SECRET, puis
// api.jwt_secret dans ce fichier.
const confParc = "/etc/secubox/secubox.conf"

func main() {
	chemin := flag.String("config", "/etc/secubox/signal.toml", "fichier de configuration")
	flag.Parse()
	log.SetFlags(0) // journald horodate deja

	if _, err := os.Stat(*chemin); errors.Is(err, os.ErrNotExist) {
		log.Printf("%s absent — valeurs par defaut", *chemin)
	}
	cfg, err := config.Load(*chemin)
	if err != nil {
		log.Fatalf("configuration : %v", err)
	}

	jwt := jeton.Nouveau(confParc)
	if !jwt.Arme() {
		log.Printf("ATTENTION : aucun secret JWT (api.jwt_secret ou SECUBOX_JWT_SECRET) — toutes les routes protegees repondront 401")
	}

	ctx, arreter := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer arreter()
	// ExecReload envoie SIGHUP. Sans cette ligne, le comportement par defaut
	// de Go serait de TUER le processus sur un « reload ». Rien ici ne se
	// recharge a chaud : on le dit, on ne meurt pas.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			log.Printf("SIGHUP : rien a recharger a chaud — redemarrer l'unite pour relire %s", *chemin)
		}
	}()

	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		log.Fatalf("etat : %v", err)
	}
	st, err := store.Open(filepath.Join(cfg.StateDir, "signal.db"), cfg.StoreBody)
	if err != nil {
		log.Fatalf("base : %v", err)
	}
	defer st.Close()

	// Le backend peut manquer (paquet moteur absent, JVM en echec) : le demon
	// reste joignable et le DIT (healthz → backend « unlinked », appels →
	// « backend signal-cli non demarre »). Un module muet se diagnostique
	// plus mal qu'un module qui se plaint.
	cli := signalcli.New(cfg.SignalCLI, filepath.Join(cfg.StateDir, "cli"),
		time.Duration(cfg.TimeoutSec)*time.Second)
	if err := cli.Start(ctx); err != nil {
		log.Printf("backend : %v", err)
	}
	defer cli.Stop()

	hub := ws.NewHub()
	a := api.New(cfg, cli, st, hub, jwt)

	// RETENTION : une purge au demarrage, puis toutes les heures.
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			if n, err := st.Purge(cfg.RetentionHours); err != nil {
				log.Printf("retention : %v", err)
			} else if n > 0 {
				log.Printf("retention : %d message(s) purge(s)", n)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	if cfg.SentinelEnabled {
		relais := sentinel.New(cfg.SentinelSocket, cfg.SentinelDest, cfg.SentinelMaxHour, a)
		go relais.Run(ctx)
	}

	// SOCKET : une socket orpheline d'un arret brutal empecherait l'ecoute.
	_ = os.Remove(cfg.SocketPath)
	ln, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		log.Fatalf("ecoute : %v", err)
	}
	// 0660 : UMask=0077 la creerait en 0600, illisible pour nginx (www-data,
	// membre du groupe `secubox`, groupe primaire de l'unite). chmod n'est
	// pas @privileged : le filtre d'appels systeme le laisse passer.
	if err := os.Chmod(cfg.SocketPath, 0o660); err != nil {
		log.Fatalf("ecoute : %v", err)
	}

	srv := &http.Server{Handler: a.Routes(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		fin, annule := context.WithTimeout(context.Background(), 5*time.Second)
		defer annule()
		_ = srv.Shutdown(fin)
	}()

	log.Printf("sbx-signald %s a l'ecoute sur %s", api.Version, cfg.SocketPath)
	notifierSystemd("READY=1")

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("service : %v", err)
		os.Exit(1)
	}
	notifierSystemd("STOPPING=1")
	_ = os.Remove(cfg.SocketPath)
	log.Printf("arret propre")
}

// notifierSystemd parle le protocole sd_notify sans dependance : un
// datagramme sur $NOTIFY_SOCKET (Type=notify dans l'unite). Hors systemd,
// la variable est absente et l'appel ne fait rien.
func notifierSystemd(etat string) {
	s := os.Getenv("NOTIFY_SOCKET")
	if s == "" {
		return
	}
	if s[0] == '@' { // socket abstraite
		s = "\x00" + s[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: s, Net: "unixgram"})
	if err != nil {
		log.Printf("sd_notify : %v", err)
		return
	}
	defer c.Close()
	_, _ = c.Write([]byte(etat))
}
