// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// gabriel-mood — détecteur d'indices prosodiques, entièrement local.
//
// Le micro est celui du navigateur ; l'analyse est ici ; rien ne sort de la
// board et aucun échantillon n'est écrit sur le disque. Voir
// docs/modules/gabriel-mood.md, et surtout l'avertissement en tête du paquet
// `internal/ser` : ce module lit des indices acoustiques, pas des émotions.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/api"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/audio"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/ser"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/store"
)

var version = "dev"

func main() {
	var (
		socket    = flag.String("socket", "/run/secubox/gabriel-mood.sock", "socket unix d'écoute")
		adresse   = flag.String("adresse", "", "adresse TCP (développement ; vide = socket unix)")
		base      = flag.String("db", "/var/lib/secubox/gabriel-mood/mood.db", "historique (vide = aucun)")
		www       = flag.String("www", "/usr/share/secubox/www/gabriel-mood", "racine du cockpit")
		retention = flag.Duration("retention", 14*24*time.Hour, "durée de conservation des résumés (0 = ne rien garder)")
		inference = flag.String("inference", "", "socket d'un service d'inférence externe (facultatif)")
		montre    = flag.Bool("version", false, "afficher la version")
	)
	flag.Parse()
	if *montre {
		fmt.Println("gabriel-mood", version)
		return
	}
	jr := log.New(os.Stderr, "gabriel-mood ", log.LstdFlags)

	// CE QUE LE MODULE ANNONCE DE LUI-MÊME AU DÉMARRAGE. Quelqu'un qui lit un
	// journal doit comprendre sans ouvrir la documentation ce que fait ce
	// service et ce qu'il ne fait pas.
	jr.Printf("version %s — indices prosodiques, analyse locale", version)
	jr.Printf("aucun échantillon audio n'est écrit sur le disque ; "+
		"confiance plafonnée à %.2f ; classifieur heuristique explicable", ser.PlafondConfiance)

	var db *store.Store
	if *base != "" && *retention > 0 {
		if err := os.MkdirAll(filepath.Dir(*base), 0o750); err != nil {
			jr.Fatalf("répertoire de la base : %v", err)
		}
		var err error
		if db, err = store.Ouvre(*base); err != nil {
			jr.Fatalf("base : %v", err)
		}
		defer db.Ferme()
		jr.Printf("historique : %s, conservation %s (agrégats par minute seulement)",
			*base, *retention)
	} else {
		jr.Print("historique DÉSACTIVÉ : rien n'est conservé entre deux sessions")
	}

	// On dit ce qu'on voit du matériel local, même si le micro vient
	// normalement du navigateur : ça évite de chercher une panne là où il n'y
	// a qu'une board sans carte son.
	if peripheriques, motif := audio.EntreesDisponibles(); len(peripheriques) > 0 {
		jr.Printf("entrées locales détectées : %v (non utilisées : le micro vient du navigateur)", peripheriques)
	} else {
		jr.Printf("pas d'entrée locale (%s) — sans effet : le micro vient du navigateur", motif)
	}

	srv := &api.Serveur{
		Sessions: api.NouveauRegistre(db),
		Store:    db,
		Version:  version,
	}
	if st, err := os.Stat(*www); err == nil && st.IsDir() {
		srv.Racine = http.FileServer(http.Dir(*www))
		jr.Printf("cockpit servi depuis %s", *www)
	} else {
		jr.Printf("cockpit absent de %s : l'API reste disponible", *www)
	}
	if *inference != "" {
		jr.Printf("inférence externe : %s (repli sur l'heuristique si elle ne répond pas)", *inference)
	}

	if db != nil && *retention > 0 {
		go purgeQuotidienne(db, *retention, jr)
	}

	ecoute, err := ouvre(*socket, *adresse)
	if err != nil {
		jr.Fatalf("écoute : %v", err)
	}
	http := &http.Server{
		Handler: srv.Routes(),
		// Pas de ReadTimeout : la WebSocket y vit. Les échéances de lecture
		// sont posées par connexion dans ws.go, ce qui est le bon endroit.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	arret := make(chan os.Signal, 1)
	signal.Notify(arret, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-arret
		jr.Print("arrêt demandé")
		ctx, annule := context.WithTimeout(context.Background(), 5*time.Second)
		defer annule()
		http.Shutdown(ctx)
	}()

	jr.Printf("à l'écoute sur %s", ecoute.Addr())
	if err := http.Serve(ecoute); err != nil && !errors.Is(err, net.ErrClosed) &&
		!errors.Is(err, os.ErrClosed) {
		jr.Printf("serveur : %v", err)
	}
	jr.Print("arrêté")
}

// ouvre écoute sur une socket unix (production, derrière nginx) ou en TCP
// (développement). La socket est recréée à chaque démarrage : un fichier
// résiduel d'un processus mort empêcherait l'écoute.
func ouvre(socket, adresse string) (net.Listener, error) {
	if adresse != "" {
		return net.Listen("tcp", adresse)
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(socket)
	l, err := net.Listen("unix", socket)
	if err != nil {
		return nil, err
	}
	// nginx tourne sous un autre utilisateur : sans ces droits, il obtient un
	// 502 et l'on cherche longtemps du côté de la configuration.
	if err := os.Chmod(socket, 0o660); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func purgeQuotidienne(db *store.Store, retention time.Duration, jr *log.Logger) {
	// UN HISTORIQUE QUI NE S'EFFACE PAS EST UN DOSSIER. Première passe tout de
	// suite : si la rétention vient d'être raccourcie, l'effet doit être
	// immédiat, pas dans vingt-quatre heures.
	for {
		if n, err := db.Purge(time.Now().Add(-retention)); err != nil {
			jr.Printf("purge : %v", err)
		} else if n > 0 {
			jr.Printf("purge : %d résumés retirés (au-delà de %s)", n, retention)
		}
		time.Sleep(24 * time.Hour)
	}
}
