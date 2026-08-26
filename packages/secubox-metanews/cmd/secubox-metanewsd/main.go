// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// secubox-metanewsd : démon MetaNews — agrège des flux RSS/Atom, regroupe en
// événements, expose une API + une UI sur une socket unix.
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
	"strings"
	"syscall"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/linker"
	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/pipeline"
	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/store"
	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/web"
)

var version = "dev"

func main() {
	var (
		socket   = flag.String("socket", "/run/secubox/metanews.sock", "socket unix d'écoute")
		base     = flag.String("db", "/var/lib/secubox/metanews/metanews.db", "base SQLite")
		conf     = flag.String("conf", "/etc/secubox/secubox.conf", "config (pour api.jwt_secret)")
		jwtFlag  = flag.String("jwt-secret", "", "secret JWT de flotte (sinon lu du conf)")
		bbsSock  = flag.String("bbs-socket", "/run/secubox/bbs.sock", "socket du BBS (pour Discuter)")
		bbsCat   = flag.String("bbs-cat", "actualites", "slug de catégorie BBS des fils MetaNews")
		pollSec  = flag.Int("poll", 300, "période de sondage des flux, en secondes")
		montre   = flag.Bool("version", false, "afficher la version")
	)
	flag.Parse()
	if *montre {
		fmt.Println("secubox-metanewsd", version)
		return
	}
	jr := log.New(os.Stderr, "metanews ", log.LstdFlags)

	secret := *jwtFlag
	if secret == "" {
		secret = jwtDepuisConf(*conf)
	}

	st, err := store.Open(*base)
	if err != nil {
		jr.Fatalf("base : %v", err)
	}
	defer st.Close()
	seed(st, jr)

	rss := linker.NewRSS(gardeReseau)
	pipe := pipeline.New(st, rss, jr)
	srv := web.New(st, pipe, web.Options{JWTSecret: secret, BBSSocket: *bbsSock, BBSCat: *bbsCat}, jr, version)

	// Boucle de sondage en arrière-plan (double-cache : la donnée peut être
	// périmée de quelques minutes sans impact).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go boucle(ctx, pipe, time.Duration(*pollSec)*time.Second, jr)

	_ = os.Remove(*socket)
	ln, err := net.Listen("unix", *socket)
	if err != nil {
		jr.Fatalf("socket : %v", err)
	}
	if err := os.Chmod(*socket, 0o660); err != nil {
		jr.Printf("chmod socket : %v", err)
	}
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		cx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = hs.Shutdown(cx)
	}()
	jr.Printf("metanews %s à l'écoute sur %s (poll %ds)", version, *socket, *pollSec)
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		jr.Fatalf("serve : %v", err)
	}
}

func boucle(ctx context.Context, pipe *pipeline.Pipe, every time.Duration, jr *log.Logger) {
	tour := func() {
		n, t, err := pipe.Tour(time.Now().Unix())
		if err != nil {
			jr.Printf("tour : %v", err)
			return
		}
		if n > 0 || t > 0 {
			jr.Printf("tour : %d articles neufs, %d sujets touchés", n, t)
		}
	}
	tour() // un premier tour au démarrage
	tk := time.NewTicker(every)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			tour()
		}
	}
}

// gardeReseau : garde anti-SSRF minimale — refuse loopback / privé / lien-local.
func gardeReseau(hote string) error {
	if hote == "" || strings.EqualFold(hote, "localhost") || strings.HasSuffix(hote, ".local") {
		return errors.New("hôte interne refusé")
	}
	ips, err := net.LookupIP(hote)
	if err != nil {
		return fmt.Errorf("résolution %q : %w", hote, err)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("adresse interne refusée : %s", ip)
		}
	}
	return nil
}

// jwtDepuisConf lit api.jwt_secret dans le fichier de config (parse minimal).
func jwtDepuisConf(chemin string) string {
	b, err := os.ReadFile(chemin)
	if err != nil {
		return ""
	}
	for _, ligne := range strings.Split(string(b), "\n") {
		l := strings.TrimSpace(ligne)
		if strings.HasPrefix(l, "jwt_secret") {
			if i := strings.Index(l, "="); i >= 0 {
				return strings.Trim(strings.TrimSpace(l[i+1:]), "\"'")
			}
		}
	}
	return ""
}

// seed : pose les flux publics manquants. IDEMPOTENT (#1360) — il tournait
// jadis « seulement si aucune source », si bien qu'ajouter un flux au code ne
// l'ajoutait jamais a une box deja semee. Desormais il ajoute par SLUG ce qui
// manque, a chaque demarrage, sans toucher a ce que l'operateur a regle.
func seed(st *store.Store, jr *log.Logger) {
	srcs, err := st.Sources()
	if err != nil {
		return
	}
	vus := make(map[string]bool, len(srcs))
	for _, x := range srcs {
		vus[x.Slug] = true
	}
	defauts := []store.Source{
		// FR
		{Slug: "franceinfo", Name: "France Info", URL: "https://www.francetvinfo.fr/titres.rss", Enabled: true, Category: "general"},
		{Slug: "lemonde-une", Name: "Le Monde — Une", URL: "https://www.lemonde.fr/rss/une.xml", Enabled: true, Category: "general"},
		{Slug: "liberation", Name: "Libération", URL: "https://www.liberation.fr/arc/outboundfeeds/rss/?outputType=xml", Enabled: true, Category: "general"},
		{Slug: "bfmtv", Name: "BFMTV", URL: "https://www.bfmtv.com/rss/news-24-7/", Enabled: true, Category: "general"},
		{Slug: "lefigaro", Name: "Le Figaro", URL: "https://www.lefigaro.fr/rss/figaro_actualites.xml", Enabled: true, Category: "general"},
		// UK / US / EU
		{Slug: "bbc-world", Name: "BBC News (World)", URL: "https://feeds.bbci.co.uk/news/world/rss.xml", Enabled: true, Category: "international"},
		{Slug: "guardian-world", Name: "The Guardian (World)", URL: "https://www.theguardian.com/world/rss", Enabled: true, Category: "international"},
		{Slug: "npr-news", Name: "NPR News", URL: "https://feeds.npr.org/1001/rss.xml", Enabled: true, Category: "international"},
		// tech / cyber
		{Slug: "numerama", Name: "Numerama", URL: "https://www.numerama.com/feed/", Enabled: true, Category: "tech"},
		{Slug: "arstechnica", Name: "Ars Technica", URL: "https://feeds.arstechnica.com/arstechnica/index", Enabled: true, Category: "tech"},
		{Slug: "zataz", Name: "ZATAZ", URL: "https://www.zataz.com/feed/", Enabled: true, Category: "cyber"},
		// local (Savoie)
		{Slug: "ledauphine-savoie", Name: "Le Dauphiné — Savoie", URL: "https://www.ledauphine.com/savoie/rss", Enabled: true, Category: "local"},
		// FR — presse indépendante et d'enquête (#1360)
		{Slug: "mediapart", Name: "Mediapart", URL: "https://www.mediapart.fr/articles/feed", Enabled: true, Category: "general"},
		{Slug: "reporterre", Name: "Reporterre", URL: "https://reporterre.net/spip.php?page=backend", Enabled: true, Category: "general"},
		{Slug: "basta", Name: "Basta!", URL: "https://basta.media/spip.php?page=backend", Enabled: true, Category: "general"},
		{Slug: "humanite", Name: "L'Humanité", URL: "https://www.humanite.fr/rss/actu.rss", Enabled: true, Category: "general"},
		{Slug: "lepoint", Name: "Le Point", URL: "https://www.lepoint.fr/rss.xml", Enabled: true, Category: "general"},
		{Slug: "slate-fr", Name: "Slate", URL: "https://www.slate.fr/rss.xml", Enabled: true, Category: "general"},
		{Slug: "courrier-inter", Name: "Courrier International", URL: "https://www.courrierinternational.com/feed/all/rss.xml", Enabled: true, Category: "international"},
		{Slug: "france-culture", Name: "France Culture", URL: "https://www.radiofrance.fr/franceculture/rss", Enabled: true, Category: "general"},
		{Slug: "alter-eco", Name: "Alternatives Économiques", URL: "https://www.alternatives-economiques.fr/rss.xml", Enabled: true, Category: "general"},
		{Slug: "france-inter", Name: "France Inter", URL: "https://www.radiofrance.fr/franceinter/rss", Enabled: true, Category: "general"},
		{Slug: "tv5monde", Name: "TV5Monde Info", URL: "https://information.tv5monde.com/rss.xml", Enabled: true, Category: "international"},
		{Slug: "afp-factuel", Name: "AFP Factuel", URL: "https://factuel.afp.com/list/all/feed", Enabled: true, Category: "general"},
		// NB : Charlie Hebdo n'expose pas de flux RSS public fiable — non ajouté.
	}
	n := 0
	for _, so := range defauts {
		if vus[so.Slug] {
			continue // deja present : on n'y touche pas
		}
		if _, err := st.AddSource(so); err != nil {
			jr.Printf("seed %s : %v", so.Slug, err)
			continue
		}
		n++
	}
	if n > 0 {
		jr.Printf("seed : %d flux publics ajoutés", n)
	}
}
