// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// secubox-socialrelayd : démon SocialRelay — relaie des sources sociales
// (fediverse open, Facebook Graph consent, ponts) en cachant leurs médias en
// local, et en ouvrant un fil BBS par post.
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

	"github.com/CyberMind-FR/secubox-deb/secubox-socialrelay/internal/fbauth"
	"github.com/CyberMind-FR/secubox-deb/secubox-socialrelay/internal/linker"
	"github.com/CyberMind-FR/secubox-deb/secubox-socialrelay/internal/mediacache"
	"github.com/CyberMind-FR/secubox-deb/secubox-socialrelay/internal/pipeline"
	"github.com/CyberMind-FR/secubox-deb/secubox-socialrelay/internal/store"
	"github.com/CyberMind-FR/secubox-deb/secubox-socialrelay/internal/web"
)

var version = "dev"

func main() {
	var (
		socket  = flag.String("socket", "/run/secubox/socialrelay.sock", "socket unix")
		base    = flag.String("db", "/var/lib/secubox/socialrelay/socialrelay.db", "base SQLite")
		mediaD  = flag.String("media", "/var/lib/secubox/socialrelay/media", "cache des médias")
		conf    = flag.String("conf", "/etc/secubox/secubox.conf", "config (api.jwt_secret)")
		jwtFlag = flag.String("jwt-secret", "", "secret JWT de flotte")
		bbsSock = flag.String("bbs-socket", "/run/secubox/bbs.sock", "socket du BBS")
		fbTok   = flag.String("fb-token", "/etc/secubox/secrets/socialrelay-facebook", "jeton Graph manuel (repli)")
		fbApp   = flag.String("fb-app", "/etc/secubox/secrets/socialrelay-facebook-app", "app Meta (App ID/Secret) pour OAuth")
		fbStore = flag.String("fb-token-store", "/var/lib/secubox/socialrelay/fb-token.json", "cache du jeton OAuth (démon)")
		pubURL  = flag.String("public-url", "https://socialrelay.gk2.secubox.in", "base publique HTTPS (redirect_uri OAuth)")
		poll    = flag.Int("poll", 600, "période de sondage (s)")
		relayer = flag.Bool("relay-bbs", true, "ouvrir un fil BBS par post")
		montre  = flag.Bool("version", false, "version")
	)
	flag.Parse()
	if *montre {
		fmt.Println("secubox-socialrelayd", version)
		return
	}
	jr := log.New(os.Stderr, "socialrelay ", log.LstdFlags)
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

	fb := fbauth.New(*fbApp, *fbStore, *pubURL)
	// Jeton actif : OAuth caché en priorité, repli sur le jeton manuel déposé.
	jetonFB := func() string {
		if t := fb.Jeton(); t != "" {
			return t
		}
		if b, err := os.ReadFile(*fbTok); err == nil {
			return strings.TrimSpace(string(b))
		}
		return ""
	}
	reg := linker.NewRegistre(gardeReseau, jetonFB)
	cache := mediacache.New(*mediaD, st, gardeReseau)
	pipe := pipeline.New(st, reg, cache, jr, *bbsSock, secret, *relayer)
	srv := web.New(st, cache, web.Options{JWTSecret: secret}, jr, version)
	srv.BrancherFB(fb)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go boucle(ctx, pipe, time.Duration(*poll)*time.Second, jr)

	_ = os.Remove(*socket)
	ln, err := net.Listen("unix", *socket)
	if err != nil {
		jr.Fatalf("socket : %v", err)
	}
	_ = os.Chmod(*socket, 0o660)
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); cx, c := context.WithTimeout(context.Background(), 5*time.Second); defer c(); _ = hs.Shutdown(cx) }()
	jr.Printf("socialrelay %s à l'écoute sur %s (poll %ds)", version, *socket, *poll)
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		jr.Fatalf("serve : %v", err)
	}
}

func boucle(ctx context.Context, pipe *pipeline.Pipe, every time.Duration, jr *log.Logger) {
	tour := func() {
		n, f, err := pipe.Tour(time.Now().Unix())
		if err != nil {
			jr.Printf("tour : %v", err)
		}
		if n > 0 || f > 0 {
			jr.Printf("tour : %d posts neufs, %d fils BBS", n, f)
		}
	}
	tour()
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

func gardeReseau(hote string) error {
	if hote == "" || strings.EqualFold(hote, "localhost") || strings.HasSuffix(hote, ".local") {
		return errors.New("hôte interne")
	}
	ips, err := net.LookupIP(hote)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return errors.New("adresse interne")
		}
	}
	return nil
}

func jwtDepuisConf(chemin string) string {
	b, err := os.ReadFile(chemin)
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "jwt_secret") {
			if i := strings.Index(l, "="); i >= 0 {
				return strings.Trim(strings.TrimSpace(l[i+1:]), "\"'")
			}
		}
	}
	return ""
}

func seed(st *store.Store, jr *log.Logger) {
	if srcs, err := st.Sources(); err != nil || len(srcs) > 0 {
		return
	}
	def := []store.Source{
		{Slug: "masto-photo", Name: "Mastodon · #photography", Kind: "mastodon", Handle: "#photography@mastodon.social", Enabled: true, Mode: "open", Salon: "reseaux"},
		{Slug: "fb-groupe", Name: "Facebook · groupe", Kind: "facebook", Handle: "473694028670754", Enabled: true, Mode: "consent", Salon: "reseaux"},
		{Slug: "fb-page", Name: "Facebook · page", Kind: "facebook", Handle: "61560790047791", Enabled: true, Mode: "consent", Salon: "reseaux"},
	}
	for _, s := range def {
		if _, err := st.AddSource(s); err != nil {
			jr.Printf("seed %s : %v", s.Slug, err)
		}
	}
	jr.Printf("seed : %d sources posées", len(def))
}
