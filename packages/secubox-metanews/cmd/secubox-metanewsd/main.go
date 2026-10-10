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

	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/diffusion"
	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/linker"
	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/pipeline"
	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/store"
	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/web"
)

var version = "dev"

func main() {
	var (
		socket  = flag.String("socket", "/run/secubox/metanews.sock", "socket unix d'écoute")
		base    = flag.String("db", "/var/lib/secubox/metanews/metanews.db", "base SQLite")
		conf    = flag.String("conf", "/etc/secubox/secubox.conf", "config (pour api.jwt_secret)")
		jwtFlag = flag.String("jwt-secret", "", "secret JWT de flotte (sinon lu du conf)")
		bbsSock = flag.String("bbs-socket", "/run/secubox/bbs.sock", "socket du BBS (pour Discuter)")
		bbsCat  = flag.String("bbs-cat", "actualites", "slug de catégorie BBS des fils MetaNews")
		pollSec = flag.Int("poll", 300, "période de sondage des flux, en secondes")
		// Billets éphémères (#2268) : les sujets qui se forment passent dans le fil des billets pour quelques minutes.
		bilActif  = flag.Bool("billets", true, "publier les nouveaux sujets comme billets éphémères")
		bilSocket = flag.String("billets-socket", "/run/secubox/billets.sock", "socket du module billets")
		bilTTL    = flag.Duration("billets-ttl", 5*time.Minute, "durée de vie d'un billet éphémère (30 s à 1 h)")
		bilMax    = flag.Int("billets-max-heure", 6, "plafond de sujets publiés par heure")
		bilMinSrc = flag.Int("billets-min-sources", 2, "sources minimum pour qu'un sujet soit publié")
		sitePub   = flag.String("site-public", "", "adresse publique de MetaNews (https://…), pour le lien du billet")
		montre    = flag.Bool("version", false, "afficher la version")
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
	// NETTOYAGE UNIQUE, EN ARRIERE-PLAN (#1362b, corrige #1362c). Detache les
	// articles mal rattaches par les anciennes regles. EN GOROUTINE : synchrone,
	// il bloquait le demarrage du serveur (socket jamais ouvert, 502 partout).
	// Idempotent — apres la premiere passe il ne trouve plus rien.
	//
	// AVANT LE PREMIER TOUR, DANS LA MEME GOROUTINE (#1835). Lancees a cote de
	// la boucle de sondage, ces passes et le premier tour regroupaient les
	// MEMES orphelins en meme temps : travail double, sujets crees deux fois
	// (48 sujets vides purges ensuite sur gk2), et vingt-cinq minutes de
	// demarrage sous le quota. `boucle` les execute d'abord, puis sonde.
	passes := func() {
		maintenant := time.Now().Unix()
		if n, err := pipe.Reclasser(maintenant); err != nil {
			jr.Printf("reclasser : %v", err)
		} else if n > 0 {
			jr.Printf("reclasser : %d articles remis a leur place", n)
		}
		// LES SUJETS FANTOMES (#1323). Reclasser vient de deplacer des
		// articles ; un sujet qui perd le dernier RESTE, avec son titre et sa
		// vignette d'alors, et n'est plus recomposable — mais reste liste. Une
		// heure de marge : Regrouper cree le sujet PUIS lui rattache
		// l'article, et le sondage tourne en meme temps que cette passe.
		if n, err := st.PurgerSujetsVides(maintenant - 3600); err != nil {
			jr.Printf("purge-sujets-vides : %v", err)
		} else if n > 0 {
			jr.Printf("purge-sujets-vides : %d sujets sans article retires", n)
		}
		// REPARATION DES TITRES-GABARITS (#1323). Certains flux publient leur
		// propre code de mise en page : « Vidéo. $content.TitleNoTags ». Le
		// correctif a l'ingestion ne vaut que pour ce qui ARRIVE ; ce qui est
		// deja en base doit etre repris. AVANT le rafraichissement, qui va
		// reprendre le titre de l'article le plus recent — donc celui-ci.
		if n, err := pipe.ReparerTitres(maintenant - 30*24*3600); err != nil {
			jr.Printf("reparer-titres : %v", err)
		} else if n > 0 {
			jr.Printf("reparer-titres : %d titres rendus lisibles", n)
		}
		// RAFRAICHISSEMENT DES SUJETS DEJA EN BASE (#1323). Un sujet n'est
		// recompose que s'il RECOIT un article ; ceux qui n'en recoivent plus
		// gardaient le titre de leur article fondateur, meme vieux de
		// semaines. Une passe au demarrage les remet a jour. Idempotente, et
		// bornee aux trente derniers jours : on ne reecrit pas les archives.
		if n, err := pipe.Rafraichir(maintenant, maintenant-30*24*3600); err != nil {
			jr.Printf("rafraichir : %v", err)
		} else if n > 0 {
			jr.Printf("rafraichir : %d sujets recomposes", n)
		}
	}
	srv := web.New(st, pipe, web.Options{JWTSecret: secret, BBSSocket: *bbsSock, BBSCat: *bbsCat}, jr, version)

	// Boucle de sondage en arrière-plan (double-cache : la donnée peut être
	// périmée de quelques minutes sans impact).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var dif *diffusion.Diffuseur
	if *bilActif {
		if *bilTTL < 30*time.Second || *bilTTL > time.Hour {
			jr.Fatalf("billets-ttl %s hors de [30 s, 1 h]", *bilTTL)
		}
		dif = diffusion.New(st, diffusion.Config{TTL: *bilTTL, MaxParHeure: *bilMax, MinSources: *bilMinSrc,
			Fenetre: 2 * time.Duration(*pollSec) * time.Second, Cooldown: time.Hour, SiteURL: *sitePub},
			diffusion.ClientSocket(*bilSocket, secret), jr)
		jr.Printf("billets éphémères : ttl %s, %d/h max, %d sources min", *bilTTL, *bilMax, *bilMinSrc)
	}
	go boucle(ctx, passes, tourDe(pipe, jr, dif), time.Duration(*pollSec)*time.Second)

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

// tourDe : un sondage suivi d'un regroupement, journalisé.
func tourDe(pipe *pipeline.Pipe, jr *log.Logger, dif *diffusion.Diffuseur) func() {
	return func() {
		now := time.Now().Unix()
		n, t, err := pipe.Tour(now)
		if err != nil {
			jr.Printf("tour : %v", err)
			return
		}
		if n > 0 || t > 0 {
			jr.Printf("tour : %d articles neufs, %d sujets touchés", n, t)
		}
		// Les sujets qui viennent de se former passent dans le fil des billets. Une panne de billets n'arrête jamais le sondage.
		if dif != nil {
			if k, err := dif.Tour(now); err != nil {
				jr.Printf("billets éphémères : %v", err)
			} else if k > 0 {
				jr.Printf("billets éphémères : %d publiés", k)
			}
		}
	}
}

// boucle : les passes de démarrage d'abord, PUIS les tours — jamais en même
// temps (#1835).
func boucle(ctx context.Context, avant func(), tour func(), every time.Duration) {
	avant()
	if ctx.Err() != nil {
		return
	}
	tour() // un premier tour, une fois les passes finies
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
		{Slug: "leparisien", Name: "Le Parisien", URL: "https://feeds.leparisien.fr/leparisien/rss", Enabled: true, Category: "general"},
		{Slug: "ledauphine-une", Name: "Le Dauphiné — Une", URL: "https://www.ledauphine.com/rss", Enabled: true, Category: "general"},
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
