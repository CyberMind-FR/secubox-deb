// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Command sbx-actord — moteur Actor Intelligence de SecuBox Toolbox NG (RFC-0013).
//
// Phase 0/1 : SHADOW, 100 % observation. Le démon reçoit les Event Envelopes des
// capteurs (sbxwaf, sbxdpi, sbx-authwatch, sbx-sentinel) sur un socket unix non
// bloquant, les valide et les persiste (bbolt append-only), et expose une API
// read-only locale que la console consomme. Il ne prend AUCUNE décision et
// n'applique AUCUN blocage — la corrélation, le scoring et la réponse graduée
// arriveront dans internal/actor/{similarity,graph,knowledge,intent,response}.
//
// Si actord tombe, les capteurs (SBX WAF/DPI) continuent de protéger : l'émission
// vers actord est fire-and-forget (RFC-0013 §15, backpressure).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/evidence"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/store"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reseau"
)

func main() {
	var (
		dbPath     = flag.String("db", "/var/lib/secubox/actor/actord.db", "chemin du magasin bbolt")
		ledgerPath = flag.String("ledger", "/var/lib/secubox/actor/evidence.db", "chemin du ledger de preuves (append-only inviolable)")
		ingestSock = flag.String("ingest-socket", "/run/secubox/actord.sock", "socket unix d'ingestion des enveloppes")
		apiSock    = flag.String("api-socket", "/run/secubox/actor.sock", "socket unix de l'API read-only")
		shadow     = flag.Bool("shadow", true, "mode observation (Phase 0/1) : ne décide ni n'applique rien")
		readOnly   = flag.Bool("read-only", false, "n'ingère pas ; sert uniquement l'API sur un store existant")
		retention  = flag.Duration("retention", 30*24*time.Hour, "durée de rétention des événements")
		rebuildMax = flag.Int("rebuild-max", DefaultRebuildMax,
			"plafond d'événements rejoués au démarrage pour reconstruire le graphe. "+
				"DISTINCT de --retention : ce qu'on garde et ce qu'on recharge en "+
				"mémoire n'ont pas les mêmes contraintes. Le rejeu est linéaire "+
				"(~220 µs/événement sur la cible) et l'API reste fermée pendant")
		queue      = flag.Int("queue", 4096, "profondeur de la file d'ingestion (backpressure)")
		workers    = flag.Int("workers", 1, "nombre de workers d'écriture (#3321 : 1 par défaut, bbolt n'admet qu'un écrivain)")
		mesPath    = flag.String("mesures", "", "fichier où publier les mesures de l'échelle de réponse (délai, défi, tarpit, ban, quarantaine) ; vide = désactivé")
		propsPath  = flag.String("propositions", "", "fichier où publier les propositions de blocage (acteurs en DENY/QUARANTINE) ; vide = désactivé")
		replayPath = flag.String("replay", "", "rejoue un journal NDJSON d'enveloppes (calibration RFC-0013 §13) puis quitte")
		sinceDur   = flag.Duration("since", 0, "avec --replay : ne rejoue que les événements plus récents que cette durée")
		geoipASN   = flag.String("geoip-asn", "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
			"base MaxMind des ASN, lue LOCALEMENT (\"\" = désactivée) : ASN des sources dont l'enveloppe n'en porte pas (#3919)")
		reseauxClasses = flag.String("reseaux-classes",
			"/usr/share/secubox/waf/reseaux-classes.toml,/etc/secubox/waf/reseaux-classes.toml",
			"catalogues de classes de réseaux, séparés par des virgules ; le dernier gagne ASN par ASN (#3919)")
	)
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.LUTC)

	if !*shadow {
		// Garde-fou : la Phase 0/1 est shadow. Activer l'enforcement viendra dans
		// une phase ultérieure et séparée (RFC-0013 §18) — refus explicite ici.
		log.Fatal("actord: --shadow=false non supporté en Phase 0/1 (aucun enforcement livré)")
	}

	// #3919 : SIGHUP (ExecReload) est capté AVANT le rejeu, qui dure des dizaines de
	// secondes : non capté, il arrête le démon, et systemd tient cet arrêt pour une
	// sortie propre (Restart=on-failure ne relance pas). Le signal reste en file.
	hupReseau := make(chan os.Signal, 1)
	signal.Notify(hupReseau, syscall.SIGHUP)

	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o750); err != nil {
		log.Fatalf("actord: création du répertoire du store : %v", err)
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("actord: %v", err)
	}
	defer st.Close()

	led, err := evidence.Open(*ledgerPath)
	if err != nil {
		log.Fatalf("actord: ledger : %v", err)
	}
	defer led.Close()

	// #3919 : arrêt propre capté dès les bases ouvertes. Un SIGTERM pendant le rejeu
	// attend sa fin puis sort par les `defer` : la liste des pages libres est écrite,
	// et l'ouverture suivante ne parcourt pas toutes les bases.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// #3919 : annuaire de réseaux, ouvert AVANT le rejeu (qui remplit les
	// fiches par source). Toujours ouvert : sans base ASN, le catalogue classe
	// encore les ASN portés par les enveloppes.
	var catalogues []string
	for _, c := range strings.Split(*reseauxClasses, ",") {
		if c = strings.TrimSpace(c); c != "" {
			catalogues = append(catalogues, c)
		}
	}
	ann := reseau.Ouvrir(*geoipASN, catalogues...)
	defer ann.Close()

	srv := &Server{
		store:      st,
		shadow:     *shadow,
		graph:      graph.New(0),
		ledger:     led,
		accum:      map[string]*actorSignals{},
		rebuildMax: *rebuildMax,
		annuaire:   ann,
	}
	srv.rebuild() // reconstruit le graphe en mémoire depuis les événements persistés
	if ctx.Err() != nil {
		log.Printf("actord: arrêt demandé pendant le rejeu")
		return
	}

	// Mode calibration (RFC-0013 §13) : rejoue un journal puis quitte, sans
	// ouvrir de socket ni décider quoi que ce soit.
	if *replayPath != "" {
		rep, err := srv.replay(*replayPath, *sinceDur)
		if err != nil {
			log.Fatalf("actord: replay: %v", err)
		}
		out, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(out))
		return
	}

	if *propsPath != "" {
		go srv.publierPropositions(*propsPath, publicationPas)
	}
	if *mesPath != "" {
		go srv.publierMesures(*mesPath, mesuresPas)
	}

	if !*readOnly {
		ch := make(chan *envelope.Envelope, *queue)
		for i := 0; i < *workers; i++ {
			go srv.worker(ch)
		}
		go func() {
			if err := srv.serveIngest(*ingestSock, ch); err != nil {
				log.Fatalf("actord: ingestion : %v", err)
			}
		}()
	} else {
		log.Printf("actord: --read-only : ingestion désactivée, API seule")
	}

	go func() {
		if err := srv.serveAPI(*apiSock); err != nil {
			log.Fatalf("actord: API : %v", err)
		}
	}()

	go srv.pruneLoop(*retention)
	go srv.consolidationLoop()

	// #3919 : annuaire rechargé au SIGHUP (capté dès le démarrage) et toutes les 24 h.
	go func() {
		tic := time.NewTicker(24 * time.Hour)
		defer tic.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-hupReseau:
			case <-tic.C:
			}
			ann.Recharger()
		}
	}()
	log.Printf("actord: démarré (db=%s, retention=%s, rejeu max=%d)", *dbPath, *retention, *rebuildMax)
	<-ctx.Done()
	log.Printf("actord: arrêt")
}

// publicationPas : propositions recalculees toutes les 90 s (#3320, etait 60 s ;
// fraicheur exigee par sbxwaf : 10 min). mesuresPas reste a 30 s (#3321 : les
// mesures pilotent l'echelle de reponse, leur latence compte).
const (
	publicationPas = 90 * time.Second
	mesuresPas     = 30 * time.Second
)

// pruneLoop applique la rétention toutes les heures, au graphe en mémoire (#3320)
// comme à la base.
func (s *Server) pruneLoop(retention time.Duration) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for range t.C {
		before := time.Now().Add(-retention).Unix()
		s.purgerSources() // #3919 : rétention propre aux fiches par source (48 h)
		if n := s.purgerMemoire(before); n > 0 {
			log.Printf("actord: graphe — %d acteur(s) non vus depuis la retention retire(s)", n)
		}
		if n, err := s.store.Prune(before); err != nil {
			log.Printf("actord: prune: %v", err)
		} else if n > 0 {
			log.Printf("actord: prune %d événements antérieurs à %s", n, time.Unix(before, 0).UTC())
		}
	}
}
