// secubox-radiod : la radio collaborative synchronisee (#1047).
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/programme"
	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/store"
	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/tirage"
	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/web"
	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/ytsas"
)

var version = "0.1.0"

func main() {
	var (
		socket = flag.String("socket", "/run/secubox/radio.sock", "socket unix d'ecoute")
		base   = flag.String("db", "/var/lib/secubox/radio/radio.db", "base SQLite")
		// LE PARC VA SUR LE SSD. L'eMMC s'est deja remplie sur cette board et a
		// produit des 502 sur des modules qui n'avaient rien demande ; un parc
		// audio-video grossit tout seul.
		parc       = flag.String("parc", "/data/secubox/radio/media", "repertoire des clips (SSD)")
		passerelle = flag.String("ytsas", "http://10.100.0.180:8091", "passerelle yt-dlp")
		parcMax    = flag.Int64("parc-max", 4<<30, "taille maximale du parc, en octets")
		clipMax    = flag.Int64("clip-max", 256<<20, "taille maximale d'un clip, en octets")
		montre     = flag.Bool("version", false, "afficher la version")
	)
	flag.Parse()
	if *montre {
		os.Stdout.WriteString("secubox-radiod " + version + "\n")
		return
	}
	log.SetFlags(0)

	if err := os.MkdirAll(filepath.Dir(*base), 0o750); err != nil {
		log.Fatalf("radio: repertoire de base : %v", err)
	}
	if err := os.MkdirAll(*parc, 0o750); err != nil {
		log.Fatalf("radio: repertoire du parc : %v", err)
	}
	st, err := store.Open(*base)
	if err != nil {
		log.Fatalf("radio: base : %v", err)
	}
	defer st.Close()

	reg := tirage.Defaut()
	// LA GRAINE VIENT DE L'HORLOGE AU DEMARRAGE, et elle est JOURNALISEE : le
	// tirage doit pouvoir etre rejoue pour expliquer pourquoi tel titre est
	// passe. Une graine fixe rendrait la radio identique a chaque redemarrage.
	graine := time.Now().UnixNano()
	log.Printf("radio: graine du tirage %d", graine)
	prog := programme.Nouveau(st, reg, graine)

	srv := web.Nouveau(st, prog, identite, reg)
	srv.Racine = *parc

	cli := ytsas.Nouveau(*passerelle, *clipMax)
	ctx, arrete := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer arrete()

	go recupere(ctx, st, cli, *parc)
	go menage(ctx, st, prog, *parcMax)

	// SOCKET UNIX, JAMAIS DE PORT TCP : un port ecoute pour toute la machine,
	// une socket obeit aux permissions du systeme de fichiers.
	os.Remove(*socket)
	l, err := net.Listen("unix", *socket)
	if err != nil {
		log.Fatalf("radio: socket : %v", err)
	}
	if err := os.Chmod(*socket, 0o660); err != nil {
		log.Fatalf("radio: permissions de la socket : %v", err)
	}
	h := &http.Server{Handler: srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		ctxA, a := context.WithTimeout(context.Background(), 5*time.Second)
		defer a()
		h.Shutdown(ctxA)
	}()
	log.Printf("radio: %s a l'ecoute sur %s", version, *socket)
	if err := h.Serve(l); err != nil && err != http.ErrServerClosed {
		log.Fatalf("radio: %v", err)
	}
}

// identite : resolue par l'authentification SecuBox, transmise par nginx.
//
// FERME PAR DEFAUT. Sans en-tete, personne n'est connecte — une chaine mal
// cablee refuse au lieu de s'ouvrir. Les en-tetes sont poses par nginx APRES
// verification et ecrasent ce que le client aurait envoye.
func identite(r *http.Request) web.Visiteur {
	id := r.Header.Get("X-Sbx-User-Id")
	if id == "" {
		return web.Visiteur{}
	}
	var n int64
	for _, c := range id {
		if c < '0' || c > '9' {
			return web.Visiteur{}
		}
		n = n*10 + int64(c-'0')
	}
	if n <= 0 {
		return web.Visiteur{}
	}
	return web.Visiteur{ID: n, Pseudo: r.Header.Get("X-Sbx-User"),
		Sysop: r.Header.Get("X-Sbx-Role") == "sysop", Connecte: true}
}

// recupere : la boucle qui rapatrie les clips.
//
// UNE PISTE A LA FOIS. La board est deja saturee cote processeur ; lancer trois
// telechargements en parallele ne les rendrait pas plus rapides et prendrait la
// place de ce qui joue.
func recupere(ctx context.Context, st *store.Store, cli *ytsas.Client, parc string) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(20 * time.Second):
		}
		pistes, err := st.Toutes()
		if err != nil {
			log.Printf("radio: lecture de la playlist : %v", err)
			continue
		}
		for _, p := range pistes {
			if p.EnCache() || p.Indisponible {
				continue
			}
			ytID := idYouTube(p.Source)
			if ytID == "" {
				st.MarqueIndisponible(p.ID, "source non reconnue")
				continue
			}
			e, err := cli.Etat(ctx, ytID)
			if err != nil {
				// Pas encore la : on demande, et l'on repassera. Ce n'est pas
				// une erreur, c'est le cours normal des choses.
				if err := cli.Demande(ctx, p.Source); err != nil {
					log.Printf("radio: piste %d : %v", p.ID, err)
				}
				break // une a la fois
			}
			if !e.Pret() {
				break
			}
			chemin, mime, n, err := cli.Rapatrie(ctx, ytID, parc)
			if err != nil {
				log.Printf("radio: piste %d ecartee : %v", p.ID, err)
				st.MarqueIndisponible(p.ID, err.Error())
				continue
			}
			if err := st.PoseCache(p.ID, chemin, mime, n, 0, e.Titre, ""); err != nil {
				log.Printf("radio: piste %d : cache non enregistre : %v", p.ID, err)
			}
			log.Printf("radio: piste %d en cache (%d Mio)", p.ID, n>>20)
			break
		}
	}
}

// menage : la purge du parc.
func menage(ctx context.Context, st *store.Store, prog *programme.Programmateur, borne int64) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Minute):
		}
		// ON PROTEGE CE QUI PASSE : evincer la piste en cours couperait
		// l'antenne au milieu d'un morceau.
		proteges := map[int64]bool{}
		if e, err := prog.Actuel(time.Now()); err == nil {
			proteges[e.Piste.ID] = true
		}
		l, err := st.APurger(borne, proteges)
		if err != nil {
			log.Printf("radio: purge : %v", err)
			continue
		}
		for _, p := range l {
			if err := os.Remove(p.Fichier); err != nil && !os.IsNotExist(err) {
				log.Printf("radio: purge de %s : %v", p.Fichier, err)
				continue
			}
			st.OublieCache(p.ID)
			log.Printf("radio: piste %d evincee du parc (%d Mio)", p.ID, p.Octets>>20)
		}
	}
}

// idYouTube extrait l'identifiant d'une cle normalisee `yt:<id>`.
func idYouTube(cle string) string {
	if len(cle) > 3 && cle[:3] == "yt:" {
		return cle[3:]
	}
	return ""
}
