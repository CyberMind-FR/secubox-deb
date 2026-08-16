// secubox-radiod : la radio collaborative synchronisee (#1047).
package main

import (
	"context"
	"crypto/subtle"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
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
		// `--parc` DISPARAIT : la radio ne garde plus rien. Le drapeau est
		// conserve muet pour ne pas casser une unite deja installee — le
		// supprimer ferait echouer le demarrage sur « flag provided but not
		// defined », ce qui est une facon detournee de casser une mise a jour.
		_          = flag.String("parc", "", "obsolete : la radio relaie, elle ne recopie plus")
		passerelle = flag.String("ytsas", "http://10.100.0.180:8091", "passerelle yt-dlp")
		clipMax    = flag.Int64("clip-max", 256<<20, "taille maximale d'un clip, en octets")
		// LA BANNIERE DE SANTE EST INJECTEE PAR LE WAF dans chaque page HTML de
		// la board. Une politique stricte la bloque ; ces deux reglages
		// l'autorisent nommement. Vides = politique fermee, et la page s'affiche
		// simplement sans banniere — on prefere cela a une politique ouverte.
		bannOrig = flag.String("banniere-origine", "", "origine du script de banniere")
		bannHash = flag.String("banniere-hash", "", "empreinte du script en ligne de la banniere")
		montre   = flag.Bool("version", false, "afficher la version")
	)
	flag.Parse()
	if *montre {
		os.Stdout.WriteString("secubox-radiod " + version + "\n")
		return
	}
	log.SetFlags(0)
	chargeSecret("/etc/secubox/secrets/radio-sysop")

	if err := os.MkdirAll(filepath.Dir(*base), 0o750); err != nil {
		log.Fatalf("radio: repertoire de base : %v", err)
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

	cli := ytsas.Nouveau(*passerelle, *clipMax)

	srv := web.Nouveau(st, prog, identite, reg)
	// LA RADIO RELAIE, ELLE NE RECOPIE PAS : voir internal/ytsas.Flux.
	srv.Flux = cli.Flux
	srv.BanniereOrigine, srv.BanniereHash = *bannOrig, *bannHash
	ctx, arrete := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer arrete()

	go recupere(ctx, st, cli)
	// PLUS DE MENAGE DE PARC : la radio ne garde rien, la retention est
	// l'affaire de la passerelle, qui a deja `conserve`, `keep` et
	// `ephemeral` pour cela.

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

// identite : qui frappe a la porte.
//
// ── POURQUOI PAS UNE AUTHENTIFICATION ICI ───────────────────────────────────
//
// Sur cette board, LE LAN EST DE CONFIANCE ET LE WAN NE L'EST PAS : c'est
// HAProxy qui tient la frontiere, et les modules servis en 9080 — le
// podcaster, ytsas, torrent — ne demandent aucune identite. La radio suit le
// meme montage : y ajouter une porte n'aurait rien ferme de plus et l'aurait
// fait diverger des autres.
//
// IL RESTE QU'UNE RADIO COLLECTIVE A BESOIN DE SAVOIR QUI PARLE — pour dire
// qui a propose, qui a aime, qui a ecrit dans le chat. On prend donc l'identite
// la ou elle est :
//
//  1. les en-tetes `X-Sbx-*` s'ils existent — une porte pourra les poser plus
//     tard sans qu'on touche au demon ;
//  2. sinon, un cookie que la page pose elle-meme : un identifiant tire au
//     hasard et un nom choisi. Ce n'est PAS une authentification, et le code ne
//     pretend pas le contraire — c'est un pseudonyme, qui suffit a attribuer
//     des gestes entre gens qui se connaissent.
//
// LE SYSOP, LUI, SE PROUVE. Valider ou refuser engage l'antenne : ces gestes
// exigent un secret que l'operateur seul detient, lu dans
// `/etc/secubox/secrets/radio-sysop`. Sans ce fichier, PERSONNE n'est sysop —
// une installation neuve n'ouvre pas la validation a qui passe.
var secretSysop string

func chargeSecret(chemin string) {
	b, err := os.ReadFile(chemin)
	if err != nil {
		log.Printf("radio: aucun secret sysop (%s) — la validation reste fermee", chemin)
		return
	}
	secretSysop = strings.TrimSpace(string(b))
	if secretSysop == "" {
		log.Printf("radio: secret sysop vide — la validation reste fermee")
	}
}

func identite(r *http.Request) web.Visiteur {
	v := web.Visiteur{}
	// 1. Une porte a-t-elle pose l'identite ?
	if id := entierSur(r.Header.Get("X-Sbx-User-Id")); id > 0 {
		v = web.Visiteur{ID: id, Pseudo: r.Header.Get("X-Sbx-User"), Connecte: true}
		v.Sysop = r.Header.Get("X-Sbx-Role") == "sysop"
	} else if c, err := r.Cookie("sbx_radio"); err == nil {
		// 2. Le pseudonyme que la page s'est donne.
		if id := entierSur(c.Value); id > 0 {
			v = web.Visiteur{ID: id, Connecte: true}
			if n, err := r.Cookie("sbx_radio_nom"); err == nil {
				v.Pseudo = propre(n.Value)
			}
		}
	}
	if v.Pseudo == "" && v.Connecte {
		v.Pseudo = "anonyme"
	}
	// LE SYSOP SE PROUVE, il ne se declare pas.
	if secretSysop != "" && subtle.ConstantTimeCompare(
		[]byte(r.Header.Get("X-Sbx-Radio-Sysop")), []byte(secretSysop)) == 1 {
		v.Sysop, v.Connecte = true, true
		if v.ID == 0 {
			v.ID = 1
		}
		if v.Pseudo == "" || v.Pseudo == "anonyme" {
			v.Pseudo = "sysop"
		}
	}
	return v
}

func entierSur(s string) int64 {
	if s == "" || len(s) > 18 {
		return 0
	}
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int64(c-'0')
	}
	return n
}

// propre borne un pseudonyme choisi librement : il finira dans une page.
func propre(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 32 {
		s = s[:32]
	}
	var b strings.Builder
	for _, c := range s {
		if c >= ' ' && c != '<' && c != '>' && c != '&' && c != '"' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// recupere : la boucle qui rapatrie les clips.
//
// UNE PISTE A LA FOIS. La board est deja saturee cote processeur ; lancer trois
// telechargements en parallele ne les rendrait pas plus rapides et prendrait la
// place de ce qui joue.
func recupere(ctx context.Context, st *store.Store, cli *ytsas.Client) {
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
				// Pas encore chez la passerelle : on demande, et l'on
				// repassera. Ce n'est pas une erreur, c'est le cours normal.
				if err := cli.Demande(ctx, "https://www.youtube.com/watch?v="+ytID); err != nil {
					log.Printf("radio: piste %d : %v", p.ID, err)
				}
				break
			}
			if !e.Pret() {
				break // recuperation en cours chez la passerelle
			}
			// ON NE RAPATRIE PLUS. On note seulement que la passerelle l'a, et
			// le flux sera relaye a la lecture. Le chemin retenu est celui de
			// la passerelle : il sert a l'affichage, pas a la lecture.
			if err := st.PoseCache(p.ID, e.Chemin, "video/mp4", 0, 0, e.Titre, ""); err != nil {
				log.Printf("radio: piste %d : etat non enregistre : %v", p.ID, err)
			}
			log.Printf("radio: piste %d prete chez la passerelle", p.ID)
			break
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
