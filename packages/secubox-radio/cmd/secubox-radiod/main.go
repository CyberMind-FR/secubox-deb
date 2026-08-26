// secubox-radiod : la radio collaborative synchronisee (#1047).
package main

import (
	"context"
	"crypto/subtle"
	"errors"
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

	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/contentbbs"
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
		bannOrig    = flag.String("banniere-origine", "", "origine du script de banniere")
		bannHash    = flag.String("banniere-hash", "", "empreinte du script en ligne de la banniere")
		cadreParent = flag.String("cadre-parent", "", "origine autorisee a incorporer le lecteur /mini (rail BBS)")
		bannStyle   = flag.String("banniere-style", "",
			"empreinte de la <style> injectee par la banniere de sante")
		// contentSock/conf : le pont vers le content spine du BBS (#1166 B2).
		// La radio signe ses appels avec le meme secret de flotte que le BBS lit
		// (api.jwt_secret) — jamais un secret different qui romprait l'auth.
		contentSock = flag.String("bbs-content-socket", "/run/secubox/bbs.sock",
			"socket unix du content spine BBS")
		conf   = flag.String("conf", "/etc/secubox/secubox.conf", "configuration du core (api.jwt_secret)")
		montre = flag.Bool("version", false, "afficher la version")
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
	// LE PONT VERS LE CONTENT SPINE DU BBS (#1166 B2). Toujours cable : un
	// secret vide fait simplement echouer chaque appel (contentbbs.Client.jeton),
	// et cet echec est journalise sans jamais bloquer une validation — voir
	// web.Serveur.ouvreContenu.
	if secret := jwtDepuisConf(*conf); secret == "" {
		log.Printf("radio: aucun api.jwt_secret dans %s — le content spine BBS restera injoignable", *conf)
	}
	srv.Contenu = contentbbs.New(*contentSock, jwtDepuisConf(*conf))
	srv.BanniereOrigine, srv.BanniereHash = *bannOrig, *bannHash
	srv.BanniereStyle = *bannStyle
	srv.CadreParent = *cadreParent
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
	} else if id := entierSur(r.URL.Query().Get("a")); id > 0 {
		// 3. LE MEME PSEUDONYME, PORTE PAR L'URL (#1254).
		//
		// Safari et iOS refusent les cookies tiers quoi qu'on fasse : encadree
		// dans le Hall, la page n'a plus de cookie du tout, et /media rendait
		// 401 -- un lecteur muet sur iPhone et sur TV.
		//
		// Ce n'est PAS un affaiblissement. Ce que le cookie portait est un
		// nombre que la page se donne elle-meme au hasard : il n'authentifie
		// rien, il attribue des gestes. La meme valeur par un autre canal
		// vaut exactement la meme chose -- et le sysop, lui, se prouve par un
		// secret d'en-tete, jamais par ce nombre.
		v = web.Visiteur{ID: id, Connecte: true}
		if n := propre(r.URL.Query().Get("n")); n != "" {
			v.Pseudo = n
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
	var dernierCookie int64
	var dernierReprise time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(20 * time.Second):
		}
		// ── UN DEPOT DE COOKIES REMET EN JEU CE QU'IL DEBLOQUE ──────────
		//
		// Sans cela, une piste ecartee faute de cookies l'est DEFINITIVEMENT :
		// l'operateur depose un cookies.txt neuf et rien ne bouge, parce que la
		// boucle saute desormais cette piste. Il faudrait reproposer chaque
		// titre a la main — ce que personne ne devinerait.
		//
		// On ne remet en jeu qu'UNE FOIS PAR DEPOT, la date du coffre servant
		// de repere : sinon une piste durablement inaccessible serait reessayee
		// toutes les vingt secondes, indefiniment.
		if e, err := cli.Cookies(ctx); err == nil && e.Present && !e.Perimes && e.Mtime > dernierCookie {
			dernierCookie = e.Mtime
			if n, err := st.RemetEnJeuBloqueesParCookies(); err == nil && n > 0 {
				log.Printf("radio: cookies renouveles — %d piste(s) remise(s) en jeu", n)
			}
		}

		// ── LES ECHECS DE TELECHARGEMENT SE REESSAIENT ─────────────────
		//
		// Un 403 sur les octets video est le plus souvent PASSAGER : la
		// passerelle reussit au coup d'apres. Sans remise en jeu, la piste
		// reste ecartee pour toujours — la boucle la saute (ligne « EnCache ||
		// Indisponible »). On la remet donc periodiquement, mais ESPACE (toutes
		// les 5 min) : une video vraiment morte serait sinon reessayee a chaque
		// tour. Le premier passage (dernierReprise zero) tombe tout de suite,
		// pour rattraper ce qu'un 403 transitoire avait ecarte avant ce demarrage.
		if now := time.Now(); now.Sub(dernierReprise) >= 5*time.Minute {
			dernierReprise = now
			if n, err := st.RemetEnJeuEchecsTelechargement(); err == nil && n > 0 {
				log.Printf("radio: %d piste(s) reessayee(s) apres echec de telechargement", n)
			}
		}

		// ── LES LISTES SE DEPLIENT ──────────────────────────────────────
		//
		// DES LA PROPOSITION, sans attendre de validation : deplier n'est pas
		// accepter, c'est montrer ce que la liste contient. Une liste restee
		// pliee dans la file ne dirait rien de ce qu'elle propose, et le sysop
		// devrait l'ouvrir ailleurs pour savoir ce qu'il valide.
		if props, err := st.Propositions(); err == nil {
			for _, pl := range props {
				if pl.Indisponible {
					continue
				}
				// NON-LISTE : PRÉCHARGEMENT DU TITRE (#1131p). Une proposition
				// n'affiche que son URL brute tant que personne ne l'a validée —
				// illisible dans « en attente ». On demande son titre à la
				// passerelle (métadonnées) et on le pose dès qu'il est connu ;
				// PoseTitre ne touche que le vide, jamais un titre saisi.
				if !pl.EstPlaylist() {
					if strings.TrimSpace(pl.Titre) != "" {
						continue
					}
					ytID := idYouTube(pl.Source)
					if ytID == "" {
						continue
					}
					if e, err := cli.Etat(ctx, ytID); err == nil {
						if titre := strings.TrimSpace(e.Titre); titre != "" {
							st.PoseTitre(pl.ID, titre)
						}
					} else {
						// Pas encore connue : on enfile la demande (qui sonde les
						// métadonnées), et l'on repassera poser le titre.
						cli.Demande(ctx, "https://www.youtube.com/watch?v="+ytID)
					}
					continue
				}
				adresse := "https://www.youtube.com/playlist?list=" +
					strings.TrimPrefix(pl.Source, "ytpl:")
				morceaux, err := cli.Enumere(ctx, adresse, store.MaxParPlaylist)
				if err != nil {
					log.Printf("radio: liste %d illisible : %v", pl.ID, err)
					st.MarqueIndisponible(pl.ID, "liste illisible : "+err.Error())
					continue
				}
				conv := make([]store.MorceauPlaylist, 0, len(morceaux))
				for _, m := range morceaux {
					conv = append(conv, store.MorceauPlaylist{URL: m.URL, Titre: m.Titre})
				}
				n, err := st.Deplie(pl.ID, conv, time.Now())
				if err != nil {
					log.Printf("radio: depliage de %d : %v", pl.ID, err)
					continue
				}
				log.Printf("radio: liste %d depliee en %d propositions", pl.ID, n)
			}
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
					// UN BESOIN DE COOKIES SE MARQUE SUR LA PISTE, il ne se
					// repete pas toutes les vingt secondes dans le journal. Le
					// panneau l'affiche alors avec sa raison, et l'operateur
					// sait quoi faire — au lieu de voir une piste bloquee en
					// « recuperation » sans explication.
					// MEME TRAITEMENT POUR CE QUI NE S'ARRANGERA PAS.
					// Une source retiree, mise en prive ou dont l'adresse est
					// malformee ne deviendra pas disponible en attendant : la
					// redemander toutes les vingt secondes remplissait le
					// journal d'une ligne identique et laissait la piste
					// affichee en « recuperation… » indefiniment. On l'ecarte
					// avec sa raison, que le panneau montre.
					switch {
					case errors.Is(err, ytsas.ErrCookies),
						errors.Is(err, ytsas.ErrIntrouvable):
						st.MarqueIndisponible(p.ID, err.Error())
					default:
						log.Printf("radio: piste %d : %v", p.ID, err)
					}
				}
				break
			}
			// UNE PISTE EN ERREUR EST ECARTEE, PAS ATTENDUE. C'est le
			// defaut qui gelait toute la file : la passerelle marquait une
			// video « error » (403 de YouTube, video retiree), le demon la
			// lisait comme « pas encore prete », et repartait en attente a
			// chaque tour SANS JAMAIS REGARDER LES SUIVANTES. Une seule video
			// refusee suffisait a bloquer les quarante autres, sans une ligne
			// de journal pour le dire.
			if e.Echoue() {
				raison := e.Erreur
				if raison == "" {
					raison = "la passerelle a renonce a cette piste"
				}
				st.MarqueIndisponible(p.ID, raison)
				log.Printf("radio: piste %d ecartee : %s", p.ID, raison)
				continue
			}
			if !e.Pret() {
				// Deja demandee, elle arrive : on passe a la suivante au lieu
				// d'arreter l'examen de la file.
				continue
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

// jwtDepuisConf lit api.jwt_secret dans le fichier de config (parse minimal,
// meme motif que secubox-bbsd/secubox-socialrelayd/secubox-metanewsd : une
// seule cle, pas de bibliotheque TOML a vendorer pour ca). Vide si le fichier
// est illisible ou la cle absente — l'appelant doit lire ce vide comme
// « aucun appel au BBS ne partira », jamais comme une auth optionnelle.
func jwtDepuisConf(chemin string) string {
	b, err := os.ReadFile(chemin)
	if err != nil {
		return ""
	}
	section := ""
	for _, ligne := range strings.Split(string(b), "\n") {
		l := strings.TrimSpace(ligne)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
			section = strings.Trim(l, "[]")
			continue
		}
		if section != "api" || !strings.HasPrefix(l, "jwt_secret") {
			continue
		}
		if i := strings.Index(l, "="); i >= 0 {
			v := strings.TrimSpace(l[i+1:])
			if j := strings.Index(v, " #"); j >= 0 {
				v = strings.TrimSpace(v[:j])
			}
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

// idYouTube extrait l'identifiant d'une cle normalisee `yt:<id>`.
func idYouTube(cle string) string {
	if len(cle) > 3 && cle[:3] == "yt:" {
		return cle[3:]
	}
	return ""
}
