// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: BBS — daemon.
//
// RECONSTRUIT LE 2026-08-11. Ce fichier n'a jamais ete suivi par git : le
// `.gitignore` du paquet portait un motif NU `secubox-bbsd`, destine au binaire
// construit, qui attrapait aussi le REPERTOIRE `cmd/secubox-bbsd/`. Rien ne le
// signalait — `git status` restait propre et `debian/rules` construisait depuis
// le disque — jusqu'a la suppression du seul repertoire qui le contenait.
//
// Reconstruit a partir de la surface du binaire deploye (`--help` sur gk2 :
// noms de drapeaux, valeurs par defaut et textes d'aide identiques) et de l'API
// des paquets internes, qui eux sont suivis. Les motifs du `.gitignore` sont
// desormais ancres (`/secubox-bbsd`) pour que le cas ne puisse pas se reproduire.
package main

import (
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

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/connectors"
	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/web"
)

// version est INJECTEE A LA CONSTRUCTION depuis debian/changelog (voir
// debian/rules, -ldflags -X). Elle etait une constante figee, et elle a derive :
// le demon annoncait 0.8.1 quand le paquet en etait a 0.12.0. Un numero de
// version qui ment est pire qu'absent — on diagnostique sur une version qui
// n'est pas celle qui tourne.
//
// La valeur ci-dessous ne sert qu'a `go run` et aux tests, ou aucun editeur de
// liens ne passe.
var version = "0.0.0-dev"

func trim(s string) string { return strings.TrimSpace(s) }

// ecoute ouvre la socket, EN REESSAYANT quelques secondes.
//
// POURQUOI REESSAYER PLUTOT QUE MOURIR. `/run/secubox` est partage par une
// centaine d'unites SecuBox. Quand l'une d'elles redemarre avec un
// `RuntimeDirectory=secubox`, systemd RECREE le repertoire — brievement en
// `root:root 0755` au lieu du `1777` attendu. Pendant cette fenetre, un service
// non-root ne peut plus y creer sa socket : `bind` echoue en EACCES.
//
// Observe sur gk2 le 2026-08-12 : cinq echecs consecutifs apres chaque
// deploiement, puis un succes — le service finissait par remonter seul, mais
// avec une minute de coupure et cinq lignes d'erreur qui faisaient chercher un
// defaut de droits inexistant.
//
// Mourir sur un etat TRANSITOIRE est le mauvais choix : la cause disparait
// d'elle-meme en quelques secondes. On reessaie brievement, puis on abandonne
// vraiment — un echec durable reste un echec, et doit se voir.
func ecoute(chemin string) (net.Listener, error) {
	var derniere error
	for essai := 0; essai < 12; essai++ {
		l, err := net.Listen("unix", chemin)
		if err == nil {
			if essai > 0 {
				log.Printf("socket ouverte apres %d essais — /run/secubox etait momentanement inaccessible", essai+1)
			}
			return l, nil
		}
		derniere = err
		// Un fichier laisse par un predecesseur : on le retire et on retente.
		_ = os.Remove(chemin)
		time.Sleep(time.Second)
	}
	return nil, derniere
}

func main() {
	var (
		racine  = flag.String("root", "/var/lib/secubox/bbs", "repertoire du BBS (content/, files/, index)")
		secrets = flag.String("secrets", "/etc/secubox/secrets/bbs", "repertoire des hashes de mots de passe")
		socket  = flag.String("socket", "/run/secubox/bbs.sock", "socket unix d'ecoute")
		titre   = flag.String("titre", "SecuBox BBS", "nom affiche du BBS")
		tls     = flag.Bool("derriere-tls", true, "poser Secure sur les cookies")
		sauveg  = flag.String("backup-dir", "/var/backups/secubox", "ou deposer les archives")
		bilSock = flag.String("billets-socket", "/run/secubox/billets.sock", "socket du module billets")
		bilBase = flag.String("billets-base", "", "origine publique de billets, pour resoudre les adresses relatives du flux ; vide = adresses telles que le flux les rend")
		conf    = flag.String("conf", "/etc/secubox/secubox.conf", "configuration du core (api.jwt_secret)")

		// La banniere de sante est injectee par le WAF de la board APRES notre
		// reponse : on ne peut pas lui poser de nonce. On l'autorise donc
		// precisement, par son origine et l'empreinte exacte de son chargeur.
		// Vides, la politique reste FERMEE — bon defaut pour une surface
		// publique, la banniere interrogeant des API d'administration.
		bannOrig  = flag.String("banniere-origine", "", "origine autorisee pour la banniere de sante injectee par le WAF ; vide = politique fermee")
		bannHash  = flag.String("banniere-empreinte", "", "empreinte CSP du chargeur de banniere (sha256-…) ; sans elle le chargeur reste bloque")
		bannStyle = flag.String("banniere-style", "", "empreinte CSP de la balise <style> injectee par la banniere (sha256-…)")

		ptOrigine = flag.String("peertube-origine", "", "instance PeerTube autorisee a fournir le lecteur video ; vide = aucune video integree")
		mediaOrig = flag.String("media-origines", "",
			"origines de NOS services dont on relaie les vignettes, separees par des virgules")
		radioBase = flag.String("radio-base", "", "URL publique de la radio ; non vide = widget lecteur incorporé dans le rail (son origine doit aussi être dans --frame-origines)")
		frameOrig = flag.String("frame-origines", "",
			"services autorises a fournir un lecteur incorpore, separes par des virgules")
		podDB     = flag.String("podcast-db", "/var/lib/secubox/podcaster/podcaster.db", "base du podcaster, lue en lecture seule")
		podRacine = flag.String("podcast-racine", "/var/lib/secubox/podcaster/media,/data/secubox/podcaster",
			"parcs media du podcaster, separes par des virgules — CONFINEMENT : rien hors de la n'est servi")
		authSock = flag.String("auth-socket", "/run/secubox/auth.sock",
			"socket de secubox-auth ; vide = les comptes synchronises ne peuvent pas se connecter")

		// ytsasOrig : origine de la SAS ytsas — le tuyau souverain qui rapatrie
		// une video YouTube en local (mirror PeerTube ou cache) avant que le WAN
		// ne devienne le seul recours. Alimente a la fois le connecteur (appels
		// /resolve) et Options.YtsasOrigine (media-src de la CSP, #1056).
		ytsasOrig = flag.String("ytsas-origine", "http://10.100.0.180:8091", "origine de la SAS ytsas")
	)
	flag.Parse()

	// noeud identifie CETTE board dans Contenu.NoeudOrigine — provenance d'un
	// media rapatrie. Aucun flag dedie n'existe encore pour ca ailleurs dans le
	// demon ; le nom de machine est la seule identite stable disponible sans en
	// inventer une nouvelle pour ce seul connecteur.
	noeud, err := os.Hostname()
	if err != nil || noeud == "" {
		noeud = "secubox-bbs"
	}
	yt := connectors.NouveauYouTube(&connectors.ClientYtsas{
		Base: *ytsasOrig, HTTP: &http.Client{Timeout: 3 * time.Second},
	}, noeud)

	st, err := store.Open(filepath.Join(*racine, "index.db"))
	if err != nil {
		log.Fatalf("ouverture de la base : %v", err)
	}
	defer st.Close()

	// Le secret de signature n'est JAMAIS un argument de ligne de commande :
	// les arguments sont visibles dans la table des processus.
	// Trois sources, dans cet ordre : l'environnement (pratique en essai), le
	// fichier de configuration du core (la source normale sur une board), puis
	// un fichier dedie.
	secret := os.Getenv("SECUBOX_JWT_SECRET")
	if secret == "" {
		secret = web.SecretDepuisConf(*conf)
	}
	if secret == "" {
		if b, err := os.ReadFile("/etc/secubox/secrets/jwt"); err == nil {
			secret = trim(string(b))
		}
	}
	if secret == "" {
		// On demarre quand meme : l'interface membre fonctionne sans jeton.
		// C'est l'API d'administration et la publication qui resteront fermees.
		log.Print("ATTENTION : aucun secret JWT — API d'administration et publication fermees")
	}

	srv, err := web.New(st, yt, web.Options{
		Titre: *titre, Secrets: *secrets, DerriereTLS: *tls,
		BilletsSocket: *bilSock, BilletsBase: *bilBase, JWTSecret: secret, BackupDir: *sauveg,
		BanniereOrigine: *bannOrig, BanniereHash: *bannHash, BanniereStyle: *bannStyle,
		PeerTubeOrigine: *ptOrigine, PodcastRacine: *podRacine, PodcastDB: *podDB,
		MediaOrigines: origines(*mediaOrig),
		FrameOrigines: origines(*frameOrig),
		RadioBase:     strings.TrimRight(*radioBase, "/"),
		AuthSocket:    *authSock,
		YtsasOrigine:  *ytsasOrig,
	})
	if err != nil {
		log.Fatalf("initialisation du serveur : %v", err)
	}

	// La socket precedente est retiree AVANT l'ecoute : un fichier laisse par
	// un arret brutal ferait echouer le bind, et le service ne remonterait
	// jamais tout seul. L'unite fait deja ce menage, mais elle n'est pas la
	// seule facon de lancer ce binaire.
	//
	// Ici c'est SANS DANGER — on est sur le point de creer la notre. C'est a
	// l'ARRET que supprimer devient une course (voir plus bas).
	_ = os.Remove(*socket)
	l, err := ecoute(*socket)
	if err != nil {
		log.Fatalf("ecoute sur %s : %v", *socket, err)
	}
	// 0660 : nginx doit pouvoir ecrire dans la socket, les autres non. Le
	// groupe est pose par l'unite systemd (Group=secubox).
	if err := os.Chmod(*socket, 0o660); err != nil {
		log.Printf("droits de la socket : %v", err)
	}

	v, _ := st.Version()
	log.Printf("secubox-bbsd %s — racine %s, socket %s (schema %d)",
		version, *racine, *socket, v)

	h := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// ARRET PROPRE — SANS TOUCHER AU FICHIER DE SOCKET.
	//
	// Le premier jet le supprimait ici. C'est une COURSE : lors d'un
	// redemarrage, systemd relance le service avant que l'ancien processus ait
	// fini de s'eteindre. Le successeur cree sa socket, puis le predecesseur
	// arrive a cette ligne et EFFACE celle du successeur. L'unite suivante
	// echoue alors sur `bind`, redemarre, et l'on boucle.
	//
	// Constate sur gk2 le 2026-08-12 : cinq echecs consecutifs
	// « bind: permission denied » avant que le hasard ne separe les deux
	// processus.
	//
	// Le menage appartient a l'unite, qui le fait EN ROOT et AVANT de lancer
	// (`ExecStartPre=+-/bin/rm -f`). Un seul endroit, sans concurrent.
	arret := make(chan os.Signal, 1)
	signal.Notify(arret, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-arret
		_ = h.Close()
	}()

	if err := h.Serve(l); err != nil && err != http.ErrServerClosed {
		log.Fatalf("service : %v", err)
	}
}

// origines decoupe la liste passee en ligne de commande.
//
// Les entrees vides sont ecartees : une virgule en trop dans un fichier d'unite
// aurait ajoute une origine vide a la liste, et `origineAdmise` compare des
// chaines — une origine vide ne correspond a rien, mais mieux vaut ne pas la
// porter du tout que de compter sur cette chance.
func origines(brut string) []string {
	var out []string
	for _, p := range strings.Split(brut, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
