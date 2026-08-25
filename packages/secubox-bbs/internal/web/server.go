// Package web sert l'interface membre du BBS.
//
// DEUX PUBLICS, DEUX INTERFACES, ET C'EST DELIBERE
//
//   - Ici : l'interface des MEMBRES, conforme a www/mockup.html — claire,
//     coloree, lisible par quelqu'un qui vient lire un fil.
//   - Ailleurs (www/bbs/index.html) : le panneau du SYSOP, terminal cyan
//     Courier Prime, conforme a WEBUI-PANEL-GUIDELINES.md.
//
// Les melanger servirait mal les deux : un membre n'a pas a lire un tableau de
// bord, et un sysop n'a pas besoin qu'on lui fasse joli pendant qu'il regarde
// pourquoi l'index diverge.
package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/billets"
	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/connectors"
	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

const Version = "0.1.0"

const (
	cookieSession = "sbx_bbs"
	cookieCSRF    = "sbx_bbs_csrf"
)

type Options struct {
	Titre string
	// Secrets : repertoire des hashes de mots de passe. HORS de l'arborescence
	// de contenu, pour qu'une archive de contenu ne les emporte jamais.
	Secrets string
	// DerriereTLS : pose l'attribut Secure sur les cookies. Faux en test et en
	// developpement sur http://localhost, ou Secure empecherait toute session.
	DerriereTLS bool
	// Billets : socket du module billets et secret de signature. Vides, le
	// bouton « publier » repond « module non configure » plutot que d'echouer
	// au moment de l'appel.
	BilletsSocket string
	// BilletsBase : origine publique de billets, pour transformer une adresse
	// relative (« /b/slug ») du flux JSON en lien cliquable (#1066 phase A).
	// Vide, la vitrine affiche les adresses telles que le flux les rend — un
	// lien relatif pointerait vers le BBS lui-meme, ce qui serait pire qu'une
	// adresse laissee telle quelle.
	BilletsBase string
	// MetaNewsSocket : socket du module MetaNews, pour le cartouche « actualités »
	// de la rédaction (une dizaine d'événements récents, sources corrélées mises
	// en avant). Vide = pas de cartouche. MetaNewsBase = origine publique (liens).
	MetaNewsSocket string
	MetaNewsBase   string
	JWTSecret      string
	// BackupDir : ou deposer les archives declenchees depuis le panneau.
	BackupDir string
	// BanniereOrigine / BanniereHash : la banniere de sante que le WAF de la
	// board injecte dans toutes les pages. Elle arrive APRES notre reponse, on
	// ne peut donc pas lui poser de nonce — on l'autorise precisement, par son
	// origine et l'empreinte exacte de son chargeur.
	//
	// Vides, la politique reste fermee et la banniere ne s'affiche pas. C'est
	// le bon defaut pour une surface publique : la banniere interroge des API
	// d'administration et revele au passage ou se trouve la console.
	BanniereOrigine string
	BanniereHash    string
	// BanniereStyle : empreinte de la balise <style> que la banniere injecte.
	// C'est un ELEMENT, pas un attribut : une empreinte simple suffit, et
	// `unsafe-hashes` — que le message du navigateur suggere — n'a pas lieu
	// d'etre. L'ajouter autoriserait d'un coup tous les styles en ligne.
	BanniereStyle string
	// PeerTubeOrigine : instance autorisee a fournir le lecteur video. Vide,
	// `frame-src` reste ferme et aucune video ne s'integre.
	PeerTubeOrigine string
	// PodcastRacine : parc media du podcaster. Sert de CONFINEMENT — aucun
	// fichier hors de ce repertoire n'est servi, quoi que dise sa base.
	PodcastRacine string
	// PodcastDB : base du podcaster, ouverte en lecture seule.
	PodcastDB string
	// FrameOrigines : services autorises a fournir un lecteur incorpore.
	//
	// DISTINCT DE MediaOrigines, ET VOLONTAIREMENT. Relayer une image ne donne
	// aucun droit au service distant ; l'incorporer dans un cadre lui donne un
	// contexte d'execution dans la page — son propre script, ses propres
	// requetes, sa propre origine. Confondre les deux listes ferait qu'ajouter
	// une vignette accorderait un lecteur, ce que personne n'aurait voulu.
	//
	// Vide, `frame-src` reste ferme et aucun lecteur ne s'integre.
	FrameOrigines []string
	// RadioBase : URL publique de la radio (#1131m). Vide → pas de widget radio
	// dans le rail. Son origine doit AUSSI figurer dans FrameOrigines pour que
	// la CSP autorise l'iframe.
	RadioBase string
	// MediaOrigines : origines de NOS services dont on accepte de relayer une
	// vignette — peertube, podcaster, radio, billets. Chacune est un vhost
	// distinct du BBS, donc `img-src 'self'` ne les couvre pas.
	//
	// ON RELAIE PLUTOT QUE D'ELARGIR LA POLITIQUE. Ajouter chaque hote a
	// `img-src` affaiblirait la politique d'une page qui affiche du contenu
	// ecrit par des membres ; relayer la laisse fermee.
	//
	// LISTE, ET JAMAIS UNE URL LIBRE. Relayer une adresse quelconque postee
	// par un membre ferait du demon un proxy ouvert : on pourrait s'en servir
	// pour sonder l'agregateur ou un conteneur depuis le WAN, en se cachant
	// derriere l'adresse de la board.
	//
	// Vide, aucun media distant n'est relaye — le bon defaut : une autre
	// installation n'a pas nos noms de vhost.
	MediaOrigines []string
	// SocialRelaySocket : socket de secubox-socialrelay. Sert à résoudre la
	// vignette (média caché local) d'un fil-passerelle par son ID BBS — anciens
	// comme nouveaux fils. Vide = pas d'enrichissement réseaux.
	SocialRelaySocket string
	// AuthSocket : socket de secubox-auth. Vide, les comptes synchronises ne
	// peuvent pas se connecter — ils n'ont pas de mot de passe local, et c'est
	// le comportement voulu plutot qu'un repli silencieux.
	AuthSocket string
	// YtsasOrigine : origine de la SAS ytsas (http://IP:8091). Alimente
	// media-src pour le <video> local d'une video YouTube rapatriee (#1056).
	YtsasOrigine string
}

type Server struct {
	st    *store.Store
	auth  *store.Auth
	opt   Options
	tpl   map[string]*template.Template
	mux   *http.ServeMux
	bil   *billets.Client
	ytsas *connectors.ClientYtsas
	// vCSS : empreinte du contenu de la feuille de style, ajoutee a son
	// adresse. Voir routes.go — le WAF de la board supprime les en-tetes de
	// cache, l'adresse est le seul levier qui reste.
	vCSS string
	// medaillons : faces du logo animé, relevées UNE FOIS au démarrage dans
	// l'FS embarqué. Vide = logo fixe. C'est la présence des fichiers qui
	// allume l'animation ; rien à régler d'un côté puis de l'autre.
	medaillons []string
	// resoudreEpisode : id d'episode -> fichier local. Remplace en test.
	resoudreEpisode resolveur
	// authAmont : verificateur de mot de passe pour les comptes d'origine
	// SecuBox. Nil = aucun compte SecuBox ne peut se connecter.
	authAmont authAmont
	// encodeQR : remplace en test pour verifier CE QUE le QR contient.
	encodeQR func(string) ([]byte, error)
	// youtube : connecteur souverain #1056, construit par l'appelant (main.go)
	// a partir de Options.YtsasOrigine — c'est lui qui detient le http.Client
	// et son delai, la Server n'a pas a les connaitre. Nil = servirMediaFiche
	// retombe sur le comportement existant (aucune resolution youtube).
	youtube *connectors.YouTube
	// pres : compteur de présence en mémoire (visiteurs en ligne + membres
	// uniques), affiché dans le bandeau. Éphémère, jamais persisté.
	pres *presence
}

func New(st *store.Store, yt *connectors.YouTube, opt Options) (*Server, error) {
	if opt.Titre == "" {
		opt.Titre = "SecuBox BBS"
	}
	auth, err := store.OpenAuth(filepath.Join(opt.Secrets, "passwd"))
	if err != nil {
		return nil, err
	}
	// UN JEU DE GABARITS PAR PAGE. Chaque page definit son bloc « corps » ;
	// les charger tous ensemble ferait que le dernier ecrase les autres, en
	// silence — toutes les pages afficheraient alors le meme contenu.
	// `vignette` empaquette les deux valeurs dont le fragment a besoin. Les
	// gabarits Go ne passent qu'UN argument a `template` : sans cette fonction, il
	// faudrait recopier le meme ternaire a six endroits — et l'oublier au septieme.
	fn := template.FuncMap{"rendu": Render, "lien": LienApercu, "date": humain, "taille": octets,
		// urlembed : dérive l'URL d'INTÉGRATION d'un lien PeerTube de visionnage
		// (/w/… → /videos/embed/…) pour un <iframe> — PeerTube refuse le cadrage
		// de ses pages /w/ (#1131b). Toute autre URL passe inchangée.
		"urlembed": peertubeEmbedURL,
		// glypheSalon : une émoji STABLE et distincte par salon (#1114), dérivée
		// du slug — plus joli que le ◆ générique, et un sous-salon garde le ↳.
		"glypheSalon": func(slug string, profondeur int) string {
			if profondeur > 0 {
				return "↳"
			}
			pal := []string{"🗨️", "💡", "🔧", "🎨", "📡", "🌐", "🛰️", "📚", "🎭", "🧭",
				"⚗️", "🪐", "🔭", "🎼", "🗺️", "🧩", "🌱", "⚙️", "📻", "🛠️"}
			var h uint32 = 2166136261
			for _, c := range slug {
				h = (h ^ uint32(c)) * 16777619
			}
			return pal[h%uint32(len(pal))]
		},
		"vignette": func(a int64, i string) map[string]any {
			return map[string]any{"A": a, "I": i}
		},
		// initiales2 : deux lettres pour une pastille d'auteur (#1056 stage 3).
		"initiales2": func(h string) string {
			h = strings.TrimSpace(strings.TrimPrefix(h, "@"))
			r := []rune(h)
			if len(r) == 0 {
				return "?"
			}
			if len(r) == 1 {
				return strings.ToUpper(string(r))
			}
			return strings.ToUpper(string(r[:2]))
		},
		// decalage rend la classe d'indentation d'un sous-salon.
		//
		// UNE CLASSE, PAS UN STYLE EN LIGNE. La politique de securite de contenu
		// de ce serveur interdit les styles en ligne ; calculer ici un
		// `style="padding-left:..."` produirait un decalage silencieusement
		// ignore par le navigateur, et personne ne verrait pourquoi.
		//
		// La profondeur est bornee a 3 : au-dela, l'arborescence tient encore en
		// base mais le rail, large de 220px, n'a plus de place a donner.
		"decalage": func(n int) string {
			if n <= 0 {
				return ""
			}
			if n > 3 {
				n = 3
			}
			return fmt.Sprintf(" sub%d", n)
		}}
	pages := map[string]*template.Template{}
	for _, nom := range []string{"index", "thread", "login"} {
		t, err := template.New("layout.html").Funcs(fn).
			ParseFS(assets, "templates/layout.html", "templates/"+nom+".html")
		if err != nil {
			return nil, fmt.Errorf("gabarit %s : %w", nom, err)
		}
		pages[nom] = t
	}
	// #1056 stage 1 : l'accueil « rédaction » est un gabarit AUTONOME (define
	// "newsroom"), sans "layout" ni bbs.css. On le compile à part — les autres
	// pages gardent la coquille à trois colonnes intacte.
	if t, err := template.New("newsroom.html").Funcs(fn).
		ParseFS(assets, "templates/newsroom.html"); err == nil {
		pages["newsroom"] = t
	} else {
		return nil, fmt.Errorf("gabarit newsroom : %w", err)
	}
	// #1114 : le fil dans le skin newsroom. Un JEU réunissant newsroom.html (blocs
	// partagés avmast/avrubriques/avacces), thread.html (le corps réutilisé) et
	// fil.html (la coquille newsroom du fil). Aucune collision de « corps » : seul
	// thread.html le définit dans ce jeu.
	if t, err := template.New("fil.html").Funcs(fn).
		ParseFS(assets, "templates/layout.html", "templates/newsroom.html", "templates/thread.html", "templates/fil.html"); err == nil {
		pages["fil"] = t
	} else {
		return nil, fmt.Errorf("gabarit fil : %w", err)
	}
	// #1114 : /compte dans le skin newsroom. Coquille GÉNÉRIQUE (pagenr) réunissant
	// newsroom.html (blocs partagés avmast/avrubriques/avacces/avrail), compte.html
	// (le corps réutilisé) et coquillenr.html. layout.html fournit le partial
	// "vignette". Aucune collision de « corps » : seul compte.html le définit ici.
	if t, err := template.New("compte.html").Funcs(fn).
		ParseFS(assets, "templates/layout.html", "templates/newsroom.html", "templates/coquillenr.html", "templates/compte.html"); err == nil {
		pages["compte"] = t
	} else {
		return nil, fmt.Errorf("gabarit compte : %w", err)
	}
	// #1114 : /mp dans le skin newsroom (define "mpnr"), rail gauche = liste des
	// conversations. layout.html fournit "vignette" (avatars) ; mp.html fournit
	// le corps. Jeu distinct de "compte" : chacun n'a qu'un seul "corps".
	if t, err := template.New("mp.html").Funcs(fn).
		ParseFS(assets, "templates/layout.html", "templates/newsroom.html", "templates/coquillenr.html", "templates/mp.html"); err == nil {
		pages["mp"] = t
	} else {
		return nil, fmt.Errorf("gabarit mp : %w", err)
	}
	// /mp/annuaire dans le skin newsroom : coquille GÉNÉRIQUE (pagenr) comme
	// /compte — la recherche de membres a besoin de la pleine largeur (elle vit
	// « sur sa propre page », pas dans la colonne des conversations). Le masthead
	// newsroom remplace l'ancienne navbar de layout.html.
	if t, err := template.New("annuaire.html").Funcs(fn).
		ParseFS(assets, "templates/layout.html", "templates/newsroom.html", "templates/coquillenr.html", "templates/annuaire.html"); err == nil {
		pages["annuaire"] = t
	} else {
		return nil, fmt.Errorf("gabarit annuaire : %w", err)
	}
	// /p/{id}/edit (#1091) dans le skin newsroom : coquille GÉNÉRIQUE (pagenr),
	// masthead cohérent avec le reste. edition.html charge lui-même editeur.js.
	if t, err := template.New("edition.html").Funcs(fn).
		ParseFS(assets, "templates/layout.html", "templates/newsroom.html", "templates/coquillenr.html", "templates/edition.html"); err == nil {
		pages["edition"] = t
	} else {
		return nil, fmt.Errorf("gabarit edition : %w", err)
	}
	// Balayage newsroom (#1114 suite) : simple/mastodon/nouveau/sysop rejoignent
	// la coquille GÉNÉRIQUE (pagenr) — même masthead médaillon, même navbar
	// partagée que compte/annuaire/edition. Chacun ne définit que "corps" dans
	// ce jeu, donc aucune collision.
	if t, err := template.New("simple.html").Funcs(fn).
		ParseFS(assets, "templates/layout.html", "templates/newsroom.html", "templates/coquillenr.html", "templates/simple.html"); err == nil {
		pages["simple"] = t
	} else {
		return nil, fmt.Errorf("gabarit simple : %w", err)
	}
	if t, err := template.New("mastodon.html").Funcs(fn).
		ParseFS(assets, "templates/layout.html", "templates/newsroom.html", "templates/coquillenr.html", "templates/mastodon.html"); err == nil {
		pages["mastodon"] = t
	} else {
		return nil, fmt.Errorf("gabarit mastodon : %w", err)
	}
	if t, err := template.New("nouveau.html").Funcs(fn).
		ParseFS(assets, "templates/layout.html", "templates/newsroom.html", "templates/coquillenr.html", "templates/nouveau.html"); err == nil {
		pages["nouveau"] = t
	} else {
		return nil, fmt.Errorf("gabarit nouveau : %w", err)
	}
	if t, err := template.New("sysop.html").Funcs(fn).
		ParseFS(assets, "templates/layout.html", "templates/newsroom.html", "templates/coquillenr.html", "templates/sysop.html"); err == nil {
		pages["sysop"] = t
	} else {
		return nil, fmt.Errorf("gabarit sysop : %w", err)
	}
	// Médiathèque : le podcaster en arborescence (#1056). Le corps reste son
	// propre `{{define "mediatheque"}}` (rendu via rendMediatheque/ExecuteTemplate
	// direct, pas "pagenr") ; layout/newsroom/coquillenr rejoignent le jeu
	// UNIQUEMENT pour que avmast/avrubriques/avacces (et `vignette`) résolvent
	// depuis son propre gabarit (masthead médaillon + navbar partagée, #1114).
	if t, err := template.New("mediatheque.html").Funcs(fn).
		ParseFS(assets, "templates/layout.html", "templates/newsroom.html", "templates/coquillenr.html", "templates/mediatheque.html"); err == nil {
		pages["mediatheque"] = t
	} else {
		return nil, fmt.Errorf("gabarit mediatheque : %w", err)
	}
	// Lecteur détaché (#1056), gabarit autonome pour la fenêtre pop-out.
	if t, err := template.New("player.html").Funcs(fn).
		ParseFS(assets, "templates/player.html"); err == nil {
		pages["player"] = t
	} else {
		return nil, fmt.Errorf("gabarit player : %w", err)
	}
	// Article collaboratif (#1056 stage 3), gabarit autonome (éditeur à plusieurs mains).
	if t, err := template.New("article.html").Funcs(fn).
		ParseFS(assets, "templates/article.html"); err == nil {
		pages["article"] = t
	} else {
		return nil, fmt.Errorf("gabarit article : %w", err)
	}
	s := &Server{st: st, auth: auth, opt: opt, tpl: pages, mux: http.NewServeMux(), youtube: yt, pres: nouvellePresence()}
	// L'empreinte de cache (?v=) couvre les TROIS feuilles/scripts servis : le
	// WAF de la board efface Cache-Control/ETag (voir layout.html), donc une
	// feuille changée sans empreinte neuve resterait invisible au navigateur.
	{
		h := sha256.New()
		for _, f := range []string{"static/bbs.css", "static/newsroom.css", "static/newsroom.js",
			"static/player.js", "static/coquille.js", "static/editeur.js", "static/bbs-logo.svg"} {
			if b, err := assets.ReadFile(f); err == nil {
				h.Write(b)
			}
		}
		s.vCSS = base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:6])
	}
	// Faces du médaillon : triées par nom, l'ordre du défilement est donc celui
	// des fichiers (01-…, 02-…). Absence du dossier = pas d'animation, pas
	// d'erreur : le logo fixe reste servi.
	if ents, err := fs.ReadDir(assets, "static/medaillons"); err == nil {
		for _, e := range ents {
			n := e.Name()
			if e.IsDir() || !strings.HasSuffix(n, ".webp") {
				continue
			}
			s.medaillons = append(s.medaillons, "/static/medaillons/"+n)
		}
		sort.Strings(s.medaillons)
	}
	if opt.AuthSocket != "" {
		s.authAmont = clientAuthSocket(opt.AuthSocket)
	}
	if opt.PodcastDB != "" {
		s.resoudreEpisode = resolveurPodcaster(opt.PodcastDB)
	}
	if opt.BilletsSocket != "" {
		s.bil = billets.NewUnix(opt.BilletsSocket)
		// #1056 : l'origine publique de billets, pour absolutiser un permalien
		// relatif rendu par billets (BILLETS_SITE_URL absent) en un lien
		// cliquable au moment de la publication.
		s.bil.SitePublic = opt.BilletsBase
	}
	// #1056 stage 3 : raccord ytsas — connecter une vidéo déposée (fetch/cache)
	// et l'archiver vers PeerTube. Même origine que le connecteur youtube.
	if opt.YtsasOrigine != "" {
		s.ytsas = &connectors.ClientYtsas{Base: opt.YtsasOrigine, HTTP: &http.Client{Timeout: 20 * time.Second}}
	}
	s.routes()
	s.routesAPI()
	s.routesFichiers()
	s.routesAPISysop()
	s.routesMembre()
	// #1114 : rattrape la visibilité publique des médias déjà cités dans des
	// posts publics (tâche de fond, ne retarde pas le démarrage).
	go s.backfillPiecesPubliques()
	return s, nil
}

func (s *Server) Auth() *store.Auth     { return s.auth }
func (s *Server) Handler() http.Handler { return s.entetes(s.mux) }
func (s *Server) Store() *store.Store   { return s.st }

// entetes : les memes en-tetes pour toute reponse, y compris les erreurs.
//
// Les poser dans chaque gestionnaire garantit qu'un jour l'un d'eux sera
// oublie — et ce sera celui qui rend du contenu ecrit par un membre.
// empreinteValide : une empreinte CSP bien formee, et rien d'autre.
//
// Une valeur erronee ne doit pas produire une politique invalide : un
// navigateur qui n'arrive pas a lire la politique peut l'ignorer ENTIEREMENT,
// ce qui est le pire resultat possible — on croit etre protege et on ne l'est
// plus du tout.
var empreinteValide = regexp.MustCompile(`^sha(256|384|512)-[A-Za-z0-9+/=]+$`)

// politique assemble la politique de securite de contenu.
//
// `media` ajoute UNE origine a `img-src` et `media-src`, et rien d'autre —
// jamais a `script-src` ni `connect-src`. Afficher une image d'un tiers est
// une chose ; lui laisser executer du code en est une autre, et confondre les
// deux est la facon habituelle de vider une politique de son sens.
//
// Vide par defaut : la politique reste 'self' partout tant qu'une page ne
// demande pas explicitement le contraire.
// frameSrc assemble `frame-src` a partir des origines configurees.
//
// Elle etait calculee en DEUX endroits, a l'identique : ajouter un service
// n'aurait porte que sur l'un des deux, et la page Mastodon aurait garde une
// politique differente du reste du site sans que rien ne le signale.
//
// Chaque entree est revalidee : un espace ou un point-virgule couperait la
// politique en deux, et un navigateur qui n'arrive pas a la lire peut
// l'IGNORER ENTIEREMENT — on se croirait protege sans l'etre.
func (s *Server) frameSrc() string {
	// `'self'` en tete : la board encadre SES PROPRES medias — la visionneuse
	// PDF integree est un `<iframe src="/f/NN">` en meme origine (#1131). Sans
	// cette entree, `frame-src` bloquerait le cadre. Elle n'ouvre rien vers
	// l'exterieur : seule notre origine s'encadre.
	ok := []string{"'self'"}
	vu := map[string]bool{"'self'": true}
	ajoute := func(o string) {
		o = strings.TrimRight(strings.TrimSpace(o), "/")
		if o == "" || strings.ContainsAny(o, " ;'\"") || vu[o] {
			return
		}
		vu[o] = true
		ok = append(ok, o)
	}
	ajoute(s.opt.PeerTubeOrigine)
	for _, o := range s.opt.FrameOrigines {
		ajoute(o)
	}
	// #1056 — la board integre YouTube : le rendu du corps emet un iframe
	// youtube-nocookie. Toujours autorise, sinon l'embed serait bloque.
	ajoute("https://www.youtube-nocookie.com")
	// En pratique CE `if` NE SE DECLENCHE PLUS : youtube-nocookie est ajoutee
	// inconditionnellement ci-dessus, donc `ok` a toujours au moins une
	// entree. Gardee pour le jour ou cet ajout deviendrait lui aussi
	// conditionnel — le defaut effectif aujourd'hui EST youtube-nocookie,
	// pas 'none'.
	if len(ok) == 0 {
		return "'none'"
	}
	return strings.Join(ok, " ")
}

func politique(style, script, connect, frame, media string) string {
	img, med := "'self' data:", "'self'"
	if media != "" {
		img += " " + media
		med += " " + media
	}
	return "default-src 'self'; img-src " + img + "; style-src " + style + "; " +
		"script-src " + script + "; connect-src " + connect + "; " +
		"frame-src " + frame + "; media-src " + med + "; " +
		// Seul le Hall souverain (hall.gk2.secubox.in) peut encadrer le BBS — pas
		// 'none' : le bureau WebOS embarque le vhost réel du BBS (#1175). Reste
		// clos à tout autre parent (anti-clickjacking maintenu, opt-in unique).
		"frame-ancestors 'self' https://hall.gk2.secubox.in https://hall.gk2.net; base-uri 'none'; form-action 'self'"
}

// OrigineMediaMastodon rejoue la politique en ouvrant les images et les sons
// d'UNE instance, pour la reponse en cours uniquement.
//
// POURQUOI PAS DANS L'INTERGICIEL. L'elargir globalement autoriserait cette
// origine sur TOUTES les pages, y compris celles qui rendent du texte ecrit
// par des membres. Ici la porte ne s'ouvre que sur /mastodon, et se referme
// avec la reponse.
//
// L'ORIGINE N'EST PAS UNE SAISIE LIBRE : c'est l'hote de l'instance ou le
// membre a prouve son identite par un aller-retour OAuth complet. On la
// revalide malgre tout — un caractere d'espacement ou un point-virgule
// couperait la politique en deux, et un navigateur qui n'arrive pas a la lire
// peut l'ignorer ENTIEREMENT.
func (s *Server) OrigineMediaMastodon(w http.ResponseWriter, hote string) {
	hote = strings.TrimSpace(hote)
	if hote == "" || strings.ContainsAny(hote, " ;'\"/\\") {
		return
	}
	script, connect, style := "'self'", "'self'", "'self'"
	frame := s.frameSrc()
	if e := strings.TrimSpace(s.opt.BanniereStyle); empreinteValide.MatchString(e) {
		style += " '" + e + "'"
	}
	if o := strings.TrimSpace(s.opt.BanniereOrigine); o != "" && !strings.ContainsAny(o, " ;'\"") {
		script += " " + o
		connect += " " + o
		if e := strings.TrimSpace(s.opt.BanniereHash); empreinteValide.MatchString(e) {
			script += " '" + e + "'"
		}
	}
	w.Header().Set("Content-Security-Policy",
		politique(style, script, connect, frame, "https://"+hote))
}

func (s *Server) entetes(h http.Handler) http.Handler {
	script := "'self'"
	connect := "'self'"
	style := "'self'"
	// `frame-src 'none'` par defaut : aucune page tierce ne s'integre. Seule
	// une instance PeerTube explicitement configuree ouvre cette porte, et
	// UNIQUEMENT pour un cadre — pas pour des scripts.
	frame := s.frameSrc()
	if e := strings.TrimSpace(s.opt.BanniereStyle); empreinteValide.MatchString(e) {
		style += " '" + e + "'"
	}
	if o := strings.TrimSpace(s.opt.BanniereOrigine); o != "" && !strings.ContainsAny(o, " ;'\"") {
		script += " " + o
		connect += " " + o
		if e := strings.TrimSpace(s.opt.BanniereHash); empreinteValide.MatchString(e) {
			script += " '" + e + "'"
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		// La politique interdit tout script en ligne et toute origine externe,
		// SAUF UNE EXCEPTION VOULUE : youtube-nocookie dans `frame-src`
		// (#1056, voir frameSrc) — un cadre n'est pas un script, et c'est
		// precisement la distinction que `media` documente plus haut.
		// Le rendu Markdown ne peut deja pas produire de balise <script> ; ceci
		// est la seconde barriere, celle qui tient si la premiere cede.
		// JAMAIS `unsafe-inline` : elle rendrait la politique decorative,
		// c'est-a-dire exactement ce contre quoi elle protege.
		hd.Set("Content-Security-Policy", politique(style, script, connect, frame, s.opt.YtsasOrigine))
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "same-origin")
		// Pas de X-Frame-Options DENY : il primerait sur frame-ancestors et
		// bloquerait l'embarquement par le Hall. Le cadrage est désormais régi
		// par `frame-ancestors 'self' https://hall.gk2.secubox.in` (cf. politique).
		h.ServeHTTP(w, r)
	})
}

// ── sessions ────────────────────────────────────────────────────────────────

type visiteur struct {
	store.UserInfo
	Connecte bool
	CSRF     string
	// Avatar : identifiant de la piece jointe servant d'image de compte, ou 0.
	// Porte par le visiteur et non lu dans chaque gabarit : une requete par
	// affichage d'initiales couterait une lecture par message.
	Avatar int64
}

// Sysop : METHODE et non comparaison dans le gabarit.
//
// `{{if eq .V.Role "sysop"}}` echoue a l'execution : les gabarits Go refusent
// de comparer un type nomme (store.Role) a une chaine litterale. L'erreur
// n'apparait qu'a l'affichage, sur toutes les pages vues par un membre
// connecte — et elle est passee inapercue parce que les tests n'exercaient que
// le chemin anonyme.
func (v visiteur) Sysop() bool { return v.Role == store.RoleSysop }

// Initiales pour la pastille du bandeau.
func (v visiteur) Initiales() string { return initiales(v.Handle) }

// qui identifie l'appelant. Un jeton inconnu, expire ou appartenant a un compte
// desactive rend un visiteur anonyme — jamais une erreur : une page publique
// doit rester lisible avec un vieux cookie dans le navigateur.
func (s *Server) qui(r *http.Request) visiteur {
	v := visiteur{CSRF: s.csrfDe(r)}
	c, err := r.Cookie(cookieSession)
	if err != nil || c.Value == "" {
		return v
	}
	id, err := s.st.UserBySession(c.Value)
	if err != nil {
		return v
	}
	info, err := s.st.UserInfo(id)
	if err != nil {
		return v
	}
	v.UserInfo, v.Connecte = info, true
	v.Avatar = s.st.Avatar(id)
	return v
}

// csrfDe rend le jeton anti-rejeu du navigateur, en le posant s'il manque.
//
// Le motif est celui du « double envoi » : le jeton vit dans un cookie ET doit
// etre repete dans le formulaire. Un site tiers peut declencher une requete que
// le navigateur accompagnera du cookie de session — mais il ne peut pas LIRE le
// cookie, donc pas recopier le jeton dans le corps.
func (s *Server) csrfDe(r *http.Request) string {
	if c, err := r.Cookie(cookieCSRF); err == nil && len(c.Value) >= 22 {
		return c.Value
	}
	return alea(24)
}

func (s *Server) poseCSRF(w http.ResponseWriter, jeton string) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieCSRF, Value: jeton, Path: "/",
		// PAS HttpOnly : ce cookie n'est pas un secret d'authentification, et
		// une page peut avoir besoin de le relire pour un envoi asynchrone.
		// Ce qu'il protege, c'est l'impossibilite pour un TIERS de le lire.
		SameSite: http.SameSiteLaxMode, Secure: s.opt.DerriereTLS,
		MaxAge: 12 * 3600,
	})
}

// verifieCSRF compare le jeton du formulaire a celui du cookie.
func (s *Server) verifieCSRF(r *http.Request) error {
	c, err := r.Cookie(cookieCSRF)
	if err != nil || c.Value == "" {
		return errors.New("jeton anti-rejeu absent")
	}
	envoye := r.PostFormValue("csrf")
	// Comparaison a temps constant : comparer deux jetons avec == laisse fuir
	// leur prefixe commun par le temps de reponse.
	if subtle.ConstantTimeCompare([]byte(c.Value), []byte(envoye)) != 1 {
		return errors.New("jeton anti-rejeu invalide")
	}
	return nil
}

func alea(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Sans alea, aucun jeton n'est sur. Mieux vaut ne pas en produire du
		// tout que d'en produire un previsible.
		panic("source d'alea indisponible : " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func empreinte(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// ── petites aides d'affichage ───────────────────────────────────────────────

func humain(ts int64) string {
	if ts == 0 {
		return ""
	}
	d := time.Since(time.Unix(ts, 0))
	switch {
	case d < time.Minute:
		return "a l'instant"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + " min"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d.Hours())) + " h"
	case d < 48*time.Hour:
		return "hier"
	default:
		return time.Unix(ts, 0).Format("2 Jan 15:04")
	}
}

func octets(n int64) string {
	switch {
	case n >= 1<<30:
		return strconv.FormatFloat(float64(n)/(1<<30), 'f', 1, 64) + " Go"
	case n >= 1<<20:
		return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + " Mo"
	case n >= 1<<10:
		return strconv.FormatInt(n/(1<<10), 10) + " Ko"
	}
	return strconv.FormatInt(n, 10) + " o"
}

func idDe(chemin, prefixe string) int64 {
	reste := strings.TrimPrefix(chemin, prefixe)
	if i := strings.IndexByte(reste, '/'); i >= 0 {
		reste = reste[:i]
	}
	n, _ := strconv.ParseInt(reste, 10, 64)
	return n
}
