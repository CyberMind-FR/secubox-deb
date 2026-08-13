package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/billets"
	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// Modules actifs. Un module eteint disparait du menu ET de ses routes : laisser
// la route repondre alors que l'entree a disparu, c'est la meme illusion que
// « la page d'administration n'est pas dans le menu ».
type Modules struct{ Media, Biblio, MP, Billets, Mastodon bool }

type page struct {
	Titre, Site, Hote, Vue, Q string
	Initiale                  string
	V                         visiteur
	Mod                       Modules
	Stats                     store.Stats
	Cats                      []store.Category
	Threads                   []store.Thread
	Cat                       store.Category
	T                         store.Thread
	Posts                     []postView
	Err, Invite               string
	Intro, Vide               string
	Note                      string
	Cards                     []card
	// Lu / non-lu des FILS (#1020). A ne pas confondre avec NonLus ci-dessous,
	// qui compte les messages prives — deux notions distinctes, et les nommer
	// pareil aurait garanti qu'on finisse par afficher l'une pour l'autre.
	//
	// FilsNonLus est un ENSEMBLE : un drapeau par fil aurait impose une requete
	// par ligne affichee, et c'est ainsi qu'une fonction de confort devient une
	// cause de lenteur.
	FilsNonLus                map[int64]bool
	FilsNonLusSalon           map[int64]int
	TotalFilsNonLus           int
	// Journal de moderation, affiche au sysop (#1020).
	Moderations               []store.Moderation
	Code, Msg                 string
	Integ                     store.Integrity
	Sain                      bool
	Runs                      []store.IngestRun
	Comptes                   []store.Compte
	Moi                       store.Compte
	// Messagerie (#1008). Convs : la boite de reception ; Fil : la conversation
	// ouverte ; Avec : l'interlocuteur ; Corres : les comptes joignables.
	Convs      []store.ConversationResume
	Fil        []store.Message
	Avec       store.Compte
	AvecAvatar int64
	Corres     []store.Compte
	// Carnet et Annuaire (#1008) : le carnet nomme ce qu'on utilise, l'annuaire
	// est une recherche bornee. Voir internal/store/carnet.go.
	Carnet   []store.Contact
	Annuaire []store.Contact
	// NonLus alimente la pastille de navigation. Evalue a CHAQUE page : un
	// compteur calcule seulement sur /mp ne previendrait de rien, puisqu'il
	// faudrait deja etre sur la page pour le voir.
	NonLus int
	// Module Mastodon (#1008).
	MastoInstance, MastoInvite string
	// Invites : qui a invite qui. Contrepartie de l'invitation sans quota.
	Invites []store.Invitation
	// VCSS : empreinte de la feuille de style, posee dans son adresse.
	//
	// LE WAF DE LA BOARD SUPPRIME `Cache-Control` ET `ETag` — verifie sur gk2 :
	// la socket et nginx les envoient, sbxwaf ne les transmet pas. Aucun module
	// ne peut donc demander une revalidation, et le navigateur garde ce qu'il a,
	// y compris une feuille d'une version anterieure — sans erreur, sans indice.
	//
	// L'adresse, elle, passe. Le fichier change, l'empreinte change, le
	// navigateur voit une autre ressource. Cela ne depend d'aucun en-tete.
	VCSS string
	// Base : origine publique du site, pour afficher une adresse partageable.
	Base string
}

type postView struct {
	store.Post
	Author, Initiales, Body string
	// Avatar de l'auteur, 0 s'il n'en a pas. Rendu par la MEME requete que le
	// pseudonyme : afficher un visage ne coute pas une lecture de plus.
	Avatar int64
}

type card struct {
	Title, Sub, Link, LinkText string
	Pills                      []pill
	// Vignette : adresse d'une miniature, vide s'il n'y en a pas. Glyphe : ce
	// qu'on montre a sa place. LES DEUX EXISTENT parce qu'une video ou un son
	// n'a pas d'image a reduire — et qu'une carte sans rien a gauche casse
	// l'alignement de toute la grille.
	Vignette string
	Glyphe   string
}
type pill struct{ Class, Text string }

func (s *Server) routes() {
	s.mux.Handle("/static/", s.statique(http.FileServer(http.FS(assets))))
	s.mux.HandleFunc("/", s.accueil)
	s.mux.HandleFunc("/lu/tout", s.toutLu)
	s.mux.HandleFunc("/mod/", s.moderer)
	s.mux.HandleFunc("/vignette/", s.servirVignette)
	s.mux.HandleFunc("/c/", s.salon)
	s.mux.HandleFunc("/t/", s.fil)
	s.mux.HandleFunc("/login", s.connexion)
	s.mux.HandleFunc("/logout", s.deconnexion)
	s.mux.HandleFunc("/invite/", s.invitation)
	s.mux.HandleFunc("/media", s.simple("media"))
	s.mux.HandleFunc("/biblio", s.simple("biblio"))
	s.mux.HandleFunc("/mp", s.mp)
	s.mux.HandleFunc("/mp/", s.mp)
	s.mux.HandleFunc("/mp/envoyer", s.mpEnvoyer)
	s.mux.HandleFunc("/mp/annuaire", s.mpAnnuaire)
	s.mux.HandleFunc("/mp/carnet", s.mpCarnet)
	s.mux.HandleFunc("/mastodon", s.mastodon)
	s.mux.HandleFunc("/billets", s.simple("billets"))
	s.mux.HandleFunc("/nouveau", s.nouveau)
	s.mux.HandleFunc("/sysop", s.sysop)
	s.mux.HandleFunc("/sysop/", s.sysopAction)
	s.mux.HandleFunc("/sysop/qr", s.qr)
	s.mux.HandleFunc("/compte", s.compte)
	s.mux.HandleFunc("/compte/", s.compteAction)
	s.mux.HandleFunc("/media/ep/", s.mediaEpisode)
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
}

// base prepare ce que toute page affiche. `publicOnly` decoule de la SEULE
// question qui compte : l'appelant est-il connecte ?
func (s *Server) base(r *http.Request, vue string) (page, bool) {
	v := s.qui(r)
	pub := !v.Connecte
	st, _ := s.st.Stats()
	cats, _ := s.st.Categories(pub)
	site := s.opt.Titre
	ini := "B"
	if site != "" {
		ini = strings.ToUpper(site[:1])
	}
	nonLus := 0
	if v.Connecte {
		nonLus, _ = s.st.NonLus(v.ID)
	}
	return page{
		Site: site, Initiale: ini, Hote: r.Host, Vue: vue, V: v, VCSS: s.vCSS,
		Base:  "https://" + r.Host,
		Mod:   Modules{Media: true, Biblio: true, MP: true, Billets: true, Mastodon: true},
		Stats: st, Cats: cats, Titre: site,
		NonLus: nonLus,
	}, pub
}

// rend ecrit la page dans un TAMPON avant de l'envoyer.
//
// Ecrire directement dans la reponse parait plus economique, et c'est un piege :
// une erreur survenue au milieu du gabarit arrive APRES que l'en-tete 200 est
// parti. Le navigateur recoit alors un document tronque presente comme valide.
// C'est exactement ce qui s'est produit ici — une comparaison de types dans le
// gabarit coupait toutes les pages des membres connectes, en silence.
//
// Avec un tampon : soit la page entiere part, soit une erreur franche.
func (s *Server) rend(w http.ResponseWriter, r *http.Request, nom string, p page) {
	t, ok := s.tpl[nom]
	if !ok {
		log.Printf("gabarit inconnu : %s", nom)
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", p); err != nil {
		log.Printf("rendu de %s : %v", nom, err)
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	s.poseCSRF(w, p.V.CSRF)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}


// poseNonLus renseigne l'etat lu/non-lu de la page (#1020).
//
// UNE SEULE REQUETE POUR TOUTE LA PAGE. Interroger fil par fil aurait produit
// cent aller-retours sur une liste de cent fils — la fonction censee faire
// gagner du temps en aurait coute.
//
// Une erreur de lecture n'est pas fatale : l'indicateur est un CONFORT, et
// perdre la page entiere parce qu'on ne sait pas dire « nouveau » serait un
// mauvais echange. On rend alors une page sans indicateur, ce qui se voit.
func (s *Server) poseNonLus(p *page) {
	if !p.V.Connecte {
		return
	}
	if nl, err := s.st.FilsNonLus(p.V.ID); err == nil {
		p.FilsNonLus = nl
		p.TotalFilsNonLus = len(nl)
	}
	if c, err := s.st.NonLusParSalon(p.V.ID); err == nil {
		p.FilsNonLusSalon = c
	}
}

// toutLu fait retomber le compteur d'un seul geste.
//
// SANS LUI L'INDICATEUR MEURT. Qui revient apres deux semaines a deux cents
// fils non-lus ; s'il faut les ouvrir un par un, il ne le fera pas, et cessera
// de regarder le compteur — qui n'aura plus servi a rien.

// moderer applique un geste de moderation.
//
// UN SEUL POINT D'ENTREE pour tous les gestes. Un handler par verbe aurait
// duplique cinq fois la meme sequence — sysop, POST, anti-rejeu, cible — et il
// aurait suffi d'en oublier une dans le sixieme pour ouvrir une breche.
//
// L'ordre des gardes n'est pas negociable : DROIT, puis METHODE, puis
// ANTI-REJEU. Verifier le jeton avant le droit dirait a un non-sysop si son
// jeton est valide ; verifier la cible avant le droit lui dirait si elle existe.
func (s *Server) moderer(w http.ResponseWriter, r *http.Request) {
	v, ok := s.sysopOK(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	geste := strings.TrimPrefix(r.URL.Path, "/mod/")
	cible, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	var err error

	switch geste {
	case "renommer":
		err = s.st.RenommeFil(v.ID, cible, r.FormValue("titre"))
	case "deplacer":
		salon, _ := strconv.ParseInt(r.FormValue("salon"), 10, 64)
		err = s.st.DeplaceFil(v.ID, cible, salon)
	case "verrouiller":
		err = s.st.VerrouilleFil(v.ID, cible, r.FormValue("etat") == "1")
	case "epingler":
		err = s.st.EpingleFil(v.ID, cible, r.FormValue("etat") == "1")
	case "retirer":
		err = s.st.RetireMessage(v.ID, cible, r.FormValue("motif"))
	case "retablir":
		err = s.st.RetablitMessage(v.ID, cible)
	case "depublier":
		err = s.st.Depublie(v.ID, cible)
	case "salon":
		parent, _ := strconv.ParseInt(r.FormValue("parent"), 10, 64)
		_, err = s.st.CreeSousSalon(v.ID, r.FormValue("slug"),
			r.FormValue("titre"), r.FormValue("desc"), parent)
	default:
		http.NotFound(w, r)
		return
	}

	// L'ERREUR EST DITE A L'OPERATEUR, pas seulement journalisee. Un geste de
	// moderation qui echoue en silence laisse croire qu'il a porte — et le
	// moderateur decouvre le contraire quand quelqu'un s'en plaint.
	retour := r.Referer()
	if retour == "" || !strings.HasPrefix(retour, "/") {
		retour = "/"
	}
	sep := "?"
	if strings.Contains(retour, "?") {
		sep = "&"
	}
	if err != nil {
		log.Printf("bbs: moderation %s sur %d par %d : %v", geste, cible, v.ID, err)
		http.Redirect(w, r, retour+sep+"err="+url.QueryEscape(err.Error()),
			http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, retour+sep+"msg="+url.QueryEscape("modération appliquée"),
		http.StatusSeeOther)
}

func (s *Server) toutLu(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	if !v.Connecte {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	// Meme protection anti-rejeu que les autres actions : marquer tout lu
	// efface un etat, et un lien piege ne doit pas pouvoir le declencher.
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := s.st.MarqueToutLu(v.ID); err != nil {
		log.Printf("bbs: tout marquer lu (%d) : %v", v.ID, err)
	}
	retour := r.Referer()
	if retour == "" || !strings.HasPrefix(retour, "/") {
		retour = "/"
	}
	http.Redirect(w, r, retour, http.StatusSeeOther)
}

func (s *Server) accueil(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	p, pub := s.base(r, "forums")
	p.Threads, _ = s.st.Recent(20, pub)
	s.poseNonLus(&p)
	p.Titre = "Forums"
	s.rend(w, r, "index", p)
}

func (s *Server) salon(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/c/")
	p, pub := s.base(r, "forums")
	for _, c := range p.Cats {
		if c.Slug == slug {
			p.Cat = c
		}
	}
	if p.Cat.ID == 0 {
		http.NotFound(w, r)
		return
	}
	p.Threads, _ = s.st.Threads(p.Cat.ID, pub)
	s.poseNonLus(&p)
	p.Titre = p.Cat.Title
	s.rend(w, r, "index", p)
}

func (s *Server) fil(w http.ResponseWriter, r *http.Request) {
	id := idDe(r.URL.Path, "/t/")
	switch {
	case strings.HasSuffix(r.URL.Path, "/reply"):
		s.repondre(w, r, id)
		return
	case strings.HasSuffix(r.URL.Path, "/publier"):
		s.publier(w, r, id)
		return
	case strings.HasSuffix(r.URL.Path, "/qr"):
		s.qrFil(w, r, id)
		return
	}

	p, pub := s.base(r, "forums")
	t, err := s.st.ThreadByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// LA GARDE DECISIVE. Masquer un fil dans une liste ne suffit pas :
	// l'adresse reste devinable, et un fil local doit repondre 404 — pas 403,
	// qui confirmerait son existence.
	if pub && t.Visibility != store.VisPublic {
		http.NotFound(w, r)
		return
	}

	// OUVRIR UN FIL LE MARQUE LU (#1020). Pose APRES la garde de visibilite :
	// marquer avant aurait laisse une trace de lecture sur un fil que le
	// visiteur n'a pas le droit de voir — et cette trace est un aveu, elle
	// confirmerait par la bande l'existence du fil.
	//
	// L'echec n'interrompt pas l'affichage : ne pas retenir une lecture est un
	// desagrement, ne pas afficher le fil demande est une panne.
	if p.V.Connecte {
		if err := s.st.MarqueLu(p.V.ID, id); err != nil {
			log.Printf("bbs: marquer lu (fil %d, membre %d) : %v", id, p.V.ID, err)
		}
	}

	var posts []store.Post
	if pub {
		posts, _ = s.st.PublicPostsOf(id)
	} else {
		posts, _ = s.st.PostsOf(id)
	}
	for _, po := range posts {
		body, err := s.st.Body(po)
		if err != nil {
			// Un corps divergent est SIGNALE, pas servi. Le lecteur doit savoir
			// que ce message ne correspond plus a ce qui a ete ecrit.
			body = "*(ce message diverge de l'index — prévenez le sysop)*"
		}
		a, av := s.st.AuteurEtAvatar(po.AuthorID)
		p.Posts = append(p.Posts, postView{Post: po, Author: a,
			Initiales: initiales(a), Body: body, Avatar: av})
	}
	for _, c := range p.Cats {
		if c.ID == t.CategoryID {
			p.Cat = c
		}
	}
	// LES FILS VOISINS ALIMENTENT LA COLONNE DU MILIEU. Sans eux, ouvrir un fil
	// viderait la liste et l'on perdrait sa place — c'est exactement ce que la
	// disposition a trois colonnes existe pour eviter : on garde la liste sous
	// les yeux en lisant.
	p.Threads, _ = s.st.Threads(t.CategoryID, pub)
	p.T, p.Titre = t, t.Title
	s.rend(w, r, "thread", p)
}

func (s *Server) repondre(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodPost {
		http.Error(w, "methode refusee", http.StatusMethodNotAllowed)
		return
	}
	v := s.qui(r)
	if !v.Connecte {
		http.Error(w, "connexion requise", http.StatusUnauthorized)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	t, err := s.st.ThreadByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	vis := store.VisLocal
	// On ne peut poser un message public que dans un fil public. Autoriser
	// l'inverse creerait un message qui n'est visible nulle part — et le jour
	// ou le fil deviendrait public, il sortirait sans que personne ne l'ait
	// relu.
	if r.PostFormValue("visibility") == "public" && t.Visibility == store.VisPublic {
		vis = store.VisPublic
	}
	body := strings.TrimSpace(r.PostFormValue("body"))
	if body == "" {
		http.Error(w, "message vide", http.StatusBadRequest)
		return
	}
	if _, err := s.st.Reply(id, v.ID, body, vis); err != nil {
		http.Error(w, "enregistrement impossible", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/t/"+itoa64(id), http.StatusSeeOther)
}

func (s *Server) connexion(w http.ResponseWriter, r *http.Request) {
	p, _ := s.base(r, "login")
	p.Titre = "Connexion"
	if r.Method != http.MethodPost {
		s.rend(w, r, "login", p)
		return
	}
	handle := strings.TrimSpace(r.PostFormValue("handle"))
	id, err := s.st.UserByHandle(handle)
	// MEME REPONSE pour un compte inconnu et un mot de passe faux. Distinguer
	// les deux transformerait le formulaire en annuaire des membres.
	if err != nil || !s.verifie(handle, id, r.PostFormValue("password")) {
		p.Err = "Pseudonyme ou mot de passe incorrect."
		w.WriteHeader(http.StatusUnauthorized)
		s.rend(w, r, "login", p)
		return
	}
	s.st.NoteLogin(id, r.RemoteAddr)
	jeton, err := s.st.NewSession(id, r.RemoteAddr, r.UserAgent())
	if err != nil {
		p.Err = "Session impossible."
		s.rend(w, r, "login", p)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieSession, Value: jeton, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: s.opt.DerriereTLS, MaxAge: 30 * 24 * 3600,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) deconnexion(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if c, err := r.Cookie(cookieSession); err == nil {
			s.st.CloseSession(c.Value)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: cookieSession, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) invitation(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimPrefix(r.URL.Path, "/invite/")
	p, _ := s.base(r, "login")
	p.Titre, p.Invite = "Invitation", code
	if r.Method != http.MethodPost {
		s.rend(w, r, "login", p)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	handle := strings.TrimSpace(r.PostFormValue("handle"))
	pw := r.PostFormValue("password")
	// AUCUNE LONGUEUR MINIMALE — retiree sur demande de l'exploitant. Seul le
	// mot de passe vide reste refuse : ce n'est pas une limite de longueur mais
	// la difference entre avoir un mot de passe et ne pas en avoir.
	if pw == "" {
		p.Err = "Mot de passe vide."
		s.rend(w, r, "login", p)
		return
	}
	id, err := s.st.RedeemInvite(code, handle, strings.TrimSpace(r.PostFormValue("display")))
	if err != nil {
		p.Err = "Invitation invalide, expirée ou déjà utilisée."
		s.rend(w, r, "login", p)
		return
	}
	if err := s.auth.SetPassword(id, pw); err != nil {
		p.Err = "Enregistrement du mot de passe impossible."
		s.rend(w, r, "login", p)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// simple sert les vues encore descriptives. Elles annoncent ce que le module
// fera plutot que de simuler un fonctionnement qui n'existe pas : une page qui
// ment sur son etat coute plus cher qu'une page qui l'avoue.
func (s *Server) simple(vue string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := s.base(r, vue)
		switch vue {
		case "media":
			p.Titre, p.Intro = "Média", "Ce qu'on écoute et regarde, au même endroit que ce qu'on en dit."
			p.Vide = "Aucune passerelle média raccordée pour l'instant."
			p.Note = "Le média n'est pas recopié : le module lit le flux du podcaster et le catalogue PeerTube là où ils sont déjà."
			p.Cards = s.cartesMedia()
		case "biblio":
			p.Titre, p.Intro = "Bibliothèque", "Les fichiers vivent à côté des messages ; le même rsync emporte les deux."
			p.Vide = "Aucun fichier déposé."
			p.Cards = s.cartesBiblio()
		case "billets":
			p.Titre, p.Intro = "Billets", "Le BBS est l'atelier, billets la vitrine."
			p.Vide = "Aucun fil n'a encore été publié en billet."
			p.Cards = s.cartesBillets()
		}
		s.rend(w, r, "simple", p)
	}
}


// cartesMedia rend les fils deposes par les passerelles media (#1020).
//
// La page annoncait « aucune passerelle raccordee » alors que 222 fils y
// etaient : 122 emissions du podcaster et 100 videos PeerTube. Elle
// n'interrogeait pas la base — meme defaut que la Bibliotheque et les Billets,
// et meme consequence : un message vide en dur est indiscernable d'un vide
// reel, donc personne ne s'apercoit qu'il ment.
func (s *Server) cartesMedia() []card {
	fs, err := s.st.MediasParSource(60)
	if err != nil {
		return []card{{Title: "Lecture impossible",
			Sub: "Les médias n'ont pas pu être lus : " + err.Error()}}
	}
	out := make([]card, 0, len(fs))
	for _, f := range fs {
		// Le NOM DE LA SOURCE est affiche, pas seulement le salon : « podcaster »
		// dit d'ou vient le contenu et donc ou le corriger, ce qu'un titre de
		// salon ne dit pas.
		pills := []pill{{Class: "ok", Text: f.Source}}
		if f.MediaKind != "" {
			pills = append(pills, pill{Class: "", Text: f.MediaKind})
		}
		if f.Visibility == store.VisLocal {
			// Une emission locale ne sort pas de la maison. Le dire evite qu'on
			// s'etonne de ne pas la retrouver publiquement.
			pills = append(pills, pill{Class: "warn", Text: "local"})
		}
		lien, texte := "/t/"+strconv.FormatInt(f.ID, 10), "Ouvrir le fil"
		if f.MediaURL != "" {
			lien, texte = f.MediaURL, "Écouter / regarder"
		}
		out = append(out, card{
			Title:    f.Title,
			Sub:      f.Salon,
			Link:     lien,
			LinkText: texte,
			Pills:    pills,
			// LE GENRE VIENT DE LA SOURCE, pas d'un fichier qu'on aurait ici :
			// une emission du podcaster et une video PeerTube vivent chez eux.
			// On ne peut donc pas en reduire l'image — le glyphe dit au moins
			// de quoi il s'agit avant d'avoir clique.
			Glyphe: glypheDeSource(f.MediaKind),
		})
	}
	return out
}

// cartesBiblio rend la bibliothèque commune (#1020).
//
// La page annonçait « aucun fichier déposé » alors que neuf l'étaient : elle
// n'interrogeait tout simplement pas la base. Un message vide en dur est
// indiscernable d'un vide réel — c'est ce qui a laissé le défaut passer.
//
// UNE ERREUR DE LECTURE NE VIDE PAS LA PAGE EN SILENCE : elle est dite. Rendre
// une liste vide sur erreur reproduirait exactement le défaut qu'on corrige.
func (s *Server) cartesBiblio() []card {
	fs, err := s.st.TousFichiers(100)
	if err != nil {
		return []card{{Title: "Lecture impossible",
			Sub: "La bibliothèque n'a pas pu être lue : " + err.Error()}}
	}
	out := make([]card, 0, len(fs))
	for _, f := range fs {
		genre := "fichier"
		switch {
		case f.EstImage():
			genre = "image"
		case f.EstAudio():
			genre = "son"
		case f.EstVideo():
			genre = "vidéo"
		}
		c := card{
			Title:    f.Name,
			Sub:      "déposé par " + f.Deposant + " · " + tailleLisible(f.Size),
			Link:     "/f/" + strconv.FormatInt(f.ID, 10) + extensionDe(f.Mime),
			LinkText: "Ouvrir",
			Pills:    []pill{{Class: "ok", Text: genre}},
			Glyphe:   glypheDe(genre),
		}
		// SEULES LES IMAGES ONT UNE VIGNETTE. Extraire une image d'une video
		// demanderait ffmpeg — un decodeur complet lance sur un fichier
		// televerse, pour orner une carte. Le rapport n'y est pas.
		if f.EstImage() {
			c.Vignette = "/vignette/" + strconv.FormatInt(f.ID, 10) + ".jpg"
		}
		out = append(out, c)
	}
	return out
}

// cartesBillets rend les fils sortis vers la vitrine (#1020).
func (s *Server) cartesBillets() []card {
	bs, err := s.st.Billets(100)
	if err != nil {
		return []card{{Title: "Lecture impossible",
			Sub: "Les billets n'ont pas pu être lus : " + err.Error()}}
	}
	out := make([]card, 0, len(bs))
	for _, b := range bs {
		titre := b.Titre
		if titre == "" {
			titre = "(fil supprimé)"
		}
		sous := strconv.Itoa(b.Repris) + " message(s) repris"
		if b.Retenus > 0 {
			// « 6 repris, 2 retenus » dit à l'auteur que la publication n'a pas
			// tout emporté, avant qu'il ne s'en aperçoive autrement.
			sous += ", " + strconv.Itoa(b.Retenus) + " retenu(s) en local"
		}
		c := card{
			Title:    titre,
			Sub:      sous,
			Link:     "/t/" + strconv.FormatInt(b.ThreadID, 10),
			LinkText: "Voir le fil",
			Pills:    []pill{{Class: "ok", Text: "publié"}},
			Glyphe:   "📰",
		}
		// L'ADRESSE PEUT MANQUER : les deux billets de gk2 ont un identifiant
		// mais pas d'URL. Plutôt que de fabriquer un lien mort, on renvoie vers
		// le fil et on DIT que l'adresse manque — un lien qui échoue coûte plus
		// cher qu'une absence signalée.
		if b.URL != "" {
			c.Link, c.LinkText = b.URL, "Lire le billet"
		} else {
			c.Pills = append(c.Pills, pill{Class: "warn", Text: "adresse manquante"})
		}
		out = append(out, c)
	}
	return out
}

// glypheDeSource traduit le genre annonce par une passerelle media.
//
// Les genres viennent de sources differentes (podcaster, PeerTube) et ne
// suivent aucune convention commune : on reconnait donc par MOTIF plutot que
// par egalite, sans quoi un « audio/mpeg » et un « podcast » se retrouveraient
// avec le glyphe generique alors qu'on sait tres bien ce qu'ils sont.
func glypheDeSource(genre string) string {
	g := strings.ToLower(genre)
	switch {
	case strings.Contains(g, "video") || strings.Contains(g, "vidéo"):
		return "🎬"
	case strings.Contains(g, "audio") || strings.Contains(g, "podcast") ||
		strings.Contains(g, "episode") || strings.Contains(g, "épisode"):
		return "🎧"
	}
	return "📡"
}

// glypheDe : ce qu'on montre quand il n'y a pas d'image a reduire.
func glypheDe(genre string) string {
	switch genre {
	case "image":
		return "🖼"
	case "son":
		return "🎧"
	case "vidéo":
		return "🎬"
	}
	return "📄"
}

// tailleLisible rend une taille d'octets sous forme courte.
func tailleLisible(n int64) string {
	switch {
	case n >= 1<<20:
		return strconv.FormatInt(n/(1<<20), 10) + " Mio"
	case n >= 1<<10:
		return strconv.FormatInt(n/(1<<10), 10) + " Kio"
	}
	return strconv.FormatInt(n, 10) + " o"
}

func initiales(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return "?"
	}
	if len(h) >= 2 {
		return strings.ToUpper(h[:2])
	}
	return strings.ToUpper(h)
}

func itoa64(i int64) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// publier envoie un fil vers le module billets.
//
// TROIS GARDES, VOLONTAIREMENT REDONDANTES :
//  1. ici : seul un sysop declenche une publication ;
//  2. ici : le fil doit etre public ;
//  3. dans le client : il refuse de nouveau un fil local, et ne transmet que
//     les messages publics.
//
// La redondance n'est pas un oubli de nettoyage. Une garde d'interface se
// contourne en tapant l'adresse ; une garde de client protege aussi les
// appelants qui viendront plus tard.
func (s *Server) publier(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodPost {
		http.Error(w, "methode refusee", http.StatusMethodNotAllowed)
		return
	}
	v := s.qui(r)
	if !v.Connecte || v.Role != store.RoleSysop {
		http.Error(w, "reserve au sysop", http.StatusForbidden)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if s.bil == nil {
		http.Error(w, "module billets non configure", http.StatusServiceUnavailable)
		return
	}
	t, err := s.st.ThreadByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if t.Visibility != store.VisPublic {
		http.Error(w, "un fil local ne se publie pas : rendez-le public d'abord",
			http.StatusForbidden)
		return
	}

	posts, err := s.st.PostsOf(id)
	if err != nil {
		http.Error(w, "lecture du fil impossible", http.StatusInternalServerError)
		return
	}
	// La session SecuBox de l'operateur est relayee : le BBS n'a pas d'identite
	// propre chez billets, il transmet l'autorite qu'on lui a presentee.
	var session string
	if c, err := r.Cookie("secubox_session"); err == nil {
		session = c.Value
	}
	f := billets.Fil{ID: id, Titre: t.Title, Public: true, Session: session,
		// L'attribution nominative est une DECISION, jamais le defaut :
		// l'autorite de l'operateur est anonymisante.
		Attribuer: r.PostFormValue("attribuer") == "1",
		Retour:    "https://" + r.Host + "/t/" + itoa64(id)}
	for _, p := range posts {
		corps, err := s.st.Body(p)
		if err != nil {
			// Un corps divergent n'est PAS publie : on ne met pas sur internet
			// un texte dont on ne sait plus s'il est celui qui a ete ecrit.
			http.Error(w, "un message diverge de l'index — publication refusee",
				http.StatusConflict)
			return
		}
		f.Messages = append(f.Messages, billets.Message{
			Auteur: s.st.Author(p.AuthorID), Corps: corps,
			Public: p.Visibility == store.VisPublic,
		})
	}

	// LES PIECES JOINTES CITEES SONT RESOLUES ICI, pas dans le client : lui
	// n'a pas acces au magasin, et c'est bien ainsi — il parle a billets, il
	// ne lit pas nos fichiers.
	f.Jointes = s.jointesCitees(f.Messages)

	res, err := s.bil.Publier(f)
	if err != nil {
		// PAS 502. nginx intercepte 502/503/504 (`secubox-waking.conf`) et les
		// remplace par la page de reveil — qui n'accepte que GET et repond 405
		// a un POST. L'erreur reelle etait donc masquee par un « Method Not
		// Allowed » incomprehensible, et j'ai cherche du cote de billets un
		// defaut qui n'y etait pas. 409 dit la meme chose sans etre avale.
		http.Error(w, "publication refusee : "+err.Error(), http.StatusConflict)
		return
	}
	if err := s.st.MarkPublished(id, res.BilletID, res.URL, res.Pris, res.Retenus); err != nil {
		http.Error(w, "billet publie mais lien non enregistre : "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/t/"+itoa64(id), http.StatusSeeOther)
}

// nouveau : ouvrir un fil.
//
// LA ROUTE MANQUAIT. Le gabarit proposait « Nouveau fil » depuis le premier
// jour et menait a une page introuvable — un defaut que seule une visite de
// l'interface revele, et qu'aucun test ne couvrait puisque tous partaient de
// fils crees directement en base.
func (s *Server) nouveau(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	if !v.Connecte {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	p, _ := s.base(r, "forums")
	p.Titre = "Ouvrir un fil"
	if r.Method != http.MethodPost {
		s.rend(w, r, "nouveau", p)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	titre := strings.TrimSpace(r.PostFormValue("title"))
	corps := strings.TrimSpace(r.PostFormValue("body"))
	if titre == "" || corps == "" {
		p.Err = "Un titre et un premier message sont nécessaires."
		s.rend(w, r, "nouveau", p)
		return
	}
	var cat int64
	fmt.Sscanf(r.PostFormValue("categorie"), "%d", &cat)
	// Le salon doit exister ET etre visible de l'appelant : un identifiant
	// choisi au hasard ne doit pas permettre d'ecrire dans un salon qu'on ne
	// voit pas.
	valide := false
	for _, c := range p.Cats {
		if c.ID == cat {
			valide = true
		}
	}
	if !valide {
		p.Err = "Salon inconnu."
		s.rend(w, r, "nouveau", p)
		return
	}
	vis := store.VisLocal
	if r.PostFormValue("visibility") == "public" {
		vis = store.VisPublic
	}
	id, err := s.st.NewThread(cat, v.ID, titre, corps, vis)
	if err != nil {
		p.Err = "Enregistrement impossible : " + err.Error()
		s.rend(w, r, "nouveau", p)
		return
	}
	http.Redirect(w, r, "/t/"+itoa64(id), http.StatusSeeOther)
}

// sysopOK : la console est fermee a tout ce qui n'est pas sysop.
//
// Le lien n'apparait que pour un sysop, mais l'ADRESSE est devinable.
// « Ce n'est pas dans le menu » n'a jamais ferme une porte.
func (s *Server) sysopOK(w http.ResponseWriter, r *http.Request) (visiteur, bool) {
	v := s.qui(r)
	if !v.Connecte || v.Role != store.RoleSysop {
		// 404 et non 403 : un 403 confirmerait que la page existe.
		http.NotFound(w, r)
		return v, false
	}
	return v, true
}

func (s *Server) sysop(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.sysopOK(w, r); !ok {
		return
	}
	p, _ := s.base(r, "sysop")
	p.Titre = "Console sysop"
	p.Code = r.URL.Query().Get("code")
	p.Msg = r.URL.Query().Get("msg")
	p.Integ, _ = s.st.Integrity()
	p.Sain = p.Integ.Diverging == 0 && p.Integ.Missing == 0 && p.Integ.Unreadable == 0
	p.Runs, _ = s.st.IngestRuns(12)
	p.Comptes, _ = s.st.Users()
	p.Err = r.URL.Query().Get("err")
	p.Invites, _ = s.st.Invites()
	p.MastoInstance, _ = s.st.Reglage(store.CleMastodonInstance)
	p.MastoInvite, _ = s.st.Reglage(store.CleMastodonInvite)
	// UN JOURNAL QUE PERSONNE NE LIT N'ENCADRE RIEN. Ecrire chaque geste de
	// moderation sans jamais l'afficher aurait donne la lettre de la
	// tracabilite sans l'usage : c'est la consultation qui rend le pouvoir
	// verifiable, pas l'ecriture.
	p.Moderations, _ = s.st.Moderations(50)
	s.rend(w, r, "sysop", p)
}

func (s *Server) sysopAction(w http.ResponseWriter, r *http.Request) {
	v, ok := s.sysopOK(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	switch strings.TrimPrefix(r.URL.Path, "/sysop/") {
	case "reglages":
		// LE LIEN EST VALIDE AVANT D'ENTRER EN BASE, pas seulement au rendu.
		// Il est colle par le sysop puis affiche dans un href visible de tous
		// les membres : un `javascript:` y deviendrait actif sur chaque page du
		// module. Une valeur invalide ne doit jamais etre stockee.
		for cle, champ := range map[string]string{
			store.CleMastodonInstance: "instance",
			store.CleMastodonInvite:   "invitation",
		} {
			val := strings.TrimSpace(r.PostFormValue(champ))
			if val != "" && !store.LienExterneValide(val) {
				http.Redirect(w, r, "/sysop?err="+url.QueryEscape(
					"lien refuse ("+champ+") : seuls http et https sont acceptes"),
					http.StatusSeeOther)
				return
			}
			if err := s.st.PoseReglage(cle, val); err != nil {
				http.Redirect(w, r, "/sysop?err="+url.QueryEscape(err.Error()),
					http.StatusSeeOther)
				return
			}
		}
		http.Redirect(w, r, "/sysop?msg="+url.QueryEscape("reglages enregistres"),
			http.StatusSeeOther)
	case "invite":
		code, err := s.st.NewInvite(v.ID)
		if err != nil {
			http.Redirect(w, r, "/sysop?msg="+url.QueryEscape("invitation impossible : "+err.Error()),
				http.StatusSeeOther)
			return
		}
		// Le code passe par l'adresse UNE fois, pour etre affiche. Il n'est
		// stocke nulle part en clair — ni en base, ni en session.
		http.Redirect(w, r, "/sysop?code="+url.QueryEscape(code), http.StatusSeeOther)
	case "compte":
		var id int64
		fmt.Sscanf(r.PostFormValue("id"), "%d", &id)
		var err error
		msg := ""
		switch r.PostFormValue("action") {
		case "disable":
			// SE DESACTIVER SOI-MEME est refuse : le dernier sysop se
			// fermerait la porte, et il faudrait alors passer par la ligne de
			// commande sur la board pour rouvrir.
			if id == v.ID {
				msg = "vous ne pouvez pas desactiver votre propre compte"
			} else {
				err, msg = s.st.DisableUser(id), "compte desactive"
			}
		case "enable":
			err, msg = s.st.EnableUser(id), "compte reactive"
		default:
			msg = "action inconnue"
		}
		if err != nil {
			msg = "echec : " + err.Error()
		}
		http.Redirect(w, r, "/sysop?msg="+url.QueryEscape(msg), http.StatusSeeOther)
	case "motdepasse":
		// REINITIALISATION PAR LE SYSOP — sans l'ancien mot de passe, c'est le
		// propre du geste : on l'emploie quand le titulaire ne peut plus entrer.
		var id int64
		fmt.Sscanf(r.PostFormValue("id"), "%d", &id)
		nouveau := r.PostFormValue("nouveau")
		if err := s.auth.ResetPassword(id, nouveau); err != nil {
			http.Redirect(w, r, "/sysop?err="+url.QueryEscape(err.Error()),
				http.StatusSeeOther)
			return
		}
		// TOUTES LES SESSIONS DU COMPTE SONT FERMEES. On reinitialise un mot de
		// passe soit parce qu'il a fuite, soit pour reprendre la main : laisser
		// vivre les sessions ouvertes ailleurs viderait le geste de son sens
		// dans les deux cas. `RevokeOtherSessions` avec un jeton vide ne
		// preserve rien — ce qui est bien l'intention ici.
		s.st.RevokeOtherSessions(id, "")
		http.Redirect(w, r, "/sysop?msg="+url.QueryEscape(
			"mot de passe reinitialise — les sessions du compte ont ete fermees"),
			http.StatusSeeOther)
	case "reindex":
		msg := "index reconstruit"
		if err := s.st.Reindex(); err != nil {
			msg = "reconstruction impossible : " + err.Error()
		}
		http.Redirect(w, r, "/sysop?msg="+url.QueryEscape(msg), http.StatusSeeOther)
	case "backup":
		dest := s.opt.BackupDir + "/bbs-" + time.Now().Format("20060102-150405") + ".tar.gz"
		msg := "archive écrite : " + dest
		if err := s.st.Backup(dest); err != nil {
			msg = "sauvegarde impossible : " + err.Error()
		}
		http.Redirect(w, r, "/sysop?msg="+url.QueryEscape(msg), http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
}

// compte : la page d'un membre sur lui-meme.
func (s *Server) compte(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	if !v.Connecte {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	p, _ := s.base(r, "compte")
	p.Titre = "Mon compte"
	p.Msg = r.URL.Query().Get("msg")
	p.Err = r.URL.Query().Get("err")
	p.Code = r.URL.Query().Get("code")
	// On ne lit QUE son propre compte : la liste complete est reservee a la
	// console sysop.
	if cs, err := s.st.Users(); err == nil {
		for _, c := range cs {
			if c.ID == v.ID {
				p.Moi = c
			}
		}
	}
	s.rend(w, r, "compte", p)
}

func (s *Server) compteAction(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	if !v.Connecte {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	jeton := ""
	if c, err := r.Cookie(cookieSession); err == nil {
		jeton = c.Value
	}

	switch strings.TrimPrefix(r.URL.Path, "/compte/") {
	case "motdepasse":
		err := s.auth.ChangePassword(v.ID,
			r.PostFormValue("ancien"), r.PostFormValue("nouveau"))
		if err != nil {
			http.Redirect(w, r, "/compte?err="+url.QueryEscape(err.Error()),
				http.StatusSeeOther)
			return
		}
		// Le changement FERME les autres sessions. On change son mot de passe
		// surtout quand on craint qu'il ait fuite ; laisser vivre les sessions
		// ouvertes ailleurs viderait le geste de son sens.
		s.st.RevokeOtherSessions(v.ID, jeton)
		http.Redirect(w, r, "/compte?msg="+url.QueryEscape(
			"mot de passe change — vos autres sessions ont ete fermees"), http.StatusSeeOther)
	case "invite":
		// TOUT MEMBRE PEUT INVITER, SANS QUOTA — choix explicite de
		// l'exploitant (#1008). La contrepartie est la tracabilite : l'emetteur
		// est enregistre, et la console sysop montre qui a invite qui. Sans
		// cela, une inscription en cascade serait indebrouillable.
		//
		// Un compte ferme ne peut pas arriver ici : `DisableUser` supprime les
		// sessions, et `UserBySession` ecarte les comptes desactives. Le
		// verifier une seconde fois serait du code mort — mais si l'une de ces
		// deux barrieres tombait, ce chemin ouvrirait la porte. C'est
		// `TestUnCompteFermeNInvitePas` qui garde la propriete.
		code, err := s.st.NewInvite(v.ID)
		if err != nil {
			http.Redirect(w, r, "/compte?err="+url.QueryEscape("invitation impossible : "+err.Error()),
				http.StatusSeeOther)
			return
		}
		// Le code ne transite qu'UNE fois, pour etre affiche. Il n'est stocke
		// nulle part en clair — ni en base, ni en session.
		http.Redirect(w, r, "/compte?code="+url.QueryEscape(code), http.StatusSeeOther)
	case "sessions":
		s.st.RevokeOtherSessions(v.ID, jeton)
		http.Redirect(w, r, "/compte?msg="+url.QueryEscape("autres sessions fermees"),
			http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
}

// statique sert les fichiers embarques avec une revalidation obligatoire.
//
// SANS EN-TETE DE CACHE, LE NAVIGATEUR DECIDE SEUL — ET IL GARDE. Une feuille
// de style servie une fois le reste longtemps, y compris apres plusieurs
// deploiements : la page s'affiche avec un CSS d'une version anterieure, sans
// erreur et sans indice. C'est arrive ici, et le temps perdu a chercher cote
// serveur un defaut qui vivait dans le cache d'un navigateur a ete
// considerable.
//
// `no-cache` ne signifie pas « ne pas mettre en cache » mais « revalider avant
// de reutiliser ». L'ETag, calcule sur le contenu, rend cette revalidation
// gratuite : tant que le fichier n'a pas change, la reponse est un 304 vide.
// jointesCitees rassemble les fichiers dont l'adresse apparait dans les corps.
//
// ON NE TRANSFERE QUE CE QUI EST CITE. Envoyer toute la bibliotheque de
// l'auteur serait une fuite : un fichier depose pour un fil local se
// retrouverait sur une page publique.
func (s *Server) jointesCitees(msgs []billets.Message) []billets.Jointe {
	vus := map[int64]bool{}
	var out []billets.Jointe
	for _, m := range msgs {
		for _, ref := range refsJointes.FindAllStringSubmatch(m.Corps, -1) {
			var id int64
			fmt.Sscanf(ref[1], "%d", &id)
			if id == 0 || vus[id] {
				continue
			}
			vus[id] = true
			fi, err := s.st.Fichier(id)
			if err != nil {
				continue // efface depuis : la reference restera en texte
			}
			b, err := os.ReadFile(s.st.CheminFichier(fi))
			if err != nil {
				continue
			}
			out = append(out, billets.Jointe{
				Ref: ref[0], Nom: fi.Name, Mime: fi.Mime, Contenu: b,
			})
		}
	}
	return out
}

// La reference telle qu'elle est ecrite dans un corps : `/f/12` ou `/f/12.png`.
var refsJointes = regexp.MustCompile(`/f/(\d+)(?:\.[a-z0-9]{2,5})?`)

func (s *Server) statique(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nom := strings.TrimPrefix(r.URL.Path, "/")
		if b, err := assets.ReadFile(nom); err == nil {
			sum := sha256.Sum256(b)
			etag := `"` + base64.RawURLEncoding.EncodeToString(sum[:9]) + `"`
			w.Header().Set("ETag", etag)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		h.ServeHTTP(w, r)
	})
}

// qrFil rend le code QR d'un fil, pour passer sur un telephone sans recopier
// l'adresse.
//
// L'ADRESSE EST CONSTRUITE ICI a partir du seul identifiant. Accepter une
// adresse en parametre ferait de cette page un generateur de QR vers n'importe
// ou, commode pour faire scanner un lien piege depuis un domaine de confiance.
//
// LA VISIBILITE EST VERIFIEE : un fil local ne rend pas de code QR pour un
// visiteur qui n'a pas le droit de le lire. Sans cela, l'image confirmerait
// l'existence d'un fil que la page refuse d'afficher.
func (s *Server) qrFil(w http.ResponseWriter, r *http.Request, id int64) {
	v := s.qui(r)
	t, err := s.st.ThreadByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !v.Connecte && t.Visibility != store.VisPublic {
		http.NotFound(w, r)
		return
	}
	svg, err := s.encoder("https://" + r.Host + "/t/" + itoa64(id))
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "private, max-age=600")
	w.Write(svg)
}

// verifie choisit QUI valide le mot de passe, selon l'origine du compte.
//
// Un membre venu par invitation a son mot de passe ICI ; l'envoyer a
// secubox-auth le divulguerait a un service qui n'a rien a en faire. Un compte
// synchronise depuis SecuBox n'a AUCUNE empreinte locale : seule la delegation
// peut l'ouvrir.
//
// Aucun repli d'un mode sur l'autre : chaque compte a une origine, une seule.
func (s *Server) verifie(handle string, id int64, motDePasse string) bool {
	src, err := s.st.AuthSource(handle)
	if err != nil {
		return false
	}
	if src == "secubox" {
		if s.authAmont == nil {
			return false
		}
		return s.authAmont(handle, motDePasse)
	}
	return s.auth.Verify(id, motDePasse)
}
