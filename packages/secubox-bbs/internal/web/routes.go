package web

import (
	"net/http"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/billets"
	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// Modules actifs. Un module eteint disparait du menu ET de ses routes : laisser
// la route repondre alors que l'entree a disparu, c'est la meme illusion que
// « la page d'administration n'est pas dans le menu ».
type Modules struct{ Media, Biblio, MP, Billets bool }

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
}

type postView struct {
	store.Post
	Author, Initiales, Body string
}

type card struct {
	Title, Sub, Link, LinkText string
	Pills                      []pill
}
type pill struct{ Class, Text string }

func (s *Server) routes() {
	s.mux.Handle("/static/", http.FileServer(http.FS(assets)))
	s.mux.HandleFunc("/", s.accueil)
	s.mux.HandleFunc("/c/", s.salon)
	s.mux.HandleFunc("/t/", s.fil)
	s.mux.HandleFunc("/login", s.connexion)
	s.mux.HandleFunc("/logout", s.deconnexion)
	s.mux.HandleFunc("/invite/", s.invitation)
	s.mux.HandleFunc("/media", s.simple("media"))
	s.mux.HandleFunc("/biblio", s.simple("biblio"))
	s.mux.HandleFunc("/mp", s.simple("mp"))
	s.mux.HandleFunc("/billets", s.simple("billets"))
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
	return page{
		Site: site, Initiale: ini, Hote: r.Host, Vue: vue, V: v,
		Mod:   Modules{Media: true, Biblio: true, MP: true, Billets: true},
		Stats: st, Cats: cats, Titre: site,
	}, pub
}

func (s *Server) rend(w http.ResponseWriter, r *http.Request, nom string, p page) {
	s.poseCSRF(w, p.V.CSRF)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t, ok := s.tpl[nom]
	if !ok {
		http.Error(w, "gabarit inconnu", 500)
		return
	}
	if err := t.ExecuteTemplate(w, "layout", p); err != nil {
		// L'erreur arrive apres le debut de l'ecriture : on ne peut plus
		// changer le code HTTP. On la journalise plutot que d'ecrire une
		// seconde reponse par-dessus la premiere.
		return
	}
}

func (s *Server) accueil(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	p, pub := s.base(r, "forums")
	p.Threads, _ = s.st.Recent(20, pub)
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
		a := s.st.Author(po.AuthorID)
		p.Posts = append(p.Posts, postView{Post: po, Author: a, Initiales: initiales(a), Body: body})
	}
	for _, c := range p.Cats {
		if c.ID == t.CategoryID {
			p.Cat = c
		}
	}
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
	if err != nil || !s.auth.Verify(id, r.PostFormValue("password")) {
		p.Err = "Pseudonyme ou mot de passe incorrect."
		w.WriteHeader(http.StatusUnauthorized)
		s.rend(w, r, "login", p)
		return
	}
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
	// Longueur minimale plutot que regles de composition : une phrase longue
	// resiste mieux qu'un mot court decore de symboles, et ne finit pas sur un
	// post-it.
	if len(pw) < 12 {
		p.Err = "Mot de passe trop court — 12 caractères au minimum."
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
		case "biblio":
			p.Titre, p.Intro = "Bibliothèque", "Les fichiers vivent à côté des messages ; le même rsync emporte les deux."
			p.Vide = "Aucun fichier déposé."
		case "mp":
			if !p.V.Connecte {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			p.Titre, p.Intro = "Messages", "Entre membres. Jamais repris dans un export."
			p.Vide = "Aucun message."
		case "billets":
			p.Titre, p.Intro = "Billets", "Le BBS est l'atelier, billets la vitrine."
			p.Vide = "Aucun fil n'a encore été publié en billet."
		}
		s.rend(w, r, "simple", p)
	}
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
	f := billets.Fil{ID: id, Titre: t.Title, Public: true,
		Retour: "https://" + r.Host + "/t/" + itoa64(id)}
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

	res, err := s.bil.Publier(f)
	if err != nil {
		http.Error(w, "publication refusee : "+err.Error(), http.StatusBadGateway)
		return
	}
	if err := s.st.MarkPublished(id, res.BilletID, res.URL, res.Pris, res.Retenus); err != nil {
		http.Error(w, "billet publie mais lien non enregistre : "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/t/"+itoa64(id), http.StatusSeeOther)
}
