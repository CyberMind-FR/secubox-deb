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
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/billets"
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
	JWTSecret     string
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
}

type Server struct {
	st   *store.Store
	auth *store.Auth
	opt  Options
	tpl  map[string]*template.Template
	mux  *http.ServeMux
	bil  *billets.Client
	// vCSS : empreinte du contenu de la feuille de style, ajoutee a son
	// adresse. Voir routes.go — le WAF de la board supprime les en-tetes de
	// cache, l'adresse est le seul levier qui reste.
	vCSS string
}

func New(st *store.Store, opt Options) (*Server, error) {
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
	fn := template.FuncMap{"rendu": Render, "date": humain, "taille": octets}
	pages := map[string]*template.Template{}
	for _, nom := range []string{"index", "thread", "login", "simple", "nouveau", "sysop", "compte"} {
		t, err := template.New("layout.html").Funcs(fn).
			ParseFS(assets, "templates/layout.html", "templates/"+nom+".html")
		if err != nil {
			return nil, fmt.Errorf("gabarit %s : %w", nom, err)
		}
		pages[nom] = t
	}
	s := &Server{st: st, auth: auth, opt: opt, tpl: pages, mux: http.NewServeMux()}
	if b, err := assets.ReadFile("static/bbs.css"); err == nil {
		sum := sha256.Sum256(b)
		s.vCSS = base64.RawURLEncoding.EncodeToString(sum[:6])
	}
	if opt.BilletsSocket != "" {
		s.bil = billets.NewUnix(opt.BilletsSocket)
	}
	s.routes()
	s.routesAPI()
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

func (s *Server) entetes(h http.Handler) http.Handler {
	script := "'self'"
	connect := "'self'"
	style := "'self'"
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
		// La politique interdit tout script en ligne et toute origine externe.
		// Le rendu Markdown ne peut deja pas produire de balise <script> ; ceci
		// est la seconde barriere, celle qui tient si la premiere cede.
		// JAMAIS `unsafe-inline` : elle rendrait la politique decorative,
		// c'est-a-dire exactement ce contre quoi elle protege.
		hd.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src "+style+"; "+
				"script-src "+script+"; connect-src "+connect+"; "+
				"frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "same-origin")
		hd.Set("X-Frame-Options", "DENY")
		h.ServeHTTP(w, r)
	})
}

// ── sessions ────────────────────────────────────────────────────────────────

type visiteur struct {
	store.UserInfo
	Connecte bool
	CSRF     string
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
