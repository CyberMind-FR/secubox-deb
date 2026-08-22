// Package web sert le contrat HTTP de la radio.
//
// LE PARTAGE DES DROITS, decide en #1047 :
//
//	tout le monde connecte   voit la file de propositions, propose, soutient
//	le sysop seul            valide, refuse, passe au titre suivant
//
// La file est visible de TOUS parce que le tri par soutien n'aurait aucun sens
// si les membres ne la voyaient pas : on ne soutient pas ce qu'on ne voit pas.
package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/programme"
	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/store"
	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/tirage"
)

// Visiteur : qui frappe a la porte.
type Visiteur struct {
	ID       int64
	Pseudo   string
	Sysop    bool
	Connecte bool
}

// Identifie resout l'identite d'une requete.
//
// INJECTE PLUTOT QUE CODE ICI : l'identite vient de l'authentification
// SecuBox, et la radio n'a pas de table d'utilisateurs. Une interface permet
// aussi de tester les droits sans monter un service d'authentification.
type Identifie func(*http.Request) Visiteur

type Serveur struct {
	st   *store.Store
	prog *programme.Programmateur
	qui  Identifie
	reg  tirage.Reglages
	mux  *http.ServeMux
	// Flux ouvre le media d'une piste chez la passerelle. INJECTE : les tests
	// n'ont alors pas besoin d'une passerelle, et le demon reste maitre du
	// delai et des bornes.
	Flux func(ctx context.Context, ytID, plage string) (*http.Response, error)
	// HTTP sert a relayer les pochettes. Remplace en test : une suite qui
	// depend d'internet echoue pour des raisons etrangeres au code.
	HTTP *http.Client
	// Banniere de sante injectee par le WAF de la board. Vide = politique
	// fermee, et la banniere ne s'affiche pas.
	BanniereOrigine, BanniereHash string
	// BanniereStyle : empreinte de la balise <style> que la banniere injecte.
	//
	// Distincte de BanniereHash : le script et la feuille sont deux ressources
	// separees, avec deux empreintes differentes, et `style-src` ne regarde pas
	// `script-src`. Les confondre laissait la banniere non stylee — repliee en
	// bas de page, illisible — avec un refus CSP dans la console pour seule
	// trace.
	BanniereStyle string
	// CadreParent : origine AUTORISÉE à incorporer le lecteur compact /mini
	// (le widget radio du rail BBS, #1131m). Vide = /mini reste non incorporable
	// (`frame-ancestors 'self'`). Une seule origine, revalidée : un espace ou un
	// point-virgule couperait la politique en deux.
	CadreParent string
	// Racine : plus utilisee depuis que l'on relaie au lieu de recopier.
	//
	// PAS L'eMMC : elle s'est deja remplie sur cette board et a produit des
	// 502 sur des modules qui n'avaient rien demande. Le parc audio d'une
	// radio grossit tout seul, c'est exactement le genre de chose qui n'a rien
	// a faire sur la memoire du systeme.
	//
	// Vide = pas de confinement, pour les tests seulement.
	Racine string
	Now    func() time.Time // remplace en test

	// Statistiques légères d'audience (#1131ah), tenues en mémoire : combien de
	// gens écoutent en ce moment (un cookie vu récemment sur `actuel`), et
	// combien de visites depuis le démarrage. Sans base : une valeur d'ambiance,
	// pas une comptabilité — on ne persiste rien, on ne piste personne.
	muStat    sync.Mutex
	auditeurs map[string]int64 // cookie → dernière seconde vue
	visites   int64
}

func Nouveau(st *store.Store, prog *programme.Programmateur, qui Identifie, reg tirage.Reglages) *Serveur {
	// FERME PAR DEFAUT. Sans resolveur, personne n'est connecte et rien n'est
	// permis — une installation mal cablee refuse, elle ne s'ouvre pas.
	if qui == nil {
		qui = func(*http.Request) Visiteur { return Visiteur{} }
	}
	brut := qui
	// UN SEUL ENDROIT TIRE LA CONSEQUENCE DU CHEMIN. Disperser ce test dans
	// chaque gestionnaire garantirait qu'un jour l'un d'eux l'oublie — et ce
	// serait celui qui valide.
	qui = func(r *http.Request) Visiteur {
		v := brut(r)
		if vientDeLAdmin(r) {
			// La porte de l'administration a deja authentifie : on ne demande
			// pas une seconde preuve a la meme personne, sur la meme session.
			v.Connecte, v.Sysop = true, true
			if v.Pseudo == "" {
				v.Pseudo = "sysop"
			}
			if v.ID == 0 {
				v.ID = 1
			}
		}
		return v
	}
	s := &Serveur{st: st, prog: prog, qui: qui, reg: reg,
		mux: http.NewServeMux(), Now: time.Now, auditeurs: map[string]int64{},
		HTTP: &http.Client{Timeout: 8 * time.Second}}
	s.routes()
	return s
}

func (s *Serveur) Handler() http.Handler { return s.mux }

// politique assemble la politique de securite de contenu de la page.
//
// STRICTE PAR DEFAUT : tout vient de nous, clips et pochettes compris. C'est
// tout l'interet de les relayer plutot que de les lier.
//
// UNE SEULE EXCEPTION, ET ELLE N'EST PAS DE NOTRE FAIT : le WAF de la board
// INJECTE un script en ligne dans chaque page HTML — la banniere de sante. Une
// politique stricte le bloque, et la page perd la banniere que tous les autres
// modules affichent. Le module BBS a exactement le meme reglage, pour la meme
// raison.
//
// L'EMPREINTE EST CONFIGUREE, PAS CODEE EN DUR : le WAF peut changer son
// extrait, et une empreinte figee dans le binaire deviendrait fausse sans que
// personne ne s'en apercoive — la banniere disparaitrait en silence. Sans
// reglage, la politique reste fermee : on prefere une page sans banniere a une
// politique ouverte par defaut.
func (s *Serveur) politique() string {
	script, connect := "'self'", "'self'"
	if o := strings.TrimSpace(s.BanniereOrigine); o != "" && !strings.ContainsAny(o, " ;'\"") {
		script += " " + o
		connect += " " + o
	}
	if e := strings.TrimSpace(s.BanniereHash); empreinteValide.MatchString(e) {
		script += " '" + e + "'"
	}
	style := "'self'"
	if e := strings.TrimSpace(s.BanniereStyle); empreinteValide.MatchString(e) {
		style += " '" + e + "'"
	}
	return s.politiqueAvecAncetres(script, style, connect, "'none'")
}

// politiqueMini : la politique du lecteur compact /mini, incorporable par la
// SEULE origine CadreParent (le rail BBS, #1131m). Tout le reste est identique à
// la politique normale — même stricte, mêmes empreintes de bannière.
func (s *Serveur) politiqueMini() string {
	script, connect := "'self'", "'self'"
	if o := strings.TrimSpace(s.BanniereOrigine); o != "" && !strings.ContainsAny(o, " ;'\"") {
		script += " " + o
		connect += " " + o
	}
	if e := strings.TrimSpace(s.BanniereHash); empreinteValide.MatchString(e) {
		script += " '" + e + "'"
	}
	style := "'self'"
	if e := strings.TrimSpace(s.BanniereStyle); empreinteValide.MatchString(e) {
		style += " '" + e + "'"
	}
	anc := "'self'"
	if o := strings.TrimSpace(s.CadreParent); o != "" && !strings.ContainsAny(o, " ;'\"") {
		anc += " " + o
	}
	return s.politiqueAvecAncetres(script, style, connect, anc)
}

func (s *Serveur) politiqueAvecAncetres(script, style, connect, ancetres string) string {
	return "default-src 'self'; media-src 'self'; img-src 'self' data:; " +
		"script-src " + script + "; style-src " + style + "; connect-src " + connect + "; " +
		"frame-ancestors " + ancetres + "; base-uri 'none'; form-action 'self'"
}

// miniPlayer sert le lecteur COMPACT — mêmes octets que l'accueil (le script
// bascule en mode « mini » d'après le chemin), mais une politique qui autorise
// l'incorporation par le rail BBS (#1131m). Le contenu identique évite un second
// gabarit à tenir en phase.
func (s *Serveur) miniPlayer(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/mini" && r.URL.Path != "/micro" {
		http.NotFound(w, r)
		return
	}
	b := pageAccueil()
	if b == nil {
		erreur(w, http.StatusInternalServerError, "page indisponible")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", s.politiqueMini())
	w.Write(b)
}

// empreinteValide : une empreinte CSP bien formee, et rien d'autre.
//
// Une valeur erronee ne doit pas produire une politique invalide : un
// navigateur qui n'arrive pas a la lire peut l'ignorer ENTIEREMENT, ce qui est
// le pire resultat possible — on se croit protege et on ne l'est plus du tout.
var empreinteValide = regexp.MustCompile(`^sha(256|384|512)-[A-Za-z0-9+/=]+$`)

// accueil sert la page d'ecoute.
//
// LA PAGE EST SERVIE A TOUT LE MONDE, ET C'EST UNE CORRECTION.
//
// La premiere version exigeait le cookie de pseudonyme... que SEULE CETTE PAGE
// sait poser. Un premier visiteur recevait donc un 401 en JSON, affiche par le
// navigateur dans son visualiseur : ni page, ni explication, ni moyen d'entrer.
// La porte demandait la cle qu'elle etait chargee de donner.
//
// La page est du HTML sans secret : la servir ne divulgue rien. Ce qui reste
// ferme, ce sont les GESTES et les CLIPS — le chat, les propositions, les
// coeurs, `/media/`. On entre dans la salle, on ne prend pas le micro.
func (s *Serveur) accueil(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// Une VISITE = ouvrir la page radio en direct (pas l'embed /micro, qui se
	// recharge à chaque navigation BBS et fausserait le compte) (#1131ah).
	s.muStat.Lock()
	s.visites++
	s.muStat.Unlock()
	b := pageAccueil()
	if b == nil {
		erreur(w, http.StatusInternalServerError, "page indisponible")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// LA POLITIQUE EST STRICTE : tout vient de nous. Les clips aussi — c'est
	// tout l'interet de les rapatrier plutot que d'embarquer un lecteur tiers.
	w.Header().Set("Content-Security-Policy", s.politique())
	w.Write(b)
}

//go:embed static
var statique embed.FS

// pageAccueil rend l'accueil avec une empreinte du contenu dans l'URL des
// fichiers statiques.
//
// SANS ELLE, CHAQUE DEPLOIEMENT SERT L'ANCIENNE FEUILLE. Le WAF de la board
// met en cache par URL pendant une heure : `/static/radio.css` valant pour
// toutes les versions, une mise a jour du paquet laissait le navigateur
// recevoir la feuille precedente — avec, ce jour-la, une regle qui
// redimensionnait la video et defaisait la mise en page. Le symptome se lisait
// comme un bug de CSS, alors que la CSS deployee etait juste.
//
// L'empreinte change avec le contenu : une nouvelle version demande une URL
// que le cache ne connait pas, et une version inchangee reste servie depuis le
// cache. On garde le benefice du cache sans en subir la peremption.
var pageAccueil = sync.OnceValue(func() []byte {
	b, err := statique.ReadFile("static/index.html")
	if err != nil {
		return nil
	}
	for _, f := range []string{"radio.css", "radio.js"} {
		c, err := statique.ReadFile("static/" + f)
		if err != nil {
			continue
		}
		somme := sha256.Sum256(c)
		b = bytes.ReplaceAll(b,
			[]byte("/static/"+f),
			[]byte("/static/"+f+"?v="+hex.EncodeToString(somme[:6])))
	}
	return b
})

const prefixe = "/api/v1/radio"

// cleAdmin marque une requete arrivee par l'agregateur.
type cleAdmin struct{}

// parAdmin marque la requete comme venant de la surface d'administration.
//
// Elle n'accorde rien par elle-meme : c'est `qui()` qui en tire les
// consequences, en un seul endroit.
func (s *Serveur) parAdmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h(w, r.WithContext(context.WithValue(r.Context(), cleAdmin{}, true)))
	}
}

// vientDeLAdmin dit si la requete a franchi la porte de l'administration.
func vientDeLAdmin(r *http.Request) bool {
	v, _ := r.Context().Value(cleAdmin{}).(bool)
	return v
}

// routeur choisit le gestionnaire d'un chemin.
func (s *Serveur) routeur(chemin string) http.HandlerFunc {
	switch chemin {
	case "/current":
		return s.actuel
	case "/playlist":
		return s.playlist
	case "/propositions":
		return s.propositions
	case "/propositions/":
		return s.gestePropo
	case "/pistes/":
		return s.gestePiste
	case "/chat":
		return s.chat
	case "/suivante":
		return s.suivante
	case "/stats":
		return s.stats
	}
	return func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }
}

// noteAuditeur retient qu'un cookie a été vu à l'instant, pour compter les
// auditeurs ACTIFS (#1131ah). Purge au passage ce qui a plus de 45 s : la carte
// ne grossit pas avec le temps, elle reflète l'audience du moment.
func (s *Serveur) noteAuditeur(cle string, maintenant int64) {
	if cle == "" {
		return
	}
	s.muStat.Lock()
	s.auditeurs[cle] = maintenant
	for k, t := range s.auditeurs {
		if maintenant-t > 45 {
			delete(s.auditeurs, k)
		}
	}
	s.muStat.Unlock()
}

// stats rend l'ambiance d'audience en emojis côté client : titres en rotation,
// propositions en attente, auditeurs à l'écoute, visites depuis le démarrage.
func (s *Serveur) stats(w http.ResponseWriter, r *http.Request) {
	maintenant := s.Now().Unix()
	s.muStat.Lock()
	actifs := 0
	for _, t := range s.auditeurs {
		if maintenant-t <= 45 {
			actifs++
		}
	}
	visites := s.visites
	s.muStat.Unlock()

	pistes, _ := s.st.Toutes()
	props, _ := s.st.Propositions()
	nprop := 0
	for _, p := range props {
		if !p.Indisponible {
			nprop++
		}
	}
	rendJSON(w, http.StatusOK, map[string]any{
		"pistes": len(pistes), "propositions": nprop,
		"auditeurs": actifs, "visites": visites,
	})
}

func (s *Serveur) routes() {
	// LES ROUTES SONT MONTEES DEUX FOIS, ET CE N'EST PAS UNE NEGLIGENCE.
	//
	// Le vhost `radio.gk2` transmet le chemin COMPLET : `/api/v1/radio/current`.
	// L'agregateur, lui, RETIRE LE PREFIXE avant de relayer vers la socket : la
	// meme requete y arrive comme `/current`. Un module qui n'ecoute que sur
	// l'un des deux rend 404 sur l'autre — sans rien dans les journaux, puisque
	// du point de vue du serveur la route n'existe pas. Ce defaut a deja coute
	// une soiree sur un autre module.
	//
	// Monter les deux coute deux lignes et supprime la classe entiere.
	// ── DEUX ENTREES, DEUX NIVEAUX DE CONFIANCE ─────────────────────────
	//
	// Le vhost `radio.gk2` transmet le chemin COMPLET (`/api/v1/radio/…`) :
	// c'est la surface des auditeurs, ouverte au LAN.
	//
	// L'agregateur, lui, RETIRE le prefixe — la meme requete y arrive comme
	// `/…`. Or il ne sert que `admin.gk2`, DEJA AUTHENTIFIEE : tout ce qui
	// arrive par ce chemin a franchi la porte de l'administration.
	//
	// LE CHEMIN EST DONC LA PREUVE, et il n'y a rien de plus a demander. La
	// premiere version reclamait un secret dans une boite de dialogue a un
	// administrateur deja connecte — une seconde authentification pour la meme
	// personne, sur la meme session.
	//
	// LA DISCRIMINATION EST SURE PARCE QUE NOTRE VHOST NE STRIPPE PAS : il
	// passe le chemin entier (voir nginx/radio.conf). Un auditeur ne peut donc
	// pas atteindre les routes courtes.
	for _, ch := range []string{"/current", "/playlist", "/propositions",
		"/propositions/", "/pistes/", "/chat", "/suivante"} {
		h := s.routeur(ch)
		s.mux.HandleFunc(prefixe+ch, h)
		s.mux.HandleFunc(ch, s.parAdmin(h))
	}
	// LA PAGE EST EMBARQUEE DANS LE BINAIRE : un fichier manquant sur le disque
	// donnerait une page blanche sans rien dire. Ici elle ne peut pas manquer.
	s.mux.Handle("/static/", http.FileServer(http.FS(statique)))
	s.mux.HandleFunc("/", s.accueil)
	s.mux.HandleFunc("/mini", s.miniPlayer)
	s.mux.HandleFunc("/micro", s.miniPlayer)
	s.mux.HandleFunc("/media/", s.servirMedia)
	s.mux.HandleFunc("/vignette/", s.servirVignette)
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
}

// ── garde-fous communs ──────────────────────────────────────────────────────

func rendJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// `nosniff` : sans lui, un navigateur peut decider qu'une reponse JSON est
	// du HTML et l'interpreter — le contenu vient de membres.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func erreur(w http.ResponseWriter, code int, msg string) {
	rendJSON(w, code, map[string]string{"error": msg})
}

// ecritureAutorisee : les gardes communes a toute action.
//
// LE JETON D'INTENTION REMPLACE LE JETON ANTI-REJEU DES FORMULAIRES. Une API
// JSON n'a pas de formulaire ; la protection classique est ailleurs : un
// navigateur ne peut PAS poser d'en-tete personnalise sur une requete
// inter-origines sans autorisation prealable du serveur. Exiger `X-Sbx-Radio`
// suffit donc a rendre inoperante une requete forgee par un site tiers, alors
// que le cookie de session, lui, serait joint automatiquement.
func (s *Serveur) ecritureAutorisee(w http.ResponseWriter, r *http.Request) (Visiteur, bool) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		erreur(w, http.StatusMethodNotAllowed, "methode refusee")
		return Visiteur{}, false
	}
	if r.Header.Get("X-Sbx-Radio") == "" {
		erreur(w, http.StatusForbidden, "en-tete d'intention manquant")
		return Visiteur{}, false
	}
	v := s.qui(r)
	if !v.Connecte {
		erreur(w, http.StatusUnauthorized, "connectez-vous")
		return Visiteur{}, false
	}
	return v, true
}

// sysopSeul : pour les gestes de validation.
//
// 403 ET NON 404 : la file est visible de tous, donc l'existence de ces routes
// n'est un secret pour personne. Repondre 404 ferait chercher une erreur
// d'adresse la ou il n'y a qu'un droit manquant.
func (s *Serveur) sysopSeul(w http.ResponseWriter, r *http.Request) (Visiteur, bool) {
	v, ok := s.ecritureAutorisee(w, r)
	if !ok {
		return v, false
	}
	if !v.Sysop {
		erreur(w, http.StatusForbidden, "reserve au sysop")
		return v, false
	}
	return v, true
}

// ── lecture ─────────────────────────────────────────────────────────────────

type vuePiste struct {
	ID       int64  `json:"id"`
	Titre    string `json:"titre"`
	Auteur   string `json:"auteur"`
	DureeMS  int64  `json:"duree_ms"`
	Coeurs   int    `json:"coeurs"`
	Source   string `json:"source"`
	Etat     string `json:"etat,omitempty"`
	Lot      string `json:"lot,omitempty"`
	LotTitre string `json:"lot_titre,omitempty"`
	Motif    string `json:"motif,omitempty"`
	EnCache  bool   `json:"en_cache"`
	Ecarte   bool   `json:"ecarte,omitempty"`
	Raison   string `json:"raison,omitempty"`
	Aime     bool   `json:"aime"`
	// LES COEURS SONT PUBLICS : on voit qui a aime. Un coeur anonyme se
	// compte, un coeur signe se discute.
	Aimeurs []store.Aimeur `json:"aimeurs,omitempty"`
}

func (s *Serveur) vue(p store.Piste, v Visiteur) vuePiste {
	aime := false
	if v.Connecte {
		aime, _ = s.st.ACoeur(p.ID, v.ID)
	}
	var aimeurs []store.Aimeur
	if v.Connecte {
		aimeurs, _ = s.st.QuiAime(p.ID)
	}
	return vuePiste{ID: p.ID, Titre: p.Titre, Auteur: p.Auteur, DureeMS: p.DureeMS,
		Aimeurs: aimeurs,
		Coeurs:  p.Coeurs, Source: p.Source, Etat: p.Etat, Motif: p.Motif,
		Lot: p.Lot, LotTitre: p.LotTitre,
		EnCache: p.EnCache(), Ecarte: p.Indisponible, Raison: p.Raison, Aime: aime}
}

// actuel : ce qui passe, et ce qui s'est dit. UNE SEULE REQUETE.
//
// Les auditeurs interrogent deja cette route pour rester synchronises : le
// chat voyage avec, plutot que d'ouvrir une seconde conversation reseau.
func (s *Serveur) actuel(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	maintenant := s.Now()
	// Cette route est interrogée par CHAQUE auditeur toutes les ~5 s : c'est le
	// meilleur endroit pour compter qui écoute (#1131ah).
	if c, err := r.Cookie("sbx_radio"); err == nil {
		s.noteAuditeur(c.Value, maintenant.Unix())
	}
	e, err := s.prog.Actuel(maintenant)

	rep := map[string]any{
		// `horloge_ms` permet au client de corriger la latence du reseau :
		// sans elle, chaque auditeur accumule son propre retard et la
		// synchronisation derive.
		"horloge_ms": maintenant.UnixMilli(),
		"silence":    e.Silence || err != nil,
	}
	if err == nil {
		rep["piste"] = s.vue(e.Piste, v)
		rep["offset_ms"] = e.OffsetMS
	} else if !errors.Is(err, programme.ErrSilence) {
		erreur(w, http.StatusInternalServerError, "programme indisponible")
		return
	}
	// Le chat n'est servi qu'aux membres : une radio peut s'ecouter de
	// l'exterieur, la conversation reste entre nous.
	if v.Connecte {
		apres, _ := strconv.ParseInt(r.URL.Query().Get("depuis"), 10, 64)
		if ph, err := s.st.Depuis(apres, 50); err == nil {
			rep["chat"] = ph
		}
	}
	rendJSON(w, http.StatusOK, rep)
}

func (s *Serveur) playlist(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	l, err := s.st.Toutes()
	if err != nil {
		erreur(w, http.StatusInternalServerError, "lecture impossible")
		return
	}
	out := make([]vuePiste, 0, len(l))
	for _, p := range l {
		out = append(out, s.vue(p, v))
	}
	rendJSON(w, http.StatusOK, map[string]any{"pistes": out})
}

// propositions : GET la file (tous les membres), POST une proposition.
func (s *Serveur) propositions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		v := s.qui(r)
		if !v.Connecte {
			erreur(w, http.StatusUnauthorized, "connectez-vous")
			return
		}
		l, err := s.st.Propositions()
		if err != nil {
			erreur(w, http.StatusInternalServerError, "lecture impossible")
			return
		}
		out := make([]vuePiste, 0, len(l))
		for _, p := range l {
			out = append(out, s.vue(p, v))
		}
		rendJSON(w, http.StatusOK, map[string]any{"propositions": out})
		return
	}
	v, ok := s.ecritureAutorisee(w, r)
	if !ok {
		return
	}
	var corps struct{ Source, Titre string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&corps); err != nil {
		erreur(w, http.StatusBadRequest, "corps illisible")
		return
	}
	// LE SYSOP MET DIRECTEMENT A L'ANTENNE, le membre propose. Deux appels
	// distincts et non un drapeau : un drapeau finit par etre passe a l'envers.
	var p store.Piste
	var neuf bool
	var err error
	if v.Sysop {
		p, neuf, err = s.st.Ajoute(corps.Source, corps.Titre, v.ID, s.Now())
	} else {
		p, neuf, err = s.st.Propose(corps.Source, corps.Titre, v.ID, s.Now())
	}
	if errors.Is(err, store.ErrDejaRefusee) {
		// 409 : ce n'est ni une panne ni un droit manquant, c'est un conflit
		// avec une decision deja prise. Le dire permet a l'interface
		// d'expliquer plutot que d'afficher « erreur ».
		erreur(w, http.StatusConflict, "cette piste a deja ete refusee")
		return
	}
	if err != nil {
		erreur(w, http.StatusBadRequest, err.Error())
		return
	}
	code := http.StatusOK
	if neuf {
		code = http.StatusCreated
	}
	rendJSON(w, code, map[string]any{"piste": s.vue(p, v), "neuve": neuf})
}

// gestePropo : /propositions/<id>/{valider,refuser,coeur}
func (s *Serveur) gestePropo(w http.ResponseWriter, r *http.Request) {
	id, geste := decoupe(r.URL.Path, "/propositions/")
	if id == 0 {
		erreur(w, http.StatusNotFound, "proposition inconnue")
		return
	}
	switch geste {
	case "coeur":
		s.coeur(w, r, id)
	case "valider", "refuser":
		v, ok := s.sysopSeul(w, r)
		if !ok {
			return
		}
		var err error
		if geste == "valider" {
			err = s.st.Valide(id, v.ID, s.Now())
		} else {
			var corps struct{ Motif string }
			json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&corps)
			err = s.st.Refuse(id, v.ID, s.Now(), corps.Motif)
		}
		if errors.Is(err, store.ErrPisteInconnue) {
			erreur(w, http.StatusNotFound, "proposition inconnue")
			return
		}
		if err != nil {
			erreur(w, http.StatusInternalServerError, "decision non enregistree")
			return
		}
		p, _ := s.st.ParID(id)
		rendJSON(w, http.StatusOK, map[string]any{"piste": s.vue(p, v)})
	default:
		erreur(w, http.StatusNotFound, "geste inconnu")
	}
}

func (s *Serveur) gestePiste(w http.ResponseWriter, r *http.Request) {
	id, geste := decoupe(r.URL.Path, "/pistes/")
	if id == 0 {
		erreur(w, http.StatusNotFound, "piste inconnue")
		return
	}
	switch geste {
	case "coeur":
		s.coeur(w, r, id)
	case "duree":
		s.poseDuree(w, r, id)
	case "supprimer":
		s.supprime(w, r, id)
	case "devalider":
		s.devalide(w, r, id)
	default:
		erreur(w, http.StatusNotFound, "geste inconnu")
	}
}

// poseDuree enregistre la VRAIE durée d'une piste, rapportée par un lecteur qui
// vient d'en charger les métadonnées (#1131z). C'est ce qui empêche le
// programme de couper un titre plus long que la durée par défaut (4 min).
//
// PAS UN JUGEMENT, une MESURE : on n'exige pas d'être « connecté », juste
// l'en-tête d'intention (un site tiers ne peut pas le poser). Bornée (5 s à
// 4 h) contre une valeur absurde, et le magasin ne remplit que le vide. La
// correction en mémoire (MajDuree) la rend effective immédiatement, sans quoi
// le programme aurait déjà sauté avant le prochain tirage.
func (s *Serveur) poseDuree(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodPost {
		erreur(w, http.StatusMethodNotAllowed, "methode refusee")
		return
	}
	if r.Header.Get("X-Sbx-Radio") == "" {
		erreur(w, http.StatusForbidden, "en-tete d'intention manquant")
		return
	}
	var corps struct {
		MS int64 `json:"ms"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256)).Decode(&corps); err != nil {
		erreur(w, http.StatusBadRequest, "corps illisible")
		return
	}
	if corps.MS < 5000 || corps.MS > 4*3600*1000 {
		erreur(w, http.StatusBadRequest, "duree hors bornes")
		return
	}
	if err := s.st.PoseDuree(id, corps.MS); err != nil {
		erreur(w, http.StatusInternalServerError, "duree non enregistree")
		return
	}
	s.prog.MajDuree(id, corps.MS) // effet immédiat sur le programme en cours
	rendJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// devalide renvoie une piste a la file de validation. RESERVEE AU SYSOP.
//
// TROIS GESTES, TROIS PORTEES, et l'interface doit les distinguer :
//
//	devalider  « pas maintenant » — retour en file, coeurs gardes, revalidable
//	refuser    « jamais »         — la reproposition ne la ramene pas
//	supprimer  « efface »         — tout part, et elle pourra revenir demain
func (s *Serveur) devalide(w http.ResponseWriter, r *http.Request, id int64) {
	v, ok := s.sysopSeul(w, r)
	if !ok {
		return
	}
	if err := s.st.Devalide(id, v.ID, s.Now()); errors.Is(err, store.ErrPisteInconnue) {
		erreur(w, http.StatusNotFound, "piste inconnue")
		return
	} else if err != nil {
		erreur(w, http.StatusInternalServerError, "devalidation impossible")
		return
	}
	// ELLE QUITTE L'ANTENNE IMMEDIATEMENT. Sans cet oubli, le programmateur
	// continuerait d'annoncer une piste qui n'est plus validee — elle ne serait
	// plus dans la playlist mais jouerait encore, ce qui est le pire des deux
	// mondes.
	s.prog.Oublie(id)
	p, _ := s.st.ParID(id)
	rendJSON(w, http.StatusOK, map[string]any{"piste": s.vue(p, v)})
}

// supprime retire une piste du repertoire. RESERVEE AU SYSOP.
//
// LA DIFFERENCE AVEC « REFUSER » EST REELLE, et l'interface doit la dire :
// refuser garde la ligne et empeche la reproposition ; SUPPRIMER efface tout,
// et la piste pourra donc etre reproposee demain. On supprime ce qui n'a rien a
// faire la ; on refuse ce qu'on ne veut pas voir revenir.
//
// Les coeurs partent avec elle (cascade). Les phrases du chat, non : elles
// perdent seulement leur lien — ce qui s'est dit pendant un morceau reste dit.
func (s *Serveur) supprime(w http.ResponseWriter, r *http.Request, id int64) {
	v, ok := s.sysopSeul(w, r)
	if !ok {
		return
	}
	p, err := s.st.ParID(id)
	if err != nil {
		erreur(w, http.StatusNotFound, "piste inconnue")
		return
	}
	// SI ELLE PASSE, ON AVANCE — SANS JAMAIS REFUSER.
	//
	// Ma premiere version refusait de supprimer la DERNIERE piste jouable, pour
	// ne pas laisser les auditeurs sur un lecteur mort. C'etait se proteger d'un
	// etat DEJA TRAITE : le silence est un etat de premiere classe, la page le
	// dit, et une radio vide est parfaitement legitime — c'est meme ce qu'on
	// veut quand on fait le menage.
	//
	// Refuser rendait donc le repertoire IMPOSSIBLE A VIDER : le sysop ne
	// pouvait jamais retirer le dernier titre. Constate en essayant.
	//
	// On avance s'il reste quelque chose, on laisse tomber au silence sinon.
	if e, err := s.prog.Actuel(s.Now()); err == nil && e.Piste.ID == id {
		if _, err := s.prog.Suivante(s.Now()); err != nil {
			// Plus rien de jouable : le programme le dira de lui-meme au
			// prochain appel. Ce n'est pas une erreur.
			log.Printf("radio: suppression de la derniere piste jouable — silence")
		}
	}
	if err := s.st.Retire(id); err != nil {
		erreur(w, http.StatusInternalServerError, "suppression impossible")
		return
	}
	// ON LE DIT AU PROGRAMMATEUR. Il tient sa piste en memoire pour repondre la
	// meme chose a tous les auditeurs ; sans cet oubli, il continuerait
	// d'annoncer un identifiant qui ne designe plus rien, et le clip rendrait
	// 404. Le test l'a montre.
	s.prog.Oublie(id)
	rendJSON(w, http.StatusOK, map[string]any{"supprimee": s.vue(p, v)})
}

// coeur : POST pose, DELETE retire. Tout membre connecte.
func (s *Serveur) coeur(w http.ResponseWriter, r *http.Request, id int64) {
	v, ok := s.ecritureAutorisee(w, r)
	if !ok {
		return
	}
	if _, err := s.st.ParID(id); err != nil {
		erreur(w, http.StatusNotFound, "piste inconnue")
		return
	}
	var err error
	if r.Method == http.MethodDelete {
		err = s.st.RetireCoeur(id, v.ID)
	} else {
		err = s.st.PoseCoeur(id, v.ID, v.Pseudo, s.Now())
	}
	if err != nil {
		erreur(w, http.StatusInternalServerError, "coeur non enregistre")
		return
	}
	p, _ := s.st.ParID(id)
	rendJSON(w, http.StatusOK, map[string]any{"piste": s.vue(p, v)})
}

func (s *Serveur) chat(w http.ResponseWriter, r *http.Request) {
	v, ok := s.ecritureAutorisee(w, r)
	if !ok {
		return
	}
	var corps struct{ Corps string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&corps); err != nil {
		erreur(w, http.StatusBadRequest, "corps illisible")
		return
	}
	var pisteID int64
	if e, err := s.prog.Actuel(s.Now()); err == nil {
		pisteID = e.Piste.ID
	}
	p, err := s.st.Dis(v.ID, v.Pseudo, corps.Corps, pisteID, s.Now())
	switch {
	case errors.Is(err, store.ErrPhraseVide):
		erreur(w, http.StatusBadRequest, "phrase vide")
	case errors.Is(err, store.ErrTropVite):
		// 429 : le client peut reessayer plus tard, ce n'est pas un refus
		// definitif — et l'interface doit pouvoir le distinguer d'une panne.
		erreur(w, http.StatusTooManyRequests, err.Error())
	case err != nil:
		erreur(w, http.StatusInternalServerError, "phrase non enregistree")
	default:
		rendJSON(w, http.StatusCreated, map[string]any{"phrase": p})
	}
}

func (s *Serveur) suivante(w http.ResponseWriter, r *http.Request) {
	v, ok := s.sysopSeul(w, r)
	if !ok {
		return
	}
	e, err := s.prog.Suivante(s.Now())
	if err != nil {
		erreur(w, http.StatusConflict, "aucune piste jouable")
		return
	}
	rendJSON(w, http.StatusOK, map[string]any{
		"piste": s.vue(e.Piste, v), "offset_ms": e.OffsetMS,
		"horloge_ms": e.Horloge.UnixMilli()})
}

// decoupe extrait l'identifiant et le geste de .../<segment>/<id>/<geste>.
//
// ON CHERCHE LE SEGMENT PLUTOT QUE DE RETIRER UN PREFIXE FIXE : le chemin
// arrive tantot complet (`/api/v1/radio/pistes/12/coeur`), tantot ampute par
// l'agregateur (`/pistes/12/coeur`). Un `TrimPrefix` sur l'un echouerait
// silencieusement sur l'autre.
func decoupe(chemin, segment string) (int64, string) {
	i := strings.Index(chemin, segment)
	if i < 0 {
		return 0, ""
	}
	reste := chemin[i+len(segment):]
	parts := strings.SplitN(reste, "/", 2)
	if len(parts) != 2 {
		return 0, ""
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || id <= 0 {
		return 0, ""
	}
	return id, strings.Trim(parts[1], "/")
}
