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
	"context"
	"embed"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
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
}

func Nouveau(st *store.Store, prog *programme.Programmateur, qui Identifie, reg tirage.Reglages) *Serveur {
	// FERME PAR DEFAUT. Sans resolveur, personne n'est connecte et rien n'est
	// permis — une installation mal cablee refuse, elle ne s'ouvre pas.
	if qui == nil {
		qui = func(*http.Request) Visiteur { return Visiteur{} }
	}
	s := &Serveur{st: st, prog: prog, qui: qui, reg: reg,
		mux: http.NewServeMux(), Now: time.Now}
	s.routes()
	return s
}

func (s *Serveur) Handler() http.Handler { return s.mux }

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
	b, err := statique.ReadFile("static/index.html")
	if err != nil {
		erreur(w, http.StatusInternalServerError, "page indisponible")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// LA POLITIQUE EST STRICTE : tout vient de nous. Les clips aussi — c'est
	// tout l'interet de les rapatrier plutot que d'embarquer un lecteur tiers.
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; media-src 'self'; img-src 'self' data:; "+
			"script-src 'self'; style-src 'self'; connect-src 'self'; "+
			"frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	w.Write(b)
}

//go:embed static
var statique embed.FS

const prefixe = "/api/v1/radio"

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
	for _, p := range []string{prefixe, ""} {
		s.mux.HandleFunc(p+"/current", s.actuel)
		s.mux.HandleFunc(p+"/playlist", s.playlist)
		s.mux.HandleFunc(p+"/propositions", s.propositions)
		s.mux.HandleFunc(p+"/propositions/", s.gestePropo)
		s.mux.HandleFunc(p+"/pistes/", s.gestePiste)
		s.mux.HandleFunc(p+"/chat", s.chat)
		s.mux.HandleFunc(p+"/suivante", s.suivante)
	}
	// LA PAGE EST EMBARQUEE DANS LE BINAIRE : un fichier manquant sur le disque
	// donnerait une page blanche sans rien dire. Ici elle ne peut pas manquer.
	s.mux.Handle("/static/", http.FileServer(http.FS(statique)))
	s.mux.HandleFunc("/", s.accueil)
	s.mux.HandleFunc("/media/", s.servirMedia)
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
	ID      int64  `json:"id"`
	Titre   string `json:"titre"`
	Auteur  string `json:"auteur"`
	DureeMS int64  `json:"duree_ms"`
	Coeurs  int    `json:"coeurs"`
	Source  string `json:"source"`
	Etat    string `json:"etat,omitempty"`
	Motif   string `json:"motif,omitempty"`
	EnCache bool   `json:"en_cache"`
	Ecarte  bool   `json:"ecarte,omitempty"`
	Raison  string `json:"raison,omitempty"`
	Aime    bool   `json:"aime"`
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
		EnCache: p.EnCache(), Ecarte: p.Indisponible, Raison: p.Raison, Aime: aime}
}

// actuel : ce qui passe, et ce qui s'est dit. UNE SEULE REQUETE.
//
// Les auditeurs interrogent deja cette route pour rester synchronises : le
// chat voyage avec, plutot que d'ouvrir une seconde conversation reseau.
func (s *Serveur) actuel(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	maintenant := s.Now()
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
	if id == 0 || geste != "coeur" {
		erreur(w, http.StatusNotFound, "geste inconnu")
		return
	}
	s.coeur(w, r, id)
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
