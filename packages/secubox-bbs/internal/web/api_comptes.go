package web

// Comptes SecuBox <-> BBS, vus depuis l'ecran des acces du Hall (#1369).
//
// L'ECRAN DES ACCES DOIT DIRE CE QUE LA BBS EN FAIT. Rattacher un appareil a
// « gk2 » ne sert a rien ici si la BBS ignore gk2, le connait sous une autre
// origine, ou l'a desactive. Ces deux routes donnent l'etat, et le geste qui
// l'aligne.

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

func (s *Server) routesAPIComptes() {
	s.mux.HandleFunc("GET /api/v1/bbs/comptes/etat", s.admin(s.apiComptesEtat))
	s.mux.HandleFunc("POST /api/v1/bbs/comptes/sync", s.admin(s.apiComptesSync))
}

// admin : la signature NE SUFFIT PAS.
//
// `jwt` ne verifie que la signature et l'expiration. Tout jeton SecuBox la
// passe — celui d'un appareil invite, d'un compte `operator`, et meme une
// session revoquee, puisque le jti n'est pas relu. C'etait la garde des routes
// d'administration : un invite pouvait lister les comptes et leurs adresses,
// emettre des invitations, telecharger une sauvegarde (#1369).
//
// Ici le jeton est soumis a secubox-auth, qui dit s'il vit encore et quel role
// il porte. Sans secubox-auth joignable : ferme.
func (s *Server) admin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.verifieJeton(r.Header.Get("Authorization")); err != nil {
			jsonErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		if s.verif == nil {
			jsonErr(w, http.StatusServiceUnavailable, "secubox-auth non configuré — administration fermée")
			return
		}
		jeton := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		ses, ok := s.verif(jeton)
		if !ok {
			jsonErr(w, http.StatusUnauthorized, "session refusée par secubox-auth")
			return
		}
		if ses.Groupes != "admin" {
			jsonErr(w, http.StatusForbidden, "réservé aux administrateurs")
			return
		}
		h(w, r)
	}
}

// GET /api/v1/bbs/comptes/etat?h=gk2&h=sbx-…
func (s *Server) apiComptesEtat(w http.ResponseWriter, r *http.Request) {
	hs := r.URL.Query()["h"]
	if len(hs) > 200 {
		hs = hs[:200]
	}
	etat, err := s.st.EtatComptes(hs)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true, "comptes": etat})
}

type compteSecubox struct {
	Handle    string `json:"handle"`
	Nom       string `json:"nom"`
	Role      string `json:"role"`
	Desactive bool   `json:"desactive"`
}

type corpsSync struct {
	// Comptes : la liste COMPLETE de secubox-users. Un compte d'origine
	// SecuBox absent de la liste est desactive : une liste partielle en
	// fermerait a tort — d'ou le refus d'une liste vide plus bas.
	Comptes []compteSecubox `json:"comptes"`
	// Adopter : comptes LOCAUX a faire passer a l'origine SecuBox. Geste
	// explicite de l'administrateur, nom par nom.
	Adopter []string `json:"adopter"`
}

// POST /api/v1/bbs/comptes/sync
func (s *Server) apiComptesSync(w http.ResponseWriter, r *http.Request) {
	var c corpsSync
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&c); err != nil {
		jsonErr(w, http.StatusBadRequest, "corps illisible")
		return
	}
	if len(c.Comptes) == 0 {
		// Une liste vide desactiverait tous les comptes synchronises. C'est
		// toujours une erreur de l'appelant, jamais une intention.
		jsonErr(w, http.StatusBadRequest, "liste de comptes vide — rien n'est touché")
		return
	}
	connus := map[string]bool{}
	liste := make([]store.ExternalUser, 0, len(c.Comptes))
	for _, u := range c.Comptes {
		h := strings.TrimSpace(u.Handle)
		if h == "" {
			continue
		}
		connus[strings.ToLower(h)] = true
		liste = append(liste, store.ExternalUser{
			Handle: h, Display: u.Nom, Role: roleBBS(u.Role), Disabled: u.Desactive,
		})
	}
	adoptes := []string{}
	for _, h := range c.Adopter {
		// On n'adopte qu'un nom QUI EXISTE chez SecuBox : sinon la synchro qui
		// suit le desactiverait aussitot, et le membre perdrait son compte.
		if !connus[strings.ToLower(strings.TrimSpace(h))] {
			jsonErr(w, http.StatusBadRequest, "« "+h+" » n'est pas un compte SecuBox")
			return
		}
		if err := s.st.AdopteCompte(h); err != nil {
			jsonErr(w, http.StatusConflict, err.Error())
			return
		}
		adoptes = append(adoptes, h)
	}
	res, err := s.st.SyncExternalUsers(liste)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true, "resultat": res, "adoptes": adoptes})
}

// roleBBS : la meme table que `bbsctl sync-users`.
func roleBBS(role string) store.Role {
	if role == "admin" || role == "sysop" {
		return store.RoleSysop
	}
	return store.RoleMember
}
