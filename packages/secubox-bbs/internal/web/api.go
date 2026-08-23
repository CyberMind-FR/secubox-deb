package web

// API JSON du module, consommee par le panneau d'administration.
//
// AUTHENTIFICATION : JWT HS256, meme secret que le reste de SecuBox
// (api.jwt_secret). La verification est faite ICI et pas deleguee a nginx : une
// garde posee dans un frontal disparait le jour ou quelqu'un atteint la socket
// autrement — et sur cette machine, la socket est atteignable.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

func (s *Server) routesAPI() {
	s.mux.HandleFunc("/api/v1/bbs/status", s.jwt(s.apiStatus))
	s.mux.HandleFunc("/api/v1/bbs/integrity", s.jwt(s.apiIntegrity))
	s.mux.HandleFunc("/api/v1/bbs/threads", s.jwt(s.apiThreads))
	// Content spine (#1166) : cf. api_content.go. Motifs Go 1.22 avec
	// méthode+PathValue — "by-ref" est un segment littéral, donc plus
	// spécifique que le joker "{id}" pour le même chemin ; l'ordre
	// d'enregistrement n'y change rien (net/http.ServeMux départage par
	// spécificité, pas par ordre).
	s.mux.HandleFunc("POST /api/v1/bbs/content", s.jwt(s.apiContentCreer))
	s.mux.HandleFunc("GET /api/v1/bbs/content/by-ref", s.jwt(s.apiContentParRef))
	s.mux.HandleFunc("GET /api/v1/bbs/content/{id}", s.jwt(s.apiContentObtenir))
	s.mux.HandleFunc("POST /api/v1/bbs/content/{id}/representation", s.jwt(s.apiContentRepresentation))
	s.mux.HandleFunc("POST /api/v1/bbs/content/{id}/event", s.jwt(s.apiContentEvent))
	s.mux.HandleFunc("POST /api/v1/bbs/content/{id}/topic", s.jwt(s.apiContentTopic))
	s.mux.HandleFunc("/api/v1/bbs/invite", s.jwt(s.apiInvite))
	s.mux.HandleFunc("/api/v1/bbs/backup", s.jwt(s.apiBackup))
	s.mux.HandleFunc("/api/v1/bbs/reindex", s.jwt(s.apiReindex))
}

// jwt enveloppe un gestionnaire d'une verification de jeton.
func (s *Server) jwt(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.verifieJeton(r.Header.Get("Authorization")); err != nil {
			jsonErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		h(w, r)
	}
}

type errJeton string

func (e errJeton) Error() string { return string(e) }

// Claims : ce que le BBS lit d'un jeton. Volontairement etroit.
type Claims struct {
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
}

// claimsJeton valide la signature ET rend le sujet.
//
// `verifieJeton` ne rendait qu'une erreur : suffisant pour une console
// d'administration, insuffisant pour agir AU NOM DE quelqu'un.
func (s *Server) claimsJeton(entete string) (Claims, error) {
	var c Claims
	if err := s.verifieJeton(entete); err != nil {
		return c, err
	}
	parts := strings.Split(strings.TrimPrefix(entete, "Bearer "), ".")
	brut, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, errJeton("charge illisible")
	}
	if err := json.Unmarshal(brut, &c); err != nil {
		return c, errJeton("charge illisible")
	}
	return c, nil
}

// verifieJeton valide un JWT HS256.
//
// L'ALGORITHME EST IMPOSE, PAS LU DANS LE JETON. Faire confiance au champ
// « alg » revient a demander a la serrure quelle clef elle accepte : un jeton
// se declarant « alg: none » serait cru sur parole. C'est l'attaque classique
// sur les JWT, et elle marche encore.
func (s *Server) verifieJeton(entete string) error {
	// Sans secret configure, rien ne peut etre authentifie. L'absence de
	// secret ne doit surtout pas valoir absence de verification.
	if strings.TrimSpace(s.opt.JWTSecret) == "" {
		return errJeton("aucun secret configure — API fermee")
	}
	if !strings.HasPrefix(entete, "Bearer ") {
		return errJeton("jeton absent")
	}
	parts := strings.Split(strings.TrimPrefix(entete, "Bearer "), ".")
	if len(parts) != 3 {
		return errJeton("jeton mal forme")
	}

	m := hmac.New(sha256.New, []byte(s.opt.JWTSecret))
	m.Write([]byte(parts[0] + "." + parts[1]))
	attendu := base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(attendu), []byte(parts[2])) != 1 {
		return errJeton("signature invalide")
	}

	brut, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errJeton("charge illisible")
	}
	var c struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(brut, &c); err != nil {
		return errJeton("charge illisible")
	}
	// Un jeton SANS expiration est refuse : un jeton eternel echappe a toute
	// revocation, et il suffit qu'il fuite une fois.
	if c.Exp == 0 || time.Now().Unix() >= c.Exp {
		return errJeton("jeton expire")
	}
	return nil
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": msg})
}

func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.st.Stats()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	cats, _ := s.st.Categories(false)
	jsonOK(w, map[string]any{
		"ok": true, "version": Version, "titre": s.opt.Titre,
		"stats":   st,
		"salons":  len(cats),
		"billets": s.bil != nil,
		"modules": Modules{Media: true, Biblio: true, MP: true, Billets: s.bil != nil},
	})
}

func (s *Server) apiIntegrity(w http.ResponseWriter, r *http.Request) {
	in, err := s.st.Integrity()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true, "integrite": in})
}

func (s *Server) apiThreads(w http.ResponseWriter, r *http.Request) {
	// L'API d'administration voit TOUT : elle n'est atteignable qu'avec un
	// jeton valide. C'est le seul endroit du programme ou publicOnly vaut faux
	// sans qu'une session membre soit en jeu.
	th, err := s.st.Recent(100, false)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true, "fils": th})
}

func (s *Server) apiInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	code, err := s.st.NewInvite(0)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	// LE CODE N'EST RENDU QU'ICI, UNE SEULE FOIS. Seule son empreinte est
	// conservee : ni un listing ulterieur, ni une lecture de la base ne
	// permettent de le retrouver.
	jsonOK(w, map[string]any{"ok": true, "code": code,
		"note": "code affiche une seule fois — il n'est pas conservé en clair"})
}

func (s *Server) apiBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	dest := r.URL.Query().Get("dest")
	if dest == "" {
		dest = s.opt.BackupDir + "/bbs-" + time.Now().Format("20060102-150405") + ".tar.gz"
	}
	if err := s.st.Backup(dest); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true, "archive": dest})
}

func (s *Server) apiReindex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	if err := s.st.Reindex(); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	in, _ := s.st.Integrity()
	jsonOK(w, map[string]any{"ok": true, "integrite": in})
}
