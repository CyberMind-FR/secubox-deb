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
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
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
	s.mux.HandleFunc("POST /api/v1/bbs/content/{id}/timeline", s.jwt(s.apiContentTimelineCreer))
	s.mux.HandleFunc("GET /api/v1/bbs/content/{id}/timeline", s.jwt(s.apiContentTimelineLister))
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
	if r.Method == http.MethodPost {
		s.apiCreerFil(w, r)
		return
	}
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

// apiCreerFil : ouvre un fil AU NOM D'UNE PASSERELLE (compte dédié désactivé),
// pour un module externe authentifié — MetaNews « Discuter » en premier. Le
// corps porte le résumé + les liens sources ; le fil est marqué de son URL
// source. Au doute, VISIBILITÉ LOCALE (une passerelle ne publie pas d'office).
func (s *Server) apiCreerFil(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Title      string `json:"title"`
		Body       string `json:"body"`
		Category   string `json:"category"`   // slug ; défaut « actualites »
		SourceURL  string `json:"source_url"`
		Visibility string `json:"visibility"` // "public" | "local" (défaut)
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<18)).Decode(&in) != nil || strings.TrimSpace(in.Title) == "" {
		jsonErr(w, http.StatusBadRequest, "title requis")
		return
	}
	aut, err := s.auteurPasserelle()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	slug := strings.TrimSpace(in.Category)
	if slug == "" {
		slug = "actualites"
	}
	cat, err := s.catParSlug(slug)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	vis := store.VisLocal
	if in.Visibility == "public" {
		vis = store.VisPublic
	}
	id, err := s.st.NewThread(cat, aut, in.Title, in.Body, vis)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if in.SourceURL != "" {
		_ = s.st.MarquerSourceMedia(id, in.SourceURL, "", "")
	}
	var fslug string
	_ = s.st.QueryRowScan(&fslug, `SELECT slug FROM threads WHERE id=?`, id)
	jsonOK(w, map[string]any{"ok": true, "thread_id": id, "slug": fslug})
}

// auteurPasserelle rend l'id du compte « passerelle » (désactivé), en le créant
// si absent — un module de passerelle ne doit pas échouer faute de ce compte.
func (s *Server) auteurPasserelle() (int64, error) {
	if id, err := s.st.UserByHandle("passerelle"); err == nil && id != 0 {
		return id, nil
	}
	// UserByHandle ne rend pas un compte désactivé : on le retrouve directement.
	if id, err := s.st.QueryRowScanInt64(`SELECT id FROM users WHERE handle='passerelle'`); err == nil && id != 0 {
		return id, nil
	}
	return s.st.CreateUser("passerelle", "Passerelle", store.RoleMember)
}

// catParSlug rend l'id de la catégorie de slug donné, en la créant si absente.
func (s *Server) catParSlug(slug string) (int64, error) {
	if id, err := s.st.QueryRowScanInt64(`SELECT id FROM categories WHERE slug=?`, slug); err == nil && id != 0 {
		return id, nil
	}
	titre := strings.ToUpper(slug[:1]) + slug[1:]
	return s.st.CreateCategory(slug, titre, "")
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
