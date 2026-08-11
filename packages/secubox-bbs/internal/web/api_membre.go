package web

// API des MEMBRES, celle que l'application companion consomme.
//
// Distincte de l'API d'administration : celle-ci agit AU NOM DE QUELQU'UN.
//
// LA SIGNATURE PROUVE QUE LE JETON VIENT DU NOYAU, PAS QUI LE PRESENTE. Sans
// resoudre le sujet vers un compte du BBS, n'importe quel jeton valide de la
// board — celui d'un autre module, d'un service — agirait au nom de personne,
// donc au nom de tout le monde. Chaque route resout `sub`, et ce qu'elle rend
// depend de ce que CE compte a le droit de voir.

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

func (s *Server) routesMembre() {
	s.mux.HandleFunc("/api/v1/bbs/m/salons", s.apiMSalons)
	s.mux.HandleFunc("/api/v1/bbs/m/fils", s.apiMFils)
	s.mux.HandleFunc("/api/v1/bbs/m/fils/", s.apiMFil)
}

// appelant resout le porteur du jeton vers un compte du BBS.
//
// Rend (0, false) si le jeton est invalide. Rend (0, true) si le jeton est
// VALIDE mais que son sujet n'est pas un membre : l'appelant est alors traite
// comme un visiteur — il ne voit que le public et ne peut rien ecrire.
func (s *Server) appelant(r *http.Request) (int64, bool) {
	claims, err := s.claimsJeton(r.Header.Get("Authorization"))
	if err != nil {
		return 0, false
	}
	sub := strings.TrimSpace(claims.Sub)
	if sub == "" {
		return 0, true
	}
	// UserByHandle ignore les comptes desactives : une revocation cote SecuBox
	// ferme donc l'API immediatement, sans attendre l'expiration du jeton.
	id, err := s.st.UserByHandle(sub)
	if err != nil {
		return 0, true
	}
	return id, true
}

func (s *Server) apiMSalons(w http.ResponseWriter, r *http.Request) {
	id, ok := s.appelant(r)
	if !ok || id == 0 {
		jsonErr(w, http.StatusUnauthorized, "jeton sans membre reconnu")
		return
	}
	cats, err := s.st.Categories(false)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(cats))
	for _, c := range cats {
		out = append(out, map[string]any{
			"slug": c.Slug, "titre": c.Title, "description": c.Desc, "fils": c.Threads,
		})
	}
	jsonOK(w, map[string]any{"ok": true, "salons": out})
}

func (s *Server) apiMFils(w http.ResponseWriter, r *http.Request) {
	id, ok := s.appelant(r)
	if !ok {
		jsonErr(w, http.StatusUnauthorized, "jeton invalide")
		return
	}
	// Un jeton sans membre reconnu ne voit que le public — le meme traitement
	// qu'un visiteur du site.
	pub := id == 0
	fils, err := s.st.Recent(50, pub)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true, "membre": id != 0, "fils": vueFils(fils)})
}

func (s *Server) apiMFil(w http.ResponseWriter, r *http.Request) {
	id, ok := s.appelant(r)
	if !ok {
		jsonErr(w, http.StatusUnauthorized, "jeton invalide")
		return
	}
	reste := strings.TrimPrefix(r.URL.Path, "/api/v1/bbs/m/fils/")
	fil := idDe(reste+"/", "")
	if fil == 0 {
		jsonErr(w, http.StatusNotFound, "fil inconnu")
		return
	}
	if strings.HasSuffix(reste, "/reponse") {
		s.apiMReponse(w, r, fil, id)
		return
	}

	t, err := s.st.ThreadByID(fil)
	if err != nil {
		jsonErr(w, http.StatusNotFound, "fil inconnu")
		return
	}
	pub := id == 0
	if pub && t.Visibility != store.VisPublic {
		// 404 et non 403 : un 403 confirmerait l'existence du fil.
		jsonErr(w, http.StatusNotFound, "fil inconnu")
		return
	}
	var posts []store.Post
	if pub {
		posts, _ = s.st.PublicPostsOf(fil)
	} else {
		posts, _ = s.st.PostsOf(fil)
	}
	msgs := make([]map[string]any, 0, len(posts))
	for _, p := range posts {
		corps, err := s.st.Body(p)
		if err != nil {
			corps = "(ce message diverge de l'index)"
		}
		msgs = append(msgs, map[string]any{
			"id": p.ID, "auteur": s.st.Author(p.AuthorID),
			"corps": corps, "visibilite": string(p.Visibility), "date": p.CreatedAt,
		})
	}
	jsonOK(w, map[string]any{"ok": true, "fil": vueFil(t), "messages": msgs})
}

func (s *Server) apiMReponse(w http.ResponseWriter, r *http.Request, fil, membre int64) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	if membre == 0 {
		jsonErr(w, http.StatusForbidden, "jeton sans membre reconnu")
		return
	}
	var in struct {
		Corps      string `json:"corps"`
		Visibilite string `json:"visibilite"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in) != nil {
		jsonErr(w, http.StatusBadRequest, "corps illisible")
		return
	}
	if strings.TrimSpace(in.Corps) == "" {
		jsonErr(w, http.StatusBadRequest, "message vide")
		return
	}
	t, err := s.st.ThreadByID(fil)
	if err != nil {
		jsonErr(w, http.StatusNotFound, "fil inconnu")
		return
	}
	// PAR DEFAUT LOCAL, et public seulement dans un fil public : une
	// application mobile ne doit pas publier plus largement que le site, et un
	// doigt sur un petit ecran se trompe plus facilement qu'une souris.
	vis := store.VisLocal
	if in.Visibilite == "public" && t.Visibility == store.VisPublic {
		vis = store.VisPublic
	}
	if _, err := s.st.Reply(fil, membre, in.Corps, vis); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true, "visibilite": string(vis)})
}

func vueFils(fils []store.Thread) []map[string]any {
	out := make([]map[string]any, 0, len(fils))
	for _, t := range fils {
		out = append(out, vueFil(t))
	}
	return out
}

func vueFil(t store.Thread) map[string]any {
	return map[string]any{
		"id": t.ID, "titre": t.Title, "auteur": t.Author,
		"visibilite": string(t.Visibility), "source": t.Source,
		"messages": t.Posts, "date": t.LastPostAt,
		"media": t.MediaURL, "media_type": t.MediaKind,
		"billet": t.Published,
	}
}
