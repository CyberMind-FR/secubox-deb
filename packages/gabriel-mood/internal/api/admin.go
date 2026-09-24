package api

// Surface d'administration (#1371).
//
// AVANT, IL N'Y EN AVAIT PAS. L'entrée « Gabriel Mood » du panneau admin
// ouvrait le cockpit public — le même que mood.gk2 —, ré-embarqué : aucun
// réglage, aucune métrique, et pour tout geste d'administration le bouton
// « Oublier » d'un visiteur, qui effaçait l'historique de TOUT LE MONDE.
//
// LA GARDE EST CELLE DE SECUBOX. Le jeton est soumis à /auth/verify, qui
// contrôle signature, révocation et compte, et rend le rôle. On n'accepte que
// `admin`. Sans secubox-auth joignable : fermé.

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/audio"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/ser"
)

// VerifAdmin : rend (utilisateur, groupes, ok) pour un jeton.
type VerifAdmin func(jeton string) (string, string, bool)

// VerifParSocket interroge secubox-auth sur sa socket unix.
func VerifParSocket(socket string) VerifAdmin {
	c := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}},
	}
	return func(jeton string) (string, string, bool) {
		if jeton == "" {
			return "", "", false
		}
		req, _ := http.NewRequest("GET", "http://auth/auth/verify", nil)
		req.Header.Set("Authorization", "Bearer "+jeton)
		rep, err := c.Do(req)
		if err != nil {
			return "", "", false
		}
		defer rep.Body.Close()
		u := rep.Header.Get("Remote-User")
		return u, rep.Header.Get("Remote-Groups"), rep.StatusCode == http.StatusOK && u != ""
	}
}

func jetonDe(r *http.Request) string {
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		return strings.TrimPrefix(a, "Bearer ")
	}
	if c, err := r.Cookie("secubox_session"); err == nil {
		return c.Value
	}
	return ""
}

func (s *Serveur) admin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Verif == nil {
			ecris(w, http.StatusServiceUnavailable, map[string]string{"erreur": "secubox-auth non configuré — administration fermée"})
			return
		}
		_, groupes, ok := s.Verif(jetonDe(r))
		if !ok {
			ecris(w, http.StatusUnauthorized, map[string]string{"erreur": "connexion requise"})
			return
		}
		if groupes != "admin" {
			ecris(w, http.StatusForbidden, map[string]string{"erreur": "réservé aux administrateurs"})
			return
		}
		h(w, r)
	}
}

func (s *Serveur) routesAdmin(m *http.ServeMux) {
	m.HandleFunc("/api/mood/admin/etat", s.admin(s.adminEtat))
	m.HandleFunc("/api/mood/admin/reglages", s.admin(s.adminReglages))
	m.HandleFunc("/api/mood/admin/purge", s.admin(s.adminPurge))
}

// GET /api/mood/admin/etat — métriques et garanties, en une lecture.
func (s *Serveur) adminEtat(w http.ResponseWriter, r *http.Request) {
	peripheriques, motif := audio.EntreesDisponibles()
	out := map[string]any{
		"version":         s.Version,
		"demarre":         s.Demarre.Unix(),
		"sessions":        s.Sessions.Nombre(),
		"reglages":        s.Reglages.Valeurs(),
		"historique_base": s.Store != nil,
		"derniere_purge":  s.dernierePurge(),
		"inference":       s.Inference,
		"entrees_locales": peripheriques,
		"entrees_motif":   motif,
		// Les garanties : affichées, jamais réglables.
		"garanties": map[string]any{
			"plafond_confiance": ser.PlafondConfiance,
			"seuil_anonymat":    SeuilAnonymat,
			"audio_sur_disque":  false,
			"classifieur":       "heuristique-prosodique-v1",
			"echantillonnage":   audio.Echantillonnage,
			"reserve":           ser.Reserve,
		},
	}
	if s.Store != nil {
		if st, err := s.Store.Statistiques(time.Now()); err == nil {
			out["stockage"] = st
		} else {
			out["stockage_erreur"] = err.Error()
		}
	}
	ecris(w, http.StatusOK, out)
}

// GET|POST /api/mood/admin/reglages
func (s *Serveur) adminReglages(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ecris(w, http.StatusOK, s.Reglages.Valeurs())
	case http.MethodPost:
		if s.Reglages == nil {
			ecris(w, http.StatusServiceUnavailable, map[string]string{"erreur": "réglages non tenus"})
			return
		}
		var v ValeursReglages
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&v); err != nil {
			ecris(w, http.StatusBadRequest, map[string]string{"erreur": "corps illisible"})
			return
		}
		avant := s.Reglages.Valeurs()
		if err := s.Reglages.Ecrit(v); err != nil {
			ecris(w, http.StatusBadRequest, map[string]string{"erreur": err.Error()})
			return
		}
		// Une rétention RACCOURCIE s'applique tout de suite : sinon la board
		// garderait jusqu'à la passe suivante ce qu'on vient de dire effacé.
		var purges int64
		if s.Store != nil && v.RetentionJours < avant.RetentionJours {
			purges, _ = s.Store.Purge(time.Now().Add(-s.Reglages.Retention()))
			s.notePurge()
		}
		ecris(w, http.StatusOK, map[string]any{"ok": true, "reglages": v, "purges": purges})
	default:
		ecris(w, http.StatusMethodNotAllowed, map[string]string{"erreur": "GET ou POST"})
	}
}

// POST /api/mood/admin/purge {"quoi": "retention" | "tout"}
func (s *Serveur) adminPurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		ecris(w, http.StatusMethodNotAllowed, map[string]string{"erreur": "POST attendu"})
		return
	}
	if s.Store == nil {
		ecris(w, http.StatusOK, map[string]any{"efface": 0, "detail": "aucun historique n'est tenu"})
		return
	}
	var c struct {
		Quoi string `json:"quoi"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&c)
	var n int64
	var err error
	switch c.Quoi {
	case "tout":
		n, err = s.Store.Tout()
	case "retention":
		n, err = s.Store.Purge(time.Now().Add(-s.Reglages.Retention()))
	default:
		ecris(w, http.StatusBadRequest, map[string]string{"erreur": `« quoi » : "retention" ou "tout"`})
		return
	}
	if err != nil {
		ecris(w, http.StatusInternalServerError, map[string]string{"erreur": err.Error()})
		return
	}
	s.notePurge()
	ecris(w, http.StatusOK, map[string]any{"ok": true, "efface": n})
}

func (s *Serveur) notePurge() {
	s.purgeMu.Lock()
	s.purgeLe = time.Now()
	s.purgeMu.Unlock()
}

func (s *Serveur) dernierePurge() int64 {
	s.purgeMu.Lock()
	defer s.purgeMu.Unlock()
	if s.purgeLe.IsZero() {
		return 0
	}
	return s.purgeLe.Unix()
}

// PurgeSelonReglages : la passe périodique, lancée par main. Elle relit la
// rétention À CHAQUE PASSE — un réglage changé n'attend pas un redémarrage.
func (s *Serveur) PurgeSelonReglages() (int64, error) {
	if s.Store == nil {
		return 0, nil
	}
	n, err := s.Store.Purge(time.Now().Add(-s.Reglages.Retention()))
	if err == nil {
		s.notePurge()
	}
	return n, err
}
