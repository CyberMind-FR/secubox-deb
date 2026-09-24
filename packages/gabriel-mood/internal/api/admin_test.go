package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/store"
)

func verif(groupes string) VerifAdmin {
	return func(string) (string, string, bool) { return "gk2", groupes, true }
}

func appel(t *testing.T, url, methode, corps string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(methode, url, strings.NewReader(corps))
	req.Header.Set("Authorization", "Bearer jeton")
	rep, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer rep.Body.Close()
	var m map[string]any
	json.NewDecoder(rep.Body).Decode(&m)
	return rep.StatusCode, m
}

func TestLAdministrationEstFermeeSansAdmin(t *testing.T) {
	s, srv := serveur(t)
	chemins := []string{"/api/mood/admin/etat", "/api/mood/admin/reglages"}
	for _, c := range chemins {
		if code, _ := appel(t, srv.URL+c, "GET", ""); code != http.StatusServiceUnavailable {
			t.Errorf("%s sans secubox-auth : %d, attendu 503", c, code)
		}
	}
	s.Verif = verif("user")
	for _, c := range chemins {
		if code, _ := appel(t, srv.URL+c, "GET", ""); code != http.StatusForbidden {
			t.Errorf("%s pour un non-admin : %d, attendu 403", c, code)
		}
	}
	s.Verif = func(string) (string, string, bool) { return "", "", false }
	if code, _ := appel(t, srv.URL+chemins[0], "GET", ""); code != http.StatusUnauthorized {
		t.Errorf("session refusée : %d, attendu 401", code)
	}
}

func TestLEtatDonneDesComptesEtLesGaranties(t *testing.T) {
	s, srv := serveur(t)
	s.Verif = verif("admin")
	s.Reglages = ChargeReglages("", 14*24*time.Hour)
	m0 := time.Now().Truncate(time.Minute).Unix()
	s.Store.Enregistre(store.Resume{Minute: m0, Session: "a", Energie: 1, Etat: "calme"})
	s.Store.Enregistre(store.Resume{Minute: m0, Session: "b", Energie: 1, Etat: "anime"})
	code, m := appel(t, srv.URL+"/api/mood/admin/etat", "GET", "")
	if code != 200 {
		t.Fatalf("etat : %d %v", code, m)
	}
	st := m["stockage"].(map[string]any)
	if st["resumes"].(float64) != 2 || st["sessions"].(float64) != 2 {
		t.Errorf("stockage : %v", st)
	}
	if h := st["par_heure"].([]any); len(h) != 24 || h[23].(float64) != 2 {
		t.Errorf("par heure : %v", h)
	}
	g := m["garanties"].(map[string]any)
	if g["seuil_anonymat"].(float64) != 3 || g["audio_sur_disque"] != false {
		t.Errorf("garanties : %v", g)
	}
	// Des comptes, jamais des lignes : aucun identifiant de session ne sort.
	b, _ := json.Marshal(m)
	if strings.Contains(string(b), `"a"`) || strings.Contains(string(b), `"session":`) {
		t.Errorf("l'état laisse passer des identifiants de session : %s", b)
	}
}

func TestLesReglagesPersistentEtSAppliquent(t *testing.T) {
	s, srv := serveur(t)
	s.Verif = verif("admin")
	chemin := filepath.Join(t.TempDir(), "reglages.json")
	s.Reglages = ChargeReglages(chemin, 14*24*time.Hour)

	vieux := time.Now().Add(-10 * 24 * time.Hour).Truncate(time.Minute).Unix()
	s.Store.Enregistre(store.Resume{Minute: vieux, Session: "ancienne", Energie: 1})

	if code, _ := appel(t, srv.URL+"/api/mood/admin/reglages", "POST",
		`{"historique":true,"memoire_voix":false,"retention_jours":400}`); code != 400 {
		t.Errorf("rétention hors bornes acceptée : %d", code)
	}
	code, m := appel(t, srv.URL+"/api/mood/admin/reglages", "POST",
		`{"historique":false,"memoire_voix":false,"retention_jours":7}`)
	if code != 200 || m["purges"].(float64) != 1 {
		t.Fatalf("réglage : %d %v", code, m)
	}
	if _, err := os.Stat(chemin); err != nil {
		t.Fatal("réglages non écrits sur disque")
	}
	relu := ChargeReglages(chemin, 14*24*time.Hour).Valeurs()
	if relu.Historique || relu.MemoireVoix || relu.RetentionJours != 7 {
		t.Errorf("relu après redémarrage : %+v", relu)
	}
}

func TestLaPurgeTotaleEstUnGesteDAdmin(t *testing.T) {
	s, srv := serveur(t)
	s.Verif = verif("admin")
	s.Store.Enregistre(store.Resume{
		Minute: time.Now().Truncate(time.Minute).Unix(), Session: "x", Energie: 1})
	if code, _ := appel(t, srv.URL+"/api/mood/admin/purge", "POST", `{}`); code != 400 {
		t.Errorf("purge sans « quoi » acceptée : %d", code)
	}
	code, m := appel(t, srv.URL+"/api/mood/admin/purge", "POST", `{"quoi":"tout"}`)
	if code != 200 || m["efface"].(float64) != 1 {
		t.Fatalf("purge : %d %v", code, m)
	}
}
