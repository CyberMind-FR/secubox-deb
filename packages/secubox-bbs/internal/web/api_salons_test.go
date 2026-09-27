package web

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// #1523 : la webui d'administration fait ce que faisait /sysop — mêmes
// fonctions du store, même journal, et un acteur NOMMÉ.

func TestSalonsAdminSansCompteBBSRefuse(t *testing.T) {
	srv, _ := banc(t)
	srv.opt.JWTSecret = "le-secret-partage"
	// « admin » n'a pas de compte BBS : le journal ne nommerait personne.
	w, _ := appelSysop(t, srv, "POST", "/api/v1/bbs/admin/salons", `{"slug":"x","titre":"X"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("code %d, attendu 403 : %s", w.Code, w.Body.String())
	}
	if w, _ := appelSysop(t, srv, "GET", "/api/v1/bbs/admin/salons", ""); w.Code != http.StatusOK {
		t.Fatalf("la lecture n'exige pas d'acteur : code %d", w.Code)
	}
}

func TestSalonsAdminParcoursComplet(t *testing.T) {
	srv, s := banc(t)
	srv.opt.JWTSecret = "le-secret-partage"
	s.CreateUser("admin", "Admin", store.RoleSysop)
	amie, _ := s.CreateUser("amie", "Amie", store.RoleMember)

	w, j := appelSysop(t, srv, "POST", "/api/v1/bbs/admin/salons", `{"slug":"technique","titre":"Technique"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("création : %d %s", w.Code, w.Body.String())
	}
	parent := int64(j["id"].(float64))
	w, j = appelSysop(t, srv, "POST", "/api/v1/bbs/admin/salons",
		fmt.Sprintf(`{"slug":"reseau","titre":"Réseau","parent":%d}`, parent))
	if w.Code != http.StatusOK {
		t.Fatalf("sous-salon : %d %s", w.Code, w.Body.String())
	}
	sous := int64(j["id"].(float64))
	// Un identifiant invalide est refusé par le store, et l'erreur DITE.
	if w, _ := appelSysop(t, srv, "POST", "/api/v1/bbs/admin/salons", `{"slug":"Pas bon!","titre":"x"}`); w.Code == http.StatusOK {
		t.Fatal("slug invalide accepté")
	}

	base := fmt.Sprintf("/api/v1/bbs/admin/salons/%d", sous)
	if w, _ := appelSysop(t, srv, "POST", base+"/prive", `{"prive":true}`); w.Code != http.StatusOK {
		t.Fatalf("fermer : %d %s", w.Code, w.Body.String())
	}
	if w, _ := appelSysop(t, srv, "POST", base+"/membres", fmt.Sprintf(`{"membre":%d,"action":"ajouter"}`, amie)); w.Code != http.StatusOK {
		t.Fatalf("convier : %d %s", w.Code, w.Body.String())
	}
	w, j = appelSysop(t, srv, "POST", base+"/invitation", "")
	if w.Code != http.StatusOK || !strings.HasPrefix(j["lien"].(string), "/salon/rejoindre?code=") {
		t.Fatalf("invitation : %d %v", w.Code, j)
	}
	// Communauté inconnue : jamais ouverte.
	if w, _ := appelSysop(t, srv, "POST", base+"/communautes", `{"communaute":"nimporte","action":"ajouter"}`); w.Code == http.StatusOK {
		t.Fatal("salon ouvert à une communauté inconnue")
	}

	// La lecture montre l'arbre, le salon privé et son membre nommé.
	_, j = appelSysop(t, srv, "GET", "/api/v1/bbs/admin/salons", "")
	var vu bool
	for _, x := range j["salons"].([]any) {
		m := x.(map[string]any)
		if int64(m["id"].(float64)) == sous {
			vu = true
			if m["prive"] != true || int64(m["parent"].(float64)) != parent || int(m["profondeur"].(float64)) != 1 {
				t.Errorf("sous-salon mal décrit : %v", m)
			}
			if ms := m["membres"].([]any); len(ms) != 1 || ms[0].(map[string]any)["handle"] != "amie" {
				t.Errorf("membres : %v", ms)
			}
		}
	}
	if !vu {
		t.Fatal("sous-salon absent de la liste")
	}

	// Le journal nomme l'administrateur.
	_, j = appelSysop(t, srv, "GET", "/api/v1/bbs/admin/moderation", "")
	journal := j["journal"].([]any)
	if len(journal) == 0 {
		t.Fatal("journal vide après des gestes de modération")
	}
	for _, e := range journal {
		if a := e.(map[string]any)["acteur"]; a != "Admin" && a != "admin" {
			t.Errorf("acteur %v, attendu l'administrateur", a)
		}
	}
	if w, _ := appelSysop(t, srv, "GET", "/api/v1/bbs/admin/passerelles", ""); w.Code != http.StatusOK {
		t.Fatalf("passerelles : %d", w.Code)
	}
}
