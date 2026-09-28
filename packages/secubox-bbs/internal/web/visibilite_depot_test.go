// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/billets"
)

// #1608 — deposer un fil au nom de la passerelle est le geste d'un module de
// passerelle, et un billet ne renvoie vers le BBS que si son lecteur peut
// suivre le lien.

// jetonService : un jeton de service tel que MetaNews ou SocialRelay le signent
// (sub + iss, sans jti).
func jetonService(secret, iss string) string {
	e := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	now := time.Now().Unix()
	c := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"sub":"%s","iss":"%s","iat":%d,"exp":%d}`, iss, iss, now, now+3600)))
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(e + "." + c))
	return e + "." + c + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func corpsDepot(salon string) string {
	return `{"title":"Depot","body":"corps du depot","category":"` + salon + `","visibility":"public"}`
}

func (b bancVis) nbFils(t *testing.T, cat int64) int {
	t.Helper()
	n, err := b.s.QueryRowScanInt64(`SELECT COUNT(*) FROM threads WHERE category_id=?`, cat)
	if err != nil {
		t.Fatal(err)
	}
	return int(n)
}

func (b bancVis) salonExiste(t *testing.T, slug string) bool {
	t.Helper()
	n, err := b.s.QueryRowScanInt64(`SELECT COUNT(*) FROM categories WHERE slug=?`, slug)
	if err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func TestDepotPasserelleRefuseAuJetonMembre(t *testing.T) {
	b := bancSalonsPrives(t)
	avant := b.nbFils(t, b.bureau)
	for _, jeton := range []string{
		jetonPour("bob"),   // session d'un membre non convie
		jetonPour("alice"), // session d'une conviee : ce n'est pas une passerelle non plus
		jetonHS256("le-secret-partage", "admin", time.Hour), // session sans emetteur
		jetonService("le-secret-partage", "secubox-radio"),  // module qui n'est pas une passerelle
	} {
		for _, salon := range []string{"bureau", "place", "salon-absent"} {
			w := api(b.srv, "POST", "/api/v1/bbs/threads", jeton, corpsDepot(salon))
			if w.Code != http.StatusForbidden {
				t.Errorf("depot dans %q : code %d, attendu 403 (%s)", salon, w.Code, w.Body.String())
			}
		}
	}
	if apres := b.nbFils(t, b.bureau); apres != avant {
		t.Errorf("fils du salon prive : %d avant, %d apres", avant, apres)
	}
	if b.salonExiste(t, "salon-absent") {
		t.Error("un salon a ete cree pour un jeton qui n'est pas une passerelle")
	}
}

func TestDepotDansSalonPriveIntrouvableAuMembre(t *testing.T) {
	// La reponse a un jeton de membre est la meme pour un salon prive, un
	// salon ouvert et un salon absent : elle ne renseigne sur aucun.
	b := bancSalonsPrives(t)
	var corps []string
	for _, salon := range []string{"bureau", "place", "salon-absent"} {
		w := api(b.srv, "POST", "/api/v1/bbs/threads", jetonPour("bob"), corpsDepot(salon))
		corps = append(corps, fmt.Sprintf("%d %s", w.Code, strings.TrimSpace(w.Body.String())))
	}
	if corps[0] != corps[1] || corps[1] != corps[2] {
		t.Errorf("reponses differentes selon le salon : %q", corps)
	}
	// Et rien n'apparait chez la conviee.
	if c := api(b.srv, "GET", "/api/v1/bbs/m/fils", jetonPour("alice"), "").Body.String(); strings.Contains(c, `"Depot"`) {
		t.Error("un depot refuse apparait dans les fils de la conviee")
	}
}

func TestDepotParLesPasserellesConnues(t *testing.T) {
	b := bancSalonsPrives(t)
	for _, iss := range []string{"metanews", "socialrelay"} {
		w := api(b.srv, "POST", "/api/v1/bbs/threads", jetonService("le-secret-partage", iss), corpsDepot("reseaux"))
		if w.Code != http.StatusOK {
			t.Fatalf("passerelle %s refusee : %d %s", iss, w.Code, w.Body.String())
		}
	}
	// Le salon fixe par la configuration de la passerelle est cree s'il manque.
	if !b.salonExiste(t, "reseaux") {
		t.Error("le salon de la passerelle n'a pas ete cree")
	}
	// Sans jeton : toujours 401.
	if w := api(b.srv, "POST", "/api/v1/bbs/threads", "", corpsDepot("reseaux")); w.Code != http.StatusUnauthorized {
		t.Errorf("depot sans jeton : %d, attendu 401", w.Code)
	}
}

// ── Publication vers billets : le lien de retour ────────────────────────────

// billetsFactice : un billets qui enregistre ce que le BBS lui envoie.
func billetsFactice(t *testing.T) (*billets.Client, func() []map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var recus []map[string]any
	amont := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		brut, _ := io.ReadAll(r.Body)
		var d map[string]any
		_ = json.Unmarshal(brut, &d)
		mu.Lock()
		recus = append(recus, d)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"B1","permalink":"https://billets.exemple/b/b1"}`)
	}))
	t.Cleanup(amont.Close)
	cl := &billets.Client{Base: amont.URL, HTTP: amont.Client()}
	return cl, func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		return append([]map[string]any(nil), recus...)
	}
}

func (b bancVis) publierFil(t *testing.T, id int64) *httptest.ResponseRecorder {
	t.Helper()
	j := b.session(t, b.sysop)
	csrf := csrfDe(t, b.srv, "/nouveau", j)
	r := httptest.NewRequest("POST", "http://bbs.exemple/t/"+itoa(id)+"/publier",
		strings.NewReader(url.Values{"csrf": {csrf}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: cookieSession, Value: j})
	r.AddCookie(&http.Cookie{Name: cookieCSRF, Value: csrf})
	// la publication part sous la session SecuBox de l'operateur
	r.AddCookie(&http.Cookie{Name: "secubox_session", Value: "jeton-du-hall"})
	w := httptest.NewRecorder()
	b.srv.Handler().ServeHTTP(w, r)
	return w
}

func TestPublierUnFilDeSalonPriveSansLienDeRetour(t *testing.T) {
	b := bancSalonsPrives(t)
	cl, recus := billetsFactice(t)
	b.srv.bil = cl
	if w := b.publierFil(t, b.filBureau); w.Code != http.StatusSeeOther {
		t.Fatalf("publication refusee : %d %s", w.Code, w.Body.String())
	}
	env := recus()
	if len(env) != 1 {
		t.Fatalf("%d envois a billets, attendu 1", len(env))
	}
	if ref, _ := env[0]["ref_url"].(string); ref != "" {
		t.Errorf("ref_url transmis pour un fil de salon prive : %q", ref)
	}
	if corps, _ := env[0]["body"].(string); strings.Contains(corps, "/t/") || strings.Contains(corps, "Discuter ce billet") {
		t.Errorf("le corps renvoie vers le fil : %q", corps)
	}
}

func TestPublierUnFilDeSalonOuvertGardeSonLienDeRetour(t *testing.T) {
	b := bancSalonsPrives(t)
	cl, recus := billetsFactice(t)
	b.srv.bil = cl
	if w := b.publierFil(t, b.filPlace); w.Code != http.StatusSeeOther {
		t.Fatalf("publication refusee : %d %s", w.Code, w.Body.String())
	}
	env := recus()
	if len(env) != 1 {
		t.Fatalf("%d envois a billets, attendu 1", len(env))
	}
	attendu := "https://bbs.exemple/t/" + itoa(b.filPlace)
	if ref, _ := env[0]["ref_url"].(string); ref != attendu {
		t.Errorf("ref_url = %q, attendu %q", ref, attendu)
	}
	if corps, _ := env[0]["body"].(string); !strings.Contains(corps, "[Discuter ce billet sur le BBS]("+attendu+")") {
		t.Errorf("lien de discussion absent du corps : %q", corps)
	}
}
