// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// #1608 — un salon prive est invisible partout ou il l'est dans le rail :
// l'API des membres, les pages, la carte du Hall, les compteurs et les
// notifications appliquent la meme regle, et repondent 404 pour ce qui n'existe
// pas pour l'appelant.

type bancVis struct {
	srv                     *Server
	s                       *store.Store
	chemin                  string
	sysop, invite, tiers    int64
	place, bureau           int64
	filPlace, filPlaceLocal int64
	filBureau, noteBureau   int64
}

// bancSalonsPrives : un salon ouvert (« place ») et un salon prive
// (« bureau ») ou alice est conviee et bob ne l'est pas. Le bureau contient un
// fil PUBLIC — c'est le cas qui compte : sa visibilite de fil ne doit pas
// l'emporter sur celle du salon.
func bancSalonsPrives(t *testing.T) bancVis {
	t.Helper()
	root := t.TempDir()
	chemin := filepath.Join(root, "bbs.db")
	s, err := store.Open(chemin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	srv, err := New(s, nil, Options{Titre: "Banc", Secrets: filepath.Join(root, "secrets")})
	if err != nil {
		t.Fatal(err)
	}
	srv.opt.JWTSecret = "le-secret-partage"
	// Aucune base SBX OS ici : seuls les membres nommes comptent.
	ancien := store.SbxDB
	store.SbxDB = filepath.Join(root, "absente.db")
	t.Cleanup(func() { store.SbxDB = ancien })

	b := bancVis{srv: srv, s: s, chemin: chemin}
	must := func(id int64, err error) int64 {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	b.sysop = must(s.CreateUser("gk2", "Gandalf", store.RoleSysop))
	b.invite = must(s.CreateUser("alice", "Alice", store.RoleMember))
	b.tiers = must(s.CreateUser("bob", "Bob", store.RoleMember))
	b.place = must(s.CreateCategory("place", "Place", ""))
	b.bureau = must(s.CreateCategory("bureau", "Bureau", ""))
	if err := s.RendPrive(b.bureau, true); err != nil {
		t.Fatal(err)
	}
	if err := s.AjouteMembre(b.bureau, b.invite, b.sysop); err != nil {
		t.Fatal(err)
	}
	b.filPlace = must(s.NewThread(b.place, b.sysop, "Sujet de la place", "corps de la place", store.VisPublic))
	b.filPlaceLocal = must(s.NewThread(b.place, b.sysop, "Aparte de la place", "corps local", store.VisLocal))
	b.filBureau = must(s.NewThread(b.bureau, b.sysop, "Sujet du bureau", "corps du bureau", store.VisPublic))
	b.noteBureau = must(s.NewThread(b.bureau, b.sysop, "Note du bureau", "corps de la note", store.VisLocal))
	return b
}

func (b bancVis) session(t *testing.T, uid int64) string {
	t.Helper()
	j, err := b.s.NewSession(uid, "", "")
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func cheminFil(id int64) string { return "/api/v1/bbs/m/fils/" + itoa(id) }

func slugsSalons(t *testing.T, w interface{ Bytes() []byte }) []string {
	t.Helper()
	var d struct {
		Salons []struct{ Slug string }
	}
	if err := json.Unmarshal(w.Bytes(), &d); err != nil {
		t.Fatalf("reponse illisible : %v", err)
	}
	out := make([]string, 0, len(d.Salons))
	for _, s := range d.Salons {
		out = append(out, s.Slug)
	}
	return out
}

func contient(liste []string, v string) bool {
	for _, x := range liste {
		if x == v {
			return true
		}
	}
	return false
}

// ── API des membres : /m/salons ────────────────────────────────────────────

func TestSalonPriveAbsentDeLaListeMembre(t *testing.T) {
	b := bancSalonsPrives(t)
	w := api(b.srv, "GET", "/api/v1/bbs/m/salons", jetonPour("bob"), "")
	if w.Code != http.StatusOK {
		t.Fatalf("code %d : %s", w.Code, w.Body.String())
	}
	slugs := slugsSalons(t, w.Body)
	if contient(slugs, "bureau") {
		t.Errorf("salon prive liste a un non-convie : %v", slugs)
	}
	if !contient(slugs, "place") {
		t.Errorf("le salon ouvert a disparu : %v", slugs)
	}
}

func TestSalonPriveListeAuMembreConvie(t *testing.T) {
	b := bancSalonsPrives(t)
	w := api(b.srv, "GET", "/api/v1/bbs/m/salons", jetonPour("alice"), "")
	if slugs := slugsSalons(t, w.Body); !contient(slugs, "bureau") || !contient(slugs, "place") {
		t.Errorf("la conviee doit voir les deux salons : %v", slugs)
	}
}

func TestSalonPriveListeAuSysop(t *testing.T) {
	b := bancSalonsPrives(t)
	w := api(b.srv, "GET", "/api/v1/bbs/m/salons", jetonPour("gk2"), "")
	if slugs := slugsSalons(t, w.Body); !contient(slugs, "bureau") {
		t.Errorf("le sysop doit voir le salon prive : %v", slugs)
	}
}

// ── API des membres : /m/fils ──────────────────────────────────────────────

func TestFilsDuSalonPriveAbsentsPourNonConvie(t *testing.T) {
	b := bancSalonsPrives(t)
	corps := api(b.srv, "GET", "/api/v1/bbs/m/fils", jetonPour("bob"), "").Body.String()
	for _, titre := range []string{"Sujet du bureau", "Note du bureau"} {
		if strings.Contains(corps, titre) {
			t.Errorf("%q rendu a un non-convie", titre)
		}
	}
	for _, titre := range []string{"Sujet de la place", "Aparte de la place"} {
		if !strings.Contains(corps, titre) {
			t.Errorf("%q absent pour un membre : le salon ouvert ne doit pas changer", titre)
		}
	}
}

func TestFilsDuSalonPriveVisiblesAuConvieEtAuSysop(t *testing.T) {
	b := bancSalonsPrives(t)
	for _, qui := range []string{"alice", "gk2"} {
		corps := api(b.srv, "GET", "/api/v1/bbs/m/fils", jetonPour(qui), "").Body.String()
		for _, titre := range []string{"Sujet du bureau", "Note du bureau", "Sujet de la place"} {
			if !strings.Contains(corps, titre) {
				t.Errorf("%s ne voit pas %q", qui, titre)
			}
		}
	}
}

func TestJetonSansMembreNeVoitPasLeFilPublicDUnSalonPrive(t *testing.T) {
	// Un jeton sans compte est traite en visiteur : il voit le public, et un
	// fil public d'un salon prive n'est pas public.
	b := bancSalonsPrives(t)
	corps := api(b.srv, "GET", "/api/v1/bbs/m/fils", jetonPour("inconnu-ici"), "").Body.String()
	if strings.Contains(corps, "Sujet du bureau") {
		t.Error("fil d'un salon prive rendu a un jeton sans membre")
	}
	if !strings.Contains(corps, "Sujet de la place") {
		t.Error("le fil public du salon ouvert doit rester visible")
	}
	if w := api(b.srv, "GET", cheminFil(b.filBureau), jetonPour("inconnu-ici"), ""); w.Code != http.StatusNotFound {
		t.Errorf("fil d'un salon prive ouvert par un jeton sans membre : %d", w.Code)
	}
}

func TestLaBorneDesFilsNeCompteQueLesSalonsVisibles(t *testing.T) {
	// Plus de fils recents dans le salon cache que la borne : la liste ne doit
	// pas revenir vide pour autant.
	b := bancSalonsPrives(t)
	for i := 0; i < 60; i++ {
		if _, err := b.s.NewThread(b.bureau, b.sysop, "Suite "+itoa(int64(i)), "x", store.VisLocal); err != nil {
			t.Fatal(err)
		}
	}
	corps := api(b.srv, "GET", "/api/v1/bbs/m/fils", jetonPour("bob"), "").Body.String()
	if !strings.Contains(corps, "Sujet de la place") {
		t.Error("les fils visibles sont evinces par ceux d'un salon cache")
	}
	if strings.Contains(corps, "Suite ") {
		t.Error("fil d'un salon cache rendu")
	}
}

// ── API des membres : /m/fils/{id} ─────────────────────────────────────────

func TestFilDUnSalonPriveRepondIntrouvable(t *testing.T) {
	b := bancSalonsPrives(t)
	cache := api(b.srv, "GET", cheminFil(b.filBureau), jetonPour("bob"), "")
	if cache.Code != http.StatusNotFound {
		t.Fatalf("fil d'un salon cache : code %d, attendu 404", cache.Code)
	}
	// Meme reponse, mot pour mot, qu'un identifiant qui ne designe rien.
	absent := api(b.srv, "GET", cheminFil(987654), jetonPour("bob"), "")
	if absent.Code != cache.Code || absent.Body.String() != cache.Body.String() {
		t.Errorf("la reponse distingue un fil cache d'un fil absent : %q / %q",
			cache.Body.String(), absent.Body.String())
	}
	if strings.Contains(cache.Body.String(), "corps du bureau") {
		t.Error("le corps du fil est rendu")
	}
}

func TestFilDUnSalonPriveLisibleParConvieEtSysop(t *testing.T) {
	b := bancSalonsPrives(t)
	for _, qui := range []string{"alice", "gk2"} {
		w := api(b.srv, "GET", cheminFil(b.noteBureau), jetonPour(qui), "")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "corps de la note") {
			t.Errorf("%s : code %d, %s", qui, w.Code, w.Body.String())
		}
	}
}

func TestFilDuSalonOuvertInchange(t *testing.T) {
	b := bancSalonsPrives(t)
	w := api(b.srv, "GET", cheminFil(b.filPlaceLocal), jetonPour("bob"), "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "corps local") {
		t.Errorf("fil local du salon ouvert : code %d", w.Code)
	}
}

func TestReponseDansUnSalonPriveRefuseeAuNonConvie(t *testing.T) {
	b := bancSalonsPrives(t)
	w := api(b.srv, "POST", cheminFil(b.filBureau)+"/reponse", jetonPour("bob"), `{"corps":"entree"}`)
	if w.Code != http.StatusNotFound {
		t.Errorf("reponse d'un non-convie : code %d, attendu 404", w.Code)
	}
	if posts, _ := b.s.PostsOf(b.filBureau); len(posts) != 1 {
		t.Errorf("%d messages : la reponse a ete ecrite", len(posts))
	}
	// La conviee, elle, repond.
	if w := api(b.srv, "POST", cheminFil(b.filBureau)+"/reponse", jetonPour("alice"), `{"corps":"present"}`); w.Code != http.StatusOK {
		t.Errorf("reponse de la conviee : code %d", w.Code)
	}
}

// ── Repli sur erreur ───────────────────────────────────────────────────────

func TestMasqueSurErreurCacheToutSalonPrive(t *testing.T) {
	cats := []store.Category{{ID: 1, Prive: false}, {ID: 2, Prive: true}}
	m := construireMasque(nil, errors.New("lecture impossible"),
		func() ([]store.Category, error) { return cats, nil })
	if m.voit(2) {
		t.Error("un salon prive reste visible quand la liste nominative est illisible")
	}
	if !m.voit(1) {
		t.Error("le salon ouvert doit rester visible")
	}
}

func TestMasqueSansListeDesSalonsNeLaisseRienPasser(t *testing.T) {
	m := construireMasque(nil, errors.New("lecture impossible"),
		func() ([]store.Category, error) { return nil, errors.New("base illisible") })
	for _, cat := range []int64{0, 1, 2, 99} {
		if m.voit(cat) {
			t.Errorf("salon %d visible alors que rien n'est lisible", cat)
		}
	}
}

func TestMasqueSansErreurSuitLaListe(t *testing.T) {
	m := construireMasque(map[int64]bool{2: true}, nil,
		func() ([]store.Category, error) { t.Fatal("repli inutile"); return nil, nil })
	if m.voit(2) || !m.voit(1) {
		t.Errorf("masque : %+v", m)
	}
}

func TestListeNominativeIllisibleFermeLeSalonMemeAuConvie(t *testing.T) {
	// De bout en bout : la table des membres disparait, alice (conviee) ne
	// voit plus le bureau. On cache trop, jamais trop peu.
	b := bancSalonsPrives(t)
	db, err := sql.Open("sqlite", b.chemin)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TABLE salon_membres`); err != nil {
		t.Fatal(err)
	}
	if slugs := slugsSalons(t, api(b.srv, "GET", "/api/v1/bbs/m/salons", jetonPour("alice"), "").Body); contient(slugs, "bureau") {
		t.Errorf("salon prive liste malgre l'erreur : %v", slugs)
	}
	if w := api(b.srv, "GET", cheminFil(b.filBureau), jetonPour("alice"), ""); w.Code != http.StatusNotFound {
		t.Errorf("fil du salon prive ouvert malgre l'erreur : %d", w.Code)
	}
	if strings.Contains(api(b.srv, "GET", "/api/v1/bbs/m/fils", jetonPour("alice"), "").Body.String(), "Sujet du bureau") {
		t.Error("fil du salon prive liste malgre l'erreur")
	}
	// Le sysop voit tout sans lire la liste nominative : la moderation reste
	// possible pendant la panne.
	if w := api(b.srv, "GET", cheminFil(b.filBureau), jetonPour("gk2"), ""); w.Code != http.StatusOK {
		t.Errorf("sysop : %d", w.Code)
	}
}

// ── Pages web ──────────────────────────────────────────────────────────────

func TestPageDUnFilDeSalonPriveIntrouvable(t *testing.T) {
	b := bancSalonsPrives(t)
	chemin := "/t/" + itoa(b.filBureau)
	if w := demande(t, b.srv, "GET", chemin, "", nil); w.Code != http.StatusNotFound {
		t.Errorf("visiteur sans compte : %d, attendu 404", w.Code)
	}
	if w := demande(t, b.srv, "GET", chemin, b.session(t, b.tiers), nil); w.Code != http.StatusNotFound {
		t.Errorf("membre non convie : %d, attendu 404", w.Code)
	}
	for _, uid := range []int64{b.invite, b.sysop} {
		w := demande(t, b.srv, "GET", chemin, b.session(t, uid), nil)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "corps du bureau") {
			t.Errorf("compte %d : code %d", uid, w.Code)
		}
	}
}

func TestOuvrirUnFilCacheNeLaissePasDeTraceDeLecture(t *testing.T) {
	b := bancSalonsPrives(t)
	demande(t, b.srv, "GET", "/t/"+itoa(b.filBureau), b.session(t, b.tiers), nil)
	nl, err := b.s.FilsNonLus(b.tiers)
	if err != nil {
		t.Fatal(err)
	}
	if !nl[b.filBureau] {
		t.Error("une lecture a ete enregistree sur un fil que le visiteur ne voit pas")
	}
}

func TestAccueilSansLesFilsDuSalonPrive(t *testing.T) {
	b := bancSalonsPrives(t)
	for nom, jeton := range map[string]string{"visiteur": "", "bob": b.session(t, b.tiers)} {
		corps := demande(t, b.srv, "GET", "/", jeton, nil).Body.String()
		if strings.Contains(corps, "Sujet du bureau") {
			t.Errorf("%s : fil du salon prive a l'accueil", nom)
		}
		if !strings.Contains(corps, "Sujet de la place") {
			t.Errorf("%s : le fil public du salon ouvert a disparu", nom)
		}
	}
	if corps := demande(t, b.srv, "GET", "/", b.session(t, b.invite), nil).Body.String(); !strings.Contains(corps, "Sujet du bureau") {
		t.Error("la conviee ne voit pas le fil de son salon a l'accueil")
	}
}

func TestCarteDuHallSansSalonPrive(t *testing.T) {
	// La carte est la meme pour tous : meme la conviee n'y voit pas le bureau.
	b := bancSalonsPrives(t)
	for _, jeton := range []string{"", b.session(t, b.invite)} {
		corps := demande(t, b.srv, "GET", "/micro", jeton, nil).Body.String()
		if strings.Contains(corps, "Sujet du bureau") {
			t.Error("fil d'un salon prive sur la carte du Hall")
		}
		if !strings.Contains(corps, "Sujet de la place") {
			t.Error("la carte a perdu le fil public du salon ouvert")
		}
	}
}

func TestReponseWebDansUnSalonPriveIntrouvable(t *testing.T) {
	b := bancSalonsPrives(t)
	jBob := b.session(t, b.tiers)
	csrf := csrfDe(t, b.srv, "/nouveau", jBob)
	w := demande(t, b.srv, "POST", "/t/"+itoa(b.filBureau)+"/reply", jBob,
		url.Values{"csrf": {csrf}, "body": {"entree"}})
	if w.Code != http.StatusNotFound {
		t.Errorf("reponse d'un non-convie : %d, attendu 404", w.Code)
	}
	if posts, _ := b.s.PostsOf(b.filBureau); len(posts) != 1 {
		t.Errorf("%d messages : la reponse a ete ecrite", len(posts))
	}
}

func TestGestesSurUnFilDeSalonPriveIntrouvables(t *testing.T) {
	b := bancSalonsPrives(t)
	jBob := b.session(t, b.tiers)
	csrf := csrfDe(t, b.srv, "/nouveau", jBob)
	base := "/t/" + itoa(b.filBureau)
	if w := demande(t, b.srv, "GET", base+"/qr", jBob, nil); w.Code != http.StatusNotFound {
		t.Errorf("qr : %d", w.Code)
	}
	if w := demande(t, b.srv, "POST", base+"/visibilite", jBob, url.Values{"csrf": {csrf}}); w.Code != http.StatusNotFound {
		t.Errorf("visibilite : %d", w.Code)
	}
	if w := demande(t, b.srv, "POST", base+"/mastodon", jBob, url.Values{"csrf": {csrf}}); w.Code != http.StatusNotFound {
		t.Errorf("republication : %d", w.Code)
	}
	if w := demande(t, b.srv, "POST", "/media/archive/"+itoa(b.filBureau), jBob, url.Values{"csrf": {csrf}}); w.Code != http.StatusNotFound {
		t.Errorf("archivage : %d", w.Code)
	}
}

func TestEditionDUnMessageDeSalonQuitteIntrouvable(t *testing.T) {
	// Alice a ecrit dans le bureau, puis en a ete retiree : son message ne
	// s'ouvre plus pour elle.
	b := bancSalonsPrives(t)
	post, err := b.s.Reply(b.filBureau, b.invite, "mot d'alice", store.VisLocal)
	if err != nil {
		t.Fatal(err)
	}
	jAlice := b.session(t, b.invite)
	if w := demande(t, b.srv, "GET", cheminEdit(post), jAlice, nil); w.Code != http.StatusOK {
		t.Fatalf("avant retrait : %d", w.Code)
	}
	if err := b.s.RetireMembre(b.bureau, b.invite); err != nil {
		t.Fatal(err)
	}
	if w := demande(t, b.srv, "GET", cheminEdit(post), jAlice, nil); w.Code != http.StatusNotFound {
		t.Errorf("apres retrait : %d, attendu 404", w.Code)
	}
}

func TestArticleNeRecopiePasLeTitreDUnDossierCache(t *testing.T) {
	b := bancSalonsPrives(t)
	corps := demande(t, b.srv, "GET", "/article/nouveau?t="+itoa(b.filBureau), b.session(t, b.tiers), nil).Body.String()
	if strings.Contains(corps, "Sujet du bureau") {
		t.Error("le titre d'un fil cache est recopie dans le composeur")
	}
	corps = demande(t, b.srv, "GET", "/article/nouveau?t="+itoa(b.filBureau), b.session(t, b.invite), nil).Body.String()
	if !strings.Contains(corps, "Sujet du bureau") {
		t.Error("la conviee doit retrouver le titre de son dossier")
	}
}

// ── Compteurs, pieces, notifications ───────────────────────────────────────

func TestCompteurDeNonLusSansSalonCache(t *testing.T) {
	b := bancSalonsPrives(t)
	m := b.srv.masquePour(b.tiers, false)
	nl, err := b.s.FilsNonLusHors(b.tiers, m.caches)
	if err != nil {
		t.Fatal(err)
	}
	if nl[b.filBureau] || nl[b.noteBureau] {
		t.Error("un fil cache compte dans les non-lus")
	}
	if !nl[b.filPlace] {
		t.Error("le fil du salon ouvert doit compter")
	}
}

func TestPastillesDeNonLusSansSalonCache(t *testing.T) {
	b := bancSalonsPrives(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: cookieSession, Value: b.session(t, b.tiers)})
	p, _ := b.srv.base(r, "forums")
	b.srv.poseNonLus(&p)
	if p.FilsNonLus[b.filBureau] || p.FilsNonLus[b.noteBureau] {
		t.Error("un fil cache est marque non lu")
	}
	if _, ok := p.FilsNonLusSalon[b.bureau]; ok {
		t.Error("le salon cache porte une pastille")
	}
	if p.TotalFilsNonLus != 2 {
		t.Errorf("total = %d, attendu 2 (les deux fils de la place)", p.TotalFilsNonLus)
	}
}

func TestPieceCiteeDansUnSalonPriveResteReservee(t *testing.T) {
	b := bancSalonsPrives(t)
	f, err := b.s.DeposeFichier(b.invite, "plan.png", "image/png", strings.NewReader("\x89PNG\r\n\x1a\nplan"))
	if err != nil {
		t.Fatal(err)
	}
	jAlice := b.session(t, b.invite)
	csrf := csrfDe(t, b.srv, "/nouveau", jAlice)
	w := demande(t, b.srv, "POST", "/t/"+itoa(b.filBureau)+"/reply", jAlice, url.Values{
		"csrf": {csrf}, "visibility": {"public"}, "body": {"voir /f/" + itoa(f.ID) + ".png"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("reponse de la conviee : %d", w.Code)
	}
	b.srv.backfillPiecesPubliques()
	if g, err := b.s.Fichier(f.ID); err != nil || g.Visibility == "public" {
		t.Errorf("une piece citee dans un salon prive est devenue publique (%v)", err)
	}
	// Dans le salon ouvert, la regle #1114 tient toujours.
	g, _ := b.s.DeposeFichier(b.invite, "carte.png", "image/png", strings.NewReader("\x89PNG\r\n\x1a\ncarte"))
	demande(t, b.srv, "POST", "/t/"+itoa(b.filPlace)+"/reply", jAlice, url.Values{
		"csrf": {csrf}, "visibility": {"public"}, "body": {"voir /f/" + itoa(g.ID) + ".png"}})
	if h, _ := b.s.Fichier(g.ID); h.Visibility != "public" {
		t.Error("une piece citee publiquement dans un salon ouvert doit devenir publique")
	}
}

func TestNotificationSeulementAQuiVoitLeSalon(t *testing.T) {
	b := bancSalonsPrives(t)
	if _, err := b.s.Reply(b.filBureau, b.invite, "present", store.VisLocal); err != nil {
		t.Fatal(err)
	}
	ids := func() map[int64]bool {
		out := map[int64]bool{}
		for _, u := range b.srv.destinatairesReponse(b.filBureau, b.sysop) {
			out[u.ID] = true
		}
		return out
	}
	if !ids()[b.invite] {
		t.Fatal("la conviee qui a participe doit etre prevenue")
	}
	if err := b.s.RetireMembre(b.bureau, b.invite); err != nil {
		t.Fatal(err)
	}
	if ids()[b.invite] {
		t.Error("une participante retiree du salon est encore prevenue")
	}
}

// ── API d'administration ───────────────────────────────────────────────────

func TestListeCompleteDesFilsReserveeAuxAdministrateurs(t *testing.T) {
	b := bancSalonsPrives(t)
	// Un jeton de membre est valide pour la board, pas pour cette liste.
	b.srv.verif = verifFixe("bob", "users")
	w := api(b.srv, "GET", "/api/v1/bbs/threads", jetonHS256Sub("le-secret-partage", "bob", "member", time.Hour), "")
	if w.Code == http.StatusOK || strings.Contains(w.Body.String(), "Sujet du bureau") {
		t.Errorf("liste complete rendue a un membre : %d", w.Code)
	}
	b.srv.verif = nil
	w, _ = appelSysop(t, b.srv, "GET", "/api/v1/bbs/threads", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Sujet du bureau") {
		t.Errorf("l'administrateur doit tout voir : %d", w.Code)
	}
}
