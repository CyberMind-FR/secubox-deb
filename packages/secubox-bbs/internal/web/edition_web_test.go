package web

import (
	"net/url"
	"strconv"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// #1091 — la page d'edition : l'auteur edite le sien, le sysop corrige les
// autres, un tiers reçoit 404 (jamais 403 : ne pas confirmer l'existence).

func cheminEdit(post int64) string { return "/p/" + strconv.FormatInt(post, 10) + "/edit" }

func corpsWeb(t *testing.T, s *store.Store, fil, post int64) string {
	t.Helper()
	ps, _ := s.PostsOf(fil)
	for _, p := range ps {
		if p.ID == post {
			b, _ := s.Body(p)
			return b
		}
	}
	t.Fatalf("post %d introuvable", post)
	return ""
}

func TestEditionPageDroitsAuteurSysopTiers(t *testing.T) {
	srv, s := banc(t)
	gk2, _ := peuple(t, s) // sysop
	alice, _ := s.CreateUser("alice", "Alice", store.RoleMember)
	bob, _ := s.CreateUser("bob", "Bob", store.RoleMember)
	jAlice, _ := s.NewSession(alice, "", "")
	jBob, _ := s.NewSession(bob, "", "")
	jGk2, _ := s.NewSession(gk2, "", "")

	cat, _ := s.CreateCategory("place", "Place", "")
	fil, _ := s.NewThread(cat, alice, "Sujet", "texte d'alice", store.VisPublic)
	post := corpsWebPremier(t, s, fil)

	// Un tiers ne peut ni ouvrir le formulaire ni poster : 404 dans les deux cas.
	if w := demande(t, srv, "GET", cheminEdit(post), jBob, nil); w.Code != 404 {
		t.Fatalf("bob GET edit = %d, veut 404", w.Code)
	}
	if w := demande(t, srv, "POST", cheminEdit(post), jBob,
		url.Values{"body": {"detournement"}}); w.Code != 404 {
		t.Fatalf("bob POST edit = %d, veut 404", w.Code)
	}
	if got := corpsWeb(t, s, fil, post); got != "texte d'alice" {
		t.Fatalf("le corps a bouge sous un tiers : %q", got)
	}

	// L'auteure édite le sien.
	csrf := csrfDe(t, srv, cheminEdit(post), jAlice)
	if w := demande(t, srv, "POST", cheminEdit(post), jAlice,
		url.Values{"csrf": {csrf}, "body": {"texte corrigé par alice"}}); w.Code != 303 {
		t.Fatalf("alice POST edit = %d, veut 303", w.Code)
	}
	if got := corpsWeb(t, s, fil, post); got != "texte corrigé par alice" {
		t.Fatalf("corps apres edition auteur = %q", got)
	}

	// Le sysop corrige le message d'un autre.
	csrf2 := csrfDe(t, srv, cheminEdit(post), jGk2)
	if w := demande(t, srv, "POST", cheminEdit(post), jGk2,
		url.Values{"csrf": {csrf2}, "body": {"corrigé par le sysop"}}); w.Code != 303 {
		t.Fatalf("sysop POST edit = %d, veut 303", w.Code)
	}
	if got := corpsWeb(t, s, fil, post); got != "corrigé par le sysop" {
		t.Fatalf("corps apres correction sysop = %q", got)
	}
}

func corpsWebPremier(t *testing.T, s *store.Store, fil int64) int64 {
	t.Helper()
	ps, err := s.PostsOf(fil)
	if err != nil || len(ps) == 0 {
		t.Fatalf("aucun post: %v", err)
	}
	return ps[0].ID
}
