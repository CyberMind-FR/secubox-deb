package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/contentbbs"
)

// ── /replay/{piste}/timeline (#1166 B5) ─────────────────────────────────────
//
// C'est ce que l'interface de reecoute interroge pour reafficher les
// commentaires de la timeline BBS au bon instant (offset_ms). Pur relais en
// LECTURE : la piste porte l'identifiant du ContentObject (pose a la
// validation, B2), le client contenu (B1) rend les commentaires deja
// persistes et ordonnes cote BBS — la radio ne fait que les transmettre.

func requeteReplay(s *Serveur, pisteID string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/api/v1/radio/replay/"+pisteID+"/timeline", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// UNE PISTE RATTACHEE AU SPINE REND LES COMMENTAIRES DANS L'ORDRE rendu par
// le client contenu (deja trie par offset_ms cote BBS, voir
// contentbbs.Client.TimelineDe).
func TestReplayTimelineRendLesCommentairesOrdonnes(t *testing.T) {
	s, st := banc(t)
	attendus := []contentbbs.Comment{
		{ID: 1, Author: "alice", AuthorID: 2, OffsetMS: 1000, Body: "salut"},
		{ID: 2, Author: "bob", AuthorID: 3, OffsetMS: 64000, Body: "belle intro"},
	}
	fake := &contenuBouchon{timelineDeSortie: attendus}
	s.Contenu = fake
	p, _, err := st.Ajoute("https://youtu.be/ABC", "Titre", 1, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.FixerContenu(p.ID, "cnt-7"); err != nil {
		t.Fatal(err)
	}

	w := requeteReplay(s, "1")
	if w.Code != http.StatusOK {
		t.Fatalf("replay refuse : %d %s", w.Code, w.Body)
	}
	if !fake.timelineDeAppele || fake.timelineDeID != "cnt-7" {
		t.Errorf("TimelineDe pas appele avec le bon id : appele=%v id=%q",
			fake.timelineDeAppele, fake.timelineDeID)
	}
	var out struct {
		Comments []contentbbs.Comment `json:"comments"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Comments) != 2 {
		t.Fatalf("attendu 2 commentaires, recu %d", len(out.Comments))
	}
	if out.Comments[0].OffsetMS != 1000 || out.Comments[1].OffsetMS != 64000 {
		t.Errorf("ordre non preserve : %+v", out.Comments)
	}
	if out.Comments[0].Body != "salut" || out.Comments[1].Body != "belle intro" {
		t.Errorf("corps inattendus : %+v", out.Comments)
	}
}

// UNE PISTE SANS CONTENT_ID (jamais validee cote spine, ou BBS injoignable a
// la validation) N'A RIEN A REJOUER : 404, sans jamais appeler le client
// contenu.
func TestReplayTimelineSansContentIDRend404(t *testing.T) {
	s, st := banc(t)
	fake := &contenuBouchon{}
	s.Contenu = fake
	p, _, err := st.Ajoute("https://youtu.be/XYZ", "Titre", 1, t0)
	if err != nil {
		t.Fatal(err)
	}
	// Volontairement pas de FixerContenu : ContentID reste vide.

	w := requeteReplay(s, strconv.FormatInt(p.ID, 10))
	if w.Code != http.StatusNotFound {
		t.Fatalf("attendu 404, recu %d %s", w.Code, w.Body)
	}
	if fake.timelineDeAppele {
		t.Error("TimelineDe appele alors que la piste n'a pas de content_id")
	}
}

// UN CLIENT CONTENU EN ERREUR (BBS injoignable) EST UN 502, PAS UN CRASH —
// meme philosophie non-bloquante que diffuseBroadcast/diffuseChat, mais ici
// il y a bien un appelant a informer : c'est le proxy lui-meme qui echoue.
func TestReplayTimelineErreurClientRend502(t *testing.T) {
	s, st := banc(t)
	fake := &contenuBouchon{timelineDeErr: http.ErrHandlerTimeout}
	s.Contenu = fake
	p, _, err := st.Ajoute("https://youtu.be/QRS", "Titre", 1, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.FixerContenu(p.ID, "cnt-9"); err != nil {
		t.Fatal(err)
	}

	w := requeteReplay(s, "1")
	if w.Code != http.StatusBadGateway {
		t.Fatalf("attendu 502, recu %d %s", w.Code, w.Body)
	}
}
