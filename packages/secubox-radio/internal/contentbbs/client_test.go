package contentbbs

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// serveur demarre un httptest.Server et rend un Client qui lui parle — SANS
// socket unix : le contrat HTTP/JSON est le meme, et un test qui exigerait une
// vraie socket ne testerait que l'environnement, pas le client.
func serveur(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &Client{
		Base:   srv.URL,
		HTTP:   &http.Client{Timeout: 5 * time.Second},
		Secret: "secret-de-test",
		Sub:    "radio",
	}
}

// dejeton decoupe un JWT Bearer et rend ses claims — sert a verifier que le
// jeton envoye est bien signe pour cette requete, pas seulement present.
func dejeton(t *testing.T, autorisation string) map[string]any {
	t.Helper()
	if !strings.HasPrefix(autorisation, "Bearer ") {
		t.Fatalf("en-tete Authorization mal forme : %q", autorisation)
	}
	tok := strings.TrimPrefix(autorisation, "Bearer ")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("jeton mal forme (%d parties) : %q", len(parts), tok)
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("charge utile illisible : %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(pb, &claims); err != nil {
		t.Fatalf("claims illisibles : %v", err)
	}
	return claims
}

// ── Creer ────────────────────────────────────────────────────────────────

func TestCreerPosteLeBonJSONEtLeJeton(t *testing.T) {
	var chemin, methode string
	var corps struct {
		Type       string `json:"type"`
		Title      string `json:"title"`
		Metadata   json.RawMessage
		Provenance []struct {
			SourceURL  string `json:"source_url"`
			SourceType string `json:"source_type"`
			Original   bool   `json:"original"`
		} `json:"provenance"`
	}
	var autorisation string
	c := serveur(t, func(w http.ResponseWriter, r *http.Request) {
		chemin, methode = r.URL.Path, r.Method
		autorisation = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&corps)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": "cnt_abc123"})
	})

	id, err := c.Creer(Objet{Type: "radio_piste", Title: "Iyah May"},
		[]Prov{{SourceURL: "https://youtu.be/MlqCLBNVzvg", SourceType: "youtube", Original: true}})
	if err != nil {
		t.Fatalf("Creer : %v", err)
	}
	if id != "cnt_abc123" {
		t.Errorf("id = %q, attendu cnt_abc123", id)
	}
	if methode != http.MethodPost || chemin != "/api/v1/bbs/content" {
		t.Errorf("%s %s — route attendue POST /api/v1/bbs/content", methode, chemin)
	}
	if corps.Type != "radio_piste" || corps.Title != "Iyah May" {
		t.Errorf("corps mal transmis : %+v", corps)
	}
	if len(corps.Provenance) != 1 || !corps.Provenance[0].Original ||
		corps.Provenance[0].SourceURL != "https://youtu.be/MlqCLBNVzvg" {
		t.Errorf("provenance mal transmise : %+v", corps.Provenance)
	}
	claims := dejeton(t, autorisation)
	if claims["sub"] != "radio" {
		t.Errorf("sub = %v, attendu radio", claims["sub"])
	}
	if _, ok := claims["exp"]; !ok {
		t.Error("exp absent du jeton : un jeton sans expiration ne devrait jamais etre signe")
	}
}

func TestCreerRemonteLeRefusDuBBS(t *testing.T) {
	c := serveur(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "au moins une provenance is_original=1 est requise"})
	})
	if _, err := c.Creer(Objet{Type: "radio_piste", Title: "X"}, nil); err == nil {
		t.Fatal("un refus du BBS a ete accepte sans erreur")
	}
}

// ── Representation ──────────────────────────────────────────────────────

func TestRepresentationPosteLeBonJSON(t *testing.T) {
	var chemin string
	var corps struct {
		Kind    string `json:"kind"`
		Module  string `json:"module"`
		Ref     string `json:"ref"`
		IsCache bool   `json:"is_cache"`
	}
	c := serveur(t, func(w http.ResponseWriter, r *http.Request) {
		chemin = r.URL.Path
		json.NewDecoder(r.Body).Decode(&corps)
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	if err := c.Representation("cnt_abc123", "radio", "secubox-radio", "piste-42", true); err != nil {
		t.Fatalf("Representation : %v", err)
	}
	if chemin != "/api/v1/bbs/content/cnt_abc123/representation" {
		t.Errorf("chemin = %q", chemin)
	}
	if corps.Kind != "radio" || corps.Module != "secubox-radio" || corps.Ref != "piste-42" || !corps.IsCache {
		t.Errorf("corps mal transmis : %+v", corps)
	}
}

// ── Event ────────────────────────────────────────────────────────────────

func TestEventPosteLeBonJSON(t *testing.T) {
	var chemin string
	var corps struct {
		Kind    string          `json:"kind"`
		Actor   string          `json:"actor"`
		Payload json.RawMessage `json:"payload"`
	}
	c := serveur(t, func(w http.ResponseWriter, r *http.Request) {
		chemin = r.URL.Path
		json.NewDecoder(r.Body).Decode(&corps)
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	if err := c.Event("cnt_abc123", "valide", "sysop", `{"raison":"ok"}`); err != nil {
		t.Fatalf("Event : %v", err)
	}
	if chemin != "/api/v1/bbs/content/cnt_abc123/event" {
		t.Errorf("chemin = %q", chemin)
	}
	if corps.Kind != "valide" || corps.Actor != "sysop" || string(corps.Payload) != `{"raison":"ok"}` {
		t.Errorf("corps mal transmis : %+v", corps)
	}
}

// ── Topic ────────────────────────────────────────────────────────────────

func TestTopicRendLIdentifiantDuFil(t *testing.T) {
	var chemin, methode string
	c := serveur(t, func(w http.ResponseWriter, r *http.Request) {
		chemin, methode = r.URL.Path, r.Method
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "bbs_topic_id": 77})
	})
	topicID, err := c.Topic("cnt_abc123")
	if err != nil {
		t.Fatalf("Topic : %v", err)
	}
	if topicID != 77 {
		t.Errorf("bbs_topic_id = %d, attendu 77", topicID)
	}
	if methode != http.MethodPost || chemin != "/api/v1/bbs/content/cnt_abc123/topic" {
		t.Errorf("%s %s", methode, chemin)
	}
}

// ── Timeline ─────────────────────────────────────────────────────────────

func TestTimelinePosteLeCommentaire(t *testing.T) {
	var corps struct {
		AuthorID int64  `json:"author_id"`
		Author   string `json:"author"`
		OffsetMS int64  `json:"offset_ms"`
		Body     string `json:"body"`
	}
	c := serveur(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&corps)
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": 5})
	})
	if err := c.Timeline("cnt_abc123", 12, "gandalf", 3410, "belle intro"); err != nil {
		t.Fatalf("Timeline : %v", err)
	}
	if corps.AuthorID != 12 || corps.Author != "gandalf" || corps.OffsetMS != 3410 || corps.Body != "belle intro" {
		t.Errorf("corps mal transmis : %+v", corps)
	}
}

// LA GATE D'IDENTITE DOIT REMONTER : un author_id<=0 est un 400 cote BBS, pas
// une acceptation silencieuse — sinon le client croirait le commentaire
// persiste alors qu'il a ete rejete (constraints.md, gate d'identite).
func TestTimelineRemonteLeRefusAnonyme(t *testing.T) {
	c := serveur(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "erreur": "anonyme non persisté"})
	})
	err := c.Timeline("cnt_abc123", 0, "anonyme", 0, "coucou")
	if err == nil {
		t.Fatal("author_id<=0 a ete accepte sans erreur")
	}
}

// ── TimelineDe ───────────────────────────────────────────────────────────

func TestTimelineDeListeLesCommentaires(t *testing.T) {
	var chemin, methode string
	c := serveur(t, func(w http.ResponseWriter, r *http.Request) {
		chemin, methode = r.URL.Path, r.Method
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "comments": []map[string]any{
			{"id": 1, "author": "gandalf", "author_id": 12, "offset_ms": 1000, "body": "un"},
			{"id": 2, "author": "gandalf", "author_id": 12, "offset_ms": 2000, "body": "deux"},
		}})
	})
	comments, err := c.TimelineDe("cnt_abc123")
	if err != nil {
		t.Fatalf("TimelineDe : %v", err)
	}
	if methode != http.MethodGet || chemin != "/api/v1/bbs/content/cnt_abc123/timeline" {
		t.Errorf("%s %s", methode, chemin)
	}
	if len(comments) != 2 || comments[0].Body != "un" || comments[1].OffsetMS != 2000 {
		t.Errorf("commentaires mal lus : %+v", comments)
	}
}

// ── Le secret ne se contourne pas ───────────────────────────────────────

// UN SECRET VIDE NE DOIT PAS SIGNER UN JETON QUI PASSERAIT — sans quoi un
// deploiement qui oublie de poser api.jwt_secret parlerait quand meme au BBS,
// avec un jeton que n'importe qui pourrait rejouer.
func TestUnSecretVideNeSigneRienDeCredible(t *testing.T) {
	c := &Client{Base: "http://exemple.invalide", HTTP: &http.Client{}, Secret: "", Sub: "radio"}
	if _, err := c.Creer(Objet{Type: "x", Title: "y"}, []Prov{{Original: true}}); err == nil {
		t.Fatal("un client sans secret a signe un appel sans erreur")
	}
}
