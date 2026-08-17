package ytsas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// La charge utile est celle que la passerelle a reellement rendue sur gk2 le
// jour ou la file s'est bloquee : une piste refusee par YouTube, une piste
// complete. Un echantillon invente aurait valide le code contre lui-meme.
const listeReelle = `[
 {"id":"MlqCLBNVzvg","url":"https://www.youtube.com/watch?v=MlqCLBNVzvg",
  "title":"Iyah May","path":"/data/ytsas/MlqCLBNVzvg","complete":0,"progress":0.0,
  "job_status":"error","job_error":"ERROR: unable to download video data: HTTP Error 403: Forbidden"},
 {"id":"7I_E0qyw7sc","url":"https://www.youtube.com/watch?v=7I_E0qyw7sc",
  "title":"La Pression","path":"/data/ytsas/7I_E0qyw7sc/7I_E0qyw7sc.mp4","complete":1,
  "progress":100.0,"job_status":"complete","job_error":null}
]`

func clientDeTest(t *testing.T, corps string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(corps))
	}))
	t.Cleanup(srv.Close)
	return &Client{Base: srv.URL, HTTP: &http.Client{Timeout: 5 * time.Second}}
}

func TestPisteRefuseeEstUnEchecPasUneAttente(t *testing.T) {
	c := clientDeTest(t, listeReelle)
	e, err := c.Etat(context.Background(), "MlqCLBNVzvg")
	if err != nil {
		t.Fatalf("etat : %v", err)
	}
	if e.Pret() {
		t.Fatal("une piste en erreur ne peut pas etre prete")
	}
	if !e.Echoue() {
		t.Fatal("piste en erreur non reconnue : la file se bloquera derriere elle")
	}
	if e.Erreur == "" {
		t.Fatal("raison perdue : le panneau affichera une piste ecartee sans explication")
	}
}

func TestPisteCompleteResteUtilisable(t *testing.T) {
	c := clientDeTest(t, listeReelle)
	e, err := c.Etat(context.Background(), "7I_E0qyw7sc")
	if err != nil {
		t.Fatalf("etat : %v", err)
	}
	if e.Echoue() {
		t.Fatal("une piste complete comptee comme echouee : elle serait ecartee a tort")
	}
	if !e.Pret() {
		t.Fatal("piste complete non prete")
	}
}
