// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package diffusion

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/store"
)

const t0 = int64(1_800_000_000)

func base(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func sujet(t *testing.T, st *store.Store, id, titre string, sources int64, maj int64, importance float64) {
	t.Helper()
	if err := st.CreerSujet(store.Topic{ID: id, Title: titre, Summary: "Résumé de " + titre, Lang: "fr", CreatedAt: maj, UpdatedAt: maj, SourcesCount: sources, Importance: importance, Confidence: 0.8}); err != nil {
		t.Fatal(err)
	}
}

type faux struct {
	charges []Charge
	err     error
}

func (f *faux) post(_ context.Context, c Charge) (Reponse, error) {
	if f.err != nil {
		return Reponse{}, f.err
	}
	f.charges = append(f.charges, c)
	return Reponse{ID: "BIL" + string(rune('A'+len(f.charges))), Slug: "slug-" + c.Titre}, nil
}

func diffuseur(st *store.Store, f *faux) *Diffuseur {
	return &Diffuseur{st: st, cfg: Config{TTL: 5 * time.Minute, MaxParHeure: 6, MinSources: 2, Fenetre: 10 * time.Minute, Cooldown: time.Hour, SiteURL: "https://metanews.exemple.org"},
		poster: f.post, jr: log.New(io.Discard, "", 0)}
}

func TestUnSujetMultiSourcesRecentEstPublieAvecSaDuree(t *testing.T) {
	st, f := base(t), &faux{}
	sujet(t, st, "T1", "Un événement", 3, t0-60, 0.9)
	n, err := diffuseur(st, f).Tour(t0)
	if err != nil || n != 1 || len(f.charges) != 1 {
		t.Fatalf("n=%d err=%v charges=%d", n, err, len(f.charges))
	}
	c := f.charges[0]
	if c.TTLs != 300 || !strings.Contains(c.Body, "**Un événement**") || !strings.Contains(c.Body, "3 sources") || c.RefURL != "https://metanews.exemple.org/#T1" {
		t.Fatalf("charge : %+v", c)
	}
}

func TestUnSujetAUneSeuleSourceOuTropAncienNEstPasPublie(t *testing.T) {
	st, f := base(t), &faux{}
	sujet(t, st, "T1", "Mono-source", 1, t0-60, 0.9)
	sujet(t, st, "T2", "Ancien", 5, t0-3600, 0.9)
	if n, _ := diffuseur(st, f).Tour(t0); n != 0 || len(f.charges) != 0 {
		t.Fatalf("rien à publier : %d %v", n, f.charges)
	}
}

func TestUnSujetDejaPublieAttendLeDelaiDeGrace(t *testing.T) {
	st, f := base(t), &faux{}
	sujet(t, st, "T1", "Un événement", 3, t0-60, 0.9)
	d := diffuseur(st, f)
	d.Tour(t0)
	if n, _ := d.Tour(t0 + 300); n != 0 {
		t.Fatalf("même sujet republié %d fois dans l'heure", n)
	}
	if err := st.MajSujet(store.Topic{ID: "T1", Title: "Un événement", Summary: "r", Lang: "fr", UpdatedAt: t0 + 3700, SourcesCount: 4, Importance: 0.9}); err != nil {
		t.Fatal(err)
	}
	if n, _ := d.Tour(t0 + 3700); n != 1 {
		t.Fatalf("après le délai de grâce, un sujet mis à jour peut reparaître : %d", n)
	}
}

func TestPlafondHoraire(t *testing.T) {
	st, f := base(t), &faux{}
	for i := 0; i < 9; i++ {
		sujet(t, st, "T"+string(rune('1'+i)), "Sujet "+string(rune('A'+i)), 3, t0-60, 0.5)
	}
	d := diffuseur(st, f)
	if n, _ := d.Tour(t0); n != 6 {
		t.Fatalf("plafond de 6 par heure : %d", n)
	}
	if n, _ := d.Tour(t0 + 600); n != 0 {
		t.Fatalf("le plafond tient sur l'heure glissante : %d", n)
	}
	// Une heure plus tard le plafond est libéré, mais l'actualité ancienne n'est PAS rejouée : seul un sujet mis à jour dans la fenêtre repart.
	if n, _ := d.Tour(t0 + 3700); n != 0 {
		t.Fatalf("un sujet resté sans mise à jour n'est pas republié : %d", n)
	}
	if err := st.MajSujet(store.Topic{ID: "T1", Title: "Sujet A", Summary: "r", Lang: "fr", UpdatedAt: t0 + 3650, SourcesCount: 4, Importance: 0.5}); err != nil {
		t.Fatal(err)
	}
	if n, _ := d.Tour(t0 + 3700); n != 1 {
		t.Fatalf("un sujet mis à jour après le délai de grâce repart : %d", n)
	}
}

func TestLesPlusImportantsPassentD_abord(t *testing.T) {
	st, f := base(t), &faux{}
	sujet(t, st, "A", "Mineur", 2, t0-60, 0.1)
	sujet(t, st, "B", "Majeur", 2, t0-60, 0.9)
	d := diffuseur(st, f)
	d.cfg.MaxParHeure = 1
	d.Tour(t0)
	if len(f.charges) != 1 || !strings.Contains(f.charges[0].Body, "Majeur") {
		t.Fatalf("le plus important d'abord : %+v", f.charges)
	}
}

func TestUneErreurDeBilletsNeMarquePasLeSujetEtArreteLeTour(t *testing.T) {
	st, f := base(t), &faux{err: errors.New("billets injoignable")}
	sujet(t, st, "T1", "Un événement", 3, t0-60, 0.9)
	sujet(t, st, "T2", "Un autre", 3, t0-60, 0.8)
	d := diffuseur(st, f)
	if n, err := d.Tour(t0); n != 0 || err == nil {
		t.Fatalf("n=%d err=%v", n, err)
	}
	f.err = nil
	if n, _ := d.Tour(t0 + 60); n != 2 {
		t.Fatalf("au retour de billets, les deux sujets partent : %d", n)
	}
}

func TestCorpsEchappeLeMarkdownDesTitresEtRestePropre(t *testing.T) {
	c := Corps(store.Topic{ID: "X", Title: "Titre **gras** [lien](http://x) <b>", Summary: "Résumé", SourcesCount: 2}, "")
	nu := strings.ReplaceAll(strings.ReplaceAll(c, `\[`, ""), `\]`, "")      // les crochets ÉCHAPPÉS sont inertes
	if strings.Contains(c, "**gras**") || strings.Contains(nu, "[lien]") || strings.Contains(c, "<b>") {
		t.Fatalf("le titre ne doit pas injecter de markdown ni de HTML : %q", c)
	}
	if strings.Contains(nu, "](") || strings.Contains(c, "https://") {
		t.Fatalf("sans SiteURL, pas de lien : %q", c)
	}
}

func TestLeClientParleSurLaSocketAvecUnJetonDeService(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "b.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var auth, chemin string
	var corps map[string]any
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, chemin = r.Header.Get("Authorization"), r.URL.Path
		json.NewDecoder(r.Body).Decode(&corps)
		w.WriteHeader(201)
		w.Write([]byte(`{"id":"B1","slug":"s-1","expires_at":"2026-07-11T12:05:00Z"}`))
	})}
	go srv.Serve(ln)
	defer srv.Close()
	rep, err := ClientSocket(sock, "secret-de-test")(context.Background(), Charge{Body: "x", RefURL: "https://a.b/c", TTLs: 300})
	if err != nil || rep.ID != "B1" || rep.Slug != "s-1" {
		t.Fatalf("rep=%+v err=%v", rep, err)
	}
	if chemin != "/service/ephemere" || !strings.HasPrefix(auth, "Bearer ") || corps["ttl_s"].(float64) != 300 {
		t.Fatalf("chemin=%q auth=%q corps=%v", chemin, auth, corps)
	}
	if strings.Count(auth, ".") != 2 {
		t.Fatalf("un JWT à trois segments : %q", auth)
	}
}

func TestLeClientRefuseUnSecretVide(t *testing.T) {
	_, err := ClientSocket("/nulle/part.sock", "")(context.Background(), Charge{Body: "x", TTLs: 300})
	if err == nil || !strings.Contains(err.Error(), "secret") {
		t.Fatalf("jamais de jeton signé avec un secret vide : %v", err)
	}
}

func TestLeClientRemonteLeRefusDeBillets(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "b.sock")
	ln, _ := net.Listen("unix", sock)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "plafond", 429) })}
	go srv.Serve(ln)
	defer srv.Close()
	if _, err := ClientSocket(sock, "s")(context.Background(), Charge{Body: "x", TTLs: 300}); err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("le refus remonte : %v", err)
	}
}
