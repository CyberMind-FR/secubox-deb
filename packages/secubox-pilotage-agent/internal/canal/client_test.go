// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package canal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/notifs"
)

type source struct{ params map[string]any }

func (source) Nom() string                                    { return "test" }
func (s source) Lire(context.Context) (map[string]any, error) { return s.params, nil }
func (s source) Chemins() []string                            { return []string{"Device.Test."} }

// faux maître : sert les requêtes données une fois, enregistre ce qui est posté.
type fauxMaitre struct {
	mu       sync.Mutex
	requetes []string // corps JSON de GET /requetes, servis un par un
	reponses [][]byte
	notifs   [][]byte
	bonjour  [][]byte
	recu     chan struct{}
}

func (f *fauxMaitre) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/canal/v1/bonjour", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.bonjour = append(f.bonjour, b)
		f.mu.Unlock()
	})
	mux.HandleFunc("/canal/v1/requetes", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		var corps string
		if len(f.requetes) > 0 {
			corps, f.requetes = f.requetes[0], f.requetes[1:]
		}
		f.mu.Unlock()
		if corps == "" {
			time.Sleep(20 * time.Millisecond)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Write([]byte(corps))
	})
	mux.HandleFunc("/canal/v1/reponses", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reponses = append(f.reponses, b)
		f.mu.Unlock()
		f.signal()
	})
	mux.HandleFunc("/canal/v1/notifs", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.notifs = append(f.notifs, b)
		f.mu.Unlock()
		f.signal()
	})
	return mux
}

func (f *fauxMaitre) signal() {
	select {
	case f.recu <- struct{}{}:
	default:
	}
}

func demarrer(t *testing.T, f *fauxMaitre, m *modele.Modele, operer func(context.Context, string, map[string]any) (any, error), ev <-chan notifs.Evenement) (stop func()) {
	t.Helper()
	f.recu = make(chan struct{}, 8)
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	c := NouveauClient(Config{Maitre: strings.TrimPrefix(srv.URL, "http://"), Attente: time.Second}, m, operer)
	ctx, cancel := context.WithCancel(context.Background())
	fini := make(chan error, 1)
	go func() { fini <- c.Tourner(ctx, ev) }()
	return func() {
		cancel()
		select {
		case err := <-fini:
			if err != context.Canceled {
				t.Errorf("Tourner doit rendre context.Canceled, a rendu %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("Tourner ne rend pas la main à l'annulation")
		}
	}
}

func attendre(t *testing.T, f *fauxMaitre) {
	t.Helper()
	select {
	case <-f.recu:
	case <-time.After(3 * time.Second):
		t.Fatal("rien reçu du côté du maître")
	}
}

func decoder(t *testing.T, b []byte) []map[string]any {
	t.Helper()
	var l []map[string]any
	if err := json.Unmarshal(b, &l); err != nil {
		t.Fatalf("JSON invalide %q : %v", b, err)
	}
	return l
}

func modeleTest(params map[string]any) *modele.Modele {
	return modele.NouveauModele(source{params})
}

func TestClientRepondAUnGet(t *testing.T) {
	f := &fauxMaitre{requetes: []string{`[{"msg_id":"0123456789abcdef","type":"GET","body":{"paths":["Device.Test."]}}]`}}
	stop := demarrer(t, f, modeleTest(map[string]any{"Device.Test.a": 1}), nil, nil)
	defer stop()
	attendre(t, f)
	f.mu.Lock()
	defer f.mu.Unlock()
	l := decoder(t, f.reponses[0])
	if l[0]["msg_id"] != "0123456789abcdef" || l[0]["type"] != "GET_RESP" {
		t.Fatalf("réponse inattendue : %v", l[0])
	}
	if !strings.Contains(string(f.reponses[0]), `"Device.Test.a":1`) {
		t.Fatalf("valeur absente : %s", f.reponses[0])
	}
	if len(f.bonjour) != 1 {
		t.Fatalf("bonjour attendu une fois, reçu %d", len(f.bonjour))
	}
}

func TestClientRepondAuSupportedDM(t *testing.T) {
	f := &fauxMaitre{requetes: []string{`[{"msg_id":"0123456789abcdef","type":"GET_SUPPORTED_DM","body":{}}]`}}
	stop := demarrer(t, f, modeleTest(nil), nil, nil)
	defer stop()
	attendre(t, f)
	f.mu.Lock()
	defer f.mu.Unlock()
	l := decoder(t, f.reponses[0])
	if l[0]["type"] != "GET_SUPPORTED_DM_RESP" || !strings.Contains(string(f.reponses[0]), "Device.Test.") {
		t.Fatalf("réponse inattendue : %s", f.reponses[0])
	}
}

func TestClientRefuseUnOperateNonLecture(t *testing.T) {
	appels := 0
	operer := func(context.Context, string, map[string]any) (any, error) { appels++; return nil, nil }
	f := &fauxMaitre{requetes: []string{`[{"msg_id":"0123456789abcdef","type":"OPERATE","body":{"command":"Device.Reboot()","args":{}}}]`}}
	stop := demarrer(t, f, modeleTest(nil), operer, nil)
	defer stop()
	attendre(t, f)
	f.mu.Lock()
	defer f.mu.Unlock()
	l := decoder(t, f.reponses[0])
	body := l[0]["body"].(map[string]any)
	if l[0]["type"] != "ERROR" || body["err"] != "commande refusée (L1 : lecture seule)" || appels != 0 {
		t.Fatalf("refus attendu : %v (appels=%d)", l[0], appels)
	}
}

func TestClientOperateMesurer(t *testing.T) {
	var vu map[string]any
	operer := func(_ context.Context, cmd string, args map[string]any) (any, error) {
		vu = args
		return map[string]any{"ok": true}, nil
	}
	f := &fauxMaitre{requetes: []string{
		`[{"msg_id":"0123456789abcdef","type":"OPERATE","body":{"command":"Device.X_SECUBOX_Releve.Mesurer()","args":{"duree_s":60}}},` +
			`{"msg_id":"fedcba9876543210","type":"OPERATE","body":{"command":"Device.X_SECUBOX_Releve.Mesurer()","args":{"duree_s":"60; rm"}}}]`}}
	stop := demarrer(t, f, modeleTest(nil), operer, nil)
	defer stop()
	attendre(t, f)
	f.mu.Lock()
	defer f.mu.Unlock()
	l := decoder(t, f.reponses[0])
	if l[0]["type"] != "OPERATE_RESP" || vu["duree_s"] != 60 {
		t.Fatalf("OPERATE_RESP attendu avec duree_s=60 : %v %v", l[0], vu)
	}
	if l[1]["type"] != "ERROR" {
		t.Fatalf("argument non entier doit être refusé : %v", l[1])
	}
}

func TestClientValideLesRequetes(t *testing.T) {
	chemins := make([]string, 65)
	for i := range chemins {
		chemins[i] = "Device.Test."
	}
	trop, _ := json.Marshal(chemins)
	f := &fauxMaitre{requetes: []string{`[` +
		`{"msg_id":"ZZZ","type":"GET","body":{"paths":["Device."]}},` + // msg_id invalide : ignoré
		`{"msg_id":"0000000000000001","type":"PAGE","body":{}},` + // type inconnu
		`{"msg_id":"0000000000000002","type":"GET","body":{"paths":["/etc/passwd"]}},` + // chemin hors Device.
		`{"msg_id":"0000000000000003","type":"GET","body":{"paths":` + string(trop) + `}},` + // trop de chemins
		`{"msg_id":"0000000000000004","type":"GET","body":{"paths":["Device.Test."]}}]`}}
	stop := demarrer(t, f, modeleTest(map[string]any{"Device.Test.a": 1}), nil, nil)
	defer stop()
	attendre(t, f)
	f.mu.Lock()
	defer f.mu.Unlock()
	l := decoder(t, f.reponses[0])
	if len(l) != 4 {
		t.Fatalf("4 réponses attendues (msg_id invalide ignoré), reçu %d : %s", len(l), f.reponses[0])
	}
	for i, att := range []string{"ERROR", "ERROR", "ERROR", "GET_RESP"} {
		if l[i]["type"] != att {
			t.Fatalf("réponse %d : %v, attendu %s", i, l[i]["type"], att)
		}
	}
}

func TestClientIgnoreUnJSONMalForme(t *testing.T) {
	c := NouveauClient(Config{Maitre: "127.0.0.1"}, modeleTest(nil), nil)
	if r := c.traiter(context.Background(), []byte(`pas du json`)); len(r) != 0 {
		t.Fatalf("liste illisible : aucune réponse attendue, reçu %v", r)
	}
	r := c.traiter(context.Background(), []byte(`[42,{"msg_id":1},{"msg_id":"0123456789abcdef","type":"GET_SUPPORTED_DM","body":{}}]`))
	if len(r) != 1 || r[0].Type != "GET_SUPPORTED_DM_RESP" {
		t.Fatalf("seule la requête valable reçoit une réponse : %v", r)
	}
}

func TestClientBorneLeNombreDeRequetes(t *testing.T) {
	var l []string
	for i := 0; i < 40; i++ {
		l = append(l, fmt.Sprintf(`{"msg_id":"%016x","type":"GET_SUPPORTED_DM","body":{}}`, i))
	}
	c := NouveauClient(Config{Maitre: "127.0.0.1"}, modeleTest(nil), nil)
	if r := c.traiter(context.Background(), []byte("["+strings.Join(l, ",")+"]")); len(r) != 32 {
		t.Fatalf("32 réponses au plus, reçu %d", len(r))
	}
}

func TestClientRefuseUnCorpsTropGros(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("[" + strings.Repeat(" ", 300<<10) + "]"))
	}))
	defer srv.Close()
	c := NouveauClient(Config{Maitre: strings.TrimPrefix(srv.URL, "http://")}, modeleTest(nil), nil)
	if _, err := c.sonder(context.Background()); err == nil {
		t.Fatal("un corps de 300 Kio doit être refusé")
	}
}

func TestClientReculeQuandLeMaitreEstAbsent(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	adresse := strings.TrimPrefix(srv.URL, "http://")
	srv.Close() // connexion refusée
	c := NouveauClient(Config{Maitre: adresse, Attente: time.Second}, modeleTest(nil), nil)
	ctx, cancel := context.WithCancel(context.Background())
	var delais []time.Duration
	c.dormir = func(ctx context.Context, d time.Duration) error {
		delais = append(delais, d)
		if len(delais) == 8 {
			cancel()
		}
		return ctx.Err()
	}
	if err := c.Tourner(ctx, nil); err != context.Canceled {
		t.Fatalf("Tourner doit rendre context.Canceled : %v", err)
	}
	att := []time.Duration{5, 10, 20, 40, 80, 160, 300, 300}
	if len(delais) != len(att) {
		t.Fatalf("délais %v", delais)
	}
	for i := range att {
		if delais[i] != att[i]*time.Second {
			t.Fatalf("délai %d = %v, attendu %v (tous : %v)", i, delais[i], att[i]*time.Second, delais)
		}
	}
}

func TestClientReculRepartApresUnSucces(t *testing.T) {
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		k := n
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/bonjour") || k == 4 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	c := NouveauClient(Config{Maitre: strings.TrimPrefix(srv.URL, "http://"), Attente: time.Second}, modeleTest(nil), nil)
	ctx, cancel := context.WithCancel(context.Background())
	var delais []time.Duration
	c.dormir = func(ctx context.Context, d time.Duration) error {
		delais = append(delais, d)
		if len(delais) == 3 {
			cancel()
		}
		return ctx.Err()
	}
	c.Tourner(ctx, nil)
	// bonjour(1) ok, sondage(2) 502 → 5 s, sondage(3) 502 → 10 s, sondage(4) 204 ok, sondage(5) 502 → 5 s
	if len(delais) != 3 || delais[0] != 5*time.Second || delais[1] != 10*time.Second || delais[2] != 5*time.Second {
		t.Fatalf("délais %v", delais)
	}
}

func TestClientTronqueAuDelaDe256Kio(t *testing.T) {
	params := map[string]any{"Device.Test.nom": "x"}
	gros := strings.Repeat("v", 1000)
	for i := 1; i <= 600; i++ {
		params[fmt.Sprintf("Device.Test.Item.%d.Valeur", i)] = gros
	}
	f := &fauxMaitre{requetes: []string{`[{"msg_id":"0123456789abcdef","type":"GET","body":{"paths":["Device.Test."]}}]`}}
	stop := demarrer(t, f, modeleTest(params), nil, nil)
	defer stop()
	attendre(t, f)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reponses[0]) > 256<<10 {
		t.Fatalf("réponse de %d octets > 256 Kio", len(f.reponses[0]))
	}
	l := decoder(t, f.reponses[0])
	body := l[0]["body"].(map[string]any)
	if l[0]["type"] != "GET_RESP" || body["tronque"] != true {
		t.Fatalf("tronque:true attendu : %v", l[0]["type"])
	}
	s := string(f.reponses[0])
	if !strings.Contains(s, "Device.Test.Item.1.Valeur") || strings.Contains(s, "Device.Test.Item.600.Valeur") {
		t.Fatal("les indices les plus hauts doivent partir en premier")
	}
	if !strings.Contains(s, "Device.Test.nom") {
		t.Fatal("les paramètres hors liste doivent rester")
	}
}

func TestClientReponseTropVolumineuse(t *testing.T) {
	params := map[string]any{"Device.Test.enorme": strings.Repeat("v", 300<<10)}
	f := &fauxMaitre{requetes: []string{`[{"msg_id":"0123456789abcdef","type":"GET","body":{"paths":["Device.Test."]}}]`}}
	stop := demarrer(t, f, modeleTest(params), nil, nil)
	defer stop()
	attendre(t, f)
	f.mu.Lock()
	defer f.mu.Unlock()
	l := decoder(t, f.reponses[0])
	if l[0]["type"] != "ERROR" || !strings.Contains(string(f.reponses[0]), "réponse trop volumineuse") {
		t.Fatalf("ERROR attendue : %.200s", f.reponses[0])
	}
}

func TestClientEnvoieLesNotifications(t *testing.T) {
	ev := make(chan notifs.Evenement, 4)
	f := &fauxMaitre{}
	stop := demarrer(t, f, modeleTest(nil), nil, ev)
	defer stop()
	ev <- notifs.Evenement{Type: "X_SECUBOX_Boot", Instant: 42}
	ev <- notifs.Evenement{Type: "X_SECUBOX_MemoryLow", Valeur: 7, Instant: 43}
	attendre(t, f)
	f.mu.Lock()
	defer f.mu.Unlock()
	s := string(f.notifs[0])
	if !strings.Contains(s, `"type":"NOTIFY"`) || !strings.Contains(s, "X_SECUBOX_Boot") {
		t.Fatalf("NOTIFY attendu : %s", s)
	}
}

func TestClientNeSuitPasLesRedirections(t *testing.T) {
	cible := 0
	autre := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { cible++ }))
	defer autre.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, autre.URL, http.StatusFound)
	}))
	defer srv.Close()
	c := NouveauClient(Config{Maitre: strings.TrimPrefix(srv.URL, "http://")}, modeleTest(nil), nil)
	if err := c.poster(context.Background(), "/bonjour", map[string]string{}); err == nil || cible != 0 {
		t.Fatalf("la redirection doit échouer sans être suivie (err=%v, cible=%d)", err, cible)
	}
}
