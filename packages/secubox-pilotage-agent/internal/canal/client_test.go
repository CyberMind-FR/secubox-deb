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
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/notifs"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/operations"
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
	sondages int // GET /requetes reçus
	recu     chan struct{}

	echecsNotifs int // nombre de POST /notifs à refuser en 503 avant d'accepter

	enPanne       atomic.Bool  // maître injoignable : toute requête reçoit 503
	refuses       atomic.Int32 // requêtes refusées pendant la panne
	sondagesRefus atomic.Int32 // dont GET /requetes (le canal a vu la panne)
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
		f.sondages++
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
		if f.echecsNotifs > 0 {
			f.echecsNotifs--
			f.mu.Unlock()
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		f.notifs = append(f.notifs, b)
		f.mu.Unlock()
		f.signal()
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.enPanne.Load() {
			f.refuses.Add(1)
			if r.URL.Path == "/canal/v1/requetes" {
				f.sondagesRefus.Add(1)
			}
			io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (f *fauxMaitre) signal() {
	select {
	case f.recu <- struct{}{}:
	default:
	}
}

func demarrer(t *testing.T, f *fauxMaitre, m *modele.Modele, operer func(context.Context, string, map[string]any) (any, error), ev <-chan notifs.Evenement) (stop func()) {
	t.Helper()
	return demarrerAvec(t, f, m, operer, ev, nil)
}

func demarrerAvec(t *testing.T, f *fauxMaitre, m *modele.Modele, operer func(context.Context, string, map[string]any) (any, error), ev <-chan notifs.Evenement, regler func(*Client)) (stop func()) {
	t.Helper()
	f.recu = make(chan struct{}, 8)
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	c := NouveauClient(Config{Maitre: strings.TrimPrefix(srv.URL, "http://"), Attente: time.Second}, m, operer)
	if regler != nil {
		regler(c)
	}
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
	attendreCond(t, f, "ERROR puis OPERATE_RESP", func() bool { return len(f.reponses) >= 2 })
	f.mu.Lock()
	defer f.mu.Unlock()
	// l'argument invalide est refusé tout de suite ; le relevé répond dans son propre POST
	// (l'ordre des deux POST n'est pas garanti)
	vus := map[string]string{}
	for _, b := range f.reponses {
		l := decoder(t, b)
		if len(l) != 1 {
			t.Fatalf("une réponse par POST attendue : %s", b)
		}
		vus[l[0]["msg_id"].(string)] = l[0]["type"].(string)
	}
	if vus["fedcba9876543210"] != "ERROR" || vus["0123456789abcdef"] != "OPERATE_RESP" || vu["duree_s"] != 60 {
		t.Fatalf("ERROR et OPERATE_RESP (duree_s=60) attendus : %v %v", vus, vu)
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
	if r, _, err := c.traiter(context.Background(), []byte(`pas du json`)); len(r) != 0 || err == nil {
		t.Fatalf("liste illisible : erreur et aucune réponse attendues, reçu %v (err=%v)", r, err)
	}
	r, _, _ := c.traiter(context.Background(), []byte(`[42,{"msg_id":1},{"msg_id":"0123456789abcdef","type":"GET_SUPPORTED_DM","body":{}}]`))
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
	if r, _, _ := c.traiter(context.Background(), []byte("["+strings.Join(l, ",")+"]")); len(r) != 32 {
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
		if strings.HasSuffix(r.URL.Path, "/bonjour") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		mu.Lock()
		n++
		k := n
		mu.Unlock()
		if k == 3 {
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
		if len(delais) == 4 {
			cancel()
		}
		return ctx.Err()
	}
	c.Tourner(ctx, nil)
	// sondage 1 et 2 en 502 → 5 s, 10 s ; sondage 3 en 204 immédiat → plancher 1 s ;
	// sondage 4 en 502 → le recul repart de 5 s
	att := []time.Duration{5 * time.Second, 10 * time.Second, time.Second, 5 * time.Second}
	if len(delais) != 4 {
		t.Fatalf("délais %v", delais)
	}
	for i := range att {
		if delais[i] != att[i] {
			t.Fatalf("délais %v, attendu %v", delais, att)
		}
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

// attendreCond attend (3 s au plus) qu'une condition, évaluée sous le verrou du faux maître, devienne vraie.
func attendreCond(t *testing.T, f *fauxMaitre, quoi string, cond func() bool) {
	t.Helper()
	fin := time.Now().Add(3 * time.Second)
	for time.Now().Before(fin) {
		f.mu.Lock()
		ok := cond()
		f.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition jamais remplie : %s", quoi)
}

func TestClientDecoupeLesReponsesEnPlusieursPost(t *testing.T) {
	params := map[string]any{"Device.Test.gros": strings.Repeat("v", 200<<10)}
	f := &fauxMaitre{requetes: []string{`[` +
		`{"msg_id":"0000000000000001","type":"GET","body":{"paths":["Device.Test."]}},` +
		`{"msg_id":"0000000000000002","type":"GET","body":{"paths":["Device.Test."]}}]`}}
	stop := demarrer(t, f, modeleTest(params), nil, nil)
	defer stop()
	attendreCond(t, f, "deux POST /reponses", func() bool { return len(f.reponses) >= 2 })
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reponses) != 2 {
		t.Fatalf("2 POST attendus, reçu %d", len(f.reponses))
	}
	for i, b := range f.reponses {
		if len(b) > 256<<10 {
			t.Fatalf("POST %d de %d octets > 256 Kio", i, len(b))
		}
		if l := decoder(t, b); len(l) != 1 || l[0]["type"] != "GET_RESP" {
			t.Fatalf("POST %d inattendu : %.100s", i, b)
		}
	}
}

func TestLotsReponsesRespecteLaTaille(t *testing.T) {
	var reps []reponse
	for i := 0; i < 10; i++ {
		reps = append(reps, reponse{MsgID: fmt.Sprintf("%016x", i), Type: "GET_RESP", Body: map[string]any{"x": strings.Repeat("a", 100)}})
	}
	lots := lotsReponses(reps, 400)
	total := 0
	for _, b := range lots {
		if len(b) > 400 {
			t.Fatalf("lot de %d octets > 400", len(b))
		}
		var l []reponse
		if err := json.Unmarshal(b, &l); err != nil {
			t.Fatalf("lot illisible : %v", err)
		}
		total += len(l)
	}
	if total != 10 || len(lots) < 2 {
		t.Fatalf("10 réponses en plusieurs lots attendues : total=%d lots=%d", total, len(lots))
	}
}

func TestClientUneReponsePileATailleMaxEstRefusee(t *testing.T) {
	// l'enveloppe « [ ] » ajoute 2 octets : une réponse qui tient à l'octet près ne tient pas dans un POST
	for taille := 800; taille < 1000; taille++ {
		cl := NouveauClient(Config{Maitre: "127.0.0.1", TailleMax: 1000}, modeleTest(map[string]any{"Device.Test.v": strings.Repeat("v", taille)}), nil)
		rep := cl.repondre(context.Background(), requete{MsgID: "0123456789abcdef", Type: "GET", Body: json.RawMessage(`{"paths":["Device.Test."]}`)})
		b, _ := json.Marshal(rep)
		if len(b)+2 > 1000 {
			t.Fatalf("réponse de %d octets, enveloppe comprise %d > 1000 (type %s)", len(b), len(b)+2, rep.Type)
		}
	}
}

func TestClientRelevePasSynchrone(t *testing.T) {
	entre := make(chan struct{}, 4)
	liberer := make(chan struct{})
	operer := func(context.Context, string, map[string]any) (any, error) {
		entre <- struct{}{}
		<-liberer
		return map[string]any{"ok": true}, nil
	}
	mesure := `"type":"OPERATE","body":{"command":"Device.X_SECUBOX_Releve.Mesurer()","args":{"duree_s":60}}`
	f := &fauxMaitre{requetes: []string{
		`[{"msg_id":"00000000000000a1",` + mesure + `}]`,
		`[{"msg_id":"00000000000000b2","type":"GET_SUPPORTED_DM","body":{}}]`,
		`[{"msg_id":"00000000000000c3",` + mesure + `}]`,
	}}
	stop := demarrer(t, f, modeleTest(nil), operer, nil)
	defer func() {
		select {
		case <-liberer:
		default:
			close(liberer)
		}
		stop()
	}()
	select {
	case <-entre:
	case <-time.After(3 * time.Second):
		t.Fatal("le relevé n'a pas démarré")
	}
	attendreCond(t, f, "GET_SUPPORTED_DM_RESP et refus du second relevé avant la fin du premier", func() bool { return len(f.reponses) >= 2 })
	f.mu.Lock()
	if !strings.Contains(string(f.reponses[0]), "GET_SUPPORTED_DM_RESP") {
		t.Errorf("la requête suivante doit être servie pendant le relevé : %s", f.reponses[0])
	}
	if !strings.Contains(string(f.reponses[1]), `"ERROR"`) || !strings.Contains(string(f.reponses[1]), "relevé déjà en cours") {
		t.Errorf("le second relevé doit recevoir ERROR : %s", f.reponses[1])
	}
	f.mu.Unlock()
	close(liberer)
	attendreCond(t, f, "OPERATE_RESP", func() bool { return len(f.reponses) >= 3 })
	f.mu.Lock()
	defer f.mu.Unlock()
	l := decoder(t, f.reponses[2])
	if len(l) != 1 || l[0]["type"] != "OPERATE_RESP" || l[0]["msg_id"] != "00000000000000a1" {
		t.Fatalf("OPERATE_RESP seule dans son POST attendue : %s", f.reponses[2])
	}
}

func TestTournerAttendLeReleve(t *testing.T) {
	entre := make(chan struct{})
	liberer := make(chan struct{})
	termine := make(chan struct{})
	operer := func(context.Context, string, map[string]any) (any, error) {
		close(entre)
		<-liberer
		close(termine)
		return nil, nil
	}
	f := &fauxMaitre{requetes: []string{`[{"msg_id":"00000000000000a1","type":"OPERATE","body":{"command":"Device.X_SECUBOX_Releve.Mesurer()","args":{}}}]`}}
	f.recu = make(chan struct{}, 8)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	c := NouveauClient(Config{Maitre: strings.TrimPrefix(srv.URL, "http://"), Attente: time.Second}, modeleTest(nil), operer)
	ctx, cancel := context.WithCancel(context.Background())
	fini := make(chan error, 1)
	go func() { fini <- c.Tourner(ctx, nil) }()
	<-entre
	cancel()
	select {
	case <-fini:
		t.Fatal("Tourner ne doit rendre la main qu'après le relevé")
	case <-time.After(100 * time.Millisecond):
	}
	close(liberer)
	select {
	case <-fini:
		select {
		case <-termine:
		default:
			t.Fatal("Tourner rendu avant la fin du relevé")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Tourner ne rend pas la main")
	}
}

func TestClientPasDeRafaleSiLeMaitreRepondVite(t *testing.T) {
	cas := map[string]func(w http.ResponseWriter){
		"204 immédiat":         func(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) },
		"200 liste vide":       func(w http.ResponseWriter) { w.Write([]byte("[]")) },
		"200 illisible":        func(w http.ResponseWriter) { w.Write([]byte("pas du json")) },
		"200 msg_id invalides": func(w http.ResponseWriter) { w.Write([]byte(`[{"msg_id":"ZZ","type":"GET","body":{}}]`)) },
	}
	for nom, rep := range cas {
		t.Run(nom, func(t *testing.T) {
			var mu sync.Mutex
			sondages := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/requetes") {
					mu.Lock()
					sondages++
					mu.Unlock()
					rep(w)
				}
			}))
			defer srv.Close()
			c := NouveauClient(Config{Maitre: strings.TrimPrefix(srv.URL, "http://"), Attente: time.Second}, modeleTest(nil), nil)
			ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
			defer cancel()
			c.Tourner(ctx, nil)
			mu.Lock()
			defer mu.Unlock()
			if sondages > 2 {
				t.Fatalf("%d sondages en 400 ms : rafale", sondages)
			}
		})
	}
}

func TestClientRetenteLesNotificationsSansNouvelEvenement(t *testing.T) {
	ev := make(chan notifs.Evenement, 4)
	f := &fauxMaitre{echecsNotifs: 2}
	stop := demarrerAvec(t, f, modeleTest(nil), nil, ev, func(c *Client) {
		c.reprise = func(time.Duration) *time.Timer { return time.NewTimer(10 * time.Millisecond) }
	})
	defer stop()
	ev <- notifs.Evenement{Type: "X_SECUBOX_Boot", Instant: 42}
	attendreCond(t, f, "Boot finit par arriver", func() bool {
		return len(f.notifs) == 1 && strings.Contains(string(f.notifs[0]), "X_SECUBOX_Boot")
	})
}

func TestClientReculDesNotifications(t *testing.T) {
	ev := make(chan notifs.Evenement, 4)
	f := &fauxMaitre{echecsNotifs: 1000}
	var mu sync.Mutex
	var delais []time.Duration
	stop := demarrerAvec(t, f, modeleTest(nil), nil, ev, func(c *Client) {
		c.reprise = func(d time.Duration) *time.Timer {
			mu.Lock()
			delais = append(delais, d)
			mu.Unlock()
			return time.NewTimer(time.Millisecond)
		}
	})
	defer stop()
	ev <- notifs.Evenement{Type: "X_SECUBOX_Boot", Instant: 1}
	fin := time.Now().Add(3 * time.Second)
	for time.Now().Before(fin) {
		mu.Lock()
		n := len(delais)
		mu.Unlock()
		if n >= 4 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	att := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second}
	if len(delais) < 4 {
		t.Fatalf("reprises %v", delais)
	}
	for i := range att {
		if delais[i] != att[i] {
			t.Fatalf("reprises %v, attendu un recul doublé %v", delais, att)
		}
	}
}

func TestClientNotificationsParLotsDe16(t *testing.T) {
	ev := make(chan notifs.Evenement, 64)
	f := &fauxMaitre{}
	for i := 0; i < 40; i++ {
		ev <- notifs.Evenement{Type: "X_SECUBOX_MemoryLow", Valeur: int64(i), Instant: int64(i)}
	}
	stop := demarrer(t, f, modeleTest(nil), nil, ev)
	defer stop()
	attendreCond(t, f, "40 notifications", func() bool {
		n := 0
		for _, b := range f.notifs {
			var l []json.RawMessage
			json.Unmarshal(b, &l)
			n += len(l)
		}
		return n == 40
	})
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range f.notifs {
		var l []json.RawMessage
		json.Unmarshal(b, &l)
		if len(l) > 16 {
			t.Fatalf("lot de %d notifications > 16", len(l))
		}
	}
}

func TestClientLieLaSourceDuTunnel(t *testing.T) {
	for _, src := range []string{"127.0.0.2", "127.0.0.2/24"} {
		t.Run(src, func(t *testing.T) {
			vu := make(chan string, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h, _, _ := net.SplitHostPort(r.RemoteAddr)
				select {
				case vu <- h:
				default:
				}
			}))
			defer srv.Close()
			c := NouveauClient(Config{Maitre: strings.TrimPrefix(srv.URL, "http://"), IPSource: src}, modeleTest(nil), nil)
			if err := c.poster(context.Background(), "/bonjour", map[string]string{}); err != nil {
				t.Fatal(err)
			}
			if h := <-vu; h != "127.0.0.2" {
				t.Fatalf("adresse source vue par le maître : %s", h)
			}
		})
	}
}

func TestClientIPSourceInvalideNeSeConnectePas(t *testing.T) {
	appels := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { appels++ }))
	defer srv.Close()
	for _, src := range []string{"pas-une-ip", "10.10.0.5/99", "10.10.0.5 ", "10.10.0.5:80"} {
		c := NouveauClient(Config{Maitre: strings.TrimPrefix(srv.URL, "http://"), IPSource: src}, modeleTest(nil), nil)
		b := false
		if _, err := c.cycle(context.Background(), &b); err == nil || !strings.Contains(err.Error(), "ip_source") {
			t.Fatalf("%q : erreur visible attendue, reçu %v", src, err)
		}
	}
	if appels != 0 {
		t.Fatalf("aucune connexion attendue, %d appels", appels)
	}
}

func TestClientDureeSBornee(t *testing.T) {
	operer := func(context.Context, string, map[string]any) (any, error) { return nil, nil }
	for _, c := range []struct {
		d  string
		ok bool
	}{{"9", false}, {"10", true}, {"300", true}, {"301", false}, {"3600", false}, {"1", false}} {
		cl := NouveauClient(Config{Maitre: "127.0.0.1"}, modeleTest(nil), operer)
		corps := `[{"msg_id":"0123456789abcdef","type":"OPERATE","body":{"command":"Device.X_SECUBOX_Releve.Mesurer()","args":{"duree_s":` + c.d + `}}}]`
		reps, lances, _ := cl.traiter(context.Background(), []byte(corps))
		cl.suivi.Wait()
		if c.ok && (lances != 1 || len(reps) != 0) {
			t.Errorf("duree_s=%s doit être acceptée : %v %d", c.d, reps, lances)
		}
		if !c.ok {
			if len(reps) != 1 || reps[0].Type != "ERROR" || !strings.Contains(fmt.Sprint(reps[0].Body["err"]), "10 à 300") {
				t.Errorf("duree_s=%s doit être refusée avec la plage 10 à 300 : %v", c.d, reps)
			}
		}
	}
}

func TestValiderCheminsDedoublonne(t *testing.T) {
	l := make([]any, 64)
	for i := range l {
		l[i] = "Device."
	}
	l = append(l[:3], "Device.A.", "Device.")
	out, err := validerChemins(l)
	if err != nil || len(out) != 2 || out[0] != "Device." || out[1] != "Device.A." {
		t.Fatalf("doublons à retirer en gardant l'ordre : %v %v", out, err)
	}
}

func TestClientRannonceSonBonjourApresUneErreur(t *testing.T) {
	var mu sync.Mutex
	bonjours, sondages := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/bonjour") {
			bonjours++
			return
		}
		sondages++
		if sondages == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := NouveauClient(Config{Maitre: strings.TrimPrefix(srv.URL, "http://"), Attente: time.Second}, modeleTest(nil), nil)
	ctx, cancel := context.WithCancel(context.Background())
	c.dormir = func(ctx context.Context, d time.Duration) error {
		time.Sleep(5 * time.Millisecond)
		return ctx.Err()
	}
	fini := make(chan struct{})
	go func() { c.Tourner(ctx, nil); close(fini) }()
	fin := time.Now().Add(3 * time.Second)
	for time.Now().Before(fin) {
		mu.Lock()
		n := bonjours
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-fini
	mu.Lock()
	defer mu.Unlock()
	if bonjours < 2 {
		t.Fatalf("/bonjour doit être réannoncé après un cycle en erreur (reçu %d)", bonjours)
	}
}

func TestClientBorneLesEnTetesDeReponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Gros", strings.Repeat("a", 64<<10))
	}))
	defer srv.Close()
	c := NouveauClient(Config{Maitre: strings.TrimPrefix(srv.URL, "http://")}, modeleTest(nil), nil)
	if err := c.poster(context.Background(), "/bonjour", map[string]string{}); err == nil {
		t.Fatal("des en-têtes de 64 Kio doivent être refusés")
	}
}

func TestErreurTronqueSansCouperUnCaractere(t *testing.T) {
	for _, msg := range []string{strings.Repeat("é", 150), "a" + strings.Repeat("é", 150), "aa" + strings.Repeat("€", 100)} {
		r := erreur("0123456789abcdef", msg)
		s := r.Body["err"].(string)
		if !utf8.ValidString(s) || len(s) > 200 || len(s) < 197 {
			t.Fatalf("message mal coupé : %d octets, valide=%v", len(s), utf8.ValidString(s))
		}
	}
}

// scenarioCoupure (tâche 2, D1, R-L2-19) : tant que la vérification de l'ancre (le ctl, remplacé ici par un faux)
// rend `echec` (ancre différente ou illisible), l'agent ne contacte pas le maître et ne traite aucun Operate ; elle
// réussit → il se connecte et notifie la coupure ; une revérification horaire qui échoue coupe de nouveau le canal.
func scenarioCoupure(t *testing.T, echec Verdict) {
	var verdict atomic.Value
	verdict.Store(echec)
	var verifs, operes atomic.Int32
	var decalage atomic.Int64 // horloge du client : temps réel + décalage
	operer := func(context.Context, string, map[string]any) (any, error) {
		operes.Add(1)
		return map[string]any{"ok": true}, nil
	}
	mesure := `[{"msg_id":"%016x","type":"OPERATE","body":{"command":"Device.X_SECUBOX_Releve.Mesurer()","args":{"duree_s":10}}}]`
	f := &fauxMaitre{requetes: []string{fmt.Sprintf(mesure, 1)}}
	stop := demarrerAvec(t, f, modeleTest(nil), operer, nil, func(c *Client) {
		c.cfg.Ancre = func(context.Context) Verdict { verifs.Add(1); return verdict.Load().(Verdict) }
		c.dormir = func(ctx context.Context, d time.Duration) error { return dormirReel(ctx, 2*time.Millisecond) }
		c.horloge = func() time.Time { return time.Now().Add(time.Duration(decalage.Load())) }
	})
	defer stop()

	etat := func() (bonjour, sondages, reponses, notifs int) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.bonjour), f.sondages, len(f.reponses), len(f.notifs)
	}

	// 1. ancre non vérifiée : vérifications répétées, rien vers le maître, aucun Operate
	attendreQue(t, "vérifications répétées", func() bool { return verifs.Load() >= 3 })
	time.Sleep(50 * time.Millisecond)
	if b, s, r, n := etat(); b+s+r+n != 0 || operes.Load() != 0 {
		t.Fatalf("sans ancre, rien ne doit partir : bonjour=%d sondages=%d réponses=%d notifs=%d operes=%d", b, s, r, n, operes.Load())
	}

	// 2. ancre vérifiée : bonjour, notification de la coupure, Operate traité
	verdict.Store(AncreOK)
	attendreQue(t, "connexion, notification et relevé", func() bool {
		b, _, r, n := etat()
		return b == 1 && r >= 1 && n >= 1
	})
	f.mu.Lock()
	notif := string(f.notifs[0])
	f.mu.Unlock()
	if !strings.Contains(notif, `"type":"`+notifs.TypeAncre+`"`) || operes.Load() != 1 {
		t.Fatalf("notification de coupure attendue (%s), Operate traité une fois (%d)", notif, operes.Load())
	}

	// 3. une heure plus tard, la revérification échoue : le canal est coupé ; un Operate mis en file ensuite n'est
	// ni sondé ni traité
	n0 := verifs.Load()
	verdict.Store(echec)
	decalage.Store(int64(61 * time.Minute))
	attendreQue(t, "revérification horaire", func() bool { return verifs.Load() > n0 })
	time.Sleep(50 * time.Millisecond) // un sondage déjà en vol se termine
	_, s1, _, _ := etat()
	f.mu.Lock()
	f.requetes = append(f.requetes, fmt.Sprintf(mesure, 2))
	f.mu.Unlock()
	time.Sleep(150 * time.Millisecond)
	_, s2, _, _ := etat()
	f.mu.Lock()
	restantes := len(f.requetes)
	f.mu.Unlock()
	if s2 != s1 || restantes != 1 || operes.Load() != 1 {
		t.Fatalf("canal non coupé : sondages %d → %d, requêtes en file %d, operes=%d", s1, s2, restantes, operes.Load())
	}
}

func attendreQue(t *testing.T, quoi string, cond func() bool) {
	t.Helper()
	for fin := time.Now().Add(3 * time.Second); time.Now().Before(fin); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("délai dépassé : %s", quoi)
}

// TestAgentSansAncreNeFaitRien : ancre illisible (ou ctl en échec) → canal coupé.
func TestAgentSansAncreNeFaitRien(t *testing.T) { scenarioCoupure(t, AncreIllisible) }

// TestAgentAncreDifferenteCoupe : le pair du maître n'a pas la clé de l'ancre → canal coupé (brief, R-L2-19).
func TestAgentAncreDifferenteCoupe(t *testing.T) { scenarioCoupure(t, AncreDifferente) }

// TestAgentAncreAbsenteLitMaisNAgitPas (R-L2-19) : sans ancre posée sur la box, le canal reste ouvert en lecture
// (comme en L1) ; tout Operate est refusé ; un lot de refus redemande la vérification au ctl, qui l'audite
// (« ancre absente »), au plus une fois par lot et par minute (R-L2-24). Aucune notification de coupure : le canal
// n'a pas été coupé.
func TestAgentAncreAbsenteLitMaisNAgitPas(t *testing.T) {
	var verifs, operes atomic.Int32
	operer := func(context.Context, string, map[string]any) (any, error) {
		operes.Add(1)
		return map[string]any{"ok": true}, nil
	}
	f := &fauxMaitre{requetes: []string{
		`[{"msg_id":"0000000000000001","type":"GET","body":{"paths":["Device.Test."]}}]`,
		`[{"msg_id":"0000000000000002","type":"OPERATE","body":{"command":"Device.X_SECUBOX_Releve.Mesurer()","args":{}}},` +
			`{"msg_id":"0000000000000003","type":"OPERATE","body":{"command":"Device.Reboot()","args":{}}}]`,
	}}
	stop := demarrerAvec(t, f, modeleTest(map[string]any{"Device.Test.a": 1}), operer, nil, func(c *Client) {
		c.cfg.Ancre = func(context.Context) Verdict { verifs.Add(1); return AncreAbsente }
	})
	defer stop()
	attendreQue(t, "lecture et refus", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.reponses) >= 2
	})
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.bonjour) != 1 || len(f.notifs) != 0 {
		t.Fatalf("canal ouvert sans notification de coupure attendu : bonjour=%d notifs=%d", len(f.bonjour), len(f.notifs))
	}
	get := decoder(t, f.reponses[0])
	if get[0]["type"] != "GET_RESP" {
		t.Fatalf("lecture servie attendue : %v", get[0])
	}
	refus := decoder(t, f.reponses[1])
	if len(refus) != 2 {
		t.Fatalf("deux refus attendus : %v", refus)
	}
	for _, r := range refus {
		body := r["body"].(map[string]any)
		if r["type"] != "ERROR" || !strings.Contains(body["err"].(string), "ancre absente") {
			t.Fatalf("refus « ancre absente » attendu : %v", r)
		}
	}
	if operes.Load() != 0 {
		t.Fatalf("aucun Operate ne doit être exécuté (%d)", operes.Load())
	}
	// démarrage + une revérification pour le lot refusé (audit « ancre absente » côté ctl, R-L2-24)
	if v := verifs.Load(); v != 2 {
		t.Fatalf("vérifications attendues : 1 au démarrage + 1 pour le lot, %d", v)
	}
}

// TestClientAncreVerifieeChaqueHeure : une ancre vérifiée n'est pas redemandée avant PeriodeAncre (1 h par défaut).
func TestClientAncreVerifieeChaqueHeure(t *testing.T) {
	var verifs atomic.Int32
	var decalage atomic.Int64
	f := &fauxMaitre{}
	stop := demarrerAvec(t, f, modeleTest(nil), nil, nil, func(c *Client) {
		c.cfg.Ancre = func(context.Context) Verdict { verifs.Add(1); return AncreOK }
		c.horloge = func() time.Time { return time.Now().Add(time.Duration(decalage.Load())) }
	})
	defer stop()
	for fin := time.Now().Add(3 * time.Second); verifs.Load() == 0 && time.Now().Before(fin); time.Sleep(5 * time.Millisecond) {
	}
	time.Sleep(150 * time.Millisecond)
	if v := verifs.Load(); v != 1 {
		t.Fatalf("une seule vérification attendue au démarrage, %d", v)
	}
	decalage.Store(int64(time.Hour))
	for fin := time.Now().Add(3 * time.Second); verifs.Load() < 2 && time.Now().Before(fin); time.Sleep(5 * time.Millisecond) {
	}
	if v := verifs.Load(); v != 2 {
		t.Fatalf("revérification attendue après une heure, %d", v)
	}
}

// TestAgentAncreAbsenteUnSeulAppelParLot (I2, R-L2-24) : un pair non vérifié n'inonde pas l'audit. 32 OPERATE dans
// un lot → au plus un appel au ctl ; un second lot dans la minute → aucun ; tous refusés, aucun exécuté.
func TestAgentAncreAbsenteUnSeulAppelParLot(t *testing.T) {
	var verifs, operes atomic.Int32
	operer := func(context.Context, string, map[string]any) (any, error) { operes.Add(1); return nil, nil }
	lot := func(base int) string {
		l := make([]string, 32)
		for i := range l {
			l[i] = fmt.Sprintf(`{"msg_id":"%016x","type":"OPERATE","body":{"command":"Device.X_SECUBOX_Releve.Mesurer()","args":{}}}`, base+i)
		}
		return "[" + strings.Join(l, ",") + "]"
	}
	f := &fauxMaitre{requetes: []string{lot(1), lot(100)}}
	stop := demarrerAvec(t, f, modeleTest(nil), operer, nil, func(c *Client) {
		c.cfg.Ancre = func(context.Context) Verdict { verifs.Add(1); return AncreAbsente }
	})
	defer stop()
	refuses := func() int {
		f.mu.Lock()
		defer f.mu.Unlock()
		n := 0
		for _, b := range f.reponses {
			for _, r := range decoder(t, b) {
				if r["type"] == "ERROR" && strings.Contains(r["body"].(map[string]any)["err"].(string), "ancre absente") {
					n++
				}
			}
		}
		return n
	}
	attendreQue(t, "64 refus", func() bool { return refuses() == 64 })
	if v := verifs.Load(); v > 2 {
		t.Fatalf("au plus 1 appel au démarrage + 1 pour les deux lots de la même minute, %d", v)
	}
	if operes.Load() != 0 {
		t.Fatalf("aucun Operate exécuté attendu, %d", operes.Load())
	}
}

// TestAgentAncreDisparueApresOkCoupe (M1) : une ancre vue « ok » puis « absente » n'est pas une box sans ancre :
// c'est traité comme illisible — coupure, puis notification X_SECUBOX_AnchorFailed à la reconnexion.
func TestAgentAncreDisparueApresOkCoupe(t *testing.T) {
	var verdict atomic.Value
	verdict.Store(AncreOK)
	var verifs atomic.Int32
	var decalage atomic.Int64
	f := &fauxMaitre{}
	stop := demarrerAvec(t, f, modeleTest(nil), nil, nil, func(c *Client) {
		c.cfg.Ancre = func(context.Context) Verdict { verifs.Add(1); return verdict.Load().(Verdict) }
		c.dormir = func(ctx context.Context, d time.Duration) error { return dormirReel(ctx, 2*time.Millisecond) }
		c.horloge = func() time.Time { return time.Now().Add(time.Duration(decalage.Load())) }
	})
	defer stop()
	sondages := func() int {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.sondages
	}
	attendreQue(t, "canal ouvert", func() bool { return sondages() >= 1 })
	n0 := verifs.Load()
	verdict.Store(AncreAbsente)
	decalage.Store(int64(61 * time.Minute))
	attendreQue(t, "revérification", func() bool { return verifs.Load() > n0 })
	time.Sleep(50 * time.Millisecond)
	s1 := sondages()
	time.Sleep(150 * time.Millisecond)
	if s2 := sondages(); s2 != s1 {
		t.Fatalf("ancre disparue après ok : canal à couper, sondages %d → %d", s1, s2)
	}
	verdict.Store(AncreOK)
	attendreQue(t, "notification de coupure", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.notifs) >= 1 && strings.Contains(string(f.notifs[0]), notifs.TypeAncre)
	})
}

// --- Tâche 3 : Operate d'action (L2) ---------------------------------------------------------------------------

// TestClientOperateActionRepondEtat : avec l'exécuteur câblé (Config.Agir), un Operate d'action reçoit tout de suite
// un OPERATE_RESP {etat, job, raison} ; l'acteur du maître (champ « acteur » du corps) est transmis tel quel, sa
// validation revenant à l'exécuteur ; le relevé reste traité par le canal.
func TestClientOperateActionRepondEtat(t *testing.T) {
	var mu sync.Mutex
	var vus []string
	agir := func(_ context.Context, cmd string, args map[string]any, acteur string) operations.Reponse {
		mu.Lock()
		vus = append(vus, fmt.Sprintf("%s|%v|%s", cmd, args["unite"], acteur))
		mu.Unlock()
		if cmd == operations.CmdReboot {
			return operations.Reponse{Etat: operations.Consentement, Raison: "consentement requis"}
		}
		return operations.Reponse{Etat: operations.Accepte, Job: "0123456789abcdef"}
	}
	f := &fauxMaitre{requetes: []string{`[` +
		`{"msg_id":"0000000000000001","type":"OPERATE","body":{"command":"Device.X_SECUBOX_Services.Agir()","args":{"unite":"secubox-lyrion.service","action":"restart"},"acteur":"gk2admin"}},` +
		`{"msg_id":"0000000000000002","type":"OPERATE","body":{"command":"Device.Reboot()","args":{},"acteur":42}}]`}}
	stop := demarrerAvec(t, f, modeleTest(nil), nil, nil, func(c *Client) {
		c.cfg.Agir = agir
		c.cfg.Ancre = func(context.Context) Verdict { return AncreOK } // M5 : jamais d'actions sans ancre
	})
	defer stop()
	attendre(t, f)
	f.mu.Lock()
	defer f.mu.Unlock()
	l := decoder(t, f.reponses[0])
	if len(l) != 2 {
		t.Fatalf("deux réponses attendues : %s", f.reponses[0])
	}
	b0, b1 := l[0]["body"].(map[string]any), l[1]["body"].(map[string]any)
	if l[0]["type"] != "OPERATE_RESP" || b0["etat"] != "accepte" || b0["job"] != "0123456789abcdef" || b0["raison"] != "" {
		t.Fatalf("OPERATE_RESP accepte attendu : %v", l[0])
	}
	if l[1]["type"] != "OPERATE_RESP" || b1["etat"] != "consentement" || b1["job"] != "" || b1["raison"] != "consentement requis" {
		t.Fatalf("OPERATE_RESP consentement attendu : %v", l[1])
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(vus, " ; ") != "Device.X_SECUBOX_Services.Agir()|secubox-lyrion.service|gk2admin ; Device.Reboot()|<nil>|" {
		t.Fatalf("appels inattendus : %v", vus)
	}
}

// TestAgentRenvoieLeResultatApresReconnexion : le canal tombe pendant une mise à niveau ; l'opération continue
// (systemd-run), sa fin est gardée en mémoire et renvoyée au maître à la reconnexion, une seule fois.
func TestAgentRenvoieLeResultatApresReconnexion(t *testing.T) {
	var finie atomic.Bool
	ctl := func(_ context.Context, args ...string) ([]byte, error) {
		if args[len(args)-2] == "etat-operation" {
			return []byte(`{"ok": true, "job": "0123456789abcdef", "etat": "termine", "verbe": "maj-paquets", "resultat": "succes", "rc": 0}`), nil
		}
		return []byte(`{"ok": true, "job": "0123456789abcdef"}`), nil
	}
	systemctl := func(context.Context, ...string) ([]byte, error) {
		if finie.Load() {
			return []byte("inactive\ninactive\n"), nil
		}
		return []byte("active\ninactive\n"), nil
	}
	boite := operations.NouvelleBoite(0)
	ev := make(chan notifs.Evenement, 8)
	ex := operations.Nouveau(operations.Config{Ctl: ctl, Systemctl: systemctl, Resultats: boite, Pas: 5 * time.Millisecond,
		Progression: func(e notifs.Evenement) {
			select {
			case ev <- e:
			default:
			}
		}})
	f := &fauxMaitre{requetes: []string{
		`[{"msg_id":"0000000000000001","type":"OPERATE","body":{"command":"Device.X_SECUBOX_Packages.MettreAJour()","args":{},"acteur":"gk2admin"}}]`}}
	stop := demarrerAvec(t, f, modeleTest(nil), nil, ev, func(c *Client) {
		c.cfg.Agir = ex.Operer
		c.cfg.Ancre = func(context.Context) Verdict { return AncreOK }
		c.cfg.Resultats = boite
		c.dormir = func(ctx context.Context, d time.Duration) error { return dormirReel(ctx, 2*time.Millisecond) }
	})
	defer func() { stop(); ex.Attendre() }()
	fins := func() int {
		f.mu.Lock()
		defer f.mu.Unlock()
		n := 0
		for _, b := range f.notifs {
			n += strings.Count(string(b), `"type":"`+notifs.TypeOperationDone+`"`)
		}
		return n
	}
	// 1. l'opération est acceptée
	attendreQue(t, "OPERATE_RESP accepte", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.reponses) == 1 && strings.Contains(string(f.reponses[0]), `"etat":"accepte"`)
	})
	// 2. le maître tombe ; l'opération finit pendant la panne : sa fin reste dans la boîte
	f.mu.Lock()
	bonjours := len(f.bonjour)
	f.mu.Unlock()
	f.enPanne.Store(true)
	attendreQue(t, "sondage refusé : le canal voit la panne", func() bool { return f.sondagesRefus.Load() >= 1 })
	finie.Store(true)
	attendreQue(t, "fin gardée, son envoi refusé", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return boite.Taille() == 1 && f.refuses.Load() > f.sondagesRefus.Load()+1
	})
	if fins() != 0 {
		t.Fatal("aucune fin ne doit être comptée remise pendant la panne")
	}
	// 3. le maître revient : bonjour, puis la fin, une seule fois
	f.enPanne.Store(false)
	attendreQue(t, "fin remise après la reconnexion", func() bool { return fins() >= 1 })
	time.Sleep(100 * time.Millisecond)
	f.mu.Lock()
	reannonce := len(f.bonjour) > bonjours
	var corps string
	for _, b := range f.notifs {
		if strings.Contains(string(b), notifs.TypeOperationDone) {
			corps = string(b)
		}
	}
	f.mu.Unlock()
	if n := fins(); n != 1 || boite.Taille() != 0 || !reannonce {
		t.Fatalf("une seule remise attendue après le bonjour : remises=%d boîte=%d réannonce=%v", n, boite.Taille(), reannonce)
	}
	for _, sous := range []string{`"job":"0123456789abcdef"`, `"rc":0`, `"resume":"maj-paquets : succès"`} {
		if !strings.Contains(corps, sous) {
			t.Fatalf("fin incomplète, %s absent : %s", sous, corps)
		}
	}
}

// TestAgentReverifieSiLeCtlRefuseFauteDAncre (M3, R-L2-28) : l'agent se croit ancré (AncreOK) mais le ctl répond
// « ancre non vérifiée » (canal enregistré périmé ou retiré) : l'agent force une revérification, au plus une par
// lot et par minute (même limiteur que R-L2-24).
func TestAgentReverifieSiLeCtlRefuseFauteDAncre(t *testing.T) {
	var verifs atomic.Int32
	var decalage atomic.Int64
	agir := func(context.Context, string, map[string]any, string) operations.Reponse {
		return operations.Reponse{Etat: operations.Refuse, Raison: "ancre non vérifiée"}
	}
	lot := func(base int) string {
		l := make([]string, 3)
		for i := range l {
			l[i] = fmt.Sprintf(`{"msg_id":"%016x","type":"OPERATE","body":{"command":"Device.Reboot()","args":{}}}`, base+i)
		}
		return "[" + strings.Join(l, ",") + "]"
	}
	f := &fauxMaitre{requetes: []string{lot(1), lot(10)}}
	stop := demarrerAvec(t, f, modeleTest(nil), nil, nil, func(c *Client) {
		c.cfg.Agir = agir
		c.cfg.Ancre = func(context.Context) Verdict { verifs.Add(1); return AncreOK }
		c.horloge = func() time.Time { return time.Now().Add(time.Duration(decalage.Load())) }
	})
	defer stop()
	nbReponses := func() int {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.reponses)
	}
	attendreQue(t, "deux lots refusés", func() bool { return nbReponses() == 2 })
	if v := verifs.Load(); v != 2 {
		t.Fatalf("1 vérification au démarrage + 1 forcée pour les deux lots de la même minute, %d", v)
	}
	decalage.Store(int64(61 * time.Second))
	f.mu.Lock()
	f.requetes = append(f.requetes, lot(20))
	f.mu.Unlock()
	attendreQue(t, "troisième lot", func() bool { return nbReponses() == 3 })
	if v := verifs.Load(); v != 3 {
		t.Fatalf("une minute plus tard, une nouvelle revérification forcée attendue, %d", v)
	}
}

// TestClientAgirSansAncreRefuse (M5, R-L2-28) : des actions sans vérification d'ancre sont une configuration
// invalide : aucune connexion.
func TestClientAgirSansAncreRefuse(t *testing.T) {
	agir := func(context.Context, string, map[string]any, string) operations.Reponse { return operations.Reponse{} }
	c := NouveauClient(Config{Maitre: "127.0.0.1", Agir: agir}, modeleTest(nil), nil)
	if c.errCfg == nil {
		t.Fatal("Agir sans Ancre : errCfg attendu")
	}
	if _, err := c.cycle(context.Background(), new(bool)); err == nil || err != c.errCfg {
		t.Fatalf("aucune connexion attendue : %v", err)
	}
	c = NouveauClient(Config{Maitre: "127.0.0.1", Agir: agir, Ancre: func(context.Context) Verdict { return AncreOK }}, modeleTest(nil), nil)
	if c.errCfg != nil {
		t.Fatalf("Agir avec Ancre : configuration valable, %v", c.errCfg)
	}
}
