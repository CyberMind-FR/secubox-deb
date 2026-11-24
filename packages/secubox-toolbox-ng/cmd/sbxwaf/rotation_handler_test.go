// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reseau"
)

// Détecteur de rotation à travers le handler (#3919) : qui est suivi, quand le verdict s'ouvre.

const pageFictive = `<!doctype html><html><head><link rel="stylesheet" href="/static/app.css"></head><body>page</body></html>`

type bancRotation struct {
	t      *testing.T
	srv    *Server
	rot    *Rotation
	ban    *banFactice
	lente  chan struct{}
	recue  chan struct{}
	suffix int
}

func nouveauBanc(t *testing.T) *bancRotation {
	b := &bancRotation{t: t, ban: &banFactice{}, lente: make(chan struct{}), recue: make(chan struct{}, 8)}
	amont := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch q.URL.Path {
		case "/lente":
			w.WriteHeader(200)
			_, _ = io.WriteString(w, pageFictive)
			w.(http.Flusher).Flush()
			b.recue <- struct{}{}
			<-b.lente
		case "/redirige":
			http.Redirect(w, q, "/", http.StatusFound)
		case "/absente":
			w.WriteHeader(404)
			_, _ = io.WriteString(w, pageFictive)
		case "/panne":
			w.WriteHeader(500)
			_, _ = io.WriteString(w, pageFictive)
		case "/api":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{}`)
		case "/flux":
			w.Header().Set("Content-Type", "application/rss+xml")
			_, _ = io.WriteString(w, `<rss/>`)
		case "/telecharge":
			w.Header().Set("Content-Disposition", "attachment; filename=x.html")
			_, _ = io.WriteString(w, pageFictive)
		case "/autonome":
			_, _ = io.WriteString(w, `<html><style>p{}</style><p>tout est dans la page</p></html>`)
		case "/br":
			w.Header().Set("Content-Encoding", "br")
			_, _ = io.WriteString(w, pageFictive)
		case "/gzip":
			w.Header().Set("Content-Encoding", "gzip")
			var z bytes.Buffer
			g := gzip.NewWriter(&z)
			_, _ = io.WriteString(g, pageFictive)
			_ = g.Close()
			_, _ = w.Write(z.Bytes())
		case "/tronquee":
			w.Header().Set("Content-Length", "5000")
			_, _ = io.WriteString(w, pageFictive)
			panic(http.ErrAbortHandler)
		case "/.env":
			w.WriteHeader(404)
		default:
			_, _ = io.WriteString(w, pageFictive)
		}
	}))
	t.Cleanup(amont.Close)
	_, ps, _ := net.SplitHostPort(amont.Listener.Addr().String())
	port, _ := strconv.Atoi(ps)
	regles := filepath.Join(t.TempDir(), "regles.json")
	if err := os.WriteFile(regles, []byte(`{"categories":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	b.rot = NewRotation(cfgEssai(t, "auto"), b.ban, &classesFactices{defaut: reseau.ClasseProxyLoue})
	b.srv = &Server{rotation: b.rot, rules: LoadRules(regles), routeLookup: func(h string) (string, int, bool) {
		return "127.0.0.1", port, h == "site.exemple.test" || h == "site.exemple.test."
	}}
	return b
}

// get : requête par un VRAI serveur HTTP (le proxy panique alors sur un amont tronqué) quand `reel`, sinon en direct.
func (b *bancRotation) get(ip, hote, chemin string, entetes ...string) *httptest.ResponseRecorder {
	b.t.Helper()
	q := httptest.NewRequest("GET", chemin, nil)
	q.Host, q.RemoteAddr = hote, net.JoinHostPort(ip, "4000")
	q.Header.Set("User-Agent", uaFictif)
	for i := 0; i+1 < len(entetes); i += 2 {
		q.Header.Set(entetes[i], entetes[i+1])
	}
	w := httptest.NewRecorder()
	b.srv.handler().ServeHTTP(w, q)
	return w
}

func (b *bancRotation) etablir() {
	b.t.Helper()
	for i := 0; i < 50; i++ {
		b.get(adressePublique(i), "site.exemple.test", "/")
	}
	b.rot.Tick(time.Now())
	if len(b.rot.campagnesActives()) != 1 {
		b.t.Fatal("campagne attendue par le handler")
	}
}

func TestHandlerRotationHoteNormalise(t *testing.T) {
	b := nouveauBanc(t)
	for _, h := range []string{"site.exemple.test", "Site.Exemple.TEST", "site.exemple.test:443", "site.exemple.test."} {
		b.get("203.0.113.7", h, "/")
	}
	if n := b.rot.nbSignatures(); n != 1 {
		t.Fatalf("casse, port et point final : une signature, %d", n)
	}
}

func TestHandlerRotationAdressePriveeJamaisObservee(t *testing.T) {
	b := nouveauBanc(t)
	for _, ip := range []string{"10.1.2.3", "192.168.1.20", "127.0.0.1", "172.16.4.4"} {
		b.get(ip, "site.exemple.test", "/")
		b.get(ip, "site.exemple.test", "/app.css", "Cookie", "s=1")
	}
	if b.rot.nbSignatures() != 0 || b.rot.memoire.nb() != 0 {
		t.Fatalf("adresse privée : ni suivie ni retenue (%d, %d)", b.rot.nbSignatures(), b.rot.memoire.nb())
	}
}

func TestHandlerRotationPreuveSurTouteRequete(t *testing.T) {
	b := nouveauBanc(t)
	b.srv.trustedHosts = parseTrustedHosts("confiance.exemple.test")
	b.get("203.0.113.1", "site.exemple.test", "/static/app.css")
	b.get("203.0.113.2", "site.exemple.test", "/", "Authorization", "Basic eA==", "User-Agent", "git/2.45.0")
	b.get("203.0.113.3", "confiance.exemple.test", "/", "Cookie", "s=1")
	b.get("203.0.113.4", "non-route.exemple.test", "/", "Referer", "https://exemple.test/")
	b.get("203.0.113.5", "site.exemple.test", "/", "If-None-Match", `"x"`)
	b.get("203.0.113.6", "site.exemple.test", "/") // aucune preuve
	if n := b.rot.memoire.nb(); n != 5 {
		t.Fatalf("5 preuves attendues, %d", n)
	}
}

// Une page complète ouvre un verdict ; tout le reste, non (I1, I2).
func TestHandlerRotationOuvertureDuVerdict(t *testing.T) {
	b := nouveauBanc(t)
	b.srv.leurre = &LeurreHTTP{actif: true}
	b.etablir()
	for i, ch := range []string{"/redirige", "/absente", "/panne", "/api", "/flux", "/telecharge", "/autonome", "/br", "/.env"} {
		b.get(adressePublique(100+i), "site.exemple.test", ch)
		if n := b.rot.nbAttente(); n != 0 {
			t.Errorf("%s n'ouvre pas de verdict (%d)", ch, n)
			b.rot.abandonnerAttente()
		}
	}
	for i, ch := range []string{"/", "/gzip"} {
		b.get(adressePublique(120+i), "site.exemple.test", ch)
		if n := b.rot.nbAttente(); n != i+1 {
			t.Errorf("%s ouvre un verdict (%d)", ch, n)
		}
	}
	if n := b.rot.captures.Load(); n != 0 {
		t.Fatalf("toutes les réponses suivies sont libérées, %d", n)
	}
	avancer(b.rot, time.Now(), time.Now().Add(11*time.Second))
	if !b.ban.banni(adressePublique(120)) || !b.ban.banni(adressePublique(121)) || len(b.ban.liste()) != 2 {
		t.Fatalf("les deux adresses muettes sont bannies, elles seules : %v", b.ban.liste())
	}
}

func TestHandlerRotationPageLente(t *testing.T) {
	b := nouveauBanc(t)
	b.etablir()
	x := adressePublique(100)
	fini := make(chan struct{})
	go func() { b.get(x, "site.exemple.test", "/lente"); close(fini) }()
	<-b.recue
	if b.rot.nbAttente() != 0 {
		t.Fatal("page en cours : aucun verdict")
	}
	avancer(b.rot, time.Now(), time.Now().Add(40*time.Second)) // bien au-delà de 10 s
	if len(b.ban.liste()) != 0 {
		t.Fatal("banni avant d'avoir reçu sa page")
	}
	close(b.lente)
	<-fini
	if b.rot.nbAttente() != 1 {
		t.Fatal("le verdict s'ouvre à la fin de la page")
	}
	b.get(x, "site.exemple.test", "/static/app.css") // ses ressources, enfin
	avancer(b.rot, time.Now().Add(41*time.Second), time.Now().Add(80*time.Second))
	if len(b.ban.liste()) != 0 {
		t.Fatal("visiteur lent mais réel : jamais banni")
	}
}

func TestHandlerRotationCoupures(t *testing.T) {
	b := nouveauBanc(t)
	b.etablir()
	// Vrai serveur : client et amont coupés. L'adresse du client est donnée par X-Forwarded-For (pair de confiance).
	front := httptest.NewServer(b.srv.handler())
	defer front.Close()
	demande := func(ctx context.Context, ip, ch string) {
		q, _ := http.NewRequestWithContext(ctx, "GET", front.URL+ch, nil)
		q.Host = "site.exemple.test"
		q.Header.Set("User-Agent", uaFictif)
		q.Header.Set("Accept-Encoding", "identity")
		q.Header.Set("X-Forwarded-For", ip)
		rep, err := http.DefaultClient.Do(q)
		if err == nil {
			_, _ = io.Copy(io.Discard, rep.Body)
			rep.Body.Close()
		}
	}
	demande(context.Background(), adressePublique(100), "/tronquee")
	ctx, couper := context.WithCancel(context.Background())
	go func() { <-b.recue; couper() }()
	demande(ctx, adressePublique(101), "/lente")
	fin := time.Now().Add(5 * time.Second)
	for b.rot.captures.Load() != 0 && time.Now().Before(fin) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := b.rot.nbAttente(); n != 0 || b.rot.captures.Load() != 0 {
		t.Fatalf("amont tronqué ou client parti : aucun verdict (%d en attente, %d suivies)", n, b.rot.captures.Load())
	}
	close(b.lente)
	demande(context.Background(), adressePublique(102), "/")
	for b.rot.captures.Load() != 0 && time.Now().Before(fin) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := b.rot.nbAttente(); n != 1 {
		t.Fatalf("témoin : une page complète ouvre un verdict, %d", n)
	}
}

// L'écran de réveil (200 text/html) remplace une page qui n'existe pas encore : jamais de verdict.
func TestHandlerRotationReveil(t *testing.T) {
	b := nouveauBanc(t)
	b.etablir()
	sock := filepath.Join(t.TempDir(), "waker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("socket Unix indisponible")
	}
	go func() {
		_ = http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, pageFictive)
		}))
	}()
	defer l.Close()
	b.srv.wakerSocket = sock
	liste := filepath.Join(t.TempDir(), "od.json")
	_ = os.WriteFile(liste, []byte(`["site.exemple.test"]`), 0o644)
	b.srv.onDemand = LoadOnDemand(liste)
	ferme, _ := net.Listen("tcp", "127.0.0.1:0")
	_, ps, _ := net.SplitHostPort(ferme.Addr().String())
	ferme.Close()
	port, _ := strconv.Atoi(ps)
	b.srv.routeLookup = func(string) (string, int, bool) { return "127.0.0.1", port, true }
	w := b.get(adressePublique(100), "site.exemple.test", "/")
	if w.Code != 200 || w.Body.Len() == 0 {
		t.Fatalf("écran de réveil attendu : %d", w.Code)
	}
	if n := b.rot.nbAttente(); n != 0 {
		t.Fatalf("écran de réveil : aucun verdict, %d", n)
	}
}

// Un 404 maquillé en leurre (200) n'est pas la page demandée, quel que soit le contenu du leurre.
func TestHandlerRotationLeurreExclu(t *testing.T) {
	suivie := &rotationReponse{ResponseWriter: httptest.NewRecorder()}
	q := httptest.NewRequest("GET", "/.env", nil)
	q.RemoteAddr = "203.0.113.9:4000"
	q = q.WithContext(context.WithValue(q.Context(), cleRotationReponse{}, suivie))
	rep := &http.Response{StatusCode: 404, Header: http.Header{}, Request: q, Body: io.NopCloser(bytes.NewReader(nil))}
	if !(&LeurreHTTP{actif: true}).LeurrerLe404(rep) || !suivie.exclu {
		t.Fatal("leurre servi : réponse exclue du verdict")
	}
}

func TestHandlerRotationReponsesSuiviesBornees(t *testing.T) {
	b := nouveauBanc(t)
	b.etablir()
	b.rot.captures.Store(rotationSuivis)
	b.get(adressePublique(100), "site.exemple.test", "/")
	if b.rot.nbAttente() != 0 || b.rot.captures.Load() != rotationSuivis {
		t.Fatal("au-delà du plafond de réponses suivies : pas de verdict, page servie")
	}
	b.rot.captures.Store(0)
}
