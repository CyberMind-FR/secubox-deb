// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package canal

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/relais"
)

// dossierCourt : une socket Unix exige un chemin court (108 octets) ; t.TempDir peut dépasser.
func dossierCourt(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "rl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// fauxRelais : écoute une socket Unix, retient chaque demande reçue et répond par repondre(demande).
type fauxRelais struct {
	mu       sync.Mutex
	demandes []relais.Demande
	appels   atomic.Int32
	chemin   string
}

func demarrerFauxRelais(t *testing.T, repondre func(relais.Demande) string) *fauxRelais {
	t.Helper()
	f := &fauxRelais{chemin: filepath.Join(dossierCourt(t), "r.sock")}
	ln, err := net.Listen("unix", f.chemin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				f.appels.Add(1)
				var d relais.Demande
				if err := json.NewDecoder(bufio.NewReader(c)).Decode(&d); err != nil {
					return
				}
				f.mu.Lock()
				f.demandes = append(f.demandes, d)
				f.mu.Unlock()
				io.WriteString(c, repondre(d)+"\n")
			}()
		}
	}()
	return f
}

func (f *fauxRelais) derniere(t *testing.T) relais.Demande {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.demandes) == 0 {
		t.Fatal("le relais n'a reçu aucune demande")
	}
	return f.demandes[len(f.demandes)-1]
}

func repondreOK(relais.Demande) string {
	return `{"statut":200,"entetes":{"Content-Type":"application/json"},"corps_b64":"` +
		base64.StdEncoding.EncodeToString([]byte(`{"ok":true}`)) + `"}`
}

// demandeHTTP : corps d'un message HTTP du maître (l'entrée du relais).
func demandeHTTP(methode, chemin, portee string, corps []byte) json.RawMessage {
	d := map[string]any{"methode": methode, "chemin": chemin, "entetes": map[string]string{"Accept": "application/json"},
		"corps_b64": base64.StdEncoding.EncodeToString(corps), "acteur": "admin", "maitre": "gk2", "portee": portee}
	b, _ := json.Marshal(d)
	return b
}

type sortieHTTP struct {
	Statut   int               `json:"statut"`
	Entetes  map[string]string `json:"entetes"`
	CorpsB64 string            `json:"corps_b64"`
}

func lireSortie(t *testing.T, b []byte) (sortieHTTP, string) {
	t.Helper()
	var s sortieHTTP
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("sortie illisible %q : %v", b, err)
	}
	corps, err := base64.StdEncoding.DecodeString(s.CorpsB64)
	if err != nil {
		t.Fatalf("corps_b64 illisible : %v", err)
	}
	return s, string(corps)
}

func clientHTTP(t *testing.T, cheminRelais string, admin func(context.Context) bool) *Client {
	t.Helper()
	c := NouveauClient(Config{Maitre: "127.0.0.1", CheminRelais: cheminRelais, PorteeAdmin: admin,
		Ancre: func(context.Context) Verdict { return AncreOK }}, modeleTest(nil), nil)
	c.verdict.Store(AncreOK)
	return c
}

func toujours(v bool) func(context.Context) bool { return func(context.Context) bool { return v } }

// TestAgentReduitLaPortee : la portée est RECALCULÉE par l'agent ; celle du maître ne peut que réduire.
func TestAgentReduitLaPortee(t *testing.T) {
	uid := uint32(os.Getuid())

	t.Run("mains liées : lecture, le POST est refusé 423 par le relais", func(t *testing.T) {
		dossierMains := dossierCourt(t)
		if err := os.WriteFile(filepath.Join(dossierMains, "mains-liees"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		os.Chmod(dossierMains, 0o755)
		_, cle, _ := ed25519.GenerateKey(nil)
		sockets := dossierCourt(t)
		r := &relais.Relais{Cle: cle, UIDAgent: uid, DossierSockets: sockets, DossierMainsLiees: dossierMains, UIDRoot: uid,
			NomBox: func() string { return "gk5" }, Journal: log.New(io.Discard, "", 0)}
		chemin := filepath.Join(dossierCourt(t), "relais.sock")
		ln, err := net.Listen("unix", chemin)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go r.Servir(ctx, ln)
		// la politique du ctl dirait « admin » : seules les mains liées (même vérification que le relais) réduisent
		admin := PorteeLocale(func() bool { return relais.MainsLieesDans(dossierMains, uid, nil) }, toujours(true), time.Second)
		c := clientHTTP(t, chemin, admin)
		s, corps := lireSortie(t, c.traiterHTTP(ctx, demandeHTTP("POST", "/api/v1/nac/sync", "admin", []byte(`{}`))))
		if s.Statut != 423 {
			t.Fatalf("423 attendu, reçu %d (%s)", s.Statut, corps)
		}
		// le relais dit « portee lecture » (et non « mains liees ») : la demande lui est arrivée DÉJÀ réduite
		if !strings.Contains(corps, "portee lecture") {
			t.Fatalf("l'agent devait envoyer la portée lecture : %s", corps)
		}
	})

	t.Run("box cliente sans support accepté : lecture", func(t *testing.T) {
		f := demarrerFauxRelais(t, repondreOK)
		c := clientHTTP(t, f.chemin, PorteeLocale(func() bool { return false }, toujours(false), time.Second))
		s, _ := lireSortie(t, c.traiterHTTP(context.Background(), demandeHTTP("GET", "/api/v1/system/status", "admin", nil)))
		if s.Statut != 200 || f.derniere(t).Portee != "lecture" {
			t.Fatalf("lecture attendue : statut %d, portée %q", s.Statut, f.derniere(t).Portee)
		}
	})

	t.Run("box du propriétaire, le maître demande lecture : lecture", func(t *testing.T) {
		f := demarrerFauxRelais(t, repondreOK)
		c := clientHTTP(t, f.chemin, PorteeLocale(func() bool { return false }, toujours(true), time.Second))
		lireSortie(t, c.traiterHTTP(context.Background(), demandeHTTP("GET", "/api/v1/system/status", "lecture", nil)))
		if p := f.derniere(t).Portee; p != "lecture" {
			t.Fatalf("lecture attendue, reçu %q", p)
		}
	})

	t.Run("box du propriétaire, admin demandé : admin", func(t *testing.T) {
		f := demarrerFauxRelais(t, repondreOK)
		c := clientHTTP(t, f.chemin, PorteeLocale(func() bool { return false }, toujours(true), time.Second))
		lireSortie(t, c.traiterHTTP(context.Background(), demandeHTTP("POST", "/api/v1/system/x", "admin", []byte("{}"))))
		if p := f.derniere(t).Portee; p != "admin" {
			t.Fatalf("admin attendu, reçu %q", p)
		}
	})

	t.Run("sans politique configurée : jamais admin", func(t *testing.T) {
		f := demarrerFauxRelais(t, repondreOK)
		c := clientHTTP(t, f.chemin, nil)
		lireSortie(t, c.traiterHTTP(context.Background(), demandeHTTP("GET", "/api/v1/system/x", "admin", nil)))
		if p := f.derniere(t).Portee; p != "lecture" {
			t.Fatalf("lecture attendue, reçu %q", p)
		}
	})
}

func TestPorteeLocaleCacheLaPolitique(t *testing.T) {
	var appels atomic.Int32
	liees := false
	p := PorteeLocale(func() bool { return liees }, func(context.Context) bool { appels.Add(1); return true }, time.Hour)
	for i := 0; i < 5; i++ {
		if !p(context.Background()) {
			t.Fatal("admin attendu")
		}
	}
	if appels.Load() != 1 {
		t.Fatalf("une seule lecture de la politique attendue (cache), reçu %d", appels.Load())
	}
	// les mains liées sont relues à CHAQUE demande, sans attendre le cache
	liees = true
	if p(context.Background()) {
		t.Fatal("mains liées : lecture attendue malgré le cache")
	}
}

func TestAgentHTTPRefuseActeurOuMaitreInvalides(t *testing.T) {
	f := demarrerFauxRelais(t, repondreOK)
	c := clientHTTP(t, f.chemin, toujours(true))
	for _, cas := range []struct{ acteur, maitre string }{
		{"ad min", "gk2"}, {"", "gk2"}, {"admin", "gk2.secubox.in"}, {"admin", ""}, {"adKmin", "gk2"},
		{strings.Repeat("a", 65), "gk2"}, {"admin", "gk_2"},
	} {
		d, _ := json.Marshal(map[string]any{"methode": "GET", "chemin": "/api/v1/system/x", "acteur": cas.acteur,
			"maitre": cas.maitre, "portee": "lecture"})
		s, _ := lireSortie(t, c.traiterHTTP(context.Background(), d))
		if s.Statut != 400 {
			t.Fatalf("%+v : 400 attendu, reçu %d", cas, s.Statut)
		}
	}
	for _, brut := range []string{`{"methode":"GET","chemin":"/api/v1/x/y","acteur":"a","maitre":"b","portee":"tout"}`,
		`{"methode":"GET","chemin":"/api/v1/x/y","acteur":"a","maitre":"b","portee":"lecture","inconnu":1}`, `[1]`, `"x"`} {
		if s, _ := lireSortie(t, c.traiterHTTP(context.Background(), json.RawMessage(brut))); s.Statut != 400 {
			t.Fatalf("%s : 400 attendu, reçu %d", brut, s.Statut)
		}
	}
	if f.appels.Load() != 0 {
		t.Fatal("aucune demande invalide ne doit atteindre le relais")
	}
	// casse ASCII : normalisée comme le relais et auth.py l'attendent
	d, _ := json.Marshal(map[string]any{"methode": "GET", "chemin": "/api/v1/system/x", "acteur": "Admin", "maitre": "GK2", "portee": "lecture"})
	lireSortie(t, c.traiterHTTP(context.Background(), d))
	if dm := f.derniere(t); dm.Acteur != "admin" || dm.Maitre != "gk2" {
		t.Fatalf("acteur/maître normalisés attendus : %+v", dm)
	}
}

func TestAgentHTTPCorpsTropGros413(t *testing.T) {
	f := demarrerFauxRelais(t, repondreOK)
	c := clientHTTP(t, f.chemin, toujours(true))
	s, _ := lireSortie(t, c.traiterHTTP(context.Background(), demandeHTTP("POST", "/api/v1/system/x", "admin", make([]byte, relais.CorpsMax+1))))
	if s.Statut != 413 {
		t.Fatalf("413 attendu, reçu %d", s.Statut)
	}
	if f.appels.Load() != 0 {
		t.Fatal("un corps trop gros ne doit pas atteindre le relais")
	}
	// pile 4 Mio : transmis
	s, _ = lireSortie(t, c.traiterHTTP(context.Background(), demandeHTTP("POST", "/api/v1/system/x", "admin", make([]byte, relais.CorpsMax))))
	if s.Statut != 200 || f.appels.Load() != 1 {
		t.Fatalf("4 Mio exactement : transmis attendu, statut %d", s.Statut)
	}
}

func TestAgentHTTPRelaisAbsent502(t *testing.T) {
	c := clientHTTP(t, filepath.Join(dossierCourt(t), "absent.sock"), toujours(true))
	s, corps := lireSortie(t, c.traiterHTTP(context.Background(), demandeHTTP("GET", "/api/v1/system/x", "lecture", nil)))
	if s.Statut != 502 || !strings.Contains(corps, "relais") {
		t.Fatalf("502 clair attendu, reçu %d %s", s.Statut, corps)
	}
	// relais qui ferme sans répondre (SO_PEERCRED refusé) : 502 aussi
	f := demarrerFauxRelais(t, func(relais.Demande) string { return "" })
	c = clientHTTP(t, f.chemin, toujours(true))
	if s, _ := lireSortie(t, c.traiterHTTP(context.Background(), demandeHTTP("GET", "/api/v1/system/x", "lecture", nil))); s.Statut != 502 {
		t.Fatalf("relais muet : 502 attendu, reçu %d", s.Statut)
	}
}

func TestAgentHTTPDelai504(t *testing.T) {
	f := demarrerFauxRelais(t, func(d relais.Demande) string { time.Sleep(2 * time.Second); return repondreOK(d) })
	c := clientHTTP(t, f.chemin, toujours(true))
	c.cfg.DelaiHTTP = 100 * time.Millisecond
	debut := time.Now()
	s, _ := lireSortie(t, c.traiterHTTP(context.Background(), demandeHTTP("GET", "/api/v1/system/x", "lecture", nil)))
	if s.Statut != 504 || time.Since(debut) > time.Second {
		t.Fatalf("504 au délai attendu, reçu %d en %s", s.Statut, time.Since(debut))
	}
}

func TestAgentHTTPAncreNonVerifiee(t *testing.T) {
	f := demarrerFauxRelais(t, repondreOK)
	c := clientHTTP(t, f.chemin, toujours(true))
	c.verdict.Store(AncreAbsente)
	s, _ := lireSortie(t, c.traiterHTTP(context.Background(), demandeHTTP("GET", "/api/v1/system/x", "lecture", nil)))
	if s.Statut != 403 || f.appels.Load() != 0 {
		t.Fatalf("ancre non vérifiée : 403 sans appel attendu, reçu %d", s.Statut)
	}
}

func TestAgentHTTPSansRelaisConfigure(t *testing.T) {
	c := clientHTTP(t, "", toujours(true))
	if s, _ := lireSortie(t, c.traiterHTTP(context.Background(), demandeHTTP("GET", "/api/v1/system/x", "lecture", nil))); s.Statut != 501 {
		t.Fatalf("501 attendu, reçu %d", s.Statut)
	}
}

func TestAgentHTTPPlafondDeConcurrence(t *testing.T) {
	libere := make(chan struct{})
	f := demarrerFauxRelais(t, func(d relais.Demande) string { <-libere; return repondreOK(d) })
	c := clientHTTP(t, f.chemin, toujours(true))
	poste := make(chan []byte, 8)
	c.posterHTTP = func(_ context.Context, _ string, sortie []byte) { poste <- sortie }
	ctx := context.Background()
	for i := 0; i < HTTPSimultanesDefaut; i++ {
		if !c.lancerHTTP(ctx, "000000000000000"+string(rune('a'+i)), demandeHTTP("GET", "/api/v1/system/x", "lecture", nil)) {
			t.Fatalf("requête %d refusée sous le plafond", i)
		}
	}
	if c.lancerHTTP(ctx, "00000000000000ff", demandeHTTP("GET", "/api/v1/system/x", "lecture", nil)) {
		t.Fatal("au-delà du plafond (4), la requête doit être refusée")
	}
	close(libere)
	for i := 0; i < HTTPSimultanesDefaut; i++ {
		select {
		case <-poste:
		case <-time.After(3 * time.Second):
			t.Fatal("réponse HTTP non postée")
		}
	}
	c.suivi.Wait()
	if !c.lancerHTTP(ctx, "00000000000000fe", demandeHTTP("GET", "/api/v1/system/x", "lecture", nil)) {
		t.Fatal("places rendues : la requête doit passer")
	}
	<-poste
	c.suivi.Wait()
}

// Bout à bout : le maître dépose un message HTTP, l'agent répond HTTP_RESP par POST /canal/v1/http.
func TestAgentHTTPAllerRetourParLeCanal(t *testing.T) {
	f := demarrerFauxRelais(t, repondreOK)
	m := &fauxMaitre{}
	msg := `[{"msg_id":"00000000000000a1","type":"HTTP","body":` + string(demandeHTTP("GET", "/api/v1/system/status?x=1", "lecture", nil)) + `}]`
	m.requetes = []string{msg}
	stop := demarrerAvec(t, m, modeleTest(nil), nil, nil, func(c *Client) {
		c.cfg.CheminRelais = f.chemin
		c.cfg.PorteeAdmin = toujours(true)
	})
	defer stop()
	attendreCond(t, m, "HTTP_RESP", func() bool { return len(m.http) > 0 })
	m.mu.Lock()
	defer m.mu.Unlock()
	var rep struct {
		MsgID string          `json:"msg_id"`
		Type  string          `json:"type"`
		Body  json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal(m.http[0], &rep); err != nil {
		t.Fatal(err)
	}
	if rep.MsgID != "00000000000000a1" || rep.Type != "HTTP_RESP" {
		t.Fatalf("réponse inattendue : %+v", rep)
	}
	if s, corps := lireSortie(t, rep.Body); s.Statut != 200 || corps != `{"ok":true}` {
		t.Fatalf("sortie du relais non transmise telle quelle : %d %s", s.Statut, corps)
	}
	if len(m.reponses) != 0 {
		t.Fatal("HTTP_RESP ne passe pas par /reponses (256 Kio)")
	}
}
