// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package api

import (
	"encoding/binary"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/audio"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/moteur"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/ser"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/store"
)

func serveur(t *testing.T) (*Serveur, *httptest.Server) {
	t.Helper()
	db, err := store.Ouvre(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Ferme() })
	s := &Serveur{Sessions: NouveauRegistre(db), Store: db, Version: "test"}
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)
	return s, srv
}

// SANS SESSION, ON NE REND NI ERREUR NI HUMEUR. Une 404 ferait croire à une
// panne ; un état ferait croire à une mesure. Personne n'écoute, c'est tout.
func TestSansSessionLaReponseEstHonnete(t *testing.T) {
	_, srv := serveur(t)
	r, err := http.Get(srv.URL + "/api/mood")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("code %d", r.StatusCode)
	}
	var h Humeur
	json.NewDecoder(r.Body).Decode(&h)
	if h.Etat != ser.Indetermine {
		t.Errorf("état %q sans personne à écouter", h.Etat)
	}
	if h.Confiance != 0 {
		t.Errorf("confiance %v", h.Confiance)
	}
	if h.Reserve == "" {
		t.Error("la réserve doit accompagner même une réponse vide")
	}
	if !strings.Contains(strings.Join(h.Pourquoi, " "), "aucune session") {
		t.Errorf("le motif n'est pas explicite : %v", h.Pourquoi)
	}
}

// LE CONTRAT ANNONCÉ DOIT ÊTRE TENU AU CHAMP PRÈS : state, confidence, pitch,
// energy, speech_rate. Quelqu'un écrit du code contre ces noms-là.
func TestLaFormeDeLaReponseSuitLeContrat(t *testing.T) {
	_, srv := serveur(t)
	r, err := http.Get(srv.URL + "/api/mood")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var brut map[string]any
	json.NewDecoder(r.Body).Decode(&brut)
	for _, champ := range []string{"state", "confidence", "pitch", "energy", "speech_rate"} {
		if _, ok := brut[champ]; !ok {
			t.Errorf("champ %q absent de la réponse", champ)
		}
	}
	// Et les garde-fous voyagent avec.
	for _, champ := range []string{"reserve", "pourquoi", "calibration", "session"} {
		if _, ok := brut[champ]; !ok {
			t.Errorf("garde-fou %q absent : le chiffre voyagerait seul", champ)
		}
	}
}

func TestLaSanteDitCeQuElleSaitEtCeQuElleIgnore(t *testing.T) {
	_, srv := serveur(t)
	r, err := http.Get(srv.URL + "/api/sante")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var m map[string]any
	json.NewDecoder(r.Body).Decode(&m)
	if m["plafond_confiance"] == nil {
		t.Error("le plafond de confiance doit être publié : c'est une garantie, pas un détail")
	}
	if m["reserve"] == nil {
		t.Error("la réserve doit être publiée")
	}
	// Sur une machine sans micro, le motif doit l'expliquer plutôt que de
	// laisser une liste vide sans commentaire.
	if m["entrees_locales"] == nil && m["entrees_motif"] == "" {
		t.Error("pas d'entrée locale et aucun motif : impossible de comprendre")
	}
}

// ── LA WEBSOCKET ───────────────────────────────────────────────────────────

func wsURL(srv *httptest.Server) string {
	return "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/mood"
}

func TestLaWebSocketAccepteDuSonEtRendDesImages(t *testing.T) {
	_, srv := serveur(t)
	c, _, err := websocket.DefaultDialer.Dial(wsURL(srv), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var accueil message
	if err := c.ReadJSON(&accueil); err != nil {
		t.Fatal(err)
	}
	if accueil.Type != "pret" || accueil.Session == "" {
		t.Fatalf("accueil inattendu : %+v", accueil)
	}
	if accueil.Reserve == "" {
		t.Error("la réserve doit être annoncée dès l'ouverture")
	}

	// Une seconde de voyelle à 130 Hz, en blocs de 20 ms.
	const bloc = audio.Echantillonnage / 50
	go func() {
		for i := 0; i < 60; i++ {
			b := make([]byte, bloc*2)
			for j := 0; j < bloc; j++ {
				n := i*bloc + j
				tt := float64(n) / audio.Echantillonnage
				v := 0.3 * (math.Sin(2*math.Pi*130*tt) + 0.5*math.Sin(2*math.Pi*260*tt) +
					0.3*math.Sin(2*math.Pi*820*tt))
				binary.LittleEndian.PutUint16(b[2*j:], uint16(int16(v*32767)))
			}
			c.WriteMessage(websocket.BinaryMessage, b)
			time.Sleep(5 * time.Millisecond)
		}
	}()

	deadline := time.Now().Add(6 * time.Second)
	var vue moteur.Image
	for time.Now().Before(deadline) {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		var img moteur.Image
		if err := c.ReadJSON(&img); err != nil {
			t.Fatalf("lecture : %v", err)
		}
		if img.Pitch > 100 && img.Pitch < 200 {
			vue = img
			break
		}
	}
	if vue.Pitch == 0 {
		t.Fatal("aucune image n'a porté la hauteur du signal envoyé")
	}
	if len(vue.FFT) != moteur.BandesAffichees {
		t.Errorf("%d bandes spectrales", len(vue.FFT))
	}
	if vue.Reserve == "" && vue.Etat != ser.Indetermine {
		t.Error("une image qui affirme un état doit porter sa réserve")
	}
}

// ON NE RÉÉCHANTILLONNE PAS EN SILENCE : un flux à 44,1 kHz lu comme du 48
// décalerait toutes les hauteurs de 8,8 %, presque un demi-ton et demi.
func TestUnEchantillonnageInattenduEstRefuseExplicitement(t *testing.T) {
	_, srv := serveur(t)
	c, _, err := websocket.DefaultDialer.Dial(wsURL(srv), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var accueil message
	c.ReadJSON(&accueil)
	c.WriteJSON(message{Type: "bonjour", Echantillonnage: 44100})

	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		var m message
		if err := c.ReadJSON(&m); err != nil {
			t.Fatal("aucun refus explicite n'a été envoyé")
		}
		if m.Type == "refus" {
			if !strings.Contains(m.Motif, "48") {
				t.Errorf("motif peu utile : %q", m.Motif)
			}
			return
		}
	}
}

// Une session fermée ne doit rien laisser derrière elle.
func TestUneSessionFermeeEstOubliee(t *testing.T) {
	s, srv := serveur(t)
	c, _, err := websocket.DefaultDialer.Dial(wsURL(srv), nil)
	if err != nil {
		t.Fatal(err)
	}
	var accueil message
	c.ReadJSON(&accueil)
	if s.Sessions.Nombre() != 1 {
		t.Fatalf("%d sessions", s.Sessions.Nombre())
	}
	c.Close()
	for i := 0; i < 100 && s.Sessions.Nombre() != 0; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if n := s.Sessions.Nombre(); n != 0 {
		t.Fatalf("%d session(s) restante(s) après fermeture", n)
	}
	if _, ok := s.Sessions.Par(accueil.Session); ok {
		t.Error("l'identifiant de session survit à la fermeture")
	}
}

// ── LA CONFIDENTIALITÉ ─────────────────────────────────────────────────────

func TestLOubliEfface(t *testing.T) {
	s, srv := serveur(t)
	s.Store.Enregistre(store.Resume{
		Minute: time.Now().Truncate(time.Minute).Unix(), Session: "x", Energie: 1})
	r, err := http.Post(srv.URL+"/api/mood/oubli", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var m map[string]any
	json.NewDecoder(r.Body).Decode(&m)
	if m["efface"].(float64) != 1 {
		t.Fatalf("%v lignes effacées", m["efface"])
	}
	res, _ := s.Store.Depuis(time.Time{}, 10)
	if len(res) != 0 {
		t.Fatalf("%d lignes subsistent", len(res))
	}
}

func TestLOubliRefuseLeGET(t *testing.T) {
	// Un effacement ne doit pas pouvoir être déclenché par une simple visite
	// d'URL — ni par un préchargeur de navigateur.
	_, srv := serveur(t)
	r, err := http.Get(srv.URL + "/api/mood/oubli")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("code %d pour un GET sur /oubli", r.StatusCode)
	}
}

// LE MICRO EST UNE PERMISSION : seule une page servie par la box peut ouvrir
// le flux. Sans ce contrôle, n'importe quel site pourrait, depuis un onglet,
// pousser du son vers la board.
func TestUneOrigineEtrangereEstRefusee(t *testing.T) {
	_, srv := serveur(t)
	h := http.Header{}
	h.Set("Origin", "https://exemple-malveillant.test")
	if _, _, err := websocket.DefaultDialer.Dial(wsURL(srv), h); err == nil {
		t.Fatal("une origine étrangère a pu ouvrir la WebSocket")
	}
}

func TestLaMemeOrigineEstAcceptee(t *testing.T) {
	_, srv := serveur(t)
	h := http.Header{}
	h.Set("Origin", srv.URL)
	c, _, err := websocket.DefaultDialer.Dial(wsURL(srv), h)
	if err != nil {
		t.Fatalf("la page servie par la box est refusée : %v", err)
	}
	c.Close()
}

// L'API ne doit pas être mise en cache : un indice d'humeur relu plus tard
// n'est pas une information, c'est un malentendu.
func TestLesReponsesNeSontPasMisesEnCache(t *testing.T) {
	_, srv := serveur(t)
	for _, chemin := range []string{"/api/mood", "/api/sante", "/api/mood/traits"} {
		r, err := http.Get(srv.URL + chemin)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if cc := r.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
			t.Errorf("%s : Cache-Control = %q", chemin, cc)
		}
	}
}
