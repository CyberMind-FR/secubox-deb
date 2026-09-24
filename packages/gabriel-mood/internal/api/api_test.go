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
	// Chacun oublie SA session (#1371) : la voisine garde la sienne.
	s, srv := serveur(t)
	m0 := time.Now().Truncate(time.Minute).Unix()
	s.Store.Enregistre(store.Resume{Minute: m0, Session: "x", Energie: 1})
	s.Store.Enregistre(store.Resume{Minute: m0, Session: "voisine", Energie: 1})
	r, err := http.Post(srv.URL+"/api/mood/oubli?session=x", "", nil)
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
	if len(res) != 1 || res[0].Session != "voisine" {
		t.Fatalf("après oubli de x : %+v", res)
	}
}

func TestLOubliSansCibleNEffacePlusToutLeMonde(t *testing.T) {
	// LA FAUTE CORRIGÉE (#1371) : sans paramètre, la route publique vidait la
	// board entière — le bouton d'un visiteur effaçait tous les autres.
	s, srv := serveur(t)
	s.Store.Enregistre(store.Resume{
		Minute: time.Now().Truncate(time.Minute).Unix(), Session: "voisine", Energie: 1})
	r, err := http.Post(srv.URL+"/api/mood/oubli", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("code %d, attendu 400", r.StatusCode)
	}
	if res, _ := s.Store.Depuis(time.Time{}, 10); len(res) != 1 {
		t.Fatal("un oubli sans cible a effacé l'historique des autres")
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

// ── LA FUITE ENTRE SESSIONS ────────────────────────────────────────────────
//
// `GET /api/mood` rendait « la session la plus récemment active » quand aucune
// n'était nommée. Sur un réseau local avec une seule personne, la commodité ne
// coûtait rien ; ouvert au WAN, cela livrait à n'importe quel passant la
// lecture en direct de qui utilisait la page. C'est exactement la donnée dont
// tout ce module s'applique à dire qu'elle ne doit servir à évaluer personne.

func TestSansSessionNommeeOnNeLivrePasCelleDunAutre(t *testing.T) {
	s, srv := serveur(t)
	// Quelqu'un ouvre une session et parle.
	c, _, err := websocket.DefaultDialer.Dial(wsURL(srv), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var accueil message
	if err := c.ReadJSON(&accueil); err != nil {
		t.Fatal(err)
	}
	if s.Sessions.Nombre() != 1 {
		t.Fatalf("%d sessions", s.Sessions.Nombre())
	}

	// Un passant interroge l'API sans rien connaître.
	r, err := http.Get(srv.URL + "/api/mood")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var h Humeur
	json.NewDecoder(r.Body).Decode(&h)
	if h.Session != "" {
		t.Fatalf("l'identifiant de session d'un autre a fuité : %q", h.Session)
	}
	if h.Etat != ser.Indetermine {
		t.Errorf("état %q rendu à qui ne possède aucune session", h.Etat)
	}
}

// Et celui qui POSSÈDE la session la lit toujours : refermer la fuite ne doit
// pas casser l'usage légitime.
func TestAvecSonIdentifiantOnLitBienSaSession(t *testing.T) {
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
	r, err := http.Get(srv.URL + "/api/mood?session=" + accueil.Session)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var h Humeur
	json.NewDecoder(r.Body).Decode(&h)
	if h.Session != accueil.Session {
		t.Fatalf("session %q rendue pour %q", h.Session, accueil.Session)
	}
}

// ── LA PERSISTANCE DE LA RÉFÉRENCE ─────────────────────────────────────────
//
// C'est LE défaut signalé : « les étalonnages ne terminent pas », 6 %, 26 %,
// 27 %. Ce n'étaient pas des compteurs bloqués mais trois sessions, chacune
// repartie de zéro parce que la référence mourait avec la connexion.

func pousseVoix(t *testing.T, c *websocket.Conn, secondes float64) {
	t.Helper()
	const bloc = audio.Echantillonnage / 50 // 20 ms
	n := int(secondes * 50)
	for i := 0; i < n; i++ {
		b := make([]byte, bloc*2)
		for j := 0; j < bloc; j++ {
			k := i*bloc + j
			tt := float64(k) / audio.Echantillonnage
			env := 0.5 + 0.5*math.Sin(2*math.Pi*4*tt)
			v := 0.3 * env * (math.Sin(2*math.Pi*130*tt) +
				0.5*math.Sin(2*math.Pi*260*tt) + 0.3*math.Sin(2*math.Pi*820*tt))
			binary.LittleEndian.PutUint16(b[2*j:], uint16(int16(v*32767)))
		}
		if err := c.WriteMessage(websocket.BinaryMessage, b); err != nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func TestLaReferenceSurvitAuRechargement(t *testing.T) {
	s, srv := serveur(t)
	const cle = "a1b2c3d4e5f60718"

	// Première visite : on parle un peu.
	c1, _, err := websocket.DefaultDialer.Dial(wsURL(srv), nil)
	if err != nil {
		t.Fatal(err)
	}
	var accueil message
	if err := c1.ReadJSON(&accueil); err != nil {
		t.Fatal(err)
	}
	if err := c1.WriteJSON(message{Type: "bonjour", Ref: cle, Echantillonnage: 48000}); err != nil {
		t.Fatal(err)
	}
	// On laisse la lecture des images se faire, sinon le tampon d'écriture du
	// serveur se remplit et bloque l'analyse.
	go func() {
		for {
			var img moteur.Image
			if c1.ReadJSON(&img) != nil {
				return
			}
		}
	}()
	pousseVoix(t, c1, 3)
	time.Sleep(400 * time.Millisecond)
	c1.Close()

	// La référence doit avoir été enregistrée à la fermeture.
	var vue int
	for i := 0; i < 100; i++ {
		if r, ok := s.Store.ChargeReference(cle); ok && r.Observations() > 0 {
			vue = r.Observations()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if vue == 0 {
		t.Fatal("rien n'a été retenu : la référence meurt encore avec la session")
	}

	// Deuxième visite, même clé : on doit reprendre là où on s'était arrêté.
	c2, _, err := websocket.DefaultDialer.Dial(wsURL(srv), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	var a2 message
	if err := c2.ReadJSON(&a2); err != nil {
		t.Fatal(err)
	}
	if err := c2.WriteJSON(message{Type: "bonjour", Ref: cle, Echantillonnage: 48000}); err != nil {
		t.Fatal(err)
	}
	// ON LE DIT : reprendre en silence laisserait croire à une lecture née de
	// la session en cours.
	deadline := time.Now().Add(3 * time.Second)
	var repris bool
	for time.Now().Before(deadline) {
		c2.SetReadDeadline(time.Now().Add(2 * time.Second))
		var m message
		if err := c2.ReadJSON(&m); err != nil {
			break
		}
		if m.Type == "reprise" {
			repris = true
			if !strings.Contains(m.Motif, "retrouvée") {
				t.Errorf("motif de reprise peu clair : %q", m.Motif)
			}
			break
		}
	}
	if !repris {
		t.Fatal("la reprise n'est pas annoncée au navigateur")
	}
}

// UNE CLÉ FARFELUE N'ENTRE PAS DANS LA BASE. Elle vient d'un inconnu : on ne
// s'en sert pas comme d'un dépotoir.
func TestUneCleInvalideEstIgnoree(t *testing.T) {
	for _, c := range []string{"", "court", strings.Repeat("a", 65),
		"../../etc/passwd", "ZZZZZZZZZZZZZZZZ", "a1b2c3d4e5f6071!"} {
		if store.CleReference(c) {
			t.Errorf("clé acceptée à tort : %q", c)
		}
	}
	if !store.CleReference("a1b2c3d4e5f60718") {
		t.Error("une clé valide est refusée")
	}
}

// « OUBLIER » DOIT ATTEINDRE LA RÉFÉRENCE. En effacer l'historique en laissant
// ce qui permet de vous reconnaître n'oublierait rien.
func TestLOubliAtteintLaReference(t *testing.T) {
	s, srv := serveur(t)
	const cle = "b1b2c3d4e5f60718"
	r := ser.NouvelleReference()
	for i := 0; i < 50; i++ {
		r.Observe(ser.Traits{F0Median: 130 + float64(i%5), Energie: .3, Debit: 150,
			Jitter: .8, Centre: 1400, TramesVoisees: 60})
	}
	if err := s.Store.EnregistreReference(cle, r); err != nil {
		t.Fatal(err)
	}
	rep, err := http.Post(srv.URL+"/api/mood/oubli?ref="+cle, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	rep.Body.Close()
	if _, ok := s.Store.ChargeReference(cle); ok {
		t.Fatal("la référence survit à l'oubli")
	}
}
