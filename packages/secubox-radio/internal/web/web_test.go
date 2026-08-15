package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/programme"
	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/store"
	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/tirage"
)

var t0 = time.Date(2026, 8, 15, 20, 0, 0, 0, time.UTC)

const (
	entete = "X-Sbx-Radio"
	sysop  = "sysop"
	membre = "membre"
	dehors = "dehors"
)

// L'identite se lit dans un en-tete DE TEST : la vraie vient de
// l'authentification SecuBox, injectee a la construction.
func banc(t *testing.T) (*Serveur, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	prog := programme.Nouveau(st, tirage.Defaut(), 42)
	s := Nouveau(st, prog, func(r *http.Request) Visiteur {
		switch r.Header.Get("X-Test-Qui") {
		case sysop:
			return Visiteur{ID: 1, Pseudo: "gk2", Sysop: true, Connecte: true}
		case membre:
			return Visiteur{ID: 2, Pseudo: "alice", Connecte: true}
		}
		return Visiteur{}
	}, tirage.Defaut())
	s.Now = func() time.Time { return t0 }
	return s, st
}

func appel(s *Serveur, methode, chemin, qui string, corps any, intention bool) *httptest.ResponseRecorder {
	var body *bytes.Buffer = bytes.NewBuffer(nil)
	if corps != nil {
		json.NewEncoder(body).Encode(corps)
	}
	r := httptest.NewRequest(methode, chemin, body)
	if qui != dehors {
		r.Header.Set("X-Test-Qui", qui)
	}
	if intention {
		r.Header.Set(entete, "1")
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// ── LE PARTAGE DES DROITS ───────────────────────────────────────────────────

func TestUnMembreProposeMaisNeValidePas(t *testing.T) {
	s, st := banc(t)
	w := appel(s, "POST", "/api/v1/radio/propositions", membre,
		map[string]string{"source": "https://youtu.be/ABC"}, true)
	if w.Code != http.StatusCreated {
		t.Fatalf("proposition refusee : %d %s", w.Code, w.Body)
	}
	// Elle n'est PAS a l'antenne.
	if l, _ := st.Toutes(); len(l) != 0 {
		t.Error("la proposition d'un membre est passee directement a l'antenne")
	}
	// Et il ne peut pas la valider lui-meme.
	pr, _ := st.Propositions()
	w = appel(s, "POST", "/api/v1/radio/propositions/1/valider", membre, nil, true)
	if w.Code != http.StatusForbidden {
		t.Errorf("un membre a pu valider : %d", w.Code)
	}
	if p, _ := st.ParID(pr[0].ID); p.Etat != store.EtatPropose {
		t.Errorf("etat = %q apres tentative de validation par un membre", p.Etat)
	}
}

func TestLeSysopMetDirectementALAntenne(t *testing.T) {
	s, st := banc(t)
	w := appel(s, "POST", "/api/v1/radio/propositions", sysop,
		map[string]string{"source": "https://youtu.be/SYS"}, true)
	if w.Code != http.StatusCreated {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	l, _ := st.Toutes()
	if len(l) != 1 {
		t.Errorf("l'ajout du sysop n'est pas a l'antenne (%d pistes)", len(l))
	}
}

func TestLeSysopValideEtLaPisteEntre(t *testing.T) {
	s, st := banc(t)
	appel(s, "POST", "/api/v1/radio/propositions", membre,
		map[string]string{"source": "https://youtu.be/ABC"}, true)
	pr, _ := st.Propositions()
	w := appel(s, "POST", "/api/v1/radio/propositions/1/valider", sysop, nil, true)
	if w.Code != http.StatusOK {
		t.Fatalf("validation : %d %s", w.Code, w.Body)
	}
	if p, _ := st.ParID(pr[0].ID); p.Etat != store.EtatValide {
		t.Errorf("etat = %q", p.Etat)
	}
}

// LA FILE EST VISIBLE DE TOUS LES MEMBRES : le tri par soutien n'aurait aucun
// sens si elle ne l'etait pas — on ne soutient pas ce qu'on ne voit pas.
func TestLaFileEstVisibleDeTousLesMembres(t *testing.T) {
	s, _ := banc(t)
	appel(s, "POST", "/api/v1/radio/propositions", membre,
		map[string]string{"source": "https://youtu.be/ABC"}, true)
	w := appel(s, "GET", "/api/v1/radio/propositions", membre, nil, false)
	if w.Code != http.StatusOK {
		t.Fatalf("un membre ne voit pas la file : %d", w.Code)
	}
	var d struct {
		Propositions []vuePiste
	}
	json.Unmarshal(w.Body.Bytes(), &d)
	if len(d.Propositions) != 1 {
		t.Errorf("%d propositions vues par un membre", len(d.Propositions))
	}
	// ...mais pas de qui n'est pas connecte.
	if w := appel(s, "GET", "/api/v1/radio/propositions", dehors, nil, false); w.Code != http.StatusUnauthorized {
		t.Errorf("la file est servie a un inconnu : %d", w.Code)
	}
}

// ── FERME PAR DEFAUT ────────────────────────────────────────────────────────
//
// Sans resolveur d'identite, personne n'est connecte et rien n'est permis :
// une installation mal cablee refuse, elle ne s'ouvre pas.
func TestSansResolveurDIdentiteToutEstRefuse(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := Nouveau(st, programme.Nouveau(st, tirage.Defaut(), 1), nil, tirage.Defaut())
	w := appel(s, "POST", "/api/v1/radio/propositions", sysop,
		map[string]string{"source": "https://youtu.be/X"}, true)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("une installation sans authentification accepte les ecritures : %d", w.Code)
	}
}

// ── L'EN-TETE D'INTENTION ───────────────────────────────────────────────────
//
// Une API JSON n'a pas de formulaire, donc pas de jeton anti-rejeu. La
// protection est ailleurs : un navigateur ne peut pas poser d'en-tete
// personnalise sur une requete inter-origines sans autorisation prealable,
// alors que le cookie de session, lui, serait joint automatiquement.
func TestUneRequeteForgeeSansEnteteEstRefusee(t *testing.T) {
	s, st := banc(t)
	w := appel(s, "POST", "/api/v1/radio/propositions", sysop,
		map[string]string{"source": "https://youtu.be/X"}, false) // pas d'en-tete
	if w.Code != http.StatusForbidden {
		t.Errorf("ecriture acceptee sans en-tete d'intention : %d", w.Code)
	}
	if l, _ := st.Toutes(); len(l) != 0 {
		t.Error("la requete forgee a ecrit")
	}
}

// ── LE CHAT VOYAGE AVEC LA SYNCHRONISATION ──────────────────────────────────
//
// C'est le point de conception : les auditeurs interrogent deja `/current`
// pour rester cales. Le chat n'ouvre pas une seconde conversation reseau.
func TestLeChatVoyageDansLaReponseDeSynchronisation(t *testing.T) {
	s, st := banc(t)
	if _, err := st.Dis(2, "alice", "bonsoir", 0, t0); err != nil {
		t.Fatal(err)
	}
	w := appel(s, "GET", "/api/v1/radio/current", membre, nil, false)
	if w.Code != http.StatusOK {
		t.Fatalf("%d", w.Code)
	}
	var d struct {
		HorlogeMS int64 `json:"horloge_ms"`
		Silence   bool
		Chat      []store.Phrase
	}
	json.Unmarshal(w.Body.Bytes(), &d)
	if len(d.Chat) != 1 || d.Chat[0].Corps != "bonsoir" {
		t.Errorf("le chat n'accompagne pas la synchronisation : %+v", d.Chat)
	}
	// L'HORLOGE DU SERVEUR EST LA : sans elle chaque auditeur accumule sa
	// propre latence et la synchronisation derive.
	if d.HorlogeMS != t0.UnixMilli() {
		t.Errorf("horloge = %d", d.HorlogeMS)
	}
}

// LA CONVERSATION RESTE ENTRE NOUS : une radio peut s'ecouter de l'exterieur,
// le chat non.
func TestLeChatNestPasServiAuxInconnus(t *testing.T) {
	s, st := banc(t)
	_, _ = st.Dis(2, "alice", "entre nous", 0, t0)
	w := appel(s, "GET", "/api/v1/radio/current", dehors, nil, false)
	if bytes.Contains(w.Body.Bytes(), []byte("entre nous")) {
		t.Error("le chat est servi a un inconnu")
	}
}

func TestUnFlotDeChatRepond429(t *testing.T) {
	s, _ := banc(t)
	for i := 0; i < store.MaxParFenetre; i++ {
		if w := appel(s, "POST", "/api/v1/radio/chat", membre,
			map[string]string{"corps": "salut"}, true); w.Code != http.StatusCreated {
			t.Fatalf("phrase %d : %d", i, w.Code)
		}
	}
	w := appel(s, "POST", "/api/v1/radio/chat", membre, map[string]string{"corps": "encore"}, true)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("le flot rend %d au lieu de 429 : l'interface ne peut pas le distinguer d'une panne", w.Code)
	}
}

// ── COEURS ──────────────────────────────────────────────────────────────────

func TestUnMembreSoutientUneProposition(t *testing.T) {
	s, st := banc(t)
	appel(s, "POST", "/api/v1/radio/propositions", membre,
		map[string]string{"source": "https://youtu.be/ABC"}, true)
	pr, _ := st.Propositions()
	w := appel(s, "POST", "/api/v1/radio/propositions/1/coeur", sysop, nil, true)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if p, _ := st.ParID(pr[0].ID); p.Coeurs != 1 {
		t.Errorf("%d coeurs", p.Coeurs)
	}
	// Retirable, et par son auteur seulement.
	if w := appel(s, "DELETE", "/api/v1/radio/propositions/1/coeur", sysop, nil, true); w.Code != http.StatusOK {
		t.Fatalf("retrait : %d", w.Code)
	}
	if p, _ := st.ParID(pr[0].ID); p.Coeurs != 0 {
		t.Errorf("%d coeurs apres retrait", p.Coeurs)
	}
}

// ── REFUS ───────────────────────────────────────────────────────────────────

func TestUnRefusRenvoie409EtNonUneErreurNue(t *testing.T) {
	s, _ := banc(t)
	appel(s, "POST", "/api/v1/radio/propositions", membre,
		map[string]string{"source": "https://youtu.be/NON"}, true)
	appel(s, "POST", "/api/v1/radio/propositions/1/refuser", sysop,
		map[string]string{"motif": "hors sujet"}, true)

	w := appel(s, "POST", "/api/v1/radio/propositions", membre,
		map[string]string{"source": "https://youtu.be/NON"}, true)
	if w.Code != http.StatusConflict {
		t.Errorf("la reproposition rend %d, attendu 409 — l'interface doit pouvoir expliquer", w.Code)
	}
}

func TestSeulLeSysopPasseAuSuivant(t *testing.T) {
	s, _ := banc(t)
	if w := appel(s, "POST", "/api/v1/radio/suivante", membre, nil, true); w.Code != http.StatusForbidden {
		t.Errorf("un membre a pu changer de titre : %d", w.Code)
	}
}

// Le silence se DIT, il ne s'echoue pas.
func TestSansPisteLaSynchronisationDitLeSilence(t *testing.T) {
	s, _ := banc(t)
	w := appel(s, "GET", "/api/v1/radio/current", membre, nil, false)
	if w.Code != http.StatusOK {
		t.Fatalf("le silence rend %d au lieu de 200", w.Code)
	}
	var d struct{ Silence bool }
	json.Unmarshal(w.Body.Bytes(), &d)
	if !d.Silence {
		t.Error("l'etat ne signale pas le silence")
	}
}

// LA LISTE DES AIMEURS EST SERVIE AUX MEMBRES, et la decision est assumee :
// on n'aime pas de la meme facon quand on sait que ca se voit.
func TestLaListeDesAimeursEstServieAuxMembres(t *testing.T) {
	s, st := banc(t)
	p, _, _ := st.Ajoute("https://youtu.be/ABC", "T", 1, t0)
	appel(s, "POST", "/api/v1/radio/pistes/"+itoa(p.ID)+"/coeur", membre, nil, true)

	w := appel(s, "GET", "/api/v1/radio/playlist", membre, nil, false)
	var d struct{ Pistes []vuePiste }
	json.Unmarshal(w.Body.Bytes(), &d)
	if len(d.Pistes) != 1 {
		t.Fatalf("%d pistes", len(d.Pistes))
	}
	if len(d.Pistes[0].Aimeurs) != 1 {
		t.Fatalf("%d aimeurs servis", len(d.Pistes[0].Aimeurs))
	}
	if d.Pistes[0].Aimeurs[0].Pseudo != "alice" {
		t.Errorf("pseudo servi = %q", d.Pistes[0].Aimeurs[0].Pseudo)
	}
}

// ...mais pas aux inconnus : la radio s'ecoute de l'exterieur, savoir qui aime
// quoi non.
//
// LE TEST VISE `/playlist` ET NON `/current`, ET C'EST TOUT LE POINT. Ma
// premiere version interrogeait `/current`, qui rend le SILENCE a un inconnu
// tant qu'aucune piste n'est en cache : aucune vue de piste n'etait produite,
// donc rien ne pouvait fuir, et le test passait sans jamais exercer la garde.
// Verifie par mutation : il ne tombait pas quand on retirait le controle.
//
// `/playlist` rend des vues de pistes a qui les demande — c'est la que la fuite
// se produirait.
func TestLaListeDesAimeursNestPasServieAuxInconnus(t *testing.T) {
	s, st := banc(t)
	p, _, _ := st.Ajoute("https://youtu.be/ABC", "T", 1, t0)
	_ = st.PoseCoeur(p.ID, 2, "alice", t0)

	w := appel(s, "GET", "/api/v1/radio/playlist", dehors, nil, false)
	if !bytes.Contains(w.Body.Bytes(), []byte("ABC")) {
		t.Fatalf("le test n'exerce rien : aucune piste rendue (%d) %s", w.Code, w.Body)
	}
	if bytes.Contains(w.Body.Bytes(), []byte("alice")) {
		t.Error("la liste des aimeurs fuit vers un inconnu")
	}
}
