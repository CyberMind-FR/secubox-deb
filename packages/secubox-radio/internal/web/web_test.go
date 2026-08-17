package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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

// ── LA PAGE D'ECOUTE ────────────────────────────────────────────────────────

// LA PAGE EST EMBARQUEE : un fichier manquant sur le disque donnerait une page
// blanche sans rien dire.
func TestLaPageDEcouteEstServieAuxMembres(t *testing.T) {
	s, _ := banc(t)
	w := appel(s, "GET", "/", membre, nil, false)
	if w.Code != http.StatusOK {
		t.Fatalf("code %d", w.Code)
	}
	corps := w.Body.String()
	for _, attendu := range []string{"<video id=\"ecran\"", "radio.js", "radio.css", "id=\"chat\""} {
		if !strings.Contains(corps, attendu) {
			t.Errorf("la page ne contient pas %q", attendu)
		}
	}
}

// LA PAGE EST SERVIE A TOUT LE MONDE, ET C'EST DELIBERE.
//
// La premiere version exigeait le cookie de pseudonyme que SEULE CETTE PAGE
// sait poser : un premier visiteur recevait un 401 en JSON, affiche par le
// navigateur dans son visualiseur. La porte demandait la cle qu'elle etait
// chargee de donner. Constate dans Firefox.
func TestLaPageDEcouteEstServieAUnPremierVisiteur(t *testing.T) {
	s, _ := banc(t)
	w := appel(s, "GET", "/", dehors, nil, false)
	if w.Code != http.StatusOK {
		t.Fatalf("un premier visiteur recoit %d : il ne peut pas entrer", w.Code)
	}
	if !strings.Contains(w.Body.String(), "id=\"ecran\"") {
		t.Error("la page servie n'est pas la page d'ecoute")
	}
}

// ...MAIS LES GESTES ET LES CLIPS RESTENT FERMES. On entre dans la salle, on ne
// prend pas le micro.
func TestUnInconnuNePeutNiParlerNiEcouterLesClips(t *testing.T) {
	s, st := banc(t)
	p, _, _ := st.Ajoute("https://youtu.be/ABC", "T", 1, t0)
	_ = st.PoseCache(p.ID, "/x", "video/mp4", 0, 1000, "T", "")

	if w := appel(s, "POST", "/api/v1/radio/chat", dehors,
		map[string]string{"corps": "coucou"}, true); w.Code != http.StatusUnauthorized {
		t.Errorf("un inconnu a parle : %d", w.Code)
	}
	if w := appel(s, "POST", "/api/v1/radio/propositions", dehors,
		map[string]string{"source": "https://youtu.be/X"}, true); w.Code != http.StatusUnauthorized {
		t.Errorf("un inconnu a propose : %d", w.Code)
	}
	if w := get(s, "/media/"+itoa(p.ID), dehors, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("un inconnu obtient un clip : %d", w.Code)
	}
}

// LA POLITIQUE EST STRICTE, ET ELLE PEUT L'ETRE : tout vient de nous, clips
// compris. C'est tout l'interet de les rapatrier plutot que d'embarquer un
// lecteur tiers — celui-ci aurait exige d'ouvrir `script-src` a Google.
func TestLaPolitiqueDeLaPageNOuvreRienVersLExterieur(t *testing.T) {
	s, _ := banc(t)
	csp := appel(s, "GET", "/", membre, nil, false).Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("aucune politique de securite de contenu")
	}
	for _, d := range []string{"default-src 'self'", "media-src 'self'", "script-src 'self'"} {
		if !strings.Contains(csp, d) {
			t.Errorf("directive manquante : %s\n%s", d, csp)
		}
	}
	for _, interdit := range []string{"unsafe-inline", "unsafe-eval", "youtube", "*"} {
		if strings.Contains(csp, interdit) {
			t.Errorf("la politique contient %q :\n%s", interdit, csp)
		}
	}
}

// Le script de synchronisation doit corriger la latence : sans cela chaque
// auditeur accumule son propre retard et la synchronisation derive.
func TestLeScriptCorrigeLaLatenceEtNeRendPasLeCorpsEnBalisage(t *testing.T) {
	b, err := statique.ReadFile("static/radio.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	if !strings.Contains(js, "dernierAppel") {
		t.Error("la latence n'est pas mesuree : la synchronisation derivera")
	}
	if !strings.Contains(js, "X-Sbx-Radio") {
		t.Error("l'en-tete d'intention n'est pas envoye : toute ecriture sera refusee")
	}
	// LE CORPS D'UNE PHRASE NE DEVIENT JAMAIS DU BALISAGE. C'est ici la seule
	// barriere cote client, et elle suffit — a condition de ne pas la contourner.
	if strings.Contains(js, "innerHTML = ' ' +") || strings.Contains(js, ".innerHTML = p.") {
		t.Error("le corps d'une phrase est injecte en balisage")
	}
	if !strings.Contains(js, "textContent") {
		t.Error("le chat n'utilise pas textContent")
	}
}

// LES DEUX CHEMINS DOIVENT REPONDRE.
//
// Le vhost transmet `/api/v1/radio/...` ; l'agregateur RETIRE le prefixe et la
// meme requete arrive comme `/...`. Un module qui n'ecoute que sur l'un rend
// 404 sur l'autre, sans rien dans les journaux — du point de vue du serveur, la
// route n'existe pas. Ce defaut a deja coute une soiree sur un autre module.
func TestLesRoutesRepondentAvecEtSansPrefixe(t *testing.T) {
	s, st := banc(t)
	p, _, _ := st.Ajoute("https://youtu.be/ABC", "T", 1, t0)

	for _, chemin := range []string{
		"/api/v1/radio/playlist", "/playlist",
		"/api/v1/radio/current", "/current",
		"/api/v1/radio/propositions", "/propositions",
	} {
		if w := appel(s, "GET", chemin, membre, nil, false); w.Code != http.StatusOK {
			t.Errorf("%s rend %d", chemin, w.Code)
		}
	}
	// ...y compris les gestes portant un identifiant.
	for _, chemin := range []string{
		"/api/v1/radio/pistes/" + itoa(p.ID) + "/coeur",
		"/pistes/" + itoa(p.ID) + "/coeur",
	} {
		if w := appel(s, "POST", chemin, membre, nil, true); w.Code != http.StatusOK {
			t.Errorf("%s rend %d", chemin, w.Code)
		}
	}
}

// ── SUPPRESSION ─────────────────────────────────────────────────────────────

func TestSeulLeSysopSupprime(t *testing.T) {
	s, st := banc(t)
	p, _, _ := st.Ajoute("https://youtu.be/ABC", "T", 1, t0)
	if w := appel(s, "POST", "/api/v1/radio/pistes/"+itoa(p.ID)+"/supprimer",
		membre, nil, true); w.Code != http.StatusForbidden {
		t.Errorf("un membre a supprime : %d", w.Code)
	}
	if _, err := st.ParID(p.ID); err != nil {
		t.Error("la piste a disparu malgre le refus")
	}
	if w := appel(s, "POST", "/api/v1/radio/pistes/"+itoa(p.ID)+"/supprimer",
		sysop, nil, true); w.Code != http.StatusOK {
		t.Fatalf("le sysop n'a pas pu supprimer : %d %s", w.Code, w.Body)
	}
	if _, err := st.ParID(p.ID); err == nil {
		t.Error("la piste est toujours la")
	}
}

// SUPPRIMER N'EST PAS REFUSER. Refuser garde la ligne et empeche la
// reproposition ; supprimer efface tout, donc la piste peut revenir.
func TestUnePisteSupprimeePeutEtreReproposee(t *testing.T) {
	s, st := banc(t)
	p, _, _ := st.Ajoute("https://youtu.be/ABC", "T", 1, t0)
	appel(s, "POST", "/api/v1/radio/pistes/"+itoa(p.ID)+"/supprimer", sysop, nil, true)

	w := appel(s, "POST", "/api/v1/radio/propositions", membre,
		map[string]string{"source": "https://youtu.be/ABC"}, true)
	if w.Code != http.StatusCreated {
		t.Errorf("une piste supprimee ne peut pas revenir : %d %s", w.Code, w.Body)
	}
}

// LA SUPPRESSION N'EFFACE PAS CE QUI S'EST DIT PENDANT. Les phrases perdent
// leur lien, pas leur contenu.
func TestSupprimerUnePisteGardeLaConversation(t *testing.T) {
	s, st := banc(t)
	p, _, _ := st.Ajoute("https://youtu.be/ABC", "T", 1, t0)
	if _, err := st.Dis(2, "alice", "celle-la est terrible", p.ID, t0); err != nil {
		t.Fatal(err)
	}
	appel(s, "POST", "/api/v1/radio/pistes/"+itoa(p.ID)+"/supprimer", sysop, nil, true)

	l, err := st.Depuis(0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 1 || l[0].Corps != "celle-la est terrible" {
		t.Errorf("la conversation a disparu avec la piste : %+v", l)
	}
}

// LE REPERTOIRE DOIT POUVOIR SE VIDER, MEME DE SA DERNIERE PISTE.
//
// Ma premiere version refusait, pour ne pas laisser les auditeurs sur un
// lecteur mort. C'etait se proteger d'un etat DEJA TRAITE : le silence est un
// etat de premiere classe et la page le dit. Le refus rendait le repertoire
// impossible a vider — constate en essayant de faire le menage.
func TestOnPeutSupprimerLaDernierePisteEtTomberAuSilence(t *testing.T) {
	s, st := banc(t)
	p, _, _ := st.Ajoute("https://youtu.be/ABC", "T", 1, t0)
	_ = st.PoseCache(p.ID, "/x", "video/mp4", 0, 180000, "T", "")
	appel(s, "GET", "/api/v1/radio/current", membre, nil, false) // elle passe

	w := appel(s, "POST", "/api/v1/radio/pistes/"+itoa(p.ID)+"/supprimer", sysop, nil, true)
	if w.Code != http.StatusOK {
		t.Fatalf("le menage est refuse : %d %s", w.Code, w.Body)
	}
	if _, err := st.ParID(p.ID); err == nil {
		t.Error("la piste est toujours la")
	}
	// ...et la radio DIT le silence, elle n'echoue pas.
	w = appel(s, "GET", "/api/v1/radio/current", membre, nil, false)
	if w.Code != http.StatusOK {
		t.Fatalf("la radio vide rend %d", w.Code)
	}
	var d struct{ Silence bool }
	json.Unmarshal(w.Body.Bytes(), &d)
	if !d.Silence {
		t.Error("la radio vide ne dit pas le silence")
	}
}

// ...MAIS AVEC UNE AUTRE PISTE DISPONIBLE, ON AVANCE PUIS ON SUPPRIME.
func TestSupprimerLaPisteEnCoursAvanceDAbord(t *testing.T) {
	s, st := banc(t)
	a, _, _ := st.Ajoute("https://youtu.be/A", "A", 1, t0)
	b, _, _ := st.Ajoute("https://youtu.be/B", "B", 1, t0)
	_ = st.PoseCache(a.ID, "/a", "video/mp4", 0, 180000, "A", "")
	_ = st.PoseCache(b.ID, "/b", "video/mp4", 0, 180000, "B", "")

	w := appel(s, "GET", "/api/v1/radio/current", membre, nil, false)
	var d struct {
		Piste vuePiste
	}
	json.Unmarshal(w.Body.Bytes(), &d)
	enCours := d.Piste.ID
	if enCours == 0 {
		t.Fatal("aucune piste a l'antenne")
	}
	if w := appel(s, "POST", "/api/v1/radio/pistes/"+itoa(enCours)+"/supprimer",
		sysop, nil, true); w.Code != http.StatusOK {
		t.Fatalf("suppression refusee : %d %s", w.Code, w.Body)
	}
	if _, err := st.ParID(enCours); err == nil {
		t.Error("la piste n'a pas ete supprimee")
	}
	// L'antenne joue autre chose, elle n'est pas restee sur un fantome.
	w = appel(s, "GET", "/api/v1/radio/current", membre, nil, false)
	json.Unmarshal(w.Body.Bytes(), &d)
	if d.Piste.ID == enCours || d.Piste.ID == 0 {
		t.Errorf("l'antenne est restee sur la piste supprimee (%d)", d.Piste.ID)
	}
}

// ── DEVALIDER ───────────────────────────────────────────────────────────────
//
// TROIS GESTES, TROIS PORTEES : devalider dit « pas maintenant », refuser dit
// « jamais », supprimer efface. Les confondre serait perdre la nuance qui rend
// la validation utile.
func TestDevaliderRenvoieEnFileEtGardeLesCoeurs(t *testing.T) {
	s, st := banc(t)
	p, _, _ := st.Ajoute("https://youtu.be/ABC", "T", 1, t0)
	_ = st.PoseCoeur(p.ID, 5, "bob", t0)
	_ = st.PoseCoeur(p.ID, 6, "eve", t0)

	if w := appel(s, "POST", "/api/v1/radio/pistes/"+itoa(p.ID)+"/devalider",
		membre, nil, true); w.Code != http.StatusForbidden {
		t.Errorf("un membre a devalide : %d", w.Code)
	}
	if w := appel(s, "POST", "/api/v1/radio/pistes/"+itoa(p.ID)+"/devalider",
		sysop, nil, true); w.Code != http.StatusOK {
		t.Fatalf("devalidation refusee : %d %s", w.Code, w.Body)
	}
	q, err := st.ParID(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if q.Etat != store.EtatPropose {
		t.Errorf("etat = %q, attendu proposee", q.Etat)
	}
	if q.Coeurs != 2 {
		t.Errorf("%d coeurs apres devalidation : le soutien est perdu", q.Coeurs)
	}
	// Elle quitte l'antenne...
	if l, _ := st.Toutes(); len(l) != 0 {
		t.Error("la piste devalidee joue encore")
	}
	// ...et revient dans la file du sysop.
	if pr, _ := st.Propositions(); len(pr) != 1 {
		t.Error("la piste devalidee n'est pas dans la file de validation")
	}
}

// DEVALIDER N'EST PAS REFUSER : la piste peut etre revalidee, et une
// reproposition ne se heurte a rien.
func TestUnePisteDevalideePeutEtreRevalidee(t *testing.T) {
	s, st := banc(t)
	p, _, _ := st.Ajoute("https://youtu.be/ABC", "T", 1, t0)
	appel(s, "POST", "/api/v1/radio/pistes/"+itoa(p.ID)+"/devalider", sysop, nil, true)
	if w := appel(s, "POST", "/api/v1/radio/propositions/"+itoa(p.ID)+"/valider",
		sysop, nil, true); w.Code != http.StatusOK {
		t.Fatalf("revalidation refusee : %d", w.Code)
	}
	if q, _ := st.ParID(p.ID); q.Etat != store.EtatValide {
		t.Errorf("etat = %q", q.Etat)
	}
}

// UNE PISTE DEVALIDEE QUITTE L'ANTENNE IMMEDIATEMENT. Sans cela elle ne serait
// plus dans la playlist mais jouerait encore : le pire des deux mondes.
func TestDevaliderLaPisteEnCoursLaSortDeLAntenne(t *testing.T) {
	s, st := banc(t)
	p, _, _ := st.Ajoute("https://youtu.be/ABC", "T", 1, t0)
	_ = st.PoseCache(p.ID, "/x", "video/mp4", 0, 180000, "T", "")
	appel(s, "GET", "/api/v1/radio/current", membre, nil, false)

	appel(s, "POST", "/api/v1/radio/pistes/"+itoa(p.ID)+"/devalider", sysop, nil, true)

	w := appel(s, "GET", "/api/v1/radio/current", membre, nil, false)
	var d struct {
		Silence bool
		Piste   vuePiste
	}
	json.Unmarshal(w.Body.Bytes(), &d)
	if d.Piste.ID == p.ID {
		t.Error("la piste devalidee passe encore a l'antenne")
	}
	if !d.Silence {
		t.Error("l'antenne ne dit pas le silence alors qu'il n'y a plus rien de valide")
	}
}
