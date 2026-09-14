// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func filigraneDEssai(t *testing.T) *Filigrane {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte("un-secret-local-assez-long-pour-etre-accepte"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := NewFiligrane(p)
	if f == nil {
		t.Fatal("filigrane non construit alors que le secret est valide")
	}
	return f
}

// ── Filigrane : la marque doit être infalsifiable et reconnaissable ──────────

func TestFiligrane_ReconnaitLesSiennesEtRienDAutre(t *testing.T) {
	f := filigraneDEssai(t)
	jeton, alea := f.Marque()
	if len(jeton) != filigraneHexLen || alea == "" {
		t.Fatalf("jeton mal formé : %q (aléa %q)", jeton, alea)
	}
	if !f.Reconnait(jeton) {
		t.Error("une marque que l'on vient de produire n'est pas reconnue")
	}
	// Un octet modifié doit casser la preuve.
	altere := []byte(jeton)
	altere[len(altere)-1] ^= 0x01
	if f.Reconnait(string(altere)) {
		t.Error("une marque altérée est acceptée : la preuve ne sert à rien")
	}
}

func TestFiligrane_UnAutreSecretNeReconnaitPas(t *testing.T) {
	a := filigraneDEssai(t)
	b := filigraneDEssai(t) // autre répertoire, même contenu ? non : même contenu.
	// Même contenu de secret → même clé. On en fabrique donc un VRAIMENT autre.
	p := filepath.Join(t.TempDir(), "autre")
	_ = os.WriteFile(p, []byte("un-autre-secret-local-totalement-different"), 0o600)
	b = NewFiligrane(p)

	jeton, _ := a.Marque()
	if b.Reconnait(jeton) {
		t.Error("une marque d'une autre box est reconnue comme nôtre")
	}
}

func TestFiligrane_LesMarquesNeSeRepetentPas(t *testing.T) {
	f := filigraneDEssai(t)
	vus := map[string]bool{}
	for i := 0; i < 500; i++ {
		j, _ := f.Marque()
		if vus[j] {
			t.Fatal("collision de filigrane : le semis ne serait plus traçable")
		}
		vus[j] = true
	}
}

func TestFiligrane_SansSecretOnNeMarquePasPlutotQueMalMarquer(t *testing.T) {
	var nul *Filigrane
	j, a := nul.Marque()
	if j != "" || a != "" {
		t.Error("une marque a été produite sans secret : elle serait invérifiable")
	}
	if nul.Reconnait("00000000000000000000000000000000") {
		t.Error("reconnaissance sans secret")
	}
	if nul.Cherche("texte quelconque") != nil {
		t.Error("recherche sans secret")
	}
}

func TestFiligrane_ChercheRetrouveUneMarqueQuiRevient(t *testing.T) {
	// LE SCÉNARIO QUI JUSTIFIE TOUT LE MÉCANISME : une fausse clé semée dans un
	// /.env revient dans une tentative d'authentification.
	f := filigraneDEssai(t)
	jeton, _ := f.Marque()
	corps := "username=admin&password=" + jeton + "&submit=login"

	trouves := f.Cherche(corps)
	if len(trouves) != 1 || trouves[0] != jeton {
		t.Fatalf("la marque semée n'est pas retrouvée : %v", trouves)
	}
	// Du bruit hexadécimal de même forme ne doit PAS être pris pour une marque.
	if got := f.Cherche("hash=" + strings.Repeat("ab", 16)); got != nil {
		t.Errorf("faux positif sur du hexadécimal quelconque : %v", got)
	}
}

// ── Le leurre : inerte, et seulement quand on l'a armé ──────────────────────

func TestLeurre_InactifParDefautLaisseLe421(t *testing.T) {
	l := NewLeurreHTTP(false, filigraneDEssai(t), nil)
	w := httptest.NewRecorder()
	servi, _, _, _ := l.Sert(w, httptest.NewRequest("GET", "http://inconnu.test/.env", nil), "inconnu.test")
	if servi {
		t.Fatal("le leurre a servi alors qu'il n'est pas armé")
	}
}

func TestLeurre_MethodesAdmises(t *testing.T) {
	// LE POST EST ADMIS DEPUIS QU'IL Y A UNE RAISON : rejouer une fausse clé,
	// c'est un POST. Sans lui, le moment le plus instructif de la boucle nous
	// resterait invisible. Le reste demeure refusé — rien n'y gagnerait.
	l := NewLeurreHTTP(true, filigraneDEssai(t), nil)
	for _, m := range []string{"GET", "HEAD", "POST"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(m, "http://inconnu.test/.env", strings.NewReader("x=1"))
		if servi, _, _, _ := l.Sert(w, r, "inconnu.test"); !servi {
			t.Errorf("%s devrait être servi", m)
		}
	}
	for _, m := range []string{"PUT", "DELETE", "PATCH", "OPTIONS"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(m, "http://inconnu.test/.env", strings.NewReader("x=1"))
		if servi, _, _, _ := l.Sert(w, r, "inconnu.test"); servi {
			t.Errorf("%s a été servi par le leurre", m)
		}
	}
}

func TestLeurre_LeCorpsPosteEstBorneALaLecture(t *testing.T) {
	// Le plafond doit s'appliquer À LA LECTURE : un corps énorme ne doit jamais
	// être chargé en mémoire, même pour être rejeté ensuite.
	l := NewLeurreHTTP(true, filigraneDEssai(t), nil)
	enorme := strings.NewReader(strings.Repeat("A", 4<<20)) // 4 Mio
	r := httptest.NewRequest("POST", "http://inconnu.test/wp-login.php", enorme)
	w := httptest.NewRecorder()
	if servi, _, _, _ := l.Sert(w, r, "inconnu.test"); !servi {
		t.Fatal("le leurre aurait dû servir malgré le corps démesuré")
	}
	// Il reste des octets non lus : la preuve qu'on s'est arrêté au plafond.
	reste, _ := io.ReadAll(enorme)
	if len(reste) == 0 {
		t.Error("tout le corps a été lu : le plafond n'a pas été appliqué")
	}
}

func TestLeurre_ReconnaitEtSimule(t *testing.T) {
	// « RECONNAÎTRE ET SIMULER » de bout en bout : l'outil moissonne une fausse
	// clé, la rejoue — et obtient ce qu'elle promet, donc il continue.
	fil := filigraneDEssai(t)
	l := NewLeurreHTTP(true, fil, nil)

	// 1. moisson
	w1 := httptest.NewRecorder()
	l.Sert(w1, httptest.NewRequest("GET", "http://inconnu.test/.env", nil), "inconnu.test")
	marques := fil.Cherche(w1.Body.String())
	if len(marques) == 0 {
		t.Fatal("rien n'a été semé")
	}

	// 2. il rejoue la clé volée dans un formulaire
	corps := "user=admin&pass=" + marques[0]
	r2 := httptest.NewRequest("POST", "http://inconnu.test/wp-login.php",
		strings.NewReader(corps))
	w2 := httptest.NewRecorder()
	servi, fam, _, _ := l.Sert(w2, r2, "inconnu.test")
	if !servi {
		t.Fatal("le rejeu n'a pas été servi")
	}

	// 3. on lui ouvre — et la page qu'il reçoit l'invite à se décrire.
	if fam != sondeEntree {
		t.Errorf("famille = %s, attendu %s (la marque rejouée doit être reconnue)",
			fam, sondeEntree)
	}
	body := w2.Body.String()
	for _, appat := range []string{"/admin/users", "/backup/db.sql", "/api/v1/keys"} {
		if !strings.Contains(body, appat) {
			t.Errorf("la page d'entrée ne propose pas %q", appat)
		}
	}
}

func TestLeurre_UnePagePourQuiNaRienRejoue(t *testing.T) {
	// Symétrique du précédent : sans marque rejouée, pas d'entrée simulée.
	// Sinon n'importe quel POST ouvrirait la porte et le signal ne vaudrait rien.
	l := NewLeurreHTTP(true, filigraneDEssai(t), nil)
	r := httptest.NewRequest("POST", "http://inconnu.test/wp-login.php",
		strings.NewReader("user=admin&pass=motdepasse123"))
	w := httptest.NewRecorder()
	_, fam, _, _ := l.Sert(w, r, "inconnu.test")
	if fam == sondeEntree {
		t.Fatal("une entrée a été simulée sans qu'aucune marque soit rejouée")
	}
}

func TestTheatre_MemoireBorneeEtExpirante(t *testing.T) {
	// Une carte indexée par IP est, telle quelle, un moyen offert à n'importe
	// qui de remplir la mémoire de la box : il suffit de varier l'adresse.
	th := NewTheatre(10, time.Hour)
	for i := 0; i < 100; i++ {
		th.Avance(th.Cle(fmt.Sprintf("203.0.113.%d", i), "emp"), sondeRacine, "")
	}
	if n := th.Taille(); n > 10 {
		t.Fatalf("mémoire non bornée : %d scènes pour un plafond de 10", n)
	}

	// Expiration : une scène trop vieille est oubliée.
	court := NewTheatre(10, time.Millisecond)
	court.Avance(court.Cle("203.0.113.1", "e"), sondeRacine, "")
	time.Sleep(5 * time.Millisecond)
	court.Avance(court.Cle("203.0.113.2", "e"), sondeRacine, "")
	if _, connu := court.Connu(court.Cle("203.0.113.1", "e")); connu {
		t.Error("une scène expirée est encore en mémoire")
	}
}

func TestTheatre_SuitLaSequenceQuiDecritLOutil(t *testing.T) {
	th := NewTheatre(10, time.Hour)
	cle := th.Cle("203.0.113.9", "emp")
	for _, f := range []familleSonde{sondeRacine, sondeSecret, sondeGit, sondeAdmin} {
		th.Avance(cle, f, "")
	}
	seq := th.Sequence(cle)
	if len(seq) != 4 || seq[0] != "racine" || seq[3] != "admin" {
		t.Fatalf("séquence = %v", seq)
	}
	// Deux outils derrière la MÊME adresse ne partagent pas de scène.
	if n, _ := th.Connu(th.Cle("203.0.113.9", "AUTRE-EMPREINTE")); n != 0 {
		t.Error("deux empreintes différentes partagent une scène")
	}
}

func TestTheatre_UneSceneNeGrossitPasIndefiniment(t *testing.T) {
	// Un fuzzer qui tire dix mille chemins ne doit pas faire enfler une entrée.
	th := NewTheatre(10, time.Hour)
	cle := th.Cle("203.0.113.4", "e")
	for i := 0; i < 5000; i++ {
		th.Avance(cle, sondeRacine, "alea")
	}
	if n := len(th.Sequence(cle)); n > 64 {
		t.Fatalf("scène de %d étapes : la borne n'est pas appliquée", n)
	}
}

func TestLeurre_ChaqueReponsePorteUneMarqueVerifiable(t *testing.T) {
	f := filigraneDEssai(t)
	l := NewLeurreHTTP(true, f, nil)
	for _, chemin := range []string{
		"/.env", "/.git/HEAD", "/wp-login.php", "/phpmyadmin/",
		"/phpinfo.php", "/dump.sql", "/",
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "http://inconnu.test"+chemin, nil)
		servi, _, alea, _ := l.Sert(w, r, "inconnu.test")
		if !servi {
			t.Fatalf("%s non servi", chemin)
		}
		if w.Code != http.StatusOK {
			t.Errorf("%s : code %d, un scanner s'arrêterait", chemin, w.Code)
		}
		if alea == "" {
			t.Errorf("%s : rien n'a été journalisé pour retrouver ce semis", chemin)
		}
		if len(f.Cherche(w.Body.String())) == 0 {
			t.Errorf("%s : le corps ne porte aucune marque vérifiable", chemin)
		}
	}
}

func TestLeurre_NeDivulgueRienDeLaVraieBox(t *testing.T) {
	// Le corps ne doit contenir aucun indice du produit : un scanner soigné qui
	// se sait face à un dispositif de sécurité change de comportement, et l'on
	// perd ce qu'on est venu observer.
	l := NewLeurreHTTP(true, filigraneDEssai(t), nil)
	interdits := []string{"secubox", "SecuBox", "sbxwaf", "cybermind", "gk2"}
	for _, chemin := range []string{"/.env", "/wp-login.php", "/phpinfo.php", "/"} {
		w := httptest.NewRecorder()
		l.Sert(w, httptest.NewRequest("GET", "http://inconnu.test"+chemin, nil), "inconnu.test")
		corps := w.Body.String()
		for _, mot := range interdits {
			if strings.Contains(corps, mot) {
				t.Errorf("%s : le corps révèle %q", chemin, mot)
			}
		}
		if w.Header().Get("Server") != "" {
			t.Errorf("%s : en-tête Server renseigné", chemin)
		}
	}
}

func TestLeurre_LeNomDHoteEstEchappe(t *testing.T) {
	// Le nom d'hôte est la SEULE valeur de l'attaquant qui réapparaît : elle
	// doit être inoffensive, sinon le leurre devient une faille de XSS.
	l := NewLeurreHTTP(true, filigraneDEssai(t), nil)
	w := httptest.NewRecorder()
	mechant := `x"><script>alert(1)</script>`
	l.Sert(w, httptest.NewRequest("GET", "http://x.test/", nil), mechant)
	corps := w.Body.String()
	if strings.Contains(corps, "<script>") {
		t.Fatalf("le nom d'hôte n'est pas échappé : %s", corps)
	}
}

func TestLeurre_ClasseLaSondeSelonCeQuElleCherche(t *testing.T) {
	cas := map[string]familleSonde{
		"/.env":                 sondeSecret,
		"/config/.env":          sondeSecret,
		"/.aws/credentials":     sondeSecret,
		"/.git/config":          sondeGit,
		"/wp-login.php":         sondeCMS,
		"/xmlrpc.php":           sondeCMS,
		"/phpmyadmin/index.php": sondeAdmin,
		"/phpinfo.php":          sondeInfo,
		"/actuator/env":         sondeInfo,
		"/backup.sql":           sondeSauvegarde,
		"/":                     sondeRacine,
		"/une/page/quelconque":  sondeRacine,
	}
	for chemin, attendu := range cas {
		if got := classeSonde(chemin); got != attendu {
			t.Errorf("%s → %s, attendu %s", chemin, got, attendu)
		}
	}
}

func TestLeurre_JournaliseCeQuIlSeme(t *testing.T) {
	var hote, chemin, alea string
	var fam familleSonde
	l := NewLeurreHTTP(true, filigraneDEssai(t),
		func(h, c string, f familleSonde, a string) { hote, chemin, fam, alea = h, c, f, a })
	w := httptest.NewRecorder()
	l.Sert(w, httptest.NewRequest("GET", "http://inconnu.test/.env", nil), "inconnu.test")
	if hote != "inconnu.test" || chemin != "/.env" || fam != sondeSecret || alea == "" {
		t.Fatalf("semis mal journalisé : %s %s %s %q", hote, chemin, fam, alea)
	}
}

// ── Empreinte comportementale ───────────────────────────────────────────────

func TestComportement_NavigateurEtOutilNeSeRessemblentPas(t *testing.T) {
	nav := httptest.NewRequest("GET", "http://x.test/page", nil)
	nav.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	nav.Header.Set("Accept-Language", "fr-FR,fr;q=0.9")
	nav.Header.Set("Accept-Encoding", "gzip, deflate, br")
	nav.Header.Set("Sec-Fetch-Mode", "navigate")
	nav.Header.Set("Sec-Fetch-Site", "none")
	nav.Header.Set("Upgrade-Insecure-Requests", "1")
	nav.Header.Set("Referer", "http://x.test/")
	nav.Header.Set("Cookie", "s=1")

	outil := httptest.NewRequest("GET", "http://x.test/.env", nil)
	outil.Header.Set("Accept", "*/*")

	tn := traitsComportementaux(nav)
	to := traitsComportementaux(outil)

	for _, mauvais := range []string{"entetes:aucun-trait-navigateur", "entetes:pauvres"} {
		for _, x := range tn {
			if x == mauvais {
				t.Errorf("un vrai navigateur est étiqueté %q", mauvais)
			}
		}
	}
	if len(to) == 0 {
		t.Error("un client sans aucun trait de navigateur ne produit aucune étiquette")
	}
}

func TestComportement_EmpreinteStableEtDiscriminante(t *testing.T) {
	mk := func(entetes map[string]string) *http.Request {
		r := httptest.NewRequest("GET", "http://x.test/", nil)
		for k, v := range entetes {
			r.Header.Set(k, v)
		}
		return r
	}
	a1 := signatureEnTetes(mk(map[string]string{"Accept": "*/*"}))
	a2 := signatureEnTetes(mk(map[string]string{"Accept": "text/html"}))
	b := signatureEnTetes(mk(map[string]string{"Accept": "*/*", "Accept-Language": "fr"}))

	// La VALEUR d'un en-tête ne doit pas changer l'empreinte — seule sa
	// présence compte, sinon l'empreinte ne regrouperait plus rien.
	if a1 != a2 {
		t.Error("l'empreinte dépend de la valeur des en-têtes, pas seulement de leur présence")
	}
	if a1 == b {
		t.Error("deux formes différentes donnent la même empreinte")
	}
}

func TestComportement_LesEntetesDeNosRelaisNePolluentPas(t *testing.T) {
	// X-Forwarded-For décrit NOTRE infrastructure. S'il entrait dans
	// l'empreinte, tout le trafic passé par HAProxy se ressemblerait.
	nu := httptest.NewRequest("GET", "http://x.test/", nil)
	nu.Header.Set("Accept", "*/*")
	relaye := httptest.NewRequest("GET", "http://x.test/", nil)
	relaye.Header.Set("Accept", "*/*")
	relaye.Header.Set("X-Forwarded-For", "203.0.113.1")
	relaye.Header.Set("X-Real-IP", "203.0.113.1")
	relaye.Header.Set("X-SecuBox-LAN", "0")

	if signatureEnTetes(nu) != signatureEnTetes(relaye) {
		t.Error("les en-têtes de relais changent l'empreinte du client")
	}
}

func TestComportement_DeductionSansUserAgent(t *testing.T) {
	// Le cœur de la demande : déduire SANS croire l'User-Agent.
	outil := httptest.NewRequest("GET", "http://x.test/.env", nil)
	outil.Header.Set("Accept", "*/*")
	outil.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)") // mensonge

	traits := traitsComportementaux(outil)
	got := familleDeduite(traits, sondeSecret)
	if got != "moissonneur-secrets?" {
		t.Fatalf("déduction = %q, attendu moissonneur-secrets? (UA menteur ignoré)", got)
	}
	if !strings.HasSuffix(got, "?") {
		t.Error("une déduction doit se présenter comme incertaine")
	}
}

func TestComportement_UnVraiNavigateurNEstPasDeduitCommeOutil(t *testing.T) {
	nav := httptest.NewRequest("GET", "http://x.test/", nil)
	nav.Header.Set("Accept", "text/html,application/xhtml+xml")
	nav.Header.Set("Accept-Language", "fr-FR")
	nav.Header.Set("Accept-Encoding", "gzip")
	nav.Header.Set("Sec-Fetch-Mode", "navigate")
	nav.Header.Set("Sec-Fetch-Site", "none")
	nav.Header.Set("Upgrade-Insecure-Requests", "1")
	if got := familleDeduite(traitsComportementaux(nav), sondeRacine); got != "" {
		t.Fatalf("un navigateur est déduit comme %q", got)
	}
}

func TestLeurre_LaPremierePartieNEstJamaisLeurree(t *testing.T) {
	// Régression #1266 transposée : un nom À NOUS non câblé appartient à un de
	// nos utilisateurs, pas à un scanner. La vérification se fait chez
	// l'appelant ; ce test verrouille l'helper sur lequel elle repose.
	suffixes := []string{"gk2.secubox.in"}
	for _, h := range []string{
		"nextcloud.gk2.secubox.in", "alias-oublie.gk2.secubox.in", "gk2.secubox.in",
	} {
		if !estPremierePartie(h, suffixes) {
			t.Errorf("%s devrait être reconnu de première partie (donc exempté)", h)
		}
	}
	for _, h := range []string{"myhome.example.com", "gk2.secubox.in.evil.tld"} {
		if estPremierePartie(h, suffixes) {
			t.Errorf("%s ne doit PAS être exempté", h)
		}
	}
}

func TestLeurre_LeLanNEstJamaisLeurre(t *testing.T) {
	// RÉGRESSION VÉCUE : dès l'armement, le leurre a répondu 200 aux sondes de
	// santé internes (10.10.0.1 → /api/v1/waf/health, Host non routé). Un
	// prober aurait conclu qu'un service inexistant est vivant. La garde se
	// fait chez l'appelant ; ce test verrouille le prédicat dont elle dépend.
	for _, ip := range []string{"10.10.0.1", "192.168.1.47", "172.16.0.5", "127.0.0.1"} {
		if !privateCIDR(ip) {
			t.Errorf("%s devrait être vu comme privé (donc exempté du leurre)", ip)
		}
	}
	for _, ip := range []string{"203.0.113.7", "8.8.8.8"} {
		if privateCIDR(ip) {
			t.Errorf("%s ne doit PAS être vu comme privé", ip)
		}
	}
}

func TestLeurre_BoucleComplete_SemerPuisReconnaitreAuRetour(t *testing.T) {
	// LE SCÉNARIO QUI JUSTIFIE TOUT LE DISPOSITIF, de bout en bout :
	//   1. un scanner moissonne notre faux /.env et emporte une fausse clé ;
	//   2. plus tard, ailleurs, il la rejoue ;
	//   3. on la reconnaît — et l'on sait que c'est LA NÔTRE.
	fil := filigraneDEssai(t)
	s := &Server{leurre: NewLeurreHTTP(true, fil, nil)}

	// 1. semis
	w := httptest.NewRecorder()
	servi, _, _, _ := s.leurre.Sert(w,
		httptest.NewRequest("GET", "http://inconnu.test/.env", nil), "inconnu.test")
	if !servi {
		t.Fatal("le leurre n'a rien servi")
	}
	marques := fil.Cherche(w.Body.String())
	if len(marques) == 0 {
		t.Fatal("aucune marque dans le contenu semé")
	}
	vole := marques[0]

	// 2. la fausse clé revient — ici dans un en-tête d'autorisation.
	retour := httptest.NewRequest("GET", "http://autre.test/api", nil)
	retour.Header.Set("Authorization", "Bearer "+vole)
	if got := s.marquesRevenues(retour); len(got) != 1 || got[0] != vole {
		t.Fatalf("marque revenue non reconnue : %v", got)
	}

	// …ou dans l'URL, l'autre porte d'entrée bon marché.
	parURL := httptest.NewRequest("GET", "http://autre.test/l?key="+vole, nil)
	if len(s.marquesRevenues(parURL)) != 1 {
		t.Error("marque revenue par l'URL non reconnue")
	}

	// 3. une requête ordinaire ne déclenche rien — sinon le signal ne vaudrait rien.
	ordinaire := httptest.NewRequest("GET", "http://autre.test/page?x=1", nil)
	ordinaire.Header.Set("Cookie", "session=abcdef0123456789")
	if got := s.marquesRevenues(ordinaire); got != nil {
		t.Errorf("faux positif sur une requête ordinaire : %v", got)
	}
}

func TestLeurre_SansFiligraneAucuneMarqueNEstJamaisReconnue(t *testing.T) {
	// Sans secret, `Cherche` doit rendre vide — et surtout ne jamais prétendre
	// reconnaître : un faux « marque revenue » enverrait l'analyse au mur.
	s := &Server{leurre: NewLeurreHTTP(true, nil, nil)}
	r := httptest.NewRequest("GET", "http://x.test/?k="+strings.Repeat("ab", 16), nil)
	if got := s.marquesRevenues(r); got != nil {
		t.Errorf("marque prétendument reconnue sans secret : %v", got)
	}
}

// ── Répertoire inexistant sur un vhost RÉEL ─────────────────────────────────

func reponse404(chemin, ip string) *http.Response {
	r := httptest.NewRequest("GET", "http://vrai-site.test"+chemin, nil)
	// ON POSE RemoteAddr, PAS X-Forwarded-For. `clientIP` ne fait confiance au
	// XFF que si le pair immédiat est un relais DÉCLARÉ — c'est la bonne règle
	// (sinon n'importe qui s'attribuerait l'adresse de son choix), et un test
	// qui la contourne ne testerait pas le vrai chemin.
	r.RemoteAddr = net.JoinHostPort(ip, "45678")
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Status:     "404 Not Found",
		Header:     http.Header{"Content-Type": {"text/html"}, "Content-Length": {"9"}},
		Body:       io.NopCloser(strings.NewReader("pas ici !")),
		Request:    r,
	}
}

func TestLeurre404_RemplaceUnAppatIntrinseque(t *testing.T) {
	fil := filigraneDEssai(t)
	l := NewLeurreHTTP(true, fil, nil)
	resp := reponse404("/.env", "203.0.113.7")
	if !l.LeurrerLe404(resp) {
		t.Fatal("/.env en 404 aurait dû être leurré")
	}
	if resp.StatusCode != 200 {
		t.Errorf("code = %d", resp.StatusCode)
	}
	corps, _ := io.ReadAll(resp.Body)
	if len(fil.Cherche(string(corps))) == 0 {
		t.Error("le corps de remplacement ne porte pas de marque")
	}
	// La longueur DOIT suivre le corps, sinon le client voit une réponse cassée.
	if resp.Header.Get("Content-Length") != strconv.Itoa(len(corps)) {
		t.Errorf("Content-Length = %q pour %d octets",
			resp.Header.Get("Content-Length"), len(corps))
	}
	if resp.ContentLength != int64(len(corps)) {
		t.Errorf("ContentLength = %d pour %d octets", resp.ContentLength, len(corps))
	}
}

func TestLeurre404_NeTouchePasUne404ORDINAIRE(t *testing.T) {
	// LE POINT LE PLUS IMPORTANT DE CE BLOC. Transformer les liens morts d'un
	// vrai site en fausses pages tromperait ses visiteurs et pourrirait son
	// référencement. Seuls les appâts intrinsèques sont concernés.
	l := NewLeurreHTTP(true, filigraneDEssai(t), nil)
	for _, chemin := range []string{
		"/une/page/supprimee", "/blog/2019/article", "/images/logo-v2.png", "/",
	} {
		resp := reponse404(chemin, "203.0.113.7")
		if l.LeurrerLe404(resp) {
			t.Errorf("%s : une 404 ordinaire a été leurrée", chemin)
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s : le 404 a été altéré", chemin)
		}
	}
}

func TestLeurre404_NAgitQueSurUn404(t *testing.T) {
	// On ne pré-empte jamais : si le service a servi la ressource, on n'y touche
	// pas — même si le chemin ressemble à un appât.
	l := NewLeurreHTTP(true, filigraneDEssai(t), nil)
	for _, code := range []int{200, 301, 403, 500} {
		resp := reponse404("/.env", "203.0.113.7")
		resp.StatusCode = code
		if l.LeurrerLe404(resp) {
			t.Errorf("code %d : la réponse réelle a été remplacée", code)
		}
	}
}

func TestLeurre404_JamaisLeLan(t *testing.T) {
	l := NewLeurreHTTP(true, filigraneDEssai(t), nil)
	for _, ip := range []string{"192.168.1.47", "10.10.0.1", "127.0.0.1"} {
		if l.LeurrerLe404(reponse404("/.env", ip)) {
			t.Errorf("%s : le LAN a été leurré sur un 404", ip)
		}
	}
}

func TestLeurre404_InactifNeToucheRien(t *testing.T) {
	l := NewLeurreHTTP(false, filigraneDEssai(t), nil)
	resp := reponse404("/.env", "203.0.113.7")
	if l.LeurrerLe404(resp) || resp.StatusCode != http.StatusNotFound {
		t.Fatal("le leurre désarmé a modifié une réponse")
	}
}

// ── Remplacement de la page de blocage ──────────────────────────────────────

func requeteExterne(chemin string) *http.Request {
	r := httptest.NewRequest("GET", "http://vrai-site.test"+chemin, nil)
	r.RemoteAddr = "203.0.113.55:44444"
	return r
}

func TestBlocage_LeLeurreRemplaceLaPageSurUnAppat(t *testing.T) {
	fil := filigraneDEssai(t)
	l := NewLeurreHTTP(true, fil, nil)
	w := httptest.NewRecorder()
	w.Header().Set("X-SecuBox-WAF", "warning") // posé par la page d'origine

	if !l.SertAuLieuDeBloquer(w, requeteExterne("/.env")) {
		t.Fatal("un chemin-appât aurait dû être leurré")
	}
	if w.Code != http.StatusOK {
		t.Errorf("code = %d, attendu 200", w.Code)
	}
	if len(fil.Cherche(w.Body.String())) == 0 {
		t.Error("la page de remplacement ne porte pas de marque")
	}
}

func TestBlocage_PlusAUCUNEMentionDuProduit(t *testing.T) {
	// C'EST LA RAISON D'ÊTRE DU CHANGEMENT. La page d'origine disait
	// « SecuBox » ×4, « WAF » ×2, « sbxwaf » ×1 — l'information la plus utile
	// de toute la reconnaissance d'un scanner, offerte gratuitement.
	l := NewLeurreHTTP(true, filigraneDEssai(t), nil)
	w := httptest.NewRecorder()
	w.Header().Set("X-SecuBox-WAF", "warning")
	l.SertAuLieuDeBloquer(w, requeteExterne("/.git/config"))

	tout := w.Body.String() + "\n" + fmt.Sprint(w.Header())
	for _, mot := range []string{"SecuBox", "secubox", "sbxwaf", "WAF", "Firewall", "firewall"} {
		if strings.Contains(tout, mot) {
			t.Errorf("le produit est encore annoncé par %q", mot)
		}
	}
	if w.Header().Get("X-SecuBox-WAF") != "" {
		t.Error("l'en-tête X-SecuBox-WAF subsiste et trahit le produit")
	}
}

func TestBlocage_UneVRAIEATTAQUEGardeSon403(t *testing.T) {
	// GARDE-FOU LE PLUS IMPORTANT DU FICHIER. Une injection vise une ressource
	// RÉELLE : répondre 200 ferait croire à l'attaquant que sa charge est
	// passée sur une page qui existe — un mensonge sans contrepartie, et une
	// invitation à recommencer plus fort. Seuls les appâts sont concernés.
	l := NewLeurreHTTP(true, filigraneDEssai(t), nil)
	for _, chemin := range []string{
		"/index.php", "/recherche", "/api/v1/users", "/", "/produits/42",
	} {
		w := httptest.NewRecorder()
		if l.SertAuLieuDeBloquer(w, requeteExterne(chemin)) {
			t.Errorf("%s : la page de blocage a été remplacée hors chemin-appât", chemin)
		}
		if w.Body.Len() != 0 {
			t.Errorf("%s : du contenu a été écrit", chemin)
		}
	}
}

func TestBlocage_JamaisLeLanNiQuandDesarme(t *testing.T) {
	l := NewLeurreHTTP(true, filigraneDEssai(t), nil)
	lan := httptest.NewRequest("GET", "http://vrai-site.test/.env", nil)
	lan.RemoteAddr = "192.168.1.9:1234"
	if l.SertAuLieuDeBloquer(httptest.NewRecorder(), lan) {
		t.Error("le LAN a reçu un leurre à la place du blocage")
	}

	off := NewLeurreHTTP(false, filigraneDEssai(t), nil)
	if off.SertAuLieuDeBloquer(httptest.NewRecorder(), requeteExterne("/.env")) {
		t.Error("le leurre désarmé a remplacé une page de blocage")
	}
}
