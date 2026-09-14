// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	servi, _, _ := l.Sert(w, httptest.NewRequest("GET", "http://inconnu.test/.env", nil), "inconnu.test")
	if servi {
		t.Fatal("le leurre a servi alors qu'il n'est pas armé")
	}
}

func TestLeurre_NeRepondQuAuxLectures(t *testing.T) {
	// Accepter un POST reviendrait à encaisser un corps d'inconnu sans raison.
	l := NewLeurreHTTP(true, filigraneDEssai(t), nil)
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(m, "http://inconnu.test/.env", strings.NewReader("x=1"))
		if servi, _, _ := l.Sert(w, r, "inconnu.test"); servi {
			t.Errorf("%s a été servi par le leurre", m)
		}
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
		servi, _, alea := l.Sert(w, r, "inconnu.test")
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
