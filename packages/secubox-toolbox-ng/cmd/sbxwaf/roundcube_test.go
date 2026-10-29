// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — tests des signatures Roundcube (#3273, R-RC1 à R-RC3, R-IMG1)
package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/emit"
)

func TestFromInvalideRoundcube(t *testing.T) {
	cas := []struct {
		v              string
		invalide, bang bool
	}{
		{"edit-identity", false, false},
		{"add-identity", false, false},
		{"123", false, false},
		{"", false, false},
		{"edit-!\";i:0;O:16:\"Crypt_GPG_Engine\":", true, true},
		{"e\xc0d\xc1i\xc2t", true, false},
		{"edit-", true, false},
		{"a b", true, false},
		{"!x", true, true},
	}
	for _, c := range cas {
		inv, bang := fromInvalideRoundcube(c.v)
		if inv != c.invalide || bang != c.bang {
			t.Errorf("fromInvalideRoundcube(%q) = (%v,%v), attendu (%v,%v)", c.v, inv, bang, c.invalide, c.bang)
		}
	}
}

func TestCrlfEtDrapeauRoundcube(t *testing.T) {
	for v, want := range map[string]bool{"1\r\nA LOGOUT": true, "1:*": false, "a\x00": true, "a\rb": true, "a\nb": true} {
		if got := crlfDans(v); got != want {
			t.Errorf("crlfDans(%q) = %v, attendu %v", v, got, want)
		}
	}
	for v, want := range map[string]bool{"read": false, "read)": true, "a b": true, "x%": true, "\x7f": true,
		"flagged": false, "a(": true, "a\"": true, "a*": true, "a{": true} {
		if got := drapeauInvalideRoundcube(v); got != want {
			t.Errorf("drapeauInvalideRoundcube(%q) = %v, attendu %v", v, got, want)
		}
	}
}

func TestNomsRoundcubeListes(t *testing.T) {
	if !reflect.DeepEqual(nomsIMAPRoundcube, []string{"_uid", "_flag", "_q", "_filter", "_headers", "_scope", "_mbox", "_search"}) {
		t.Errorf("nomsIMAPRoundcube = %v", nomsIMAPRoundcube)
	}
	if !reflect.DeepEqual(nomsEnvoiRoundcube, []string{"_subject", "_from", "_replyto", "_followupto", "_charset"}) {
		t.Errorf("nomsEnvoiRoundcube = %v", nomsEnvoiRoundcube)
	}
	// Tout nom lu doit être retenu par la lecture des paramètres (tâche 1).
	for _, n := range append(append([]string{}, nomsIMAPRoundcube...), nomsEnvoiRoundcube...) {
		if !nomsRetenusPHP[n] {
			t.Errorf("%s n'est pas dans nomsRetenusPHP : sa valeur ne serait jamais lue", n)
		}
	}
}

func TestAnalyserMultipartFilenameSession(t *testing.T) {
	un := func(fn string) ResultatMultipart {
		return analyserMultipart(fabriquerMultipart("BND", []partieTest{{nom: "_file[]", filename: fn, fichier: true, contenu: "x"}}, false), ctTest, false, LimitesMultipart{})
	}
	// Filename de la PoC (article FearsOff) : les guillemets sont échappés.
	poc := `x|b:0;preferences_time|b:0;preferences|s:179:\"a:3:{i:0;s:57:\".png`
	if r := un(poc); !r.FilenameSession || r.FilenameObjet {
		t.Errorf("PoC : %+v, attendu FilenameSession seul", r)
	}
	if r := un("photo|2024.png"); r.FilenameSession {
		t.Errorf("photo|2024.png : %+v", r)
	}
	if r := un("a:1;.png"); r.FilenameSession {
		t.Errorf("a:1;.png (sans |) : %+v", r)
	}
	if r := un("a|b:0;"); !r.FilenameSession {
		t.Errorf("a|b:0; : %+v", r)
	}
	if r := un("a|N;"); r.FilenameSession {
		t.Errorf("a|N; ne correspond pas à [abdisNO]:[0-9;] : %+v", r)
	}
}

func TestAnalyserMultipartNonRaster(t *testing.T) {
	un := func(fn, contenu string) ResultatMultipart {
		return analyserMultipart(fabriquerMultipart("BND", []partieTest{{nom: "f", filename: fn, fichier: true, contenu: contenu}}, false), ctTest, false, LimitesMultipart{})
	}
	if r := un("a.png", "<svg>"+strings.Repeat("x", 100)+"</svg>"); !r.NonRaster {
		t.Errorf("SVG : %+v", r)
	}
	if r := un("a.png", "\x89PNG\r\n\x1a\n"+strings.Repeat("\x00", 80)+"<svg>"); r.NonRaster {
		t.Errorf("PNG : %+v", r)
	}
	if r := un("", "<svg>"); r.NonRaster {
		t.Errorf("filename vide : %+v", r)
	}
	// Un champ ordinaire n'est pas un fichier lu.
	r := analyserMultipart(fabriquerMultipart("BND", []partieTest{{nom: "c", contenu: "<svg>"}}, false), ctTest, false, LimitesMultipart{})
	if r.NonRaster {
		t.Errorf("champ ordinaire : %+v", r)
	}
	// Fichier sauté (au-delà de max_file_uploads = 20) : jamais lu.
	var ps []partieTest
	for i := 0; i < 21; i++ {
		ps = append(ps, partieTest{nom: "f", filename: "a.png", fichier: true, contenu: "ok"})
	}
	ps = append(ps, partieTest{nom: "f", filename: "a.png", fichier: true, contenu: "<svg>"})
	if r := analyserMultipart(fabriquerMultipart("BND", ps, false), ctTest, false, LimitesMultipart{}); r.NonRaster {
		t.Errorf("fichier sauté : %+v", r)
	}
}

func TestAnalyserMultipartChamps(t *testing.T) {
	r := analyserMultipart(fabriquerMultipart("BND", []partieTest{
		{nom: "_action", contenu: "upload-photo"}, {nom: "x", contenu: "y"},
	}, false), ctTest, false, LimitesMultipart{})
	if want := []ParametrePHP{{"_action", "upload-photo"}}; !reflect.DeepEqual(r.Champs, want) {
		t.Errorf("Champs = %v, attendu %v", r.Champs, want)
	}
	// Le nom est normalisé comme PHP.
	r = analyserMultipart(fabriquerMultipart("BND", []partieTest{{nom: " _action[0]", contenu: "a"}, {nom: ".x", contenu: "b"}}, false), ctTest, false, LimitesMultipart{})
	if want := []ParametrePHP{{"_action", "a"}}; !reflect.DeepEqual(r.Champs, want) {
		t.Errorf("nom normalisé : Champs = %v, attendu %v", r.Champs, want)
	}
	var ps []partieTest
	for i := 0; i < 100; i++ {
		ps = append(ps, partieTest{nom: "_uid", contenu: "1"})
	}
	r = analyserMultipart(fabriquerMultipart("BND", ps, false), ctTest, false, LimitesMultipart{})
	if len(r.Champs) != parametresRetenusMax {
		t.Errorf("len(Champs) = %d, attendu %d", len(r.Champs), parametresRetenusMax)
	}
	// Un fichier n'est pas un champ.
	r = analyserMultipart(fabriquerMultipart("BND", []partieTest{{nom: "_action", filename: "a", fichier: true, contenu: "z"}}, false), ctTest, false, LimitesMultipart{})
	if len(r.Champs) != 0 {
		t.Errorf("fichier compté comme champ : %v", r.Champs)
	}
}

// corpusRoundcubeTest : une catégorie roundcube en detect, ids rc-001 à rc-006.
const corpusRoundcubeTest = `{"categories": {"roundcube": {"name": "R", "severity": "high", "mode": "detect",
  "structural": [
   {"id": "rc-001", "check": "rc_from_invalide", "severity": "critical", "services": ["roundcube"], "cve": "CVE-2025-49113"},
   {"id": "rc-002", "check": "filename_session", "severity": "high", "services": ["roundcube"], "cve": "CVE-2025-49113"},
   {"id": "rc-003", "check": "rc_crlf_imap", "severity": "high", "services": ["roundcube"]},
   {"id": "rc-004", "check": "rc_crlf_envoi", "severity": "medium", "services": ["roundcube"]},
   {"id": "rc-005", "check": "rc_markasjunk_uid_requete", "severity": "low", "services": ["roundcube"]},
   {"id": "rc-006", "check": "rc_image_non_raster", "severity": "high", "services": ["roundcube"]}
  ]}}}`

// entreeRC construit une EntreePHP comme analyserRequetePHP la remplirait.
func entreeRC(service, methode, requete, ctCorps string, corps []byte) *EntreePHP {
	e := &EntreePHP{Service: service, Methode: methode, requeteBrute: requete}
	e.lireRequete()
	switch {
	case corps == nil:
	case estMultipartPHP(ctCorps):
		r := analyserMultipart(corps, ctCorps, false, LimitesMultipart{})
		e.Multipart = &r
	default:
		p := lireParametresPHP(string(corps))
		e.Corps = &p
	}
	return e
}

func idsDe(r *Rules, e *EntreePHP) []string {
	ids := []string{}
	for _, d := range r.EvaluerPHP(e) {
		ids = append(ids, d.RuleID)
	}
	return ids
}

func TestRoundcubeSignatures(t *testing.T) {
	r := LoadRules(ecrisRegles(t, corpusRoundcubeTest))
	if _, c, rej, av := r.Integrite(); c != 6 || len(rej) != 0 || len(av) != 0 {
		t.Fatalf("charges=%d rejetes=%v avertis=%v", c, rej, av)
	}
	if !r.litLaRequete() {
		t.Fatal("les contrôles Roundcube doivent inscrire la requête (controlesRequete)")
	}
	const urlenc = "application/x-www-form-urlencoded"
	svg := []partieTest{{nom: "_photo", filename: "a.png", fichier: true, contenu: "<svg onload=1>"}}
	pdf := []partieTest{{nom: "_photo", filename: "a.png", fichier: true, contenu: "%PDF-1.7"}}
	avecAction := func(ps []partieTest, a string) []byte {
		return fabriquerMultipart("BND", append([]partieTest{{nom: "_action", contenu: a}}, ps...), false)
	}
	cas := []struct {
		nom     string
		e       *EntreePHP
		attendu []string
	}{
		{"from !", entreeRC("roundcube", "POST", "_task=settings&_action=upload&_from=edit-!%22;i:0;O:16:%22Crypt_GPG_Engine%22:", "", nil), []string{"rc-001"}},
		{"from point", entreeRC("roundcube", "POST", "_task=settings&.from=edit-%21x", "", nil), []string{"rc-001"}},
		{"from légitime", entreeRC("roundcube", "GET", "_from=edit-identity", "", nil), []string{}},
		{"from dans le corps seulement", entreeRC("roundcube", "POST", "", urlenc, []byte("_from=edit-!x")), []string{}},
		{"uid crlf corps", entreeRC("roundcube", "POST", "", urlenc, []byte("_uid=1%0d%0aA001+LOGOUT")), []string{"rc-003"}},
		{"uid crlf requête", entreeRC("roundcube", "GET", "_uid=1%0aX", "", nil), []string{"rc-003"}},
		{"flag", entreeRC("roundcube", "POST", "", urlenc, []byte("_flag=read)")), []string{"rc-003"}},
		{"flag légitime", entreeRC("roundcube", "POST", "", urlenc, []byte("_flag=read&_uid=1:*")), []string{}},
		{"subject", entreeRC("roundcube", "POST", "", urlenc, []byte("_subject=a%0db")), []string{"rc-004"}},
		{"destinataires exclus", entreeRC("roundcube", "POST", "", urlenc, []byte("_to=a%0Ab&_cc=c%0Ad&_message=l1%0Al2")), []string{}},
		{"markasjunk POST", entreeRC("roundcube", "POST", "_task=mail&_action=plugin.markasjunk.junk&_uid=5", "", nil), []string{"rc-005"}},
		{"markasjunk post minuscule", entreeRC("roundcube", "post", "_task=mail&_action=plugin.markasjunk.junk&_uid=5", "", nil), []string{"rc-005"}},
		{"markasjunk GET", entreeRC("roundcube", "GET", "_task=mail&_action=plugin.markasjunk.junk&_uid=5", "", nil), []string{}},
		{"markasjunk uid dans le corps", entreeRC("roundcube", "POST", "_action=plugin.markasjunk.junk", urlenc, []byte("_uid=5")), []string{}},
		{"image upload-photo", entreeRC("roundcube", "POST", "_task=addressbook&_action=upload-photo", ctTest, fabriquerMultipart("BND", svg, false)), []string{"rc-006"}},
		{"image settings upload", entreeRC("roundcube", "POST", "_task=settings&_action=upload", ctTest, fabriquerMultipart("BND", pdf, false)), []string{"rc-006"}},
		{"image mail upload", entreeRC("roundcube", "POST", "_task=mail&_action=upload", ctTest, fabriquerMultipart("BND", pdf, false)), []string{}},
		{"image mail upload svg", entreeRC("roundcube", "POST", "_task=mail&_action=upload", ctTest, fabriquerMultipart("BND", svg, false)), []string{}},
		{"image action en champ", entreeRC("roundcube", "POST", "", ctTest, avecAction(svg, "upload-photo")), []string{"rc-006"}},
		{"image raster", entreeRC("roundcube", "POST", "_action=upload-photo", ctTest, fabriquerMultipart("BND", []partieTest{{nom: "_photo", filename: "a.png", fichier: true, contenu: "\x89PNG"}}, false)), []string{}},
		{"filename session", entreeRC("roundcube", "POST", "_task=settings&_action=upload", ctTest, fabriquerMultipart("BND", []partieTest{{nom: "_file[]", filename: `x|b:0;preferences|s:179:\"a:3:{i:0;s:57:\".png`, fichier: true, contenu: "x"}}, false)), []string{"rc-002"}},
	}
	for _, c := range cas {
		if got := idsDe(r, c.e); !reflect.DeepEqual(got, c.attendu) {
			t.Errorf("%s : %v, attendu %v", c.nom, got, c.attendu)
		}
	}
	// from_bang : seulement si la valeur invalide commence par « ! ».
	e := entreeRC("roundcube", "POST", "_task=settings&_action=upload&_from=edit-!%22;i:0;", "", nil)
	if e.Signaux()["from_bang"] != 1 {
		t.Errorf("from_bang = %v, attendu 1", e.Signaux())
	}
	e = entreeRC("roundcube", "POST", "_from=a%20b", "", nil)
	if _, ok := e.Signaux()["from_bang"]; ok && e.Signaux()["from_bang"] != 0 {
		t.Errorf("from_bang sans « ! » : %v", e.Signaux())
	}
	// Un autre service : aucune signature Roundcube.
	for _, c := range cas {
		c.e.Service = "nextcloud"
		if got := idsDe(r, c.e); len(got) != 0 {
			t.Errorf("%s en service nextcloud : %v, attendu aucune", c.nom, got)
		}
	}
}

func TestRoundcubeEnvoiLegitimeMuet(t *testing.T) {
	r := LoadRules(ecrisRegles(t, corpusRoundcubeTest))
	champs := [][2]string{
		{"_to", "a@x\r\nb@y"}, {"_cc", "c@x\r\nd@y\r\ne@z"}, {"_bcc", "f@x\r\ng@y"},
		{"_subject", "Bonjour"}, {"_from", "1"}, {"_message", "l1\r\nl2"},
		{"_task", "mail"}, {"_action", "send"},
	}
	var urlenc []string
	var ps []partieTest
	for _, c := range champs {
		urlenc = append(urlenc, c[0]+"="+strings.NewReplacer("\r", "%0D", "\n", "%0A", "@", "%40").Replace(c[1]))
		ps = append(ps, partieTest{nom: c[0], contenu: c[1]})
	}
	e := entreeRC("roundcube", "POST", "_task=mail&_action=send", "application/x-www-form-urlencoded", []byte(strings.Join(urlenc, "&")))
	if got := idsDe(r, e); len(got) != 0 {
		t.Errorf("urlencoded : %v, attendu aucune détection", got)
	}
	e = entreeRC("roundcube", "POST", "", ctTest, fabriquerMultipart("BND", ps, false))
	if got := idsDe(r, e); len(got) != 0 {
		t.Errorf("multipart : %v, attendu aucune détection", got)
	}
}

// Contrôle de coût : un contrôle de requête absent du corpus ne lit rien.
func TestRoundcubeControlesRequeteInscrits(t *testing.T) {
	for _, c := range []string{"rc_from_invalide", "rc_crlf_imap", "rc_crlf_envoi", "rc_markasjunk_uid_requete", "rc_image_non_raster"} {
		if !controlesRequete[c] {
			t.Errorf("%s doit être inscrit dans controlesRequete", c)
		}
		if _, ok := parametreRequis[c]; !ok {
			t.Errorf("%s absent de parametreRequis", c)
		}
	}
	if controlesRequete["filename_session"] {
		t.Error("filename_session ne lit pas la requête")
	}
}

func TestRoundcubeFromJournaliseSansBloquer(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "actord.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	recu := make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 1<<16)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						recu <- string(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	b := nouveauBancMultipart(t, nil)
	vp, err := chargerVhostProfilesDepuis([]byte(`{
		"services": {"roundcube": {"legit_paths": []}},
		"vhosts": {"webmail.example": "roundcube"},
		"php_services": ["roundcube"]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	b.s.vhostProfiles = vp
	b.s.rules = LoadRules(ecrisRegles(t, corpusRoundcubeTest))
	em := emit.New(sock, 16)
	defer em.Close()
	b.s.threatLog.SetEmitter(em)

	get := func(ip string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://webmail.example/?_task=settings&_action=upload&_from=edit-!x", nil)
		req.Host = "webmail.example"
		req.RemoteAddr = ip + ":40000"
		rec := httptest.NewRecorder()
		b.s.handler().ServeHTTP(rec, req)
		return rec
	}
	if rec := get(ipPublique); rec.Code != http.StatusOK {
		t.Fatalf("statut %d, attendu 200 (detect ne bloque pas)", rec.Code)
	}
	ls := lignesDe(b.lignes(t), "roundcube")
	if len(ls) != 1 {
		t.Fatalf("une ligne roundcube attendue, eu %v", b.lignes(t))
	}
	l := ls[0]
	if l["rule_id"] != "rc-001" || l["severity"] != "critical" || l["action"] != "detect" || l["mode"] != "detect" {
		t.Errorf("ligne inattendue : %v", l)
	}
	if sig, _ := l["signals"].(map[string]any); sig == nil || sig["from_bang"] != float64(1) {
		t.Errorf("signals.from_bang = 1 attendu : %v", l["signals"])
	}
	if strings.Contains(strings.ToLower(toutTexte(l)), "edit-") {
		t.Errorf("la valeur de _from ne doit jamais être journalisée : %v", l)
	}
	b.verifierSansSanction(t, ipPublique)

	var tout strings.Builder
	limite := time.After(3 * time.Second)
	for !strings.Contains(tout.String(), ipPublique) {
		select {
		case m := <-recu:
			tout.WriteString(m)
		case <-limite:
			t.Fatalf("l'adresse publique n'a pas été émise : %q", tout.String())
		}
	}
	if !strings.Contains(tout.String(), `"severity":90`) {
		t.Errorf("enveloppe sans severity 90 : %q", tout.String())
	}
	// Même requête depuis le LAN : journalisée « local », jamais émise.
	get("192.168.1.10")
	time.Sleep(200 * time.Millisecond)
	for len(recu) > 0 {
		tout.WriteString(<-recu)
	}
	if strings.Contains(tout.String(), "192.168.1.10") {
		t.Errorf("une adresse privée est partie vers actord : %q", tout.String())
	}
	ls = lignesDe(b.lignes(t), "roundcube")
	if len(ls) != 2 || ls[1]["client_ip"] != "local" {
		t.Errorf("seconde ligne « local » attendue : %v", ls)
	}
}

func toutTexte(m map[string]any) string {
	var b bytes.Buffer
	for k, v := range m {
		b.WriteString(k + "=")
		if s, ok := v.(string); ok {
			b.WriteString(s)
		}
		b.WriteString(";")
	}
	return b.String()
}
