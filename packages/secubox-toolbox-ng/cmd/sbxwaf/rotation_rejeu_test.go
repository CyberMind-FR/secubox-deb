// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reseau"
)

// Rejeu hors ligne du détecteur de rotation (#3919, tâche 10). Navigateurs FICTIFS, adresses de documentation générées.

var rejeuT0 = time.Date(2026, 3, 10, 8, 0, 0, 0, time.UTC)

// ligneNginx : format combiné.
func ligneNginx(ip string, t time.Time, methode, chemin string, statut int, referent, ua string) string {
	return fmt.Sprintf("%s - - [%s] \"%s %s HTTP/1.1\" %d 512 \"%s\" \"%s\"\n", ip, t.Format("02/Jan/2006:15:04:05 -0700"), methode, chemin, statut, referent, ua)
}

func ecrireJournal(t *testing.T, dossier, nom, contenu string) string {
	t.Helper()
	p := filepath.Join(dossier, nom)
	if err := os.WriteFile(p, []byte(contenu), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func ecrireJournalGz(t *testing.T, dossier, nom, contenu string) string {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	_, _ = z.Write([]byte(contenu))
	_ = z.Close()
	return ecrireJournal(t, dossier, nom, b.String())
}

func rejouerEssai(t *testing.T, cl classeur, adresses bool, fichiers ...string) rejeuRapport {
	t.Helper()
	return rejouerCfg(t, RotationConfig{Grace: -1}, cl, adresses, fichiers...)
}

func rejouerCfg(t *testing.T, cfg RotationConfig, cl classeur, adresses bool, fichiers ...string) rejeuRapport {
	t.Helper()
	var b bytes.Buffer
	if err := Rejouer(fichiers, cfg, cl, adresses, &b); err != nil {
		t.Fatal(err)
	}
	var r rejeuRapport
	if err := json.Unmarshal(b.Bytes(), &r); err != nil {
		t.Fatalf("JSON illisible : %v\n%s", err, b.String())
	}
	if !adresses && (strings.Contains(b.String(), "203.0.113.") || strings.Contains(b.String(), "2001:db8")) {
		t.Fatalf("adresse imprimée sans --rotation-rejeu-adresses :\n%s", b.String())
	}
	return r
}

func louees() *classesFactices { return &classesFactices{defaut: reseau.ClasseProxyLoue} }

// campagneSynthetique : n adresses (à partir de `depart`), une page chacune, régulièrement sur `duree`.
func campagneSynthetique(b *strings.Builder, depart, n int, t0 time.Time, duree time.Duration) {
	for i := 0; i < n; i++ {
		b.WriteString(ligneNginx(adressePublique(depart+i), t0.Add(duree*time.Duration(i)/time.Duration(n)), "GET", fmt.Sprintf("/page/%d", i), 200, "-", uaFictif))
	}
}

func TestRejeuFormatCombine(t *testing.T) {
	d := t.TempDir()
	var b strings.Builder
	b.WriteString(ligneNginx(adressePublique(1), rejeuT0, "GET", "/accueil?x=a.css", 200, "-", uaFictif))
	b.WriteString(ligneNginx(adressePublique(1), rejeuT0.Add(time.Second), "GET", "/style.css?v=3", 200, "-", uaFictif))
	b.WriteString(ligneNginx("192.168.1.5", rejeuT0.Add(2*time.Second), "GET", "/", 200, "-", uaFictif))
	f1 := ecrireJournal(t, d, "Boutique.exemple.test_access.log.1", b.String())
	// L'hôte porté par la ligne l'emporte (format sbx_host), avec ou sans port.
	f2 := ecrireJournal(t, d, "secubox-hosts.log", "forge.exemple.test:443 "+ligneNginx(adressePublique(2), rejeuT0.Add(3*time.Second), "GET", "/x", 200, "-", uaFictif))
	f3 := ecrireJournal(t, d, "access.log", ligneNginx(adressePublique(3), rejeuT0.Add(4*time.Second), "GET", "/y", 200, "https://ailleurs.exemple.test/", uaFictif))
	r := rejouerEssai(t, louees(), false, f1, f2, f3)
	if r.Lignes.Lues != 5 || r.Lignes.Malformees != 0 || r.Lignes.Privees != 1 || r.Lignes.Navigations != 3 || r.Lignes.Preuves != 2 {
		t.Fatalf("lignes : %+v", r.Lignes)
	}
	v := r.ParVhost["boutique.exemple.test"]
	if v == nil || v.Lignes != 3 || v.Navigations != 1 || v.Preuves != 1 || r.ParVhost["forge.exemple.test"] == nil || r.ParVhost["access.log"] == nil {
		t.Fatalf("vhosts : %+v", r.ParVhost)
	}
	if len(r.Approximations) < 5 || !r.Majorant || r.Mode != "propose" {
		t.Fatalf("approximations : %+v", r)
	}
}

func TestRejeuAnalyseLigne(t *testing.T) {
	l, ok := analyserLigne(`203.0.113.9 - bob [10/Mar/2026:09:00:00 +0100] "GET /a HTTP/2.0" 304 0 "-" "Mozilla/5.0 \x22x\x22"`)
	if !ok || l.t != rejeuT0.Unix() || l.ip != "203.0.113.9" || l.methode != "GET" || l.chemin != "/a" || l.statut != 304 || !l.authentifie || l.hote != "" ||
		l.ua != `Mozilla/5.0 \x22x\x22` || l.referent {
		t.Fatalf("%+v %v", l, ok)
	}
	if !l.preuve() {
		t.Fatal("304 (requête conditionnelle) et authentification sont des preuves")
	}
	l, ok = analyserLigne(`h.exemple.test 2001:db8::1 - - [10/Mar/2026:08:00:00 +0000] "GET https://h.exemple.test/%7Ea.b/?q HTTP/1.1" 200 5 "-" "-"`)
	if !ok || l.hote != "h.exemple.test" || l.chemin != "/%7Ea.b/" || l.ua != "" {
		t.Fatalf("%+v %v", l, ok)
	}
	// Requête binaire ou vide : ligne valable, sans requête.
	for _, req := range []string{`\x16\x03\x01`, `-`, ``} {
		l, ok = analyserLigne(`203.0.113.9 - - [10/Mar/2026:08:00:00 +0000] "` + req + `" 400 5 "-" "-"`)
		if !ok || l.methode != "" || l.preuve() || l.navigation() {
			t.Fatalf("%q : %+v %v", req, l, ok)
		}
	}
	for _, s := range []string{"", "n'importe quoi", `203.0.113.9 - - [10/Mar/2026:08:00:00 +0000] "GET / HTTP/1.1"`,
		`203.0.113.9 - - [99/Mar/2026:08:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "-"`, `203.0.113.9 - - [10/Mar/2026:08:00:00 +0000] "GET / HTTP/1.1" 2x0 5 "-" "-"`,
		`pas-une-ip - - [10/Mar/2026:08:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "-"`, `203.0.113.9 - - [10/Mar/2026:08:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "coupé`} {
		if _, ok := analyserLigne(s); ok {
			t.Errorf("acceptée : %q", s)
		}
	}
}

func TestRejeuHoteDuFichier(t *testing.T) {
	for nom, hote := range map[string]string{"/var/log/nginx/forge.exemple.test_access.log": "forge.exemple.test", "a_access.log.2.gz": "a", "a_access.log.gz": "a",
		"a_access.log-20260310.gz": "a", "apt.exemple.test.access.log.14": "apt.exemple.test", "netboot-access.log.1": "netboot",
		"access.log": "access.log", "access.log.3.gz": "access.log", "secubox-hosts.log.1": "secubox-hosts.log"} {
		if h := hoteDuFichier(nom); h != hote {
			t.Errorf("%s → %q, attendu %q", nom, h, hote)
		}
	}
}

func TestRejeuPageProbable(t *testing.T) {
	for chemin, oui := range map[string]bool{"/": true, "/a/b": true, "/index.html": true, "/a.php": true, "/v1.2": true, "/a.zip": false, "/a.tar.gz": false, "/a.deb": false,
		"/flux.rss": false, "/x.JSON": false, "/a.patch": false, "/a.css": false, "/d/p/src/branch/m/x.json": true, "/d/p/raw/branch/m/x.txt": false} {
		if pageProbable(chemin) != oui {
			t.Errorf("%s : %v", chemin, !oui)
		}
	}
}

func TestRejeuCampagneEtDelai(t *testing.T) {
	d := t.TempDir()
	var b strings.Builder
	campagneSynthetique(&b, 0, 120, rejeuT0, 30*time.Minute)
	f1 := ecrireJournal(t, d, hoteFictif+"_access.log", b.String())
	// Un vrai navigateur, même signature : 25 pages, chacune suivie d'une ressource.
	b.Reset()
	reel := adressePublique(400)
	for i := 0; i < 25; i++ {
		x := rejeuT0.Add(16*time.Minute + time.Duration(i)*20*time.Second)
		b.WriteString(ligneNginx(reel, x, "GET", "/accueil", 200, "-", uaFictif))
		b.WriteString(ligneNginx(reel, x.Add(2*time.Second), "GET", "/style.css", 200, "-", uaFictif))
	}
	f2 := ecrireJournal(t, d, hoteFictif+"_access.log.1", b.String())
	r := rejouerEssai(t, louees(), true, f1, f2)
	if len(r.Campagnes) != 1 {
		t.Fatalf("campagnes : %+v", r.Campagnes)
	}
	c := r.Campagnes[0]
	if c.Hote != hoteFictif || c.Signature != Signature(uaFictif, "", hoteFictif) || c.PremiereRequete != rejeuT0.Format(time.RFC3339) || c.DelaiS <= 0 || c.DelaiS >= 900 ||
		c.Sources < 50 || c.Une != 100 || c.Le3 != 100 || c.Classes[reseau.ClasseProxyLoue] != 100 || c.Epargnees < 1 {
		t.Fatalf("campagne : %+v", c)
	}
	// Les 50 premières ont établi la campagne ; les suivantes, sans preuve, auraient été bannies (la dernière page est en attente à la fin du journal).
	if c.AuraientEteBannies < 60 || c.AuraientEteBannies > 70 || r.AuraientEteBannies.Adresses != c.AuraientEteBannies || r.AuraientEteBannies.ParClasse[reseau.ClasseProxyLoue] != c.AuraientEteBannies {
		t.Fatalf("auraient été bannies : %+v / %+v", c, r.AuraientEteBannies)
	}
	if len(c.Exemples) != 20 || r.Epargnees["preuve"] < 1 {
		t.Fatalf("exemples %d, épargnées %v", len(c.Exemples), r.Epargnees)
	}
	for _, a := range c.Exemples {
		if a == reel {
			t.Fatal("le vrai navigateur aurait été banni")
		}
	}
	if len(r.HotesAvecCampagne) != 1 || r.HotesAvecCampagne[0] != hoteFictif || r.ParVhost[hoteFictif].Campagnes != 1 || r.ParVhost[hoteFictif].AuraientEteBannies != c.AuraientEteBannies {
		t.Fatalf("vhosts : %v %+v", r.HotesAvecCampagne, r.ParVhost[hoteFictif])
	}
	if s := r.SuspectsFauxPositifs; s.Adresses != 0 {
		t.Fatalf("aucun suspect attendu : %+v", s)
	}
	// Par défaut : des comptes, aucune adresse.
	r = rejouerEssai(t, louees(), false, f1, f2)
	if len(r.Campagnes) != 1 || len(r.Campagnes[0].Exemples) != 0 || r.Campagnes[0].AuraientEteBannies < 60 {
		t.Fatalf("sans adresses : %+v", r.Campagnes)
	}
}

// Les journaux sont fusionnés dans l'ordre du temps, pas lus l'un après l'autre : sinon la ressource, dans un autre fichier, viendrait trop tard.
func TestRejeuFusionChronologique(t *testing.T) {
	d := t.TempDir()
	var b strings.Builder
	campagneSynthetique(&b, 200, 240, rejeuT0, 45*time.Minute)
	f1 := ecrireJournal(t, d, hoteFictif+"_access.log", b.String())
	var pages, ressources strings.Builder
	for i := 0; i < 30; i++ {
		x := rejeuT0.Add(11*time.Minute + time.Duration(i)*time.Minute)
		pages.WriteString(ligneNginx(adressePublique(100+i), x, "GET", "/p", 200, "-", uaFictif))
		ressources.WriteString(ligneNginx(adressePublique(100+i), x.Add(3*time.Second), "GET", "/img/logo.webp", 200, "-", uaFictif))
	}
	ressources.WriteString(ligneNginx(adressePublique(460), rejeuT0.Add(50*time.Minute), "GET", "/img/logo.webp", 200, "-", uaFictif))
	f2 := ecrireJournalGz(t, d, hoteFictif+"_access.log.2.gz", pages.String())
	f3 := ecrireJournal(t, d, "statiques_access.log", ressources.String())
	for _, ordre := range [][]string{{f1, f2, f3}, {f3, f2, f1}} {
		r := rejouerEssai(t, louees(), false, ordre...)
		if len(r.Campagnes) != 1 || r.Campagnes[0].AuraientEteBannies < 180 || r.Campagnes[0].AuraientEteBannies > 190 {
			t.Fatalf("campagnes : %+v", r.Campagnes)
		}
		if r.Epargnees["preuve"] != 30 || r.Lignes.Lues != 301 || r.Lignes.HorsOrdre != 0 {
			t.Fatalf("épargnées %v, lignes %+v", r.Epargnees, r.Lignes)
		}
	}
}

func TestRejeuFichiersCompressesEtRotations(t *testing.T) {
	d := t.TempDir()
	var a, b strings.Builder
	campagneSynthetique(&a, 0, 40, rejeuT0, 20*time.Minute)
	campagneSynthetique(&b, 40, 40, rejeuT0.Add(20*time.Minute), 20*time.Minute)
	recent := ecrireJournal(t, d, hoteFictif+"_access.log", b.String())
	ancien := ecrireJournalGz(t, d, hoteFictif+"_access.log.2.gz", a.String())
	r := rejouerEssai(t, louees(), false, recent, ancien)
	if len(r.Campagnes) != 1 || r.Campagnes[0].Hote != hoteFictif || r.Fichiers.Lus != 2 {
		t.Fatalf("une campagne à cheval sur deux journaux : %+v %+v", r.Campagnes, r.Fichiers)
	}
	// Archive tronquée, fichier absent, dossier, doublon : signalés, le reste est lu.
	brut, _ := os.ReadFile(ancien)
	coupe := ecrireJournal(t, d, "coupe_access.log.gz", string(brut[:len(brut)-40]))
	r = rejouerEssai(t, louees(), false, recent, ancien, recent, coupe, filepath.Join(d, "absent_access.log"), d)
	if len(r.Campagnes) < 1 || len(r.Fichiers.EnErreur) != 4 {
		t.Fatalf("erreurs : %+v", r.Fichiers)
	}
	var out bytes.Buffer
	if err := Rejouer([]string{filepath.Join(d, "absent")}, RotationConfig{}, louees(), false, &out); err == nil || out.Len() != 0 {
		t.Fatal("aucun journal lisible : erreur attendue")
	}
}

func TestRejeuLignesMalformees(t *testing.T) {
	d := t.TempDir()
	var b strings.Builder
	b.WriteString("début illisible\n\n")
	campagneSynthetique(&b, 0, 60, rejeuT0, 10*time.Minute)
	b.WriteString(strings.Repeat("x", 300000) + "\n")
	b.WriteString(ligneNginx(adressePublique(200), rejeuT0.Add(11*time.Minute), "GET", "/fin", 200, "-", uaFictif))
	b.WriteString("203.0.113.9 - - [10/Mar/2026:08:2") // ligne coupée, sans fin
	f := ecrireJournal(t, d, hoteFictif+"_access.log", b.String())
	g := ecrireJournal(t, d, "erreurs.log", "2026/03/10 08:00:00 [error] 12#12: rien\n")
	r := rejouerEssai(t, louees(), false, f, g)
	if r.Lignes.Lues != 66 || r.Lignes.Malformees != 5 || len(r.Campagnes) != 1 {
		t.Fatalf("%+v %d", r.Lignes, len(r.Campagnes))
	}
}

// Un saut d'horloge de la box (lignes très en retard) ne fausse pas la fenêtre : les preuves restent, les navigations ne comptent pas.
func TestRejeuHorsOrdreEtTrous(t *testing.T) {
	d := t.TempDir()
	var b strings.Builder
	b.WriteString(ligneNginx(adressePublique(0), rejeuT0.Add(-20*365*24*time.Hour), "GET", "/", 200, "-", uaFictif)) // horloge non réglée
	b.WriteString(ligneNginx(adressePublique(1), rejeuT0.Add(2*time.Hour), "GET", "/", 200, "-", uaFictif))
	campagneSynthetique(&b, 0, 100, rejeuT0, 10*time.Minute)
	f := ecrireJournal(t, d, hoteFictif+"_access.log", b.String())
	debut := time.Now()
	r := rejouerEssai(t, louees(), false, f)
	if r.Lignes.HorsOrdre != 100 || len(r.Campagnes) != 0 || time.Since(debut) > 3*time.Second {
		t.Fatalf("%+v %d campagne(s), %s", r.Lignes, len(r.Campagnes), time.Since(debut))
	}
}

func TestRejeuGrace(t *testing.T) {
	d := t.TempDir()
	var b strings.Builder
	campagneSynthetique(&b, 0, 120, rejeuT0, 30*time.Minute)
	f := ecrireJournal(t, d, hoteFictif+"_access.log", b.String())
	r := rejouerCfg(t, RotationConfig{Grace: 24 * time.Hour}, louees(), false, f)
	if len(r.Campagnes) != 1 || r.AuraientEteBannies.Adresses != 0 || r.SansGrace {
		t.Fatalf("en grâce, rien n'est jugé : %+v", r.AuraientEteBannies)
	}
	if r = rejouerEssai(t, louees(), false, f); !r.SansGrace {
		t.Fatal("sans_grace attendu")
	}
}

// Adresses que le détecteur aurait bannies, mais que le reste des journaux innocente.
func TestRejeuSuspectsFauxPositifs(t *testing.T) {
	d := t.TempDir()
	var b strings.Builder
	campagneSynthetique(&b, 0, 60, rejeuT0, 10*time.Minute)
	x := rejeuT0.Add(11 * time.Minute)
	for i := 0; i < 5; i++ {
		b.WriteString(ligneNginx(adressePublique(100+i), x, "GET", "/p", 200, "-", uaFictif))
	}
	b.WriteString(ligneNginx(adressePublique(100), x.Add(time.Hour), "GET", "/app.js", 200, "-", uaFictif))                // ressource, 1 h après
	b.WriteString(ligneNginx(adressePublique(101), x.Add(2*time.Hour), "GET", "/b", 200, "https://a.exemple/", "Autre/1")) // référent, 2 h après
	b.WriteString(ligneNginx(adressePublique(102), x.Add(3*time.Hour), "GET", "/c", 304, "-", uaFictif))                   // revalidation
	b.WriteString(ligneNginx(adressePublique(103), x.Add(4*time.Hour), "GET", "/d", 200, "-", "RobotFictifBot/2.0 (+https://robot.exemple/)"))
	b.WriteString(ligneNginx(adressePublique(104), x.Add(25*time.Hour), "GET", "/app.js", 200, "-", uaFictif)) // trop tard
	f := ecrireJournal(t, d, hoteFictif+"_access.log", b.String())
	r := rejouerEssai(t, louees(), true, f)
	s := r.SuspectsFauxPositifs
	if s.Adresses != 4 || s.PreuveA24h != 3 || s.ParPreuve["ressource"] != 1 || s.ParPreuve["referent"] != 1 || s.ParPreuve["revalidation"] != 1 || s.RobotsDeclares != 1 ||
		s.PriveLanMaillage != 0 || s.PreuveAvant != 0 || s.PreuveApres != 3 || len(s.Exemples) != 4 {
		t.Fatalf("suspects : %+v", s)
	}
	if r = rejouerEssai(t, louees(), false, f); r.SuspectsFauxPositifs.Adresses != 4 || len(r.SuspectsFauxPositifs.Exemples) != 0 {
		t.Fatalf("suspects sans adresses : %+v", r.SuspectsFauxPositifs)
	}
	for ip, oui := range map[string]bool{"10.10.0.5": true, "192.168.1.2": true, "100.64.3.4": true, "fd00::1": true, "203.0.113.9": true, "198.51.100.4": false} {
		if adresseDeConfiance(netip.MustParseAddr(ip), parseCIDRs("203.0.113.0/24")) != oui {
			t.Errorf("%s : %v", ip, !oui)
		}
	}
}

func TestRejeuClassesProtegees(t *testing.T) {
	d := t.TempDir()
	var b strings.Builder
	campagneSynthetique(&b, 0, 60, rejeuT0, 10*time.Minute)
	cl := louees()
	cl.poser(adressePublique(100), reseau.ClasseAcces)
	cl.poser(adressePublique(101), reseau.ClasseHebergeur)
	b.WriteString(ligneNginx(adressePublique(100), rejeuT0.Add(11*time.Minute), "GET", "/p", 200, "-", uaFictif))
	b.WriteString(ligneNginx(adressePublique(101), rejeuT0.Add(11*time.Minute), "GET", "/p", 200, "-", uaFictif))
	b.WriteString(ligneNginx(adressePublique(102), rejeuT0.Add(11*time.Minute), "GET", "/p", 404, "-", uaFictif)) // pas une page servie
	b.WriteString(ligneNginx(adressePublique(103), rejeuT0.Add(12*time.Minute), "GET", "/p.zip", 200, "-", uaFictif))
	b.WriteString(ligneNginx(adressePublique(104), rejeuT0.Add(13*time.Minute), "GET", "/p", 404, "-", "Autre/1"))
	f := ecrireJournal(t, d, hoteFictif+"_access.log", b.String())
	r := rejouerEssai(t, cl, false, f)
	if r.Epargnees["classe_protegee"] != 1 || r.AuraientEteBannies.ParClasse[reseau.ClasseHebergeur] != 1 || r.AuraientEteBannies.Adresses > 11 {
		t.Fatalf("%v %+v", r.Epargnees, r.AuraientEteBannies)
	}
	// Sans annuaire : aucune campagne, et le rapport le dit.
	r = rejouerEssai(t, nil, false, f)
	if len(r.Campagnes) != 0 || r.Annuaire.AvecReseau != 0 || !strings.Contains(strings.Join(r.Approximations, "\n"), "AUCUNE adresse") {
		t.Fatalf("sans annuaire : %+v", r)
	}
}

// Rien n'est écrit, même si la configuration reçue nomme des fichiers ; le mode est toujours « propose ».
func TestRejeuNEcritAucunFichier(t *testing.T) {
	d, vide := t.TempDir(), t.TempDir()
	var b strings.Builder
	campagneSynthetique(&b, 0, 120, rejeuT0, 30*time.Minute)
	f := ecrireJournal(t, d, hoteFictif+"_access.log", b.String())
	t.Setenv("TMPDIR", vide)
	ici, _ := os.Getwd()
	avant, _ := os.ReadDir(ici)
	cfg := RotationConfig{Mode: "auto", Grace: -1, Etat: filepath.Join(vide, "e", "etat.json"), Navigateurs: filepath.Join(vide, "nav.bin"), Audit: filepath.Join(vide, "a", "audit.log")}
	r := rejouerCfg(t, cfg, louees(), false, f)
	if r.Mode != "propose" || r.AuraientEteBannies.Adresses == 0 {
		t.Fatalf("%+v", r)
	}
	if l, _ := os.ReadDir(vide); len(l) != 0 {
		t.Fatalf("fichiers écrits : %v", l)
	}
	if apres, _ := os.ReadDir(ici); len(apres) != len(avant) {
		t.Fatal("fichiers écrits dans le dossier courant")
	}
	if l, _ := os.ReadDir(d); len(l) != 1 {
		t.Fatalf("fichiers écrits à côté du journal : %v", l)
	}
}
