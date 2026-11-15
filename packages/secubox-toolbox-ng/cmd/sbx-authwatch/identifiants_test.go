// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// joue fait parler un client scripté avec le leurre `service` ; rend la capture
// et tout ce que le leurre a écrit.
func joue(t *testing.T, service string, envoi ...[]byte) (Capture, string) {
	t.Helper()
	srv, cli := duo(t)
	var recu bytes.Buffer
	var mu sync.Mutex
	fini := make(chan struct{})
	go func() {
		b := make([]byte, 256)
		for {
			n, err := cli.Read(b)
			mu.Lock()
			recu.Write(b[:n])
			mu.Unlock()
			if err != nil {
				close(fini)
				return
			}
		}
	}()
	go func() {
		for _, e := range envoi {
			if _, err := cli.Write(e); err != nil {
				return
			}
		}
		time.Sleep(20 * time.Millisecond) // laisse le leurre répondre au dernier essai
		_ = cli.Close()
	}()
	debut := time.Now()
	c := Dialogue(srv, service)
	if time.Since(debut) > 5*time.Second {
		t.Errorf("dialogue %s trop long : %v", service, time.Since(debut))
	}
	_ = srv.Close()
	<-fini
	mu.Lock()
	defer mu.Unlock()
	return c, recu.String()
}

func TestTelnet_PlusieursEssaisParConnexion(t *testing.T) {
	c, sortie := joue(t, "telnet", []byte("root\r\n123456\r\nadmin\r\n123456\r\nsupport\r\nsupport\r\n"))
	want := []Essai{{"root", "123456"}, {"admin", "123456"}, {"support", "support"}}
	if len(c.Essais) != len(want) {
		t.Fatalf("essais : %+v", c.Essais)
	}
	for i := range want {
		if c.Essais[i] != want[i] {
			t.Errorf("essai %d : %+v, attendu %+v", i, c.Essais[i], want[i])
		}
	}
	if c.Agent != "force-brute" || c.Client != "telnet sans négociation" {
		t.Errorf("agent %q client %q", c.Agent, c.Client)
	}
	if strings.Count(sortie, "Password: ") != 3 || !strings.Contains(sortie, "Login incorrect") {
		t.Errorf("invites : %q", sortie)
	}
}

func TestTelnet_NegociationEcarteeEtGardeeCommeSignature(t *testing.T) {
	c, _ := joue(t, "telnet", []byte("\xff\xfd\x18\xff\xfb\x1f\xff\xfa\x18\x00xterm\xff\xf0root\r\nvizxv\r\n"))
	if len(c.Essais) != 1 || c.Essais[0] != (Essai{"root", "vizxv"}) {
		t.Fatalf("essais : %+v", c.Essais)
	}
	if !strings.HasPrefix(c.Client, "telnet négociation fffd18fffb1ffffa") {
		t.Errorf("client : %q", c.Client)
	}
}

func TestTelnet_LigneSansFinEstBornee(t *testing.T) {
	c, _ := joue(t, "telnet", bytes.Repeat([]byte("A"), 10000))
	if c.Octets > octetsMax {
		t.Errorf("%d octets lus, plafond %d", c.Octets, octetsMax)
	}
	for _, e := range c.Essais {
		if len(e.Compte) > champMax {
			t.Errorf("compte de %d caractères", len(e.Compte))
		}
	}
}

func TestBalayeurMuet(t *testing.T) {
	c, _ := joue(t, "rdp")
	if c.Agent != "balayeur" || len(c.Essais) != 0 {
		t.Errorf("capture : %+v", c)
	}
}

func startupPGTest(params ...string) []byte {
	corps := []byte{0, 3, 0, 0}
	for _, p := range params {
		corps = append(append(corps, p...), 0)
	}
	corps = append(corps, 0)
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(4+len(corps)))
	return append(b, corps...)
}

func TestPostgres_CompteMotDePasseEtApplication(t *testing.T) {
	ssl := []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}
	mdp := []byte("p\x00\x00\x00\x0cpostgres\x00")
	c, sortie := joue(t, "postgres", ssl,
		startupPGTest("user", "postgres", "database", "template1", "application_name", "pgcrack"), mdp)
	if len(c.Essais) != 1 || c.Essais[0] != (Essai{"postgres", "postgres"}) {
		t.Fatalf("essais : %+v", c.Essais)
	}
	if c.Client != "postgres application_name=pgcrack base=template1" {
		t.Errorf("client : %q", c.Client)
	}
	if !strings.HasPrefix(sortie, "N") || !strings.Contains(sortie, "28P01") {
		t.Errorf("réponses : %q", sortie)
	}
}

func TestPostgres_LongueurAberranteRefusee(t *testing.T) {
	c, _ := joue(t, "postgres", []byte{0x7f, 0xff, 0xff, 0xff, 0, 3, 0, 0})
	if len(c.Essais) != 0 {
		t.Errorf("essais : %+v", c.Essais)
	}
}

func TestRedis_RejeuAuthEnRESPEtEnLigne(t *testing.T) {
	c, sortie := joue(t, "redis",
		[]byte("*1\r\n$4\r\nINFO\r\n"),
		[]byte("*2\r\n$4\r\nAUTH\r\n$6\r\nfoobar\r\n"),
		[]byte("*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$6\r\nfoobar\r\n"),
		[]byte("AUTH 123456\r\n"))
	want := []Essai{{"", "foobar"}, {"default", "foobar"}, {"", "123456"}}
	if len(c.Essais) != 3 {
		t.Fatalf("essais : %+v", c.Essais)
	}
	for i := range want {
		if c.Essais[i] != want[i] {
			t.Errorf("essai %d : %+v", i, c.Essais[i])
		}
	}
	if c.Client != "redis INFO,AUTH,AUTH,AUTH" || !strings.Contains(sortie, "NOAUTH") || !strings.Contains(sortie, "WRONGPASS") {
		t.Errorf("client %q, réponses %q", c.Client, sortie)
	}
}

func TestHTTP_BasicEtUserAgent(t *testing.T) {
	long := strings.Repeat("x", 90) // au-delà de 64 : l'en-tête ne doit pas être tronqué avant décodage
	auth := "elastic:" + long
	enc := base64.StdEncoding.EncodeToString([]byte(auth))
	c, sortie := joue(t, "elasticsearch",
		[]byte("GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: Mozilla/5.0 zgrab/0.x\r\n\r\n"),
		[]byte("GET /_cat/indices HTTP/1.1\r\nAuthorization: Basic "+enc+"\r\n\r\n"))
	if len(c.Essais) != 1 || c.Essais[0].Compte != "elastic" || c.Essais[0].MotDePasse != long[:champMax] {
		t.Fatalf("essais : %+v", c.Essais)
	}
	if c.Client != "Mozilla/5.0 zgrab/0.x" || strings.Count(sortie, "401 Unauthorized") != 2 {
		t.Errorf("client %q, réponses %q", c.Client, sortie)
	}
}

func trameRDP(cookie string, protocoles uint32) []byte {
	x224 := []byte{0, 0xe0, 0, 0, 0, 0, 0}
	x224 = append(x224, cookie...)
	neg := []byte{0x01, 0, 8, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(neg[4:], protocoles)
	x224 = append(x224, neg...)
	x224[0] = byte(len(x224) - 1)
	t := []byte{3, 0, 0, 0}
	binary.BigEndian.PutUint16(t[2:], uint16(4+len(x224)))
	return append(t, x224...)
}

func TestRDP_CompteDuCookieEtProtocoles(t *testing.T) {
	c, _ := joue(t, "rdp", trameRDP("Cookie: mstshash=administrator\r\n", 3))
	if len(c.Essais) != 1 || c.Essais[0].Compte != "administrator" {
		t.Fatalf("essais : %+v", c.Essais)
	}
	if c.Client != "rdp cookie mstshash, protocoles TLS+CredSSP" || c.Agent != "force-brute" {
		t.Errorf("client %q agent %q", c.Client, c.Agent)
	}
	c, _ = joue(t, "rdp", trameRDP("", 0))
	if len(c.Essais) != 0 || c.Client != "rdp protocoles RDP standard" || c.Agent != "sondeur" {
		t.Errorf("sans cookie : %+v", c)
	}
}

func TestVNC_VersionDuClient(t *testing.T) {
	c, _ := joue(t, "vnc", []byte("RFB 003.003\n"))
	if c.Client != "vnc client RFB 003.003" {
		t.Errorf("client : %q", c.Client)
	}
}

func chaineBSONTest(cle, v string) []byte {
	b := append(append([]byte{0x02}, cle...), 0, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(b[len(b)-4:], uint32(len(v)+1))
	return append(append(b, v...), 0)
}

func TestMongo_Pilote(t *testing.T) {
	doc := append([]byte("\x03driver\x00"), chaineBSONTest("name", "nodejs|Mongoose")...)
	doc = append(doc, chaineBSONTest("version", "6.3.0")...)
	c, _ := joue(t, "mongodb", append([]byte{0x10, 0, 0, 0}, doc...))
	if c.Client != "mongo pilote nodejs|Mongoose 6.3.0" {
		t.Errorf("client : %q", c.Client)
	}
}

func TestEmet_JournalPorteEssaisEnClairClientEtAgent(t *testing.T) {
	signaux := make(chan Signal, 1)
	emet(context.Background(), signaux, Leurre{23, "telnet"}, "203.0.113.9",
		Capture{Essais: []Essai{{"root", "xc3511"}, {"admin", "xc3511"}}, Client: "telnet sans négociation",
			Agent: "force-brute", Octets: 40})
	sig := <-signaux
	if sig.Cible != "root" || !strings.Contains(sig.Detail, "force-brute") ||
		!strings.Contains(sig.Detail, "2 essais : « root » / « xc3511 », « admin » / « xc3511 »") {
		t.Fatalf("signal : %+v", sig)
	}
	chemin := filepath.Join(t.TempDir(), "menaces.log")
	NewJournalMenaces(chemin).Inscrit(sig, "banned", 1)
	brut, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}
	var e map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(brut), &e); err != nil {
		t.Fatal(err)
	}
	if e["agent"] != "force-brute" || e["user_agent"] != "telnet sans négociation" || e["path"] != "root" ||
		e["category"] != "leurre:telnet" || e["tool"] != "authwatch" {
		t.Errorf("entrée : %v", e)
	}
	essais, _ := e["essais"].([]any)
	if len(essais) != 2 || essais[1].(map[string]any)["mot_de_passe"] != "xc3511" {
		t.Errorf("essais : %v", e["essais"])
	}
}

func TestTelnet_MotDePasseVideGarde(t *testing.T) {
	c, _ := joue(t, "telnet", []byte("root\r\n\r\nadmin\r\x00admin\n"))
	if len(c.Essais) != 2 || c.Essais[0] != (Essai{"root", ""}) || c.Essais[1] != (Essai{"admin", "admin"}) {
		t.Fatalf("essais : %+v", c.Essais)
	}
}
