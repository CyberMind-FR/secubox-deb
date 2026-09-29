// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// banneurFaux capture les bannissements sans toucher a nft.
type banneurFaux struct{ bannies []string }

func (b *banneurFaux) run(ctx context.Context, args ...string) ([]byte, error) {
	if len(args) > 0 && args[0] == "add" {
		// « add element inet secubox waf_ban { IP timeout Ns } »
		for _, a := range args {
			if strings.HasPrefix(a, "{") {
				b.bannies = append(b.bannies, strings.Fields(strings.Trim(a, "{} "))[0])
			}
		}
	}
	return nil, nil
}

func banneurTest(t *testing.T) (*Banneur, *banneurFaux) {
	t.Helper()
	fx := &banneurFaux{}
	b := NewBanneur("nft", "secubox", "waf_ban", "waf_ban6", time.Hour, false)
	b.exec = fx.run
	return b, fx
}

func journalTest(t *testing.T) (*JournalMenaces, string) {
	t.Helper()
	chemin := filepath.Join(t.TempDir(), "threats.log")
	return NewJournalMenaces(chemin), chemin
}

func lignesJournal(t *testing.T, chemin string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(chemin)
	if err != nil {
		return nil
	}
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("ligne de journal illisible : %v", err)
		}
		out = append(out, m)
	}
	return out
}

// Un leurre est un signal CERTAIN : bannissement au premier contact, sans
// attendre la repetition. C'est toute la difference avec l'analyse de journaux.
func TestLeurreBannitDesLePremierContact(t *testing.T) {
	b, fx := banneurTest(t)
	j, chemin := journalTest(t)
	lb, _ := NewListeBlanche("")
	sig := Signal{IP: "203.0.113.5", Service: "rdp", Categorie: "leurre:rdp",
		Severite: "high", Detail: "connexion sur un service inexistant (port 3389)"}

	ctx, annule := context.WithCancel(context.Background())
	signaux := make(chan Signal, 1)
	signaux <- sig
	go traite(ctx, signaux, NewCompteur(time.Minute, 99, time.Minute), nil, nil, b, j, lb, false, nil)
	time.Sleep(80 * time.Millisecond)
	annule()

	if len(fx.bannies) != 1 || fx.bannies[0] != "203.0.113.5" {
		t.Fatalf("le leurre doit bannir immediatement, obtenu %v", fx.bannies)
	}
	lignes := lignesJournal(t, chemin)
	if len(lignes) != 1 || lignes[0]["action"] != "banned" {
		t.Fatalf("journal attendu action=banned, obtenu %v", lignes)
	}
	if lignes[0]["host"] != "rdp" || lignes[0]["tool"] != "authwatch" {
		t.Errorf("le journal doit porter le service et l'outil : %v", lignes[0])
	}
}

// L'analyse de journaux est PATIENTE : un echec isole ne bannit pas.
func TestJournalAttendLaRepetition(t *testing.T) {
	b, fx := banneurTest(t)
	j, chemin := journalTest(t)
	lb, _ := NewListeBlanche("")
	ctx, annule := context.WithCancel(context.Background())
	signaux := make(chan Signal, 8)
	sig := Signal{IP: "203.0.113.6", Service: "smtp", Categorie: "auth_smtp:sasl_failed",
		Severite: "high", Detail: "authentification SASL refusee"}
	signaux <- sig // poids 2, seuil 6 : insuffisant
	go traite(ctx, signaux, NewCompteur(time.Minute, 6, time.Minute), nil, nil, b, j, lb, false, nil)
	time.Sleep(80 * time.Millisecond)

	if len(fx.bannies) != 0 {
		t.Fatalf("un echec isole ne doit pas bannir, obtenu %v", fx.bannies)
	}
	if l := lignesJournal(t, chemin); len(l) != 1 || l[0]["action"] != "warning" {
		t.Fatalf("l'echec doit etre journalise en warning, obtenu %v", l)
	}
	// Deux de plus (2+2+2 = 6) franchissent le seuil.
	signaux <- sig
	signaux <- sig
	time.Sleep(120 * time.Millisecond)
	annule()
	if len(fx.bannies) != 1 || fx.bannies[0] != "203.0.113.6" {
		t.Fatalf("le seuil franchi doit bannir, obtenu %v", fx.bannies)
	}
}

// La liste blanche est une piece de securite : jamais de bannissement, mais
// une trace — « pourquoi cette adresse passe-t-elle toujours ? » doit avoir
// une reponse dans le journal.
func TestListeBlancheJamaisBannieMaisTracee(t *testing.T) {
	b, fx := banneurTest(t)
	j, chemin := journalTest(t)
	lb, _ := NewListeBlanche("203.0.113.7")
	ctx, annule := context.WithCancel(context.Background())
	signaux := make(chan Signal, 4)
	for i := 0; i < 3; i++ {
		signaux <- Signal{IP: "203.0.113.7", Service: "rdp", Categorie: "leurre:rdp",
			Severite: "high", Detail: "leurre"}
	}
	go traite(ctx, signaux, NewCompteur(time.Minute, 1, time.Minute), nil, nil, b, j, lb, false, nil)
	time.Sleep(120 * time.Millisecond)
	annule()

	if len(fx.bannies) != 0 {
		t.Fatalf("une adresse en liste blanche ne doit JAMAIS etre bannie, obtenu %v", fx.bannies)
	}
	lignes := lignesJournal(t, chemin)
	if len(lignes) != 3 {
		t.Fatalf("les tentatives doivent rester tracees, %d ligne(s)", len(lignes))
	}
	if lignes[0]["action"] != "detect" {
		t.Errorf("action attendue detect, obtenu %v", lignes[0]["action"])
	}
}

// En simulation, on detecte et on journalise, mais on ne touche jamais a nft.
func TestSimulationNeBannitJamais(t *testing.T) {
	b, fx := banneurTest(t)
	j, chemin := journalTest(t)
	lb, _ := NewListeBlanche("")
	ctx, annule := context.WithCancel(context.Background())
	signaux := make(chan Signal, 1)
	signaux <- Signal{IP: "203.0.113.8", Service: "vnc", Categorie: "leurre:vnc",
		Severite: "high", Detail: "leurre"}
	go traite(ctx, signaux, NewCompteur(time.Minute, 1, time.Minute), nil, nil, b, j, lb, true, nil)
	time.Sleep(80 * time.Millisecond)
	annule()

	if len(fx.bannies) != 0 {
		t.Fatalf("la simulation ne doit rien bannir, obtenu %v", fx.bannies)
	}
	if l := lignesJournal(t, chemin); len(l) != 1 || l[0]["action"] != "detect" {
		t.Fatalf("la simulation doit journaliser en detect, obtenu %v", l)
	}
}

// Le garde-fou du dernier moment : une adresse privee n'entre jamais dans le set.
func TestAdressePriveeRefuseeParLeBanneur(t *testing.T) {
	b, fx := banneurTest(t)
	for _, ip := range []string{"192.168.1.10", "10.100.0.40", "127.0.0.1", "172.16.0.5"} {
		if err := b.Bannit(context.Background(), ip); err == nil {
			t.Errorf("%s aurait du etre refusee", ip)
		}
	}
	if len(fx.bannies) != 0 {
		t.Fatalf("aucune commande nft ne doit partir, obtenu %v", fx.bannies)
	}
}

// Le compte vise doit etre exploitable par le panneau : il est porte dans
// `path`, ou une requete web mettrait ce qui etait demande. Meme question.
func TestCompteVisePorteDansLeJournal(t *testing.T) {
	b, _ := banneurTest(t)
	j, chemin := journalTest(t)
	lb, _ := NewListeBlanche("")
	ctx, annule := context.WithCancel(context.Background())
	signaux := make(chan Signal, 1)
	signaux <- Signal{IP: "203.0.113.90", Service: "smtp", Categorie: "auth_smtp:sasl_failed",
		Severite: "high", Detail: "SASL refusee", Cible: "gerald@gk2.net"}
	go traite(ctx, signaux, NewCompteur(time.Hour, 999, time.Hour), nil, nil, b, j, lb, false, nil)
	time.Sleep(80 * time.Millisecond)
	annule()

	lignes := lignesJournal(t, chemin)
	if len(lignes) != 1 {
		t.Fatalf("une ligne attendue, obtenu %d", len(lignes))
	}
	if lignes[0]["path"] != "gerald@gk2.net" {
		t.Errorf("path doit porter le compte visé, obtenu %v", lignes[0]["path"])
	}
	if lignes[0]["host"] != "smtp" {
		t.Errorf("host doit porter le service, obtenu %v", lignes[0]["host"])
	}
}

// ── #1693 : un rechargement du pare-feu ne doit pas effacer nos bans ────────

type noyauAbsent struct {
	absente bool
	cmds    []string
}

func (k *noyauAbsent) run(_ context.Context, args ...string) ([]byte, error) {
	j := strings.Join(args, " ")
	k.cmds = append(k.cmds, j)
	if k.absente && strings.HasPrefix(j, "add element") {
		return []byte("Error: No such file or directory; did you mean table 'secubox-nat' in family inet?"), errors.New("exit status 1")
	}
	return nil, nil
}

func TestBanRetenuPuisReaffirmeApresRechargement(t *testing.T) {
	k := &noyauAbsent{absente: true}
	b := NewBanneur("nft", "secubox", "waf_ban", "waf_ban6", time.Hour, false)
	b.exec = k.run

	if err := b.Bannit(context.Background(), "203.0.113.50"); !errors.Is(err, ErrTableAbsente) {
		t.Fatalf("table absente : ErrTableAbsente attendue, obtenu %v", err)
	}
	k.absente = false // sbxwaf a recréé la table
	k.cmds = nil
	if n := b.Reaffirme(context.Background()); n != 1 {
		t.Fatalf("le ban retenu devait être ré-appliqué, obtenu %d", n)
	}
	if len(k.cmds) != 1 || !strings.Contains(k.cmds[0], "waf_ban { 203.0.113.50 timeout ") {
		t.Fatalf("commande de ré-affirmation inattendue: %v", k.cmds)
	}
}

func TestReaffirmeOublieLesEchusEtGroupeParFamille(t *testing.T) {
	k := &noyauAbsent{}
	b := NewBanneur("nft", "secubox", "waf_ban", "waf_ban6", time.Hour, false)
	b.exec = k.run
	_ = b.Bannit(context.Background(), "203.0.113.1")
	_ = b.Bannit(context.Background(), "203.0.113.2")
	_ = b.Bannit(context.Background(), "2001:db8::7")
	b.mu.Lock()
	b.actifs["198.51.100.9"] = time.Now().Add(-time.Second) // échu
	b.mu.Unlock()

	k.cmds = nil
	if n := b.Reaffirme(context.Background()); n != 3 {
		t.Fatalf("3 bans actifs attendus, obtenu %d", n)
	}
	if len(k.cmds) != 2 {
		t.Fatalf("une commande par famille attendue, obtenu %v", k.cmds)
	}
	b.mu.Lock()
	_, reste := b.actifs["198.51.100.9"]
	b.mu.Unlock()
	if reste {
		t.Fatal("un ban échu doit être oublié")
	}
}

func TestSimulationNeRetientRien(t *testing.T) {
	k := &noyauAbsent{}
	b := NewBanneur("nft", "secubox", "waf_ban", "waf_ban6", time.Hour, true)
	b.exec = k.run
	_ = b.Bannit(context.Background(), "203.0.113.3")
	if n := b.Reaffirme(context.Background()); n != 0 || len(k.cmds) != 0 {
		t.Fatalf("la simulation ne doit rien retenir ni toucher nft (n=%d, %v)", n, k.cmds)
	}
}

// Un redémarrage d'authwatch ne doit pas oublier ses bans : ils sont retrouvés
// dans le journal des menaces, y compris le tourné (bans d'avant minuit).
func TestRechargeJournalRetrouveLesBansActifs(t *testing.T) {
	dir := t.TempDir()
	courant, tourne := filepath.Join(dir, "waf-threats.log"), filepath.Join(dir, "waf-threats.log.1")
	now := time.Now()
	l := func(ip, action, tool string, il time.Duration) string {
		return fmt.Sprintf(`{"timestamp":%q,"client_ip":%q,"host":"ssh","action":%q,"tool":%q}`+"\n",
			now.Add(-il).Format(time.RFC3339), ip, action, tool)
	}
	_ = os.WriteFile(tourne, []byte(l("203.0.113.10", "banned", "authwatch", 50*time.Minute)), 0o600)
	_ = os.WriteFile(courant, []byte(
		l("203.0.113.11", "banned", "authwatch", 10*time.Minute)+
			l("203.0.113.12", "banned", "authwatch", 2*time.Hour)+ // échu (durée 1 h)
			l("203.0.113.13", "banned", "", 5*time.Minute)+ // ban du WAF : pas le nôtre
			l("203.0.113.14", "warning", "authwatch", 5*time.Minute)+ // pas un ban
			l("local", "banned", "authwatch", 5*time.Minute)+ // interne
			"pas du json\n"), 0o600)

	b := NewBanneur("nft", "secubox", "waf_ban", "waf_ban6", time.Hour, false)
	if n := b.RechargeJournal([]string{courant, tourne, filepath.Join(dir, "absent")}, now); n != 2 {
		t.Fatalf("2 bans actifs attendus (…10 et …11), obtenu %d : %v", n, b.actifs)
	}
	for _, ip := range []string{"203.0.113.10", "203.0.113.11"} {
		if _, ok := b.actifs[ip]; !ok {
			t.Fatalf("%s devait être retenu", ip)
		}
	}
}

// La queue d'un gros journal : la ligne coupée par le saut est écartée.
func TestRechargeJournalQueueLigneCoupee(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "waf-threats.log")
	now := time.Now()
	ban := fmt.Sprintf(`{"timestamp":%q,"client_ip":"203.0.113.20","action":"banned","tool":"authwatch"}`+"\n",
		now.Add(-time.Minute).Format(time.RFC3339))
	remplissage := strings.Repeat(`{"timestamp":"x","client_ip":"198.51.100.1","action":"detect"}`+"\n", queueJournal/60+10)
	_ = os.WriteFile(chemin, []byte(remplissage+ban), 0o600)
	b := NewBanneur("nft", "secubox", "waf_ban", "waf_ban6", time.Hour, false)
	if n := b.RechargeJournal([]string{chemin}, now); n != 1 {
		t.Fatalf("le ban en fin de gros journal devait être retrouvé, obtenu %d", n)
	}
}
