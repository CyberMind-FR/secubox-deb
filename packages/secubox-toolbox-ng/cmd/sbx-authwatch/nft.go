// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbx-authwatch — alimentation du set nft (#1220)
//
// On alimente L'ENSEMBLE DEJA EXISTANT du WAF, `inet secubox waf_ban{,6}`, et
// non un ensemble a nous. C'est le point de la demande : un seul endroit ou
// regarder qui est banni, une seule chaine qui applique, quelle que soit la
// surface qui a leve l'alerte — HTTP, SSH ou SMTP.
//
// LA GARDE, tiree de #1218. Ce jour-la on a decouvert que le WAF remplissait
// depuis des mois un set que RIEN ne consultait : ni chaine, ni regle, zero
// reference a @waf_ban dans tout le jeu de regles. Quatre-vingt-onze adresses
// « bannies » qui passaient toutes. On ne refera pas la meme erreur en silence :
// au demarrage, ce programme VERIFIE qu'une regle consulte reellement le set,
// et refuse de demarrer sinon. Mieux vaut un service qui ne demarre pas et le
// dit qu'un service qui compte des bannissements sans effet.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrTableAbsente : l'ensemble n'existe plus — un rechargement du pare-feu
// (`flush ruleset`) vient d'effacer la table du WAF, que sbxwaf recrée (#1693).
// Le ban est retenu et ré-appliqué par Reaffirme dès qu'elle revient.
var ErrTableAbsente = errors.New("table nft absente (rechargement du pare-feu ?) — ban retenu, ré-appliqué à son retour")

// executeur execute « nft <args…> ». Injectable : les tests observent les
// commandes sans toucher au pare-feu de la machine qui les fait tourner.
type executeur func(ctx context.Context, args ...string) ([]byte, error)

type Banneur struct {
	nftPath string
	table   string
	set4    string
	set6    string
	duree   time.Duration
	simule  bool
	exec    executeur

	// Bans actifs (ip → échéance), ré-affirmés périodiquement (#1693). La table
	// ne vit que dans le noyau et chaque rechargement du pare-feu l'efface ;
	// sbxwaf la recrée avec SES bans, pas avec ceux d'authwatch.
	mu     sync.Mutex
	actifs map[string]time.Time

	// LEURRES DE SERVICE (#3988). Un contact sur un service inexistant n'a
	// aucune lecture innocente : 24 h au premier contact, 7 j à la récidive
	// (fenêtre de 30 jours), au lieu de la durée des mots de passe ratés.
	dureeLeurre         time.Duration
	dureeLeurreRecidive time.Duration
	leurres             map[string][]time.Time // ip → bans de leurre posés dans la fenêtre
}

// Durées par défaut des bans de leurre de service (#3988).
const (
	DureeLeurreDefaut         = 24 * time.Hour
	DureeLeurreRecidiveDefaut = 7 * 24 * time.Hour
	fenetreRecidiveLeurre     = 30 * 24 * time.Hour
)

func NewBanneur(nftPath, table, set4, set6 string, duree time.Duration, simule bool) *Banneur {
	if nftPath == "" {
		nftPath = "nft"
	}
	b := &Banneur{nftPath: nftPath, table: table, set4: set4, set6: set6, duree: duree, simule: simule,
		actifs: map[string]time.Time{}, leurres: map[string][]time.Time{},
		dureeLeurre: DureeLeurreDefaut, dureeLeurreRecidive: DureeLeurreRecidiveDefaut}
	b.exec = b.execReel
	return b
}

// RegleLeurres fixe les durées des bans de leurre ; une valeur nulle ou
// négative garde le défaut (24 h, puis 7 j).
func (b *Banneur) RegleLeurres(premier, recidive time.Duration) {
	if premier > 0 {
		b.dureeLeurre = premier
	}
	if recidive > 0 {
		b.dureeLeurreRecidive = recidive
	}
	if b.dureeLeurreRecidive < b.dureeLeurre {
		b.dureeLeurreRecidive = b.dureeLeurre // la récidive ne raccourcit jamais
	}
}

// dureeLeurrePour note un ban de leurre posé à `at` et rend sa durée :
// premier contact dans la fenêtre → dureeLeurre, sinon dureeLeurreRecidive.
// Appelant : b.mu tenu.
func (b *Banneur) dureeLeurrePour(ip string, at time.Time) time.Duration {
	garde := b.leurres[ip][:0]
	for _, t := range b.leurres[ip] {
		if at.Sub(t) < fenetreRecidiveLeurre && !t.After(at) {
			garde = append(garde, t)
		}
	}
	d := b.dureeLeurre
	if len(garde) > 0 {
		d = b.dureeLeurreRecidive
	}
	b.leurres[ip] = append(garde, at)
	return d
}

func (b *Banneur) execReel(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, b.nftPath, args...).CombinedOutput()
}

func (b *Banneur) run(ctx context.Context, args ...string) ([]byte, error) {
	return b.exec(ctx, args...)
}

// Verifie s'assure que les ensembles existent ET qu'une regle les consulte.
// Rend une erreur PARLANTE : le message doit suffire a savoir quoi reparer.
func (b *Banneur) Verifie(ctx context.Context) error {
	sortie, err := b.run(ctx, "list", "ruleset")
	if err != nil {
		return fmt.Errorf("lecture du jeu de regles nft impossible (droits ?) : %v", err)
	}
	texte := string(sortie)

	for _, set := range []string{b.set4, b.set6} {
		if !strings.Contains(texte, "set "+set+" ") && !strings.Contains(texte, "set "+set+" {") {
			return fmt.Errorf("l'ensemble %s n'existe pas dans la table %s — "+
				"sbxwaf doit tourner au moins une fois pour le creer", set, b.table)
		}
	}
	// La verification qui compte : une REGLE doit consulter l'ensemble.
	if !strings.Contains(texte, "@"+b.set4) {
		return fmt.Errorf("aucune regle ne consulte @%s : les bannissements seraient "+
			"comptes sans effet (c'est exactement le defaut #1218). "+
			"Verifier la chaine waf_drop de sbxwaf", b.set4)
	}
	return nil
}

// Bannit ajoute l'adresse a l'ensemble correspondant a sa famille.
//
// GARDE-FOU identique a celui du WAF : jamais une adresse privee. Le drop est
// reel ; une seule erreur en amont couperait l'administration de la box depuis
// la box. Le refus est ici, au dernier moment, ou rien ne peut le contourner.
func (b *Banneur) Bannit(ctx context.Context, ip string) error {
	return b.bannitPour(ctx, ip, b.duree)
}

// BannitLeurre bannit pour un contact sur un leurre de service (#3988) :
// durée graduée 24 h puis 7 j, indépendante de `--duree-ban`. Mêmes garde-fous
// que Bannit (jamais une adresse privée). Rend la durée appliquée.
func (b *Banneur) BannitLeurre(ctx context.Context, ip string) (time.Duration, error) {
	if p := net.ParseIP(ip); p == nil || p.IsLoopback() || p.IsPrivate() || p.IsLinkLocalUnicast() || p.IsUnspecified() {
		return 0, b.bannitPour(ctx, ip, 0) // même refus, même message
	}
	b.mu.Lock()
	d := b.dureeLeurrePour(ip, time.Now())
	b.mu.Unlock()
	return d, b.bannitPour(ctx, ip, d)
}

func (b *Banneur) bannitPour(ctx context.Context, ip string, duree time.Duration) error {
	p := net.ParseIP(ip)
	if p == nil {
		return fmt.Errorf("adresse invalide : %q", ip)
	}
	if p.IsLoopback() || p.IsPrivate() || p.IsLinkLocalUnicast() || p.IsUnspecified() {
		return fmt.Errorf("adresse privee refusee : %s", ip)
	}
	set := b.set6
	if p.To4() != nil {
		set = b.set4
	}
	elem := fmt.Sprintf("{ %s timeout %ds }", ip, int(duree.Seconds()))
	if b.simule {
		return nil
	}
	b.mu.Lock()
	if fin := time.Now().Add(duree); fin.After(b.actifs[ip]) {
		b.actifs[ip] = fin
	}
	b.mu.Unlock()
	if out, err := b.run(ctx, "add", "element", "inet", b.table, set, elem); err != nil {
		if strings.Contains(string(out), "No such file or directory") {
			return ErrTableAbsente
		}
		return fmt.Errorf("nft add element %s : %v : %s", set, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Reaffirme ré-injecte les bans encore actifs avec le temps qui leur reste, en
// une commande par famille, et oublie les échus. `add element` sur un élément
// déjà présent ne change rien : sans rechargement du pare-feu, c'est neutre.
// Renvoie le nombre d'adresses ré-affirmées.
func (b *Banneur) Reaffirme(ctx context.Context) int {
	maintenant := time.Now()
	par := map[string][]string{}
	b.mu.Lock()
	for ip, fin := range b.actifs {
		reste := int(fin.Sub(maintenant).Seconds())
		if reste <= 0 {
			delete(b.actifs, ip)
			continue
		}
		set := b.set6
		if net.ParseIP(ip).To4() != nil {
			set = b.set4
		}
		par[set] = append(par[set], fmt.Sprintf("%s timeout %ds", ip, reste))
	}
	b.mu.Unlock()
	n := 0
	for set, elems := range par {
		sort.Strings(elems)
		arg := "{ " + strings.Join(elems, ", ") + " }"
		if _, err := b.run(ctx, "add", "element", "inet", b.table, set, arg); err == nil {
			n += len(elems)
		}
	}
	return n
}

// queueJournal borne la relecture : la fin de chaque journal suffit, un ban ne
// dure que quelques heures.
const queueJournal = 16 << 20

// RechargeJournal retrouve les bans encore actifs dans le journal des menaces,
// où authwatch inscrit chacun d'eux (« tool »: « authwatch », « action »:
// « banned »). Sans cela, un redémarrage d'authwatch oubliait tous ses bans, et
// le rechargement du pare-feu suivant les effaçait pour de bon — 163 bans en 4 h
// sur gk2, contre 100 pour le WAF HTTP (#1693). `chemins` : le journal courant
// puis le tourné (un ban posé avant minuit court encore après). Renvoie le
// nombre d'adresses retenues.
func (b *Banneur) RechargeJournal(chemins []string, maintenant time.Time) int {
	if b.simule {
		return 0
	}
	type ligne struct {
		Timestamp string `json:"timestamp"`
		ClientIP  string `json:"client_ip"`
		Category  string `json:"category"`
	}
	type ban struct {
		ip     string
		at     time.Time
		leurre bool
	}
	var bans []ban
	b.mu.Lock()
	defer b.mu.Unlock()
	avant := len(b.actifs)
	for _, chemin := range chemins {
		f, err := os.Open(chemin)
		if err != nil {
			continue
		}
		entamee := false // en sautant à la queue, la première ligne est coupée
		if st, err := f.Stat(); err == nil && st.Size() > queueJournal {
			_, err = f.Seek(st.Size()-queueJournal, io.SeekStart)
			entamee = err == nil
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			l := sc.Bytes()
			if entamee {
				entamee = false
				continue
			}
			if !bytes.Contains(l, []byte(`"tool":"authwatch"`)) || !bytes.Contains(l, []byte(`"action":"banned"`)) {
				continue
			}
			var e ligne
			if json.Unmarshal(l, &e) != nil {
				continue
			}
			p := net.ParseIP(e.ClientIP)
			if p == nil || p.IsLoopback() || p.IsPrivate() || p.IsLinkLocalUnicast() || p.IsUnspecified() {
				continue
			}
			at, err := time.Parse(time.RFC3339, e.Timestamp)
			if err != nil {
				continue
			}
			bans = append(bans, ban{e.ClientIP, at, strings.HasPrefix(e.Category, "leurre:")})
		}
		f.Close()
	}
	// Ordre chronologique : le journal tourné vient après le courant dans
	// `chemins`, et la récidive des leurres (#3988) se compte dans l'ordre.
	sort.SliceStable(bans, func(i, j int) bool { return bans[i].at.Before(bans[j].at) })
	for _, x := range bans {
		d := b.duree
		if x.leurre {
			d = b.dureeLeurrePour(x.ip, x.at)
		}
		if fin := x.at.Add(d); fin.After(maintenant) && fin.After(b.actifs[x.ip]) {
			b.actifs[x.ip] = fin
		}
	}
	return len(b.actifs) - avant
}
