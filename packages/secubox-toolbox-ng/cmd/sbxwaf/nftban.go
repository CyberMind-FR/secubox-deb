// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Ban nft natif (#1070, phase B).
//
// Jusqu'ici le WAF déléguait TOUT le ban à un relais externe (→ bouncer → nft). Un
// WAF sans ce relais ne bloquait donc rien. NftBanner rend le WAF AUTONOME : il
// gère son PROPRE set nft `inet secubox waf_ban{,6}` avec un `timeout` par
// élément — le noyau retire l'IP à l'échéance (le retrait différé). Le journal
// (BanStore) assure la persistance au restart et l'audit.
//
// LE WAF BLOQUE LUI-MÊME, sans relais externe (#1218) : l'ancienne voie
// échouait de toute façon en silence (droits/config du relais externe),
// que le compte de service ne peut pas ouvrir.
//
// PIÈGE CORRIGÉ (#1218) : Ensure() ne créait que la table et les deux SETS. Rien
// ne les consultait — aucune chaîne, aucune règle, zéro référence à @waf_ban
// dans tout le jeu de règles. Le banner remplissait donc consciencieusement un
// ensemble que le noyau n'interrogeait jamais : 91 adresses « bannies » qui
// passaient toutes. Un set sans règle ne bloque rien ; la chaîne ci-dessous est
// ce qui rend le blocage réel.
//
// Le processus a besoin de CAP_NET_ADMIN (ou `sudo nft`) — sinon `nft` échoue et
// aucun ban natif n'est posé, en journalisant.

// nftRunner exécute `nft <args...>`. Injectable pour les tests.
type nftRunner func(ctx context.Context, args ...string) ([]byte, error)

// NftBanner pose des bans dans un set nft à timeout.
type NftBanner struct {
	nftPath  string
	table    string
	chain    string
	set4     string
	set6     string
	duration time.Duration
	store    *BanStore
	runner   nftRunner
	scripts  nftScript // `nft -f -` (nftban_repose.go)

	// robots vérifiés (crawlers.go) : jamais bannis. nil = pas de vérification (tests).
	robots         *Crawlers
	robotPlausible func(ip string) bool // ordre des vérifications (nftban_robots.go) ; nil : sans ordre
	robotsPas      time.Duration
	robotsVus      map[string]uint8 // adresse bannie → essais sans réponse, ou robotConclu ; sous mu

	// Jamais bannies, quel que soit l'appelant (#3932) : plages SECUBOX_WAF_PROTEGEES (--actor-ban-protegees), posées avant
	// Ensure. Le CGNAT est dans adresseBan. protegeesLevees : le rattrapage du démarrage a abouti ; sous reposeMu.
	protegees       []*net.IPNet
	protegeesLevees bool
	audit           string // journal d'audit ; "" = aucun (tests)

	cooldown time.Duration
	mu       sync.Mutex
	recent   map[string]time.Time // ip → dernier ban (anti-tempête)
	enPose   map[string]struct{}  // bans qui attendent poseMu ou nft : une adresse n'y entre qu'une fois ; sous mu
	ready    bool
	voulu    bool     // Ensure a été demandé : tant que la pose échoue, la veille la retente ; sous mu
	attente  []func() // à lancer à la première pose réussie (QuandPret) ; sous mu

	// Auto-réparation (#1693). repMu sérialise les réparations : une rafale de
	// bans qui échouent en même temps ne doit recréer la table qu'une fois.
	repMu        sync.Mutex
	reparations  int
	derniereRep  time.Time
	dernierEchec string
	echecA       time.Time
	dernierBan   time.Time
	etatFichier  string // "" = pas d'état écrit (tests)
	etatMu       sync.Mutex
	etatEchoue   bool

	// Repose par lots (#3930, nftban_repose.go). reposeMu : une seule repose à la fois, jamais pris par la veille ni par un
	// ban. Ordre des verrous : reposeMu → poseMu → repMu → mu ; aucun n'est pris en sens inverse.
	reposeMu       sync.Mutex
	reposeAttend   atomic.Bool            // une repose demandée attend déjà reposeMu
	generation     atomic.Int64           // +1 à chaque table recréée : la passe en cours repart de zéro
	poseMu         sync.Mutex             // un lot qui part / la levée d'un robot
	aRetirer       map[netip.Addr]poseLot // posés par un lot, levés depuis, pas encore retirés ; sous poseMu
	listeMu        sync.Mutex             // un seul gros `list set` à la fois (mémoire)
	reposeEnCours  bool
	derniereRepose time.Time
	bansAttendus   compteBans
	bansPoses      compteBans
	nftFige        atomic.Bool
}

// NewNftBanner construit le banneur. `store` peut être nil (pas de persistance).
func NewNftBanner(nftPath, table string, duration time.Duration, store *BanStore) *NftBanner {
	if nftPath == "" {
		nftPath = "nft"
	}
	if table == "" {
		table = "secubox"
	}
	b := &NftBanner{
		nftPath:  nftPath,
		table:    table,
		chain:    "waf_drop",
		set4:     "waf_ban",
		set6:     "waf_ban6",
		duration: duration,
		store:    store,
		cooldown: 30 * time.Second,
		recent:   make(map[string]time.Time),
		enPose:   make(map[string]struct{}),

		bansAttendus: compteInconnu,
		bansPoses:    compteInconnu,

		robotsPas: robotsPas,
		robotsVus: make(map[string]uint8),
	}
	b.runner = b.execNft
	b.scripts = b.execScript
	return b
}

func (b *NftBanner) execNft(ctx context.Context, args ...string) ([]byte, error) {
	// argv discrets : une IP influençable ne peut pas injecter d'argument (elle
	// est déjà validée en amont), et il n'y a pas de shell.
	return lancerNft(exec.CommandContext(ctx, b.nftPath, args...), nil)
}

// Ensure crée table, sets, chaîne et règles de façon idempotente, en UNE transaction (#3932) : soit tout est en place, soit
// rien n'a changé, et la chaîne n'est jamais vide. À appeler une fois au démarrage. Erreur : nft n'est pas utilisable
// (droits, nft figé…) ; le banneur n'est pas prêt et la veille retente la pose.
func (b *NftBanner) Ensure() error {
	_, err := b.EnsureDemarrage()
	return err
}

// EnsureDemarrage est Ensure, qui dit en plus si les ensembles étaient déjà là : les bans y sont appliqués par le noyau,
// l'écoute n'a pas à attendre la repose.
func (b *NftBanner) EnsureDemarrage() (dejaLa bool, err error) {
	b.mu.Lock()
	b.voulu = true
	b.mu.Unlock()
	b.repMu.Lock()
	defer b.repMu.Unlock()
	return b.ensure(delaiEnsureDemarrage)
}

// Au démarrage les requêtes attendent Ensure (deux commandes nft) ; une réparation, elle, n'attend personne.
const (
	delaiEnsureDemarrage  = 10 * time.Second
	delaiEnsureReparation = 60 * time.Second
)

// ensure : repMu tenu.
func (b *NftBanner) ensure(delai time.Duration) (dejaLa bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), delai)
	defer cancel()
	// COMPTEURS PAR ÉLÉMENT (#2240, phase 4). Un ban dont l'ensemble porte `counter` compte les paquets que l'adresse bannie continue d'envoyer : c'est la
	// SEULE façon de savoir, à l'échéance, si elle insiste (rien d'autre ne la voit, la chaîne la rejette avant tout journal). Un ensemble créé avant
	// cela n'a pas le compteur et `add set` refuserait une définition différente (« File exists ») : on le migre — chaîne vidée, ensemble supprimé puis
	// recréé, dans la même transaction que les règles ; Reload() réinjecte les bans du journal avec leur temps restant.
	// Le relevé sans éléments (-t) suffit d'ordinaire : `list set` lit tous les éléments, plusieurs secondes et 100 Mo à 50 000 bans, au démarrage
	// (#3930). La lecture complète ne sert qu'à confirmer avant de migrer.
	apercu, errApercu := b.runner(ctx, "-j", "-t", "list", "sets", "inet")
	dejaLa = true
	var migres []string
	for _, nom := range []string{b.set4, b.set6} {
		if errApercu == nil && ensembleACompteur(apercu, b.table, nom) {
			continue
		}
		dejaLa = false
		if out, err := b.lireEnsemble(ctx, nom); err == nil && ensembleSansCompteur(out) {
			migres = append(migres, nom)
		}
	}
	if out, err := b.scripts(ctx, b.scriptChaine(migres)); err != nil {
		return false, fmt.Errorf("pose de la chaîne %s : %v: %s", b.chain, err, tronque(strings.TrimSpace(string(out)), 300))
	}
	for _, nom := range migres {
		log.Printf("sbxwaf: nft — ensemble %s migré pour porter des compteurs par élément", nom)
	}
	b.mu.Lock()
	b.ready = true
	lancer := b.attente
	b.attente = nil
	b.mu.Unlock()
	for _, f := range lancer {
		f()
	}
	return dejaLa, nil
}

// scriptChaine : la transaction qui pose le blocage. `migres` : ensembles à recréer avec leur compteur.
func (b *NftBanner) scriptChaine(migres []string) []byte {
	var s []byte
	ajouter := func(format string, args ...any) { s = fmt.Appendf(s, format+"\n", args...) }
	// La chaîne qui CONSULTE les sets. Sans elle, les sets sont une comptabilité sans effet. Priorité -100 : avant le filtrage général, pour qu'une
	// source bannie soit écartée au plus tôt. Politique accept : cette chaîne ne fait que retirer les bannis, elle ne décide de rien d'autre.
	chaine := fmt.Sprintf("add chain inet %s %s { type filter hook input priority -100; policy accept; }", b.table, b.chain)
	ajouter("add table inet %s", b.table)
	if len(migres) > 0 {
		ajouter("%s", chaine)
		ajouter("flush chain inet %s %s", b.table, b.chain)
		for _, nom := range migres {
			ajouter("delete set inet %s %s", b.table, nom)
		}
	}
	ajouter("add set inet %s %s { type ipv4_addr; flags timeout; counter; }", b.table, b.set4)
	ajouter("add set inet %s %s { type ipv6_addr; flags timeout; counter; }", b.table, b.set6)
	ajouter("%s", chaine)
	// `add rule` n'est PAS idempotent : sans ce flush, chaque démarrage empilerait un doublon de plus.
	ajouter("flush chain inet %s %s", b.table, b.chain)
	ajouter("add rule inet %s %s ip saddr @%s counter drop", b.table, b.chain, b.set4)
	ajouter("add rule inet %s %s ip6 saddr @%s counter drop", b.table, b.chain, b.set6)
	return s
}

func (b *NftBanner) pret() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ready
}

// QuandPret lance f dès que le blocage est en place : tout de suite, ou à la première pose réussie (veille). Les
// automatismes qui DÉCIDENT des bans n'ont rien à décider tant qu'aucun ne peut être appliqué. f ne doit pas bloquer.
func (b *NftBanner) QuandPret(f func()) {
	b.mu.Lock()
	if !b.ready {
		b.attente = append(b.attente, f)
		b.mu.Unlock()
		return
	}
	b.mu.Unlock()
	f()
}

func (b *NftBanner) setDe(a netip.Addr) string {
	if a.Is4() {
		return b.set4
	}
	return b.set6
}

// Ban ajoute l'IP au set nft avec un timeout, et journalise ban. Anti-tempête
// par IP (cooldown) : la réponse graduée appelle Ban à CHAQUE requête bannie.
//
// GARDE-FOU : une adresse privée n'est JAMAIS ajoutée. Les appelants exemptent
// déjà le LAN, mais ce drop est réel depuis qu'il existe une règle — une seule
// erreur en amont couperait l'accès d'administration à la box, depuis la box.
// Le refus est ici, au dernier moment, où rien ne peut le contourner.
func (b *NftBanner) Ban(ip, cat, sev string) { b.BanFor(ip, cat, sev, b.duration) }

// BanFor est Ban avec une durée choisie par l'appelant (bans gradués : leurre, campagnes). Mêmes garde-fous, même journal.
func (b *NftBanner) BanFor(ip, cat, sev string, duree time.Duration) {
	b.banAt(ip, cat, sev, duree, time.Now())
}

// banAt est BanFor avec l'instant du ban passé en argument (le kill switch pose ses prolongations à SON horloge, qui est testable).
//
// L'échéance la plus TARDIVE est gardée (#3930) : depuis le noyau 6.12, `add element` sur un élément présent change son délai — un ban d'une heure
// raccourcirait un ban de 7 jours posé par une campagne ou à la main.
func (b *NftBanner) banAt(ip, cat, sev string, duree time.Duration, now time.Time) {
	b.poser(ip, cat, sev, duree, now, false)
}

// poser : banAt, ou la prolongation d'un ban (`prolonge`) — ni anti-tempête, ni place dans la file : un ban de la même
// adresse qui attend son tour n'avale pas la prolongation, et l'échéance la plus tardive des deux l'emporte, dans un ordre
// comme dans l'autre (#3932).
func (b *NftBanner) poser(ip, cat, sev string, duree time.Duration, now time.Time, prolonge bool) {
	a, ok := adresseBan(ip)
	if !ok {
		return
	}
	ip = a.String() // une seule écriture par adresse : celle que `wafctl unban` met au journal
	b.mu.Lock()
	if !b.ready {
		b.mu.Unlock()
		return
	}
	if b.protegee(a) {
		dire := time.Since(b.recent[ip]) >= b.cooldown // une ligne par période, pas une par requête
		if dire {
			b.recent[ip] = time.Now()
		}
		b.mu.Unlock()
		if dire {
			log.Printf("sbxwaf: ban écarté %s ← %s : plage protégée (SECUBOX_WAF_PROTEGEES)", ip, cat)
		}
		return
	}
	if b.robots != nil {
		b.mu.Unlock() // la vérification DNS peut durer : jamais sous le verrou
		if nom := b.robots.Verifie(ip); nom != "" {
			log.Printf("sbxwaf: ban écarté %s ← %s : robot d'indexation vérifié (%s), on ne bannit pas un moteur de recherche", ip, cat, nom)
			return
		}
		b.mu.Lock()
	}
	// Horloge réelle, pas `now` : scriptLot compare `recent` au début de la repose.
	reel := time.Now()
	if !prolonge {
		last, deja := b.recent[ip]
		if _, attend := b.enPose[ip]; attend || (deja && reel.Sub(last) < b.cooldown) {
			b.mu.Unlock()
			return
		}
		b.recent[ip] = reel
		b.enPose[ip] = struct{}{}
	}
	if len(b.recent) > 4096 {
		for k, t := range b.recent {
			if reel.Sub(t) > b.cooldown {
				delete(b.recent, k)
			}
		}
	}
	b.mu.Unlock()

	// poseMu : l'élément et sa ligne de journal vont ensemble ; ni un lot ni le retrait de fin de repose ne s'intercalent.
	// L'attente peut dépasser le cooldown : enPose garde la place, et le cooldown repart de la pose (#3930).
	b.poseMu.Lock()
	defer b.poseMu.Unlock()
	pose := false
	defer func() {
		b.mu.Lock()
		if !prolonge {
			delete(b.enPose, ip)
		}
		if pose {
			b.recent[ip] = time.Now()
		} else if !prolonge {
			delete(b.recent, ip) // laisser le prochain coup réessayer
		}
		b.mu.Unlock()
	}()
	set := b.setDe(a)
	secs, expire := int64(duree.Seconds()), now.Add(duree).Unix()
	aussiLong := false
	if actif, ok := b.store.Actif(ip, now.Unix()); ok {
		// #3919 : un verdict de rotation ne remplace pas la ligne d'un ban au moins aussi long d'une autre famille. La réévaluation lit la dernière
		// catégorie, et `rotation:` n'est jamais prolongé : un leurre de 7 jours perdrait sa gradation.
		aussiLong = (actif.Expires == 0 || actif.Expires >= expire) && strings.HasPrefix(cat, "rotation:") &&
			!strings.HasPrefix(actif.Category, "rotation:")
		switch {
		case actif.Expires == 0:
			expire = 0
		case actif.Expires > expire:
			expire, secs = actif.Expires, actif.Expires-now.Unix()
		}
	}
	if secs > resteMax {
		secs = resteMax
	}
	out, intact, err := b.poserElement(set, ip, secs, prolonge)
	if err != nil && tableEffacee(out) {
		// La table venait d'être effacée par un rechargement du ruleset : elle
		// est recréée (ici, ou par un autre ban de la même rafale qui a pris le
		// verrou d'abord), et le ban est rejoué une fois plutôt que perdu.
		// Les bans du journal sont remis en arrière-plan : ce ban-ci n'attend pas.
		if b.recreer("échec d'un ban") {
			b.lancerRepose()
		}
		out, intact, err = b.poserElement(set, ip, secs, prolonge)
	}
	if err != nil {
		msg := strings.TrimSpace(string(out))
		log.Printf("sbxwaf: nft ban échec %s (%s): %v: %s", ip, cat, err, msg)
		b.noterEchec(msg)
		return
	}
	pose = true
	if prolonge && intact {
		log.Printf("sbxwaf: nft — prolongation de %s inutile : l'élément en place finit au moins aussi tard", ip)
		return // rien n'a changé : aucune ligne au journal
	}
	b.mu.Lock()
	b.dernierBan = reel
	b.mu.Unlock()
	if b.store != nil && !aussiLong {
		_ = b.store.Append(BanRecord{
			IP: ip, Category: cat, Severity: sev,
			At: now.Unix(), Expires: expire, Action: "ban",
		})
	}
	log.Printf("sbxwaf: nft BAN %s ← %s (sev=%s, dur=%s)", ip, cat, sev, duree)
}

var reElementPresent = regexp.MustCompile(`(?m)^(?:\S+:\d+:\d+-\d+: )?Error: Could not process rule: File exists\s*$`)

// poserElement crée l'élément, et n'allonge un élément en place que s'il finit plus tôt. `create` d'abord (#3930) : `nft get element` charge
// l'ensemble entier (0,7 s à 60 000 éléments, sous poseMu), il ne sert qu'à un élément déjà là. Présent mais illisible : laissé tel quel, jamais
// raccourci ; la repose le remettra s'il finit avant l'échéance du journal.
//
// `intact` : lu en place, finissant au moins aussi tard, laissé tel quel. `remplacer` (prolongation) : l'élément est refait, compteur remis à zéro, en UNE transaction — aucun instant où l'adresse
// est libre, et sur un noyau d'avant 6.12 où `add` ne change pas le délai d'un élément présent (#3932).
func (b *NftBanner) poserElement(set, ip string, secs int64, remplacer bool) (out []byte, intact bool, err error) {
	elem := fmt.Sprintf("{ %s timeout %ds }", ip, secs)
	nft := func(verbe string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return b.runner(ctx, verbe, "element", "inet", b.table, set, elem)
	}
	out, err = nft("create")
	if err == nil || !reElementPresent.Match(out) {
		return out, false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	switch reste, present := b.resteElement(ctx, set, ip); {
	case present && reste >= 0 && reste < secs && remplacer:
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, err = b.scripts(c, scriptRemplacer(b.table, set, ip, secs))
		return out, false, err
	case present && reste >= 0 && reste < secs:
		out, err = nft("add")
		return out, false, err
	case present:
		return nil, true, nil
	}
	if out, err = nft("create"); err != nil && reElementPresent.Match(out) { // sinon : échu entre-temps, créé
		return nil, false, nil
	}
	return out, false, err
}

// scriptRemplacer refait un élément avec un nouveau délai. Le premier ajout absorbe un élément échu entre-temps : retirer un
// élément absent ferait refuser la transaction.
func scriptRemplacer(table, set, ip string, secs int64) []byte {
	return fmt.Appendf(nil, "add element inet %s %s { %s timeout 60s }\ndelete element inet %s %s { %s }\nadd element inet %s %s { %s timeout %ds }\n",
		table, set, ip, table, set, ip, table, set, ip, secs)
}

var reElementNft = regexp.MustCompile(`expires ((?:[0-9]+(?:ms|[wdhms]))+)`)
var reDureeNft = regexp.MustCompile(`([0-9]+)(ms|[wdhms])`)

// resteElement : secondes restantes d'un élément (-1 : sans échéance). present=false : absent, ou nft n'a pas répondu.
// En TEXTE : nftables 1.1 répond à `-j get element` en texte.
func (b *NftBanner) resteElement(ctx context.Context, set, ip string) (reste int64, present bool) {
	reste, present, _ = b.resteElementSur(ctx, set, ip)
	return reste, present
}

// resteElementSur est resteElement, qui dit en plus si nft n'a pas répondu : « absent » est alors inconnu.
func (b *NftBanner) resteElementSur(ctx context.Context, set, ip string) (reste int64, present bool, err error) {
	out, err := b.runner(ctx, "get", "element", "inet", b.table, set, fmt.Sprintf("{ %s }", ip))
	switch {
	case err != nil && tableEffacee(out):
		return 0, false, nil
	case err != nil:
		return 0, false, fmt.Errorf("nft get element %s : %v: %s", set, err, tronque(strings.TrimSpace(string(out)), 120))
	case !strings.Contains(string(out), ip):
		return 0, false, nil
	}
	m := reElementNft.FindSubmatch(out)
	if m == nil {
		return -1, true, nil
	}
	unites := map[string]int64{"w": 7 * 86400, "d": 86400, "h": 3600, "m": 60, "s": 1, "ms": 0}
	for _, d := range reDureeNft.FindAllSubmatch(m[1], -1) {
		n, _ := strconv.ParseInt(string(d[1]), 10, 64)
		reste += n * unites[string(d[2])]
	}
	return reste, true, nil
}

// ── Auto-réparation (#1693) ──────────────────────────────────────────────────
//
// Ensure ne tourne qu'au démarrage, mais la table ne vit que dans le noyau :
// tout `nft -f /etc/nftables.conf` commence par `flush ruleset` et l'efface
// (`systemctl reload nftables.service` dans un postinst, un outil qui réécrit
// nftables.conf, un redémarrage de nftables.service). Le WAF continuait alors
// à décider des bans que plus rien n'appliquait : chaque `add element`
// échouait, le SOC lisait un ensemble absent comme « aucun ban actif », et
// seul le redémarrage suivant (RuntimeMaxSec=12h) remettait la table. Six
// trous de 6 à 12 h en une semaine sur gk2. Le WAF ne dépend plus de qui
// recharge le pare-feu : il vérifie et répare lui-même.

// tableEffacee reconnaît la réponse de nft quand la table ou l'ensemble visé
// n'existe plus : sa ligne d'erreur, pas les mots n'importe où (un binaire ou un
// fichier manquant les dit aussi).
func tableEffacee(out []byte) bool { return reTableEffacee.Match(out) }

var reTableEffacee = regexp.MustCompile(`(?m)^(?:\S+:\d+:\d+-\d+: )?Error: (?:Could not process rule: )?No such file or directory(?:;.*)?\s*$`)

// Presente dit si le blocage est en place : la chaîne existe ET consulte
// l'ensemble. Tester la seule table ne suffit pas — un `flush table` garde la
// chaîne mais retire les règles, et un ensemble que rien ne consulte ne bloque
// rien (#1218).
func (b *NftBanner) Presente(ctx context.Context) bool {
	out, err := b.runner(ctx, "list", "chain", "inet", b.table, b.chain)
	return err == nil && strings.Contains(string(out), "@"+b.set4)
}

// recreer recrée la table si elle a disparu. Elle n'attend jamais une repose : la
// passe en cours voit la génération changer et repart de zéro. Les bans du journal
// sont à remettre par l'appelant (Reload ou lancerRepose).
//
// Jamais prêt parce que la première pose a échoué (nft figé, droits) : la pose est retentée à chaque appel (#3932).
func (b *NftBanner) recreer(motif string) bool {
	b.mu.Lock()
	voulu := b.ready || b.voulu
	b.mu.Unlock()
	if !voulu {
		return false
	}
	b.repMu.Lock()
	defer b.repMu.Unlock()
	if !b.pret() {
		if _, err := b.ensure(delaiEnsureReparation); err != nil {
			if b.noterEchec(err.Error()) {
				log.Printf("sbxwaf: nft — blocage TOUJOURS PAS en place, aucun ban n'est appliqué : %v", err)
			}
			b.EcrireEtat()
			return false
		}
		b.generation.Add(1)
		b.EcrireEtat()
		log.Printf("sbxwaf: nft — blocage posé (table inet %s) après un échec au démarrage : bans du journal à appliquer", b.table)
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	presente := b.Presente(ctx)
	if !presente && ctx.Err() != nil {
		// nft n'a pas répondu à temps (box chargée) : on ne sait pas, on ne vide pas une chaîne peut-être en place.
		b.noterFige()
		return false
	}
	b.nftFige.Store(false)
	if presente {
		return false
	}
	if _, err := b.ensure(delaiEnsureReparation); err != nil {
		log.Printf("sbxwaf: nft — table inet %s absente (%s) et IMPOSSIBLE à recréer : %v", b.table, motif, err)
		b.noterEchec(err.Error())
		b.EcrireEtat()
		return false
	}
	b.generation.Add(1)
	b.mu.Lock()
	b.reparations++
	b.derniereRep = time.Now()
	b.mu.Unlock()
	b.EcrireEtat()
	log.Printf("sbxwaf: nft — table inet %s effacée (%s, rechargement du pare-feu ?) : recréée, bans du journal à ré-appliquer",
		b.table, motif)
	return true
}

// Reparer recrée la table si elle a disparu et y ré-applique les bans actifs du
// journal. Renvoie true si une réparation a eu lieu. Sans effet sur un banneur
// dont le blocage n'a jamais été demandé (Ensure).
func (b *NftBanner) Reparer(motif string) bool {
	if !b.recreer(motif) {
		return false
	}
	b.Reload()
	b.EcrireEtat()
	return true
}

// Veiller vérifie la table toutes les `pas` et ré-affirme les bans du journal
// toutes les `pasReload` (un `flush set` vide l'ensemble sans toucher la
// chaîne). Ne rend jamais la main.
func (b *NftBanner) Veiller(pas, pasReload time.Duration) { b.veillerJusqua(nil, pas, pasReload) }

// veillerJusqua : l'état est publié à CHAQUE pas, quoi que fasse nft. Vérification
// et repose tournent à part : une repose longue ne fait plus passer le WAF pour
// arrêté, ni n'empêche de voir la table disparaître (#3930).
func (b *NftBanner) veillerJusqua(fin <-chan struct{}, pas, pasReload time.Duration) {
	t := time.NewTicker(pas)
	defer t.Stop()
	var enVerification atomic.Bool
	var dernier atomic.Int64
	dernier.Store(time.Now().UnixNano())
	b.EcrireEtat()
	for {
		select {
		case <-fin:
			return
		case <-t.C:
		}
		b.EcrireEtat()
		if !enVerification.CompareAndSwap(false, true) {
			b.noterFige() // nft n'a pas encore répondu au tour d'avant
			continue
		}
		go func() {
			defer enVerification.Store(false)
			repare := b.recreer("veille")
			if !b.pret() {
				return // rien à reposer : l'état dit que le blocage n'est pas en place, le prochain tour réessaie
			}
			if !repare && time.Since(time.Unix(0, dernier.Load())) < pasReload {
				return
			}
			dernier.Store(time.Now().UnixNano())
			b.lancerRepose()
		}()
	}
}

// compteBans : un compte, ou compteInconnu (null) tant qu'aucune repose n'a fini — jamais 0, qui dirait « rien à appliquer ».
type compteBans int

const compteInconnu compteBans = -1

func (c compteBans) MarshalJSON() ([]byte, error) {
	if c < 0 {
		return []byte("null"), nil
	}
	return strconv.AppendInt(nil, int64(c), 10), nil
}

// EtatNft est l'état du blocage, pour le tableau de bord : un WAF qui décide
// des bans que rien n'applique ne doit plus passer pour un WAF calme.
// Verifie date l'instantané : un fichier qui ne se renouvelle plus veut dire
// un WAF arrêté — ce que personne n'a vu sur gk3, en boucle de redémarrage.
type EtatNft struct {
	Actif        bool   `json:"actif"`
	Table        string `json:"table"`
	Verifie      int64  `json:"verifie"`
	Reparations  int    `json:"reparations"`
	DerniereRep  int64  `json:"derniere_reparation,omitempty"`
	DernierBan   int64  `json:"dernier_ban,omitempty"`
	DernierEchec string `json:"dernier_echec,omitempty"`
	EchecA       int64  `json:"echec_a,omitempty"`

	// Repose des bans du journal (#3930) : bans_poses < bans_attendus, des bans décidés ne sont pas (encore) appliqués.
	ReposeEnCours  bool       `json:"repose_en_cours"`
	DerniereRepose int64      `json:"derniere_repose"`
	BansAttendus   compteBans `json:"bans_attendus"`
	BansPoses      compteBans `json:"bans_poses"`
	NftFige        bool       `json:"nft_fige"` // la dernière vérification de la table n'a pas eu de réponse
}

func unixOuZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// Etat renvoie un instantané de l'état du banneur.
func (b *NftBanner) Etat() EtatNft {
	b.mu.Lock()
	defer b.mu.Unlock()
	return EtatNft{
		Actif:        b.ready,
		Table:        "inet " + b.table,
		Verifie:      time.Now().Unix(),
		Reparations:  b.reparations,
		DerniereRep:  unixOuZero(b.derniereRep),
		DernierBan:   unixOuZero(b.dernierBan),
		DernierEchec: b.dernierEchec,
		EchecA:       unixOuZero(b.echecA),

		ReposeEnCours:  b.reposeEnCours,
		DerniereRepose: unixOuZero(b.derniereRepose),
		BansAttendus:   b.bansAttendus,
		BansPoses:      b.bansPoses,
		NftFige:        b.nftFige.Load(),
	}
}

// noterFige : nft ne répond plus ; l'état le dit jusqu'à sa prochaine réponse.
func (b *NftBanner) noterFige() {
	if !b.nftFige.Swap(true) {
		log.Printf("sbxwaf: nft ne répond pas : table non vérifiée")
		b.noterEchec("nft ne répond pas : table non vérifiée")
		b.EcrireEtat()
	}
}

// noterEchec rend true si le motif est nouveau.
func (b *NftBanner) noterEchec(msg string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	nouveau := b.dernierEchec != msg
	b.dernierEchec, b.echecA = msg, time.Now()
	return nouveau
}

// EcrireEtat publie l'état dans etatFichier (écriture atomique). Une erreur
// d'écriture est journalisée une fois, sans jamais gêner le blocage.
func (b *NftBanner) EcrireEtat() {
	if b.etatFichier == "" {
		return
	}
	b.etatMu.Lock()
	defer b.etatMu.Unlock()
	buf, err := json.Marshal(b.Etat())
	if err == nil {
		tmp := b.etatFichier + ".tmp"
		if err = os.WriteFile(tmp, buf, 0o640); err == nil {
			err = os.Rename(tmp, b.etatFichier)
		}
	}
	if err != nil && !b.etatEchoue {
		log.Printf("sbxwaf: état nft non publié dans %s : %v", b.etatFichier, err)
	}
	b.etatEchoue = err != nil
}

// ensembleSansCompteur : la sortie de `nft -j list set` décrit un ensemble qui EXISTE mais ne porte pas de `stmt` compteur. Une sortie illisible, vide ou
// sans ensemble n'est pas « sans compteur » : l'ensemble est absent, il sera simplement créé.
func ensembleSansCompteur(out []byte) bool {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Stmt []map[string]any `json:"stmt"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if json.Unmarshal(out, &doc) != nil {
		return false
	}
	for _, e := range doc.Nftables {
		if e.Set == nil {
			continue
		}
		for _, st := range e.Set.Stmt {
			if _, ok := st["counter"]; ok {
				return false
			}
		}
		return true
	}
	return false
}

// ensembleACompteur : le relevé `nft -j -t list sets` décrit CET ensemble et il porte un compteur.
func ensembleACompteur(out []byte, table, nom string) bool {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Nom   string           `json:"name"`
				Table string           `json:"table"`
				Stmt  []map[string]any `json:"stmt"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if json.Unmarshal(out, &doc) != nil {
		return false
	}
	for _, e := range doc.Nftables {
		if e.Set == nil || e.Set.Nom != nom || e.Set.Table != table {
			continue
		}
		for _, st := range e.Set.Stmt {
			if _, ok := st["counter"]; ok {
				return true
			}
		}
	}
	return false
}

// lireEnsemble : `nft -j list set`, un seul à la fois (100 Mo à 50 000 éléments, l'unité en a 384). Le délai part une fois le
// tour venu : l'attente de listeMu n'est pas comptée (#3932 — à 50 000 bans, une repose le tient plusieurs secondes).
func (b *NftBanner) lireEnsemble(ctx context.Context, nom string) ([]byte, error) {
	b.listeMu.Lock()
	defer b.listeMu.Unlock()
	c, cancel := context.WithTimeout(ctx, delaiListe)
	defer cancel()
	return b.runner(c, "-j", "list", "set", "inet", b.table, nom)
}

// ElemBan est un ban vivant dans nft : combien de paquets l'adresse a envoyés DEPUIS qu'elle est bannie, et le temps qu'il lui reste.
type ElemBan struct {
	Paquets      uint64
	Reste        int64
	AvecCompteur bool
}

// ElementsAvecCompteurs lit les deux ensembles. Un élément sans compteur (ensemble ancien, avant migration) est rendu avec AvecCompteur=false : l'appelant
// n'en tire AUCUNE preuve de persistance.
func (b *NftBanner) ElementsAvecCompteurs(ctx context.Context) (map[string]ElemBan, error) {
	out := map[string]ElemBan{}
	for _, nom := range []string{b.set4, b.set6} {
		brut, err := b.lireEnsemble(ctx, nom)
		if err != nil {
			return nil, fmt.Errorf("nft list set %s: %v", nom, err)
		}
		var doc struct {
			Nftables []struct {
				Set *struct {
					Elem []struct {
						Elem struct {
							Val     string `json:"val"`
							Expires int64  `json:"expires"`
							Counter *struct {
								Packets uint64 `json:"packets"`
							} `json:"counter"`
						} `json:"elem"`
					} `json:"elem"`
				} `json:"set"`
			} `json:"nftables"`
		}
		if err := json.Unmarshal(brut, &doc); err != nil {
			return nil, fmt.Errorf("sortie nft illisible (%s): %v", nom, err)
		}
		for _, e := range doc.Nftables {
			if e.Set == nil {
				continue
			}
			for _, el := range e.Set.Elem {
				v := ElemBan{Reste: el.Elem.Expires}
				if el.Elem.Counter != nil {
					v.AvecCompteur, v.Paquets = true, el.Elem.Counter.Packets
				}
				out[el.Elem.Val] = v
			}
		}
	}
	return out, nil
}

// Epargne dit pourquoi une adresse ne sera PAS bannie (#4008) : plage protégée ou robot d'indexation vérifié ; « » sinon. Mêmes
// règles que poser, que le journal des menaces consulte AVANT d'écrire « banned » : un ban écarté ne s'y annonce plus comme posé.
// La vérification des robots passe par leur cache ; elle n'a lieu que pour une requête que l'on s'apprête à bannir.
func (b *NftBanner) Epargne(ip string) string {
	if b == nil {
		return ""
	}
	a, ok := adresseBan(ip)
	if !ok {
		return ""
	}
	b.mu.Lock()
	p := b.protegee(a)
	b.mu.Unlock()
	if p {
		return "plage protégée"
	}
	if b.robots != nil {
		if nom := b.robots.Verifie(a.String()); nom != "" {
			return "robot vérifié " + nom
		}
	}
	return ""
}

// Prolonger repose un ban avec une nouvelle durée, sans attendre ni le cooldown ni un ban de la même adresse déjà en file ;
// l'échéance la plus tardive l'emporte, l'adresse n'est jamais libre entre-temps (poserElement). Le journal de bans reçoit une
// nouvelle ligne : le ban prolongé est visible et annulable comme les autres.
func (b *NftBanner) Prolonger(ip, cat, sev string, duree time.Duration, now time.Time) {
	b.poser(ip, cat, sev, duree, now, true)
}
