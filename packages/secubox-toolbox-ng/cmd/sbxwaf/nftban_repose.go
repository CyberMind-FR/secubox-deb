// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// REPOSE DES BANS PAR LOTS (#3930).
//
// Reload lançait un `nft add element` et un DNS inverse (robots) PAR ban, l'un après l'autre. À 10 441 bans sur gk2 la
// boucle durait des heures : la veille, qui l'appelait, n'écrivait plus son état (page « waf_arrete ») et ne réparait
// plus la table ; après un `flush ruleset`, 130 bans seulement revenaient. Désormais :
//
//   - un script nft par lot de 1 000 éléments, lu sur l'entrée standard (`nft -f -`) ; un lot refusé est recoupé en deux
//     jusqu'à l'élément fautif, dans un budget d'essais ;
//   - la table est lue une fois, et seuls les bans MANQUANTS sont reposés. Ce n'est pas qu'une économie : depuis le noyau
//     6.12, `add element … timeout` sur un élément présent CHANGE son échéance (avant, il ne changeait rien). Une
//     repose de tout raccourcirait un ban allongé hors du journal (wafctl prolonger). Ensemble illisible : un second
//     essai, puis la famille est laissée à la passe suivante, et l'état le dit ;
//   - aucun DNS : seule la mémoire des robots est consultée (Connu) ; les vérifications sont faites à part, à débit
//     borné (nftban_robots.go) ;
//   - une seule repose à la fois, hors de la veille ; une table recréée pendant une repose la fait repartir de zéro.
//
// Rien n'est retiré, sauf ce qu'un lot vient lui-même de poser et que le journal dit LEVÉ depuis (wafctl unban, robot) : la
// levée écrit son `unban` au journal AVANT de retirer l'élément. Le journal est suivi (octets ajoutés seulement, Levees)
// juste avant le lot, qui écarte les levées, juste après, pour celles que le lot a croisées, et en fin de passe (#3932). Une levée suivie d'un
// ban posé à la main (wafctl, hors journal) n'est pas défaite : l'élément n'est retiré que si son échéance est celle que le
// lot a posée. Reste une fenêtre, celle du lot (sa transaction nft, d'ordinaire moins d'une seconde, delaiLot au pire) : un
// ban à la main plus court que l'élément remis (wafctl ne raccourcit rien, il n'y touche donc pas) y est indiscernable de
// lui et repart avec lui.
const (
	tailleLot       = 1000
	delaiLot        = 20 * time.Second
	delaiListe      = 30 * time.Second
	delaiRepose     = 3 * time.Minute
	maxReprises     = 3                      // passes rejouées quand la table a été recréée entre-temps
	budgetIsolement = 256                    // essais nft en plus, pour isoler des éléments refusés
	resteMax        = int64(365 * 24 * 3600) // un délai aberrant ferait refuser tout son lot (« value too large »)
	sortieNftMax    = 32 << 20               // 50 000 éléments : 5,4 Mo

	// Une levée écrite au journal ne se défait pas : au-delà, la plage est douteuse et aucun ban n'est levé (#3932).
	maxLeveesProtegees = 200
)

// nftScript exécute un script nft lu sur l'entrée standard. Injectable pour les tests.
type nftScript func(ctx context.Context, script []byte) ([]byte, error)

func (b *NftBanner) execScript(ctx context.Context, script []byte) ([]byte, error) {
	return lancerNft(exec.CommandContext(ctx, b.nftPath, "-f", "-"), script)
}

var errSortieNft = fmt.Errorf("sortie nft de plus de %d octets", sortieNftMax)

// tamponBorne refuse d'accumuler plus de `reste` octets. Tampon nommé, pas embarqué : son ReadFrom contournerait Write.
type tamponBorne struct {
	tampon bytes.Buffer
	reste  int
}

func (t *tamponBorne) Write(p []byte) (int, error) {
	if len(p) > t.reste {
		return 0, errSortieNft
	}
	t.reste -= len(p)
	return t.tampon.Write(p)
}

func lancerNft(cmd *exec.Cmd, entree []byte) ([]byte, error) {
	sortie := &tamponBorne{reste: sortieNftMax}
	if entree != nil {
		cmd.Stdin = bytes.NewReader(entree)
	}
	cmd.Stdout, cmd.Stderr = sortie, sortie
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	return sortie.tampon.Bytes(), err
}

// banARePoser est un ban du journal prêt pour nft : l'adresse vient de net/netip, jamais du texte du journal.
type banARePoser struct {
	adr     netip.Addr
	ip      string // adresse normalisée (clé de l'anti-tempête)
	pose    int64
	expires int64 // 0 : pas d'échéance au journal, la durée d'office est réarmée
}

// adresseBan normalise une adresse du journal. Refusé : ce qui n'est pas une adresse, une zone (texte libre), et ce que
// banAt n'aurait jamais banni (boucle locale, privé, lien local, CGNAT 100.64.0.0/10 #3932) — même garde-fou, au même dernier moment.
func adresseBan(ip string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified() || rejeuCGNAT.Contains(a) {
		return netip.Addr{}, false
	}
	return a, true
}

// protegee : plage déclarée par l'administrateur (SECUBOX_WAF_PROTEGEES).
func (b *NftBanner) protegee(a netip.Addr) bool {
	if len(b.protegees) == 0 {
		return false
	}
	ip := net.IP(a.AsSlice())
	for _, n := range b.protegees {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (p banARePoser) reste(now int64, duree time.Duration) int64 {
	r := p.expires - now
	if p.expires == 0 {
		r = int64(duree.Seconds())
	}
	if r > resteMax {
		r = resteMax
	}
	return r
}

// bansARePoser lit le journal : bans actifs, adresses valides et uniques, hors robots connus, les plus récents d'abord.
func (b *NftBanner) bansARePoser(now int64) []banARePoser {
	actifs := b.store.ActiveBans(now)
	vus := make(map[netip.Addr]int, len(actifs))
	out := make([]banARePoser, 0, len(actifs))
	for _, r := range actifs {
		a, ok := adresseBan(r.IP)
		if !ok || b.protegee(a) || (b.robots != nil && b.robots.Connu(r.IP) != "") {
			continue // un robot vérifié n'est pas reposé ; LibererRobots écrit son unban
		}
		p := banARePoser{adr: a, ip: a.String(), pose: r.At, expires: r.Expires}
		if p.reste(now, b.duration) <= 0 {
			continue
		}
		if i, deja := vus[a]; deja { // deux écritures de la même adresse : l'échéance la plus lointaine
			if p.reste(now, b.duration) > out[i].reste(now, b.duration) {
				out[i] = p
			}
			continue
		}
		vus[a] = len(out)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].pose != out[j].pose {
			return out[i].pose > out[j].pose
		}
		return out[i].adr.Less(out[j].adr)
	})
	return out
}

var errEnsembleAbsent = errors.New("ensemble nft absent")

// lirePresents rend les adresses d'un ensemble, sans compteurs (`-s`). listeMu : un `nft -j list set` de 50 000 éléments
// prend ~100 Mo, l'unité en a 384 — jamais deux à la fois.
func (b *NftBanner) lirePresents(ctx context.Context, set string) (map[netip.Addr]struct{}, error) {
	b.listeMu.Lock()
	defer b.listeMu.Unlock()
	c, cancel := context.WithTimeout(ctx, delaiListe)
	defer cancel()
	out, err := b.runner(c, "-j", "-s", "list", "set", "inet", b.table, set)
	if err != nil {
		if tableEffacee(out) {
			return nil, errEnsembleAbsent
		}
		return nil, fmt.Errorf("nft list set %s : %v: %s", set, err, tronque(strings.TrimSpace(string(out)), 120))
	}
	e, err := decoderPresents(bytes.NewReader(out))
	if err != nil {
		err = fmt.Errorf("nft list set %s : %v", set, err)
	}
	return e, err
}

// decoderPresents décode `nft -j list set` au fil de l'eau. Une sortie tronquée ou sans ensemble est une erreur, jamais
// un ensemble vide.
func decoderPresents(r io.Reader) (map[netip.Addr]struct{}, error) {
	dec := json.NewDecoder(r)
	attendre := func(d json.Delim) error {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if t != d {
			return fmt.Errorf("sortie nft inattendue : %v au lieu de %v", t, d)
		}
		return nil
	}
	// objet parcourt un objet JSON ; `valeur` consomme la valeur de chaque clé.
	objet := func(valeur func(cle string) error) error {
		if err := attendre('{'); err != nil {
			return err
		}
		for dec.More() {
			t, err := dec.Token()
			if err != nil {
				return err
			}
			cle, _ := t.(string)
			if err := valeur(cle); err != nil {
				return err
			}
		}
		return attendre('}')
	}
	tableau := func(element func() error) error {
		if err := attendre('['); err != nil {
			return err
		}
		for dec.More() {
			if err := element(); err != nil {
				return err
			}
		}
		return attendre(']')
	}
	var brut json.RawMessage
	passer := func() error { return dec.Decode(&brut) }
	out := map[netip.Addr]struct{}{}
	trouve := false
	element := func() error {
		if err := passer(); err != nil {
			return err
		}
		var val string
		if len(brut) > 0 && brut[0] == '"' {
			_ = json.Unmarshal(brut, &val)
		} else {
			var e struct {
				Elem struct {
					Val json.RawMessage `json:"val"`
				} `json:"elem"`
			}
			if json.Unmarshal(brut, &e) == nil {
				_ = json.Unmarshal(e.Elem.Val, &val)
			}
		}
		if a, err := netip.ParseAddr(val); err == nil {
			out[a.Unmap()] = struct{}{}
		}
		return nil
	}
	ensemble := func(cle string) error {
		if cle == "elem" {
			return tableau(element)
		}
		return passer()
	}
	err := objet(func(cle string) error {
		if cle != "nftables" {
			return passer()
		}
		return tableau(func() error {
			return objet(func(cle string) error {
				if cle != "set" {
					return passer()
				}
				trouve = true
				return objet(ensemble)
			})
		})
	})
	if err != nil {
		return nil, err
	}
	if !trouve {
		return nil, errors.New("sortie nft sans ensemble")
	}
	return out, nil
}

// manquants retire de `bans` ceux que nft porte déjà. Ensemble absent : tout manque (le lot le constatera et fera recréer
// la table). Ensemble illisible, deux fois : ses bans ne sont ni posés ni comptés — jamais un ajout à l'aveugle.
// parFamille : les ensembles lus (true : IPv4).
func (b *NftBanner) manquants(ctx context.Context, bans []banARePoser) (absents []banARePoser, presents int, parFamille map[bool]map[netip.Addr]struct{}, illisible error) {
	parFamille = map[bool]map[netip.Addr]struct{}{}
	sautee := map[bool]bool{}
	for _, quatre := range []bool{true, false} {
		set := b.set6
		if quatre {
			set = b.set4
		}
		e, err := b.lirePresents(ctx, set)
		if err != nil && err != errEnsembleAbsent {
			e, err = b.lirePresents(ctx, set)
		}
		if err != nil && err != errEnsembleAbsent {
			sautee[quatre], illisible = true, err
		}
		parFamille[quatre] = e
	}
	for _, p := range bans {
		quatre := p.adr.Is4()
		if _, ok := parFamille[quatre][p.adr]; ok {
			presents++
		} else if !sautee[quatre] {
			absents = append(absents, p)
		}
	}
	return absents, presents, parFamille, illisible
}

// scriptLot écrit le script d'un lot, à l'instant où il part : délais exacts. Écartés : les échus, les robots reconnus
// depuis (Connu), et les adresses rebannies ou prolongées depuis `debut` — le lot porte leur ANCIENNE échéance, que le
// noyau ≥ 6.12 imposerait ; elles comptent comme posées.
func (b *NftBanner) scriptLot(lot []banARePoser, debut time.Time) (script []byte, poses []poseLot, deja, levees int) {
	now := time.Now().Unix()
	adrs := make([]netip.Addr, len(lot))
	for i, p := range lot {
		adrs[i] = p.adr
	}
	// Levées depuis le relevé : elles ne partent pas. Journal illisible : le lot part, verifierLeves le dira.
	leves, _ := b.store.Levees(adrs, now)
	var e4, e6 []byte
	b.mu.Lock()
	recent := make([]bool, len(lot))
	for i, p := range lot {
		t, ok := b.recent[p.ip]
		recent[i] = ok && !t.Before(debut)
	}
	b.mu.Unlock()
	for i, p := range lot {
		reste := p.reste(now, b.duration)
		if _, leve := leves[p.adr]; leve {
			levees++
			continue
		}
		switch {
		case reste <= 0 || (b.robots != nil && b.robots.Connu(p.ip) != ""):
			continue
		case recent[i]:
			deja++
			continue
		}
		e := &e6
		if p.adr.Is4() {
			e = &e4
		}
		if len(*e) > 0 {
			*e = append(*e, ',', ' ')
		}
		*e = p.adr.AppendTo(*e)
		*e = append(*e, " timeout "...)
		*e = strconv.AppendInt(*e, reste, 10)
		*e = append(*e, 's')
		poses = append(poses, poseLot{adr: p.adr, fin: now + reste})
	}
	for _, x := range []struct {
		set   string
		elems []byte
	}{{b.set4, e4}, {b.set6, e6}} {
		if len(x.elems) > 0 {
			script = append(script, "add element inet "+b.table+" "+x.set+" { "...)
			script = append(script, x.elems...)
			script = append(script, " }\n"...)
		}
	}
	return script, poses, deja, levees
}

// poseLot : un élément posé par un lot, et la fenêtre de son échéance dans le noyau (secondes Unix) : `fin`, calculée quand
// le lot est écrit, à `finMax`, si la transaction n'est passée qu'au retour de nft.
type poseLot struct {
	adr         netip.Addr
	fin, finMax int64
}

// margeEcheance : arrondis (délais entiers, `expires` lu à la seconde).
const margeEcheance = 3

// bilanRepose suit une passe.
type bilanRepose struct {
	attendus, presents, ajoutes int
	refuses                     int
	budget                      int
	tableAbsente                bool // table ou ensemble disparu en cours de passe
	complet                     bool
	dernierRefus                string
	illisible                   error     // un ensemble n'a pas pu être lu : ses bans n'ont pas été reposés
	envoyes                     []poseLot // posés par cette passe, les sautés exclus
}

func (r *bilanRepose) poses() int { return r.presents + r.ajoutes }

// poserLot pose un lot ; refusé, il est recoupé en deux pour n'abandonner que l'élément fautif.
func (b *NftBanner) poserLot(ctx context.Context, lot []banARePoser, debut time.Time, r *bilanRepose) {
	if len(lot) == 0 || ctx.Err() != nil || r.tableAbsente {
		return
	}
	// poseMu : la levée d'un robot (retrait nft + unban au journal) ne s'intercale jamais entre le tri et la pose.
	b.poseMu.Lock()
	script, poses, deja, levees := b.scriptLot(lot, debut)
	n := len(poses)
	r.presents += deja
	r.attendus -= levees
	if n == 0 {
		b.poseMu.Unlock()
		return
	}
	avant := time.Now().Unix()
	c, cancel := context.WithTimeout(ctx, delaiLot)
	out, err := b.scripts(c, script)
	cancel()
	if err == nil {
		// Le délai part quand la transaction passe, entre l'écriture du lot et le retour de nft.
		for i := range poses {
			poses[i].finMax = poses[i].fin + time.Now().Unix() - avant + 1
		}
		traites := b.retirerLeves(poses)
		for _, p := range poses { // une levée traitée l'est : la fin de passe ne la relit pas
			if _, ok := traites[p.adr]; !ok {
				r.envoyes = append(r.envoyes, p)
			}
		}
	}
	b.poseMu.Unlock()
	if err == nil {
		r.ajoutes += n
		return
	}
	r.presents -= deja // recomptés par les moitiés
	r.attendus += levees
	switch msg := strings.TrimSpace(string(out)); {
	case tableEffacee(out):
		r.tableAbsente = true
		return
	case ctx.Err() != nil:
		return
	default:
		r.dernierRefus = fmt.Sprintf("%v: %s", err, tronque(msg, 200))
	}
	if len(lot) == 1 {
		r.refuses++
		log.Printf("sbxwaf: nft — ban de %s refusé à la repose : %s", lot[0].adr, r.dernierRefus)
		return
	}
	if r.budget < 2 {
		r.refuses += n
		return
	}
	r.budget -= 2
	m := len(lot) / 2
	b.poserLot(ctx, lot[:m], debut, r)
	b.poserLot(ctx, lot[m:], debut, r)
}

func tronque(s string, n int) string {
	if len(s) > n {
		return strings.ToValidUTF8(s[:n], "") + "…"
	}
	return s
}

// passe pose une fois les bans manquants ; complet=false : à rejouer (table recréée) ou délai épuisé.
func (b *NftBanner) passe(ctx context.Context, generation int64) (r bilanRepose) {
	debut := time.Now()
	b.poseMu.Lock()
	b.retirerLeves(nil) // retraits de la passe d'avant restés en échec
	b.poseMu.Unlock()
	bans := b.bansARePoser(debut.Unix())
	r = bilanRepose{attendus: len(bans), budget: budgetIsolement}
	if len(bans) == 0 && b.protegeesLevees {
		r.complet = true
		return r
	}
	absents, presents, ensembles, illisible := b.manquants(ctx, bans)
	r.presents, r.illisible = presents, illisible
	if !b.protegeesLevees {
		b.protegeesLevees = b.leverProtegees(ensembles) && illisible == nil
	}
	defer func() {
		b.poseMu.Lock()
		defer b.poseMu.Unlock()
		b.retirerLeves(r.envoyes)
	}()
	for i := 0; i < len(absents); i += tailleLot {
		if ctx.Err() != nil || b.generation.Load() != generation {
			return r
		}
		b.poserLot(ctx, absents[i:min(i+tailleLot, len(absents))], debut, &r)
		if r.tableAbsente {
			return r
		}
	}
	r.complet = ctx.Err() == nil && r.illisible == nil
	return r
}

// finRepose publie le compte d'une repose FINIE (#3932) : pendant qu'elle court, l'état garde celui d'avant, ou null.
func (b *NftBanner) finRepose(r bilanRepose) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reposeEnCours = false
	if r.complet {
		b.derniereRepose = time.Now()
	}
	b.bansAttendus = compteBans(r.attendus)
	if r.illisible == nil { // sinon le compte est inconnu : le précédent reste
		b.bansPoses = compteBans(r.poses())
	}
}

// retirerLeves retire de nft les éléments que le lot vient de poser (`poses`, et ceux des passes d'avant restés à retirer)
// et dont la dernière ligne au journal est une levée, s'ils y sont encore AVEC l'échéance posée par le lot : un autre
// élément (ban à la main posé depuis la levée) n'est pas le nôtre. Une échéance passée n'est pas une levée, une adresse
// absente du journal non plus. Journal illisible ou retrait refusé : gardés, revus à la passe suivante. Rend les adresses
// que le journal dit levées. poseMu tenu.
func (b *NftBanner) retirerLeves(poses []poseLot) map[netip.Addr]struct{} {
	if len(poses)+len(b.aRetirer) == 0 || b.store == nil {
		return nil
	}
	now := time.Now().Unix()
	tous := make(map[netip.Addr]poseLot, len(poses)+len(b.aRetirer))
	for a, p := range b.aRetirer {
		if p.finMax+margeEcheance > now { // sinon échu : le noyau l'a retiré
			tous[a] = p
		}
	}
	for _, p := range poses {
		tous[p.adr] = p
	}
	b.aRetirer = nil
	if len(tous) == 0 {
		return nil
	}
	adrs := make([]netip.Addr, 0, len(tous))
	for a := range tous {
		adrs = append(adrs, a)
	}
	levees, err := b.store.Levees(adrs, now)
	if err != nil {
		b.aRetirer = tous
		msg := fmt.Sprintf("journal des bans illisible, levées faites pendant la repose non vérifiées : %v", err)
		if b.noterEchec(msg) {
			log.Printf("sbxwaf: nft — %s", msg)
		}
		return nil
	}
	if len(levees) == 0 {
		return nil
	}
	echeance := b.lecteurEcheances(len(levees))
	nos := make([]netip.Addr, 0, len(levees))
	for a := range levees {
		min, max, present, err := echeance(a)
		switch {
		case err != nil: // nft n'a pas répondu : ni retiré, ni oublié
			b.garderARetirer(tous[a])
		case !present:
		case max < tous[a].fin-margeEcheance || min > tous[a].finMax+margeEcheance:
			log.Printf("sbxwaf: nft — ban de %s levé puis reposé par un autre pendant la repose : laissé", a)
		default:
			nos = append(nos, a)
		}
	}
	sort.Slice(nos, func(i, j int) bool { return nos[i].Less(nos[j]) })
	retires := 0
	for i := 0; i < len(nos); i += tailleLot {
		lot := nos[i:min(i+tailleLot, len(nos))]
		ctx, cancel := context.WithTimeout(context.Background(), delaiLot)
		out, err := b.scripts(ctx, b.scriptRetrait(lot))
		cancel()
		if err != nil {
			for _, a := range lot {
				b.garderARetirer(tous[a])
			}
			msg := fmt.Sprintf("retrait de bans levés pendant la repose, à refaire : %v: %s", err, tronque(strings.TrimSpace(string(out)), 200))
			log.Printf("sbxwaf: nft — %s", msg)
			b.noterEchec(msg)
			continue
		}
		retires += len(lot)
	}
	if retires > 0 {
		log.Printf("sbxwaf: nft — %d ban(s) levé(s) pendant la repose, retiré(s)", retires)
	}
	return levees
}

// lecteurEcheances rend de quoi lire l'échéance de `n` éléments : `get element` un par un s'ils sont peu nombreux (chacun
// charge l'ensemble), les ensembles une seule fois au-delà — poseMu est tenu. La lecture dure (des secondes à 50 000 bans) :
// l'échéance est une fenêtre, de `min` à `max`. Sans échéance : jamais la nôtre, une fenêtre hors d'atteinte.
func (b *NftBanner) lecteurEcheances(n int) func(a netip.Addr) (min, max int64, present bool, err error) {
	if n <= 3 {
		return func(a netip.Addr) (int64, int64, bool, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			debut := time.Now().Unix()
			reste, present, err := b.resteElementSur(ctx, b.setDe(a), a.String())
			if reste < 0 {
				return math.MaxInt64, math.MaxInt64, present, err
			}
			return debut + reste, time.Now().Unix() + reste, present, err
		}
	}
	debut := time.Now().Unix()
	elems, err := b.ElementsAvecCompteurs(context.Background())
	fin := time.Now().Unix()
	return func(a netip.Addr) (int64, int64, bool, error) {
		e, ok := elems[a.String()]
		if ok && e.Reste == 0 { // sans échéance, ou dans sa dernière seconde
			return math.MaxInt64, math.MaxInt64, true, err
		}
		return debut + e.Reste, fin + e.Reste, ok, err
	}
}

func (b *NftBanner) garderARetirer(p poseLot) {
	if b.aRetirer == nil {
		b.aRetirer = map[netip.Addr]poseLot{}
	}
	b.aRetirer[p.adr] = p
}

// scriptRetrait retire des éléments : ajout puis retrait, en une transaction — retirer un élément déjà parti ferait échouer le lot.
func (b *NftBanner) scriptRetrait(lot []netip.Addr) (script []byte) {
	for _, a := range lot {
		script = fmt.Appendf(script, "add element inet %s %s { %s timeout 60s }\ndelete element inet %s %s { %s }\n",
			b.table, b.setDe(a), a, b.table, b.setDe(a), a)
	}
	return script
}

// leverProtegees rattrape les bans posés sur une adresse devenue protégée, ou en CGNAT (#3932) : levés du journal (`unban`)
// puis de nft, et audités. `ensembles` : les adresses que nft porte. false : à refaire (retrait refusé). reposeMu tenu ; une
// fois par démarrage, à la première passe. Plus de maxLeveesProtegees sur des plages déclarées : aucune n'est levée.
func (b *NftBanner) leverProtegees(ensembles map[bool]map[netip.Addr]struct{}) bool {
	intouchable := func(a netip.Addr) bool { return rejeuCGNAT.Contains(a) || b.protegee(a) }
	complet := true
	cibles := map[netip.Addr]struct{}{}
	dansNft := map[netip.Addr]bool{}
	for _, e := range ensembles {
		for a := range e {
			if intouchable(a) {
				cibles[a], dansNft[a] = struct{}{}, true
			}
		}
	}
	for _, r := range b.store.ActiveBans(time.Now().Unix()) {
		if a, err := netip.ParseAddr(r.IP); err == nil && a.Zone() == "" && intouchable(a.Unmap()) {
			cibles[a.Unmap()] = struct{}{}
		}
	}
	lot := make([]netip.Addr, 0, len(cibles))
	proteges := 0
	for a := range cibles {
		if b.protegee(a) {
			proteges++
		}
	}
	if proteges > maxLeveesProtegees {
		msg := fmt.Sprintf("%d bans sur des plages protégées au démarrage, plus de %d : AUCUN n'est levé (SECUBOX_WAF_PROTEGEES trop large ?)", proteges, maxLeveesProtegees)
		log.Printf("sbxwaf: nft — ATTENTION : %s", msg)
		b.noterEchec(msg)
		b.auditer(time.Now(), "ban_protegee_plafond", msg)
	}
	for a := range cibles {
		if proteges <= maxLeveesProtegees || !b.protegee(a) {
			lot = append(lot, a)
		}
	}
	sort.Slice(lot, func(i, j int) bool { return lot[i].Less(lot[j]) })
	for i := 0; i < len(lot); i += tailleLot {
		if !b.leverLot(lot[i:min(i+tailleLot, len(lot))], dansNft) {
			complet = false
		}
	}
	return complet
}

func (b *NftBanner) leverLot(lot []netip.Addr, dansNft map[netip.Addr]bool) bool {
	b.poseMu.Lock()
	defer b.poseMu.Unlock()
	now := time.Now()
	var retraits, leves []netip.Addr
	ok := true
	for _, a := range lot {
		// Le journal d'abord : un arrêt entre les deux laisse un ban sans journal, jamais un ban que la repose remettrait.
		if err := b.store.Append(BanRecord{IP: a.String(), Category: "levee:protegee", Severity: "info", At: now.Unix(), Action: "unban"}); err != nil {
			log.Printf("sbxwaf: ban de %s (plage protégée) non levé : journal : %v", a, err)
			ok = false
			continue
		}
		leves = append(leves, a)
		if dansNft[a] {
			retraits = append(retraits, a)
		}
	}
	if len(retraits) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), delaiLot)
		out, err := b.scripts(ctx, b.scriptRetrait(retraits))
		cancel()
		if err != nil {
			msg := fmt.Sprintf("retrait de bans sur des plages protégées, à refaire : %v: %s", err, tronque(strings.TrimSpace(string(out)), 200))
			log.Printf("sbxwaf: nft — %s", msg)
			b.noterEchec(msg)
			return false
		}
	}
	for _, a := range leves {
		log.Printf("sbxwaf: ban levé %s : plage protégée (SECUBOX_WAF_PROTEGEES) ou CGNAT", a)
		b.auditer(now, "ban_protegee_leve", a.String())
	}
	return ok
}

// auditer écrit une ligne au journal d'audit du WAF.
func (b *NftBanner) auditer(now time.Time, action, detail string) {
	if b.audit == "" {
		return
	}
	ligne, _ := json.Marshal(map[string]any{"ts": now.UTC().Format("2006-01-02T15:04:05Z"), "module": "waf", "action": action, "detail": detail})
	mu := verrouAjout(b.audit)
	mu.Lock()
	defer mu.Unlock()
	f, err := os.OpenFile(b.audit, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		log.Printf("sbxwaf: audit %s : %v", b.audit, err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(ligne, '\n')); err != nil {
		log.Printf("sbxwaf: audit %s : %v", b.audit, err)
	}
}

// Reload remet dans nft les bans actifs du journal qui n'y sont pas (démarrage, réparation) et rend leur nombre. C'est
// ce qui fait SURVIVRE les bans au redémarrage du WAF. Le timeout ré-armé est le RESTE à courir, pas la durée pleine.
// Une seule repose à la fois : l'appel attend celle qui court.
func (b *NftBanner) Reload() int {
	if b.store == nil {
		return 0
	}
	b.reposeMu.Lock()
	defer b.reposeMu.Unlock()
	return b.reposer()
}

// lancerRepose fait une repose en arrière-plan. Les demandes faites pendant qu'une repose court n'en font qu'une de plus.
func (b *NftBanner) lancerRepose() {
	if b.store == nil || !b.reposeAttend.CompareAndSwap(false, true) {
		return
	}
	go func() {
		b.reposeMu.Lock()
		defer b.reposeMu.Unlock()
		b.reposeAttend.Store(false)
		b.reposer()
	}()
}

// reposer : reposeMu tenu.
func (b *NftBanner) reposer() int {
	debut := time.Now()
	b.mu.Lock()
	b.reposeEnCours = true
	pret := b.ready
	b.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), delaiRepose)
	defer cancel()
	n := 0
	var r bilanRepose
	for i := 0; i <= maxReprises; i++ {
		generation := b.generation.Load()
		r = b.passe(ctx, generation)
		n += r.ajoutes
		if r.tableAbsente && pret {
			b.recreer("repose des bans")
		}
		if ctx.Err() != nil || b.generation.Load() == generation {
			break // finie, ou rien ne changera en rejouant
		}
	}
	b.finRepose(r)
	if !r.complet || r.refuses > 0 {
		msg := fmt.Sprintf("repose incomplète : %d ban(s) sur %d en place", r.poses(), r.attendus)
		if r.illisible != nil {
			msg = fmt.Sprintf("repose incomplète, ensemble illisible : %v", r.illisible)
		}
		if r.dernierRefus != "" {
			msg += " (" + r.dernierRefus + ")"
		}
		b.noterEchec(msg)
		log.Printf("sbxwaf: nft — %s, %d refusé(s), %s", msg, r.refuses, time.Since(debut).Round(time.Millisecond))
	} else if n > 0 {
		log.Printf("sbxwaf: nft — %d ban(s) ré-injecté(s) depuis le journal, %d/%d en place, %s", n, r.poses(), r.attendus,
			time.Since(debut).Round(time.Millisecond))
	}
	return n
}

// PremiereRepose rejoue le journal au démarrage sans retarder l'écoute de plus de `attente` ; au-delà, la repose finit en
// arrière-plan. Rend le nombre de bans reposés, et false si elle n'est pas finie.
func (b *NftBanner) PremiereRepose(attente time.Duration) (int, bool) {
	fini := make(chan int, 1)
	go func() { fini <- b.Reload() }()
	t := time.NewTimer(attente)
	defer t.Stop()
	select {
	case n := <-fini:
		return n, true
	case <-t.C:
		return 0, false
	}
}
