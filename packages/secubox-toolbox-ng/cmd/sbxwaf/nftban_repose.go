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
	"net/netip"
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
// Rien n'est retiré, sauf ce que la passe vient elle-même de poser et qui a été levé entre-temps (wafctl unban, robot) :
// la levée écrit son `unban` au journal AVANT de retirer l'élément, le journal relu en fin de passe la dit donc.
const (
	tailleLot       = 1000
	delaiLot        = 20 * time.Second
	delaiListe      = 30 * time.Second
	delaiRepose     = 3 * time.Minute
	maxReprises     = 3                      // passes rejouées quand la table a été recréée entre-temps
	budgetIsolement = 256                    // essais nft en plus, pour isoler des éléments refusés
	resteMax        = int64(365 * 24 * 3600) // un délai aberrant ferait refuser tout son lot (« value too large »)
	sortieNftMax    = 32 << 20               // 50 000 éléments : 5,4 Mo
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
// banAt n'aurait jamais banni (boucle locale, privé, lien local) — même garde-fou, au même dernier moment.
func adresseBan(ip string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
		return netip.Addr{}, false
	}
	return a, true
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
		if !ok || (b.robots != nil && b.robots.Connu(r.IP) != "") {
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
func (b *NftBanner) manquants(ctx context.Context, bans []banARePoser) (absents []banARePoser, presents int, illisible error) {
	parFamille := map[bool]map[netip.Addr]struct{}{}
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
	return absents, presents, illisible
}

// scriptLot écrit le script d'un lot, à l'instant où il part : délais exacts. Écartés : les échus, les robots reconnus
// depuis (Connu), et les adresses rebannies ou prolongées depuis `debut` — le lot porte leur ANCIENNE échéance, que le
// noyau ≥ 6.12 imposerait ; elles comptent comme posées.
func (b *NftBanner) scriptLot(lot []banARePoser, debut time.Time) (script []byte, poses, deja int) {
	now := time.Now().Unix()
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
		poses++
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
	return script, poses, deja
}

// bilanRepose suit une passe.
type bilanRepose struct {
	attendus, presents, ajoutes int
	refuses                     int
	budget                      int
	tableAbsente                bool // table ou ensemble disparu en cours de passe
	complet                     bool
	dernierRefus                string
	illisible                   error        // un ensemble n'a pas pu être lu : ses bans n'ont pas été reposés
	envoyes                     []netip.Addr // posés par cette passe
}

func (r *bilanRepose) poses() int { return r.presents + r.ajoutes }

// poserLot pose un lot ; refusé, il est recoupé en deux pour n'abandonner que l'élément fautif.
func (b *NftBanner) poserLot(ctx context.Context, lot []banARePoser, debut time.Time, r *bilanRepose) {
	if len(lot) == 0 || ctx.Err() != nil || r.tableAbsente {
		return
	}
	// poseMu : la levée d'un robot (retrait nft + unban au journal) ne s'intercale jamais entre le tri et la pose.
	b.poseMu.Lock()
	script, n, deja := b.scriptLot(lot, debut)
	r.presents += deja
	if n == 0 {
		b.poseMu.Unlock()
		return
	}
	c, cancel := context.WithTimeout(ctx, delaiLot)
	out, err := b.scripts(c, script)
	cancel()
	b.poseMu.Unlock()
	if err == nil {
		r.ajoutes += n
		for _, p := range lot {
			r.envoyes = append(r.envoyes, p.adr)
		}
		return
	}
	r.presents -= deja // recomptés par les moitiés
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
	bans := b.bansARePoser(debut.Unix())
	r = bilanRepose{attendus: len(bans), budget: budgetIsolement}
	if len(bans) == 0 {
		r.complet = true
		return r
	}
	var absents []banARePoser
	absents, r.presents, r.illisible = b.manquants(ctx, bans)
	b.publierRepose(r)
	defer func() { b.retirerLeves(r.envoyes) }()
	for i := 0; i < len(absents); i += tailleLot {
		if ctx.Err() != nil || b.generation.Load() != generation {
			return r
		}
		b.poserLot(ctx, absents[i:min(i+tailleLot, len(absents))], debut, &r)
		if r.tableAbsente {
			return r
		}
		b.publierRepose(r)
	}
	r.complet = ctx.Err() == nil && r.illisible == nil
	return r
}

func (b *NftBanner) publierRepose(r bilanRepose) {
	b.mu.Lock()
	b.bansAttendus = r.attendus
	if r.illisible == nil { // sinon le compte est inconnu : le précédent reste
		b.bansPoses = r.poses()
	}
	b.mu.Unlock()
}

// retirerLeves retire de nft les adresses que la passe a posées et dont le ban n'est plus actif au journal.
func (b *NftBanner) retirerLeves(envoyes []netip.Addr) {
	if len(envoyes) == 0 {
		return
	}
	b.poseMu.Lock() // ni ban ni levée de robot entre la relecture et le retrait
	defer b.poseMu.Unlock()
	actifs := map[netip.Addr]struct{}{}
	for _, r := range b.store.ActiveBans(time.Now().Unix()) {
		if a, ok := adresseBan(r.IP); ok {
			actifs[a] = struct{}{}
		}
	}
	var leves []netip.Addr
	for _, a := range envoyes {
		if _, ok := actifs[a]; !ok {
			leves = append(leves, a)
		}
	}
	for i := 0; i < len(leves); i += tailleLot {
		var script []byte
		for _, a := range leves[i:min(i+tailleLot, len(leves))] {
			// Ajout puis retrait, en une transaction : le retrait d'un élément déjà parti ferait échouer le lot.
			script = fmt.Appendf(script, "add element inet %s %s { %s timeout 60s }\ndelete element inet %s %s { %s }\n",
				b.table, b.setDe(a), a, b.table, b.setDe(a), a)
		}
		ctx, cancel := context.WithTimeout(context.Background(), delaiLot)
		out, err := b.scripts(ctx, script)
		cancel()
		if err != nil {
			msg := fmt.Sprintf("retrait de bans levés pendant la repose : %v: %s", err, tronque(strings.TrimSpace(string(out)), 200))
			log.Printf("sbxwaf: nft — %s", msg)
			b.noterEchec(msg)
			return
		}
	}
	if len(leves) > 0 {
		log.Printf("sbxwaf: nft — %d ban(s) levé(s) pendant la repose, retiré(s)", len(leves))
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
	b.mu.Lock()
	b.reposeEnCours = false
	if r.complet {
		b.derniereRepose = time.Now()
	}
	b.mu.Unlock()
	b.publierRepose(r)
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
