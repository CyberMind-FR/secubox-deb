// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"
)

// UN ROBOT VÉRIFIÉ NE RESTE PAS BANNI, SANS TEMPÊTE DNS (#3930).
//
// banAt vérifie chaque adresse AVANT de la bannir : un robot n'est banni que si le DNS n'a pas répondu à cet instant (ou
// s'il l'était avant l'exemption). LibererRobots rattrape ceux-là : les adresses bannies dont la vérification n'a jamais
// CONCLU sont revérifiées, à 5 par seconde au plus et 20 min par passe ; une passe au démarrage, puis chaque heure. Une
// réponse ferme (« pas un robot ») vaut tant que l'adresse reste bannie ; une panne DNS est retentée à chaque passe, après
// les adresses jamais essayées. Les réseaux des moteurs passent d'abord (robotPlausible) : leurs adresses sont libérées dans
// les premières secondes, l'ordre n'exclut personne.
//
// Une fois libéré, le robot ne revient pas : le journal finit par un `unban` (donc rien à reposer, redémarrage compris),
// et la mémoire (Connu, positifs jamais évincés par des négatifs) l'écarte des lots déjà préparés.
const (
	robotsPas       = 200 * time.Millisecond // 5 vérifications par seconde
	robotsPasse     = 20 * time.Minute
	robotsParallele = 10 // à 2 s par réponse perdue, 10 suffisent à tenir 5/s
	robotConclu     = 255
)

// asnMoteurs : réseaux d'où sortent les robots de domainesRobots. Ne sert qu'à l'ORDRE des vérifications.
var asnMoteurs = map[uint32]bool{
	15169: true, 396982: true, // Google
	8075: true,             // Microsoft
	714:  true, 6185: true, // Apple
	13238: true, 208722: true, // Yandex
	38365: true, 55967: true, 4134: true, 4808: true, 4837: true, 23724: true, // Baidu et ses transitaires
}

// robotsAVerifier : adresses bannies (nft et journal) dont rien n'a encore conclu, plausibles d'abord. Les robots déjà
// connus passent en tête de tout.
func (b *NftBanner) robotsAVerifier(ctx context.Context) []string {
	candidats := map[string]struct{}{}
	for _, set := range []string{b.set4, b.set6} {
		e, err := b.lirePresents(ctx, set)
		if err != nil {
			continue // le journal suffit
		}
		for a := range e {
			candidats[a.String()] = struct{}{}
		}
	}
	for _, r := range b.store.ActiveBans(time.Now().Unix()) {
		if a, ok := adresseBan(r.IP); ok {
			candidats[a.String()] = struct{}{}
		}
	}
	essais := make(map[string]uint8, len(candidats))
	b.mu.Lock()
	for ip := range b.robotsVus { // adresse libre : on l'oublie, un nouveau ban la revérifiera
		if _, ok := candidats[ip]; !ok {
			delete(b.robotsVus, ip)
		}
	}
	for ip := range candidats {
		if essais[ip] = b.robotsVus[ip]; essais[ip] == robotConclu {
			delete(candidats, ip)
		}
	}
	b.mu.Unlock()
	var tete, queue []string
	for ip := range candidats {
		if b.robots.Connu(ip) != "" || (b.robotPlausible != nil && b.robotPlausible(ip)) {
			tete = append(tete, ip)
		} else {
			queue = append(queue, ip)
		}
	}
	sort.SliceStable(tete, func(i, j int) bool { return essais[tete[i]] < essais[tete[j]] })
	sort.SliceStable(queue, func(i, j int) bool { return essais[queue[i]] < essais[queue[j]] })
	return append(tete, queue...)
}

// LibererRobots fait une passe : retire des ensembles nft (et du journal, par un unban) les bans posés sur des robots
// d'indexation vérifiés. Rend le nombre d'adresses libérées.
func (b *NftBanner) LibererRobots() int {
	if b.robots == nil {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), robotsPasse)
	defer cancel()
	ips := b.robotsAVerifier(ctx)
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		n       int
		places  = make(chan struct{}, robotsParallele)
		cadence = time.NewTicker(b.robotsPas)
	)
	defer cadence.Stop()
	liberer := func(ip, nom string) {
		b.leverRobot(ip, nom)
		mu.Lock()
		n++
		mu.Unlock()
	}
	premier := true
	for _, ip := range ips {
		if b.robots.Resolu(ip) { // connu : aucun DNS
			nom, conclu := b.robots.VerifieConclu(ip)
			if nom != "" {
				liberer(ip, nom)
			} else if conclu {
				b.noterRobot(ip, true)
			}
			continue
		}
		if !premier {
			select {
			case <-ctx.Done():
			case <-cadence.C:
			}
		}
		premier = false
		select {
		case <-ctx.Done():
		case places <- struct{}{}:
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer func() { <-places }()
			nom, conclu := b.robots.VerifieConclu(ip)
			if nom == "" {
				b.noterRobot(ip, conclu)
				return
			}
			liberer(ip, nom)
		}(ip)
	}
	wg.Wait()
	return n
}

func (b *NftBanner) noterRobot(ip string, conclu bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if conclu {
		b.robotsVus[ip] = robotConclu
	} else if b.robotsVus[ip] < robotConclu-1 {
		b.robotsVus[ip]++
	}
}

func (b *NftBanner) leverRobot(ip, nom string) {
	a, ok := adresseBan(ip)
	if !ok {
		return
	}
	b.poseMu.Lock()
	defer b.poseMu.Unlock()
	// Le journal d'abord : un arrêt entre les deux laisse un ban sans journal, jamais un ban que la repose remettrait.
	_ = b.store.Append(BanRecord{IP: a.String(), Category: "robot-verifie:" + nom, Severity: "info", At: time.Now().Unix(), Action: "unban"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = b.runner(ctx, "delete", "element", "inet", b.table, b.setDe(a), fmt.Sprintf("{ %s }", a))
	log.Printf("sbxwaf: ban levé %s : robot d'indexation vérifié (%s)", a, nom)
}

// VeillerRobots fait une passe tout de suite, puis toutes les `pas`. Ne rend jamais la main.
func (b *NftBanner) VeillerRobots(pas time.Duration) {
	for {
		if n := b.LibererRobots(); n > 0 {
			log.Printf("sbxwaf: %d ban(s) levé(s) sur des robots d'indexation vérifiés", n)
		}
		time.Sleep(pas)
	}
}
