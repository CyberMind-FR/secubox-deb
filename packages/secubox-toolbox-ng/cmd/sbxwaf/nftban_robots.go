// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"
)

// UN ROBOT VÉRIFIÉ NE RESTE PAS BANNI, SANS TEMPÊTE DNS (#3930).
//
// banAt vérifie chaque adresse AVANT de la bannir : un robot n'est banni que si le DNS n'a pas répondu à cet instant (ou
// s'il l'était avant l'exemption). LibererRobots rattrape ceux-là : les adresses bannies dont la vérification n'a jamais
// CONCLU sont revérifiées, à 5 par seconde au plus et 20 min par passe ; une passe au démarrage, puis chaque heure. Une
// réponse ferme (« pas un robot ») vaut tant que l'adresse reste bannie ; une panne DNS est retentée, 3 fois au plus par
// vie du processus (12 h). Les réseaux des moteurs passent d'abord (robotPlausible) : leurs adresses sont libérées dans
// les premières secondes, l'ordre n'exclut personne.
//
// Une fois libéré, le robot ne revient pas : le journal finit par un `unban` (donc rien à reposer, redémarrage compris),
// et la mémoire (Connu, positifs jamais évincés par des négatifs) l'écarte des lots déjà préparés.
const (
	robotsPas       = 200 * time.Millisecond // 5 vérifications par seconde
	robotsPasse     = 20 * time.Minute
	robotsParallele = 10 // à 2 s par réponse perdue, 10 suffisent à tenir 5/s
	robotsEssaisMax = 3
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
// Chaque adresse garde les écritures que le journal en a : c'est sous elles que l'unban doit être écrit.
func (b *NftBanner) robotsAVerifier(ctx context.Context) ([]string, map[string][]string) {
	candidats := map[string][]string{}
	for _, set := range []string{b.set4, b.set6} {
		e, err := b.lirePresents(ctx, set)
		if err != nil {
			continue // le journal suffit
		}
		for a := range e {
			candidats[a.String()] = nil
		}
	}
	for _, r := range b.store.ActiveBans(time.Now().Unix()) {
		if a, ok := adresseBan(r.IP); ok {
			candidats[a.String()] = append(candidats[a.String()], r.IP)
		}
	}
	b.mu.Lock()
	for ip := range b.robotsVus { // adresse libre : on l'oublie, un nouveau ban la revérifiera
		if _, ok := candidats[ip]; !ok {
			delete(b.robotsVus, ip)
		}
	}
	for ip := range candidats {
		if b.robotsVus[ip] >= robotsEssaisMax {
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
	return append(tete, queue...), candidats
}

// LibererRobots fait une passe : retire des ensembles nft (et du journal, par un unban) les bans posés sur des robots
// d'indexation vérifiés. Rend le nombre d'adresses libérées.
func (b *NftBanner) LibererRobots() int {
	if b.robots == nil {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), robotsPasse)
	defer cancel()
	ips, ecritures := b.robotsAVerifier(ctx)
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		n       int
		places  = make(chan struct{}, robotsParallele)
		cadence = time.NewTicker(b.robotsPas)
	)
	defer cadence.Stop()
	liberer := func(ip, nom string) {
		b.leverRobot(ip, nom, ecritures[ip])
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
	} else if b.robotsVus[ip] < robotsEssaisMax {
		b.robotsVus[ip]++
	}
}

func (b *NftBanner) leverRobot(ip, nom string, ecritures []string) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	set := b.set6
	if a.Is4() {
		set = b.set4
	}
	b.poseMu.Lock()
	defer b.poseMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = b.runner(ctx, "delete", "element", "inet", b.table, set, fmt.Sprintf("{ %s }", a))
	if len(ecritures) == 0 {
		ecritures = []string{ip} // dans nft seulement
	}
	for _, e := range ecritures {
		_ = b.store.Append(BanRecord{IP: e, Category: "robot-verifie:" + nom, Severity: "info", At: time.Now().Unix(), Action: "unban"})
	}
	log.Printf("sbxwaf: ban levé %s : robot d'indexation vérifié (%s)", ip, nom)
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
