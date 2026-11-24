// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

// BASCULE DES LEURRES DE MESSAGERIE (#3924).
//
// La règle du site envoie 25, 465, 587, 993 et 995 au conteneur de courrier ;
// on n'y touche jamais. Une table À NOUS, posée seulement pendant l'arrêt du
// conteneur, redirige ces ports plus tôt dans le crochet prerouting : le
// premier verdict NAT d'une connexion l'emporte, la règle du site ne s'applique
// plus à elle.
//
// LE COURRIER EST PRIORITAIRE, MÊME SI NOUS MOURONS. Trois retraits
// indépendants, aucun n'ayant besoin des autres :
//   1. une sonde réussie retire la table aussitôt ; l'arrêt propre aussi ;
//   2. ExecStopPost de l'unité la retire après tout arrêt, plantage compris ;
//   3. la redirection passe par un ensemble dont CHAQUE élément expire en trois
//      battements : sans nous, elle s'éteint seule, dans le noyau.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	tableMail        = "secubox_leurres_mail"
	sondeConnexion   = 2 * time.Second
	sondeEchecsPour  = 2 // sondes ratées d'affilée avant de basculer
	sondeIntervalMin = 5 * time.Second
	sondeIntervalMax = 5 * time.Minute
)

// scriptRetrait retire la table, présente ou non.
const scriptRetrait = "add table ip " + tableMail + "\ndelete table ip " + tableMail + "\n"

// scriptBascule rend la transaction COMPLÈTE (reposée à chaque battement : un
// rechargement du pare-feu qui l'aurait effacée est réparé, et l'échéance
// repart — `add element` ne prolonge pas un élément existant).
//
//   - priorité -120 : avant `dstnat` (-100), celle de toutes les règles connues ;
//   - ni le pont des conteneurs, ni la boucle locale, ni une adresse privée :
//     l'hôte (crochet output, jamais touché), le LAN et le maillage gardent leur
//     chemin ; `fib daddr type local` laisse passer ce qui ne fait que transiter ;
//   - chaîne d'entrée : les ports locaux ne se joignent QUE par la redirection.
func scriptBascule(leurres []LeurreMail, echeance time.Duration) string {
	var elements, table, locaux []string
	s := int(echeance.Seconds())
	for _, l := range leurres {
		elements = append(elements, fmt.Sprintf("%d timeout %ds", l.Port, s))
		table = append(table, fmt.Sprintf("%d : %d", l.Port, l.Local))
		locaux = append(locaux, fmt.Sprint(l.Local))
	}
	v := func(x []string) string { return strings.Join(x, ", ") }
	return scriptRetrait + "table ip " + tableMail + " {\n" +
		"\tset actifs {\n" +
		"\t\ttype inet_service\n" +
		"\t\tflags timeout\n" +
		"\t\telements = { " + v(elements) + " }\n" +
		"\t}\n" +
		"\tchain redirection {\n" +
		"\t\ttype nat hook prerouting priority -120; policy accept;\n" +
		"\t\tiifname != { \"br-lxc\", \"lo\" } ip saddr != { 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 } fib daddr type local tcp dport @actifs redirect to :tcp dport map { " + v(table) + " }\n" +
		"\t}\n" +
		"\tchain entree {\n" +
		"\t\ttype filter hook input priority -20; policy accept;\n" +
		"\t\ttcp dport { " + v(locaux) + " } ct status & dnat != dnat drop\n" +
		"\t}\n" +
		"}\n"
}

// BasculeMail est la machine à états. Ses fonctions sont injectables.
type BasculeMail struct {
	intervalle time.Duration
	sonder     func(context.Context) bool
	etat       func() error // nil : conteneur connu arrêté ou absent
	nft        func(context.Context, string) error
	ouvrir     func(context.Context) ([]LeurreMail, func())

	mu     sync.Mutex
	echecs int
	motif  string // dernière raison de ne pas prendre la place, dite une fois
	actif  bool
	depuis time.Time
	ports  []LeurreMail
	fermer func()
}

// NewBasculeMail : `conteneur` est l'adresse IPv4 privée du conteneur de courrier.
func NewBasculeMail(conteneur, nom string, lxcpaths []string, intervalle time.Duration, b *Banneur, m *ServeurMail) (*BasculeMail, error) {
	p := net.ParseIP(conteneur)
	if p == nil || p.To4() == nil || !p.IsPrivate() {
		return nil, fmt.Errorf("--mail-conteneur %q : adresse IPv4 privée attendue", conteneur)
	}
	if intervalle < sondeIntervalMin || intervalle > sondeIntervalMax {
		return nil, fmt.Errorf("--mail-sonde %s : entre %s et %s", intervalle, sondeIntervalMin, sondeIntervalMax)
	}
	if !nomConteneur.MatchString(nom) {
		return nil, fmt.Errorf("--mail-nom %q : nom de conteneur attendu", nom)
	}
	lxc := EtatLXC{Nom: nom, Adresse: p.String(), LxcPaths: lxcpaths, Cgroup: "/sys/fs/cgroup", ProcUnix: "/proc/net/unix"}
	return &BasculeMail{
		intervalle: intervalle,
		etat:       lxc.Remplacable,
		sonder:     func(ctx context.Context) bool { return sondeMail(ctx, p.String()) },
		nft: func(ctx context.Context, script string) error {
			ctx, fin := context.WithTimeout(ctx, 10*time.Second)
			defer fin()
			if out, err := b.run(ctx, script); err != nil {
				return fmt.Errorf("%v : %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		},
		ouvrir: m.Relais,
	}, nil
}

// sondeMail : le conteneur est DEBOUT si le port 25 accepte une connexion, ou à
// défaut l'un des autres ports relayés — un postfix en panne ne doit pas faire
// masquer un dovecot qui sert. La connexion suffit : attendre une bannière
// prendrait un postfix lent pour un conteneur arrêté.
func sondeMail(ctx context.Context, adresse string) bool {
	if sondePort(ctx, adresse, 25) {
		return true
	}
	debout := make(chan bool, len(LeurresMailRelais))
	n := 0
	for _, l := range LeurresMailRelais {
		if l.Port == 25 {
			continue
		}
		n++
		go func(port int) { debout <- sondePort(ctx, adresse, port) }(l.Port)
	}
	res := false
	for ; n > 0; n-- {
		res = <-debout || res
	}
	return res
}

func sondePort(ctx context.Context, adresse string, port int) bool {
	d := net.Dialer{Timeout: sondeConnexion}
	c, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(adresse, fmt.Sprint(port)))
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// tour : une sonde et ce qu'elle entraîne.
func (b *BasculeMail) tour(ctx context.Context) {
	debout := b.sonder(ctx)
	if ctx.Err() != nil {
		return // l'arrêt interrompt la sonde : ce n'est pas un conteneur arrêté
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if debout {
		b.echecs, b.motif = 0, ""
		b.desactive(ctx, "le conteneur répond")
		return
	}
	// Muet mais EN MARCHE (démarrage, gel, panne de postfix) ou état inconnu :
	// on ne prend pas sa place, et on la rend.
	if err := b.etat(); err != nil {
		b.echecs = 0
		b.desactive(ctx, err.Error())
		if b.motif != err.Error() {
			b.motif = err.Error()
			log.Printf("sbx-authwatch: leurres de messagerie non activés — %v, bien qu'il ne réponde pas", err)
		}
		return
	}
	b.motif = ""
	if b.echecs < sondeEchecsPour {
		b.echecs++
	}
	if b.echecs >= sondeEchecsPour {
		b.active(ctx)
	}
}

// active pose la redirection, ou la prolonge (verrou tenu).
func (b *BasculeMail) active(ctx context.Context) {
	if !b.actif {
		b.ports, b.fermer = b.ouvrir(ctx)
	}
	err := fmt.Errorf("aucun port local n'a pu être ouvert")
	if len(b.ports) > 0 {
		err = b.nft(ctx, scriptBascule(b.ports, 3*b.intervalle))
	}
	if err != nil {
		log.Printf("sbx-authwatch: leurres de messagerie non posés : %v", err)
		if !b.actif {
			b.fermer()
			b.ports, b.fermer = nil, nil
		}
		return
	}
	if !b.actif {
		b.actif, b.depuis = true, time.Now()
		log.Printf("sbx-authwatch: conteneur de courrier arrêté — %d leurre(s) de messagerie à sa place", len(b.ports))
	}
}

// desactive retire la redirection PUIS ferme les ports (verrou tenu). Un retrait
// refusé garde les leurres ouverts et se retente au tour suivant ; sans
// battement, les éléments expirent de toute façon.
func (b *BasculeMail) desactive(ctx context.Context, motif string) {
	if !b.actif {
		return
	}
	if err := b.nft(ctx, scriptRetrait); err != nil {
		log.Printf("sbx-authwatch: retrait de la redirection de messagerie refusé (elle expire seule) : %v", err)
		return
	}
	b.fermer()
	b.actif, b.ports, b.fermer = false, nil, nil
	log.Printf("sbx-authwatch: leurres de messagerie retirés — %s", motif)
}

// Boucle sonde jusqu'à l'arrêt, puis retire la redirection.
func (b *BasculeMail) Boucle(ctx context.Context) {
	// Reste d'une vie précédente : rien n'est redirigé avant deux sondes ratées.
	if err := b.nft(ctx, scriptRetrait); err != nil {
		log.Printf("sbx-authwatch: table des leurres de messagerie : %v", err)
	}
	t := time.NewTicker(b.intervalle)
	defer t.Stop()
	for {
		b.tour(ctx)
		select {
		case <-ctx.Done():
			b.mu.Lock()
			defer b.mu.Unlock()
			b.desactive(context.Background(), "arrêt du service")
			return
		case <-t.C:
		}
	}
}

// EtatMail : fichier d'état (root seul : il porte les adresses de visiteurs qui
// ne sont pas des attaquants).
type EtatMail struct {
	Actif    bool                  `json:"actif"`
	Depuis   int64                 `json:"depuis,omitempty"`
	Paniques int                   `json:"paniques"`
	TLS      map[string]ServiceTLS `json:"tls"`
}

// EcrireEtat publie l'état par renommage atomique, 0600.
func (b *BasculeMail) EcrireEtat(m *ServeurMail, chemin string, maintenant time.Time) error {
	m.mu.Lock()
	paniques := m.paniques
	m.mu.Unlock()
	b.mu.Lock()
	e := EtatMail{Actif: b.actif, Paniques: paniques, TLS: m.tls.Etat(maintenant)}
	if b.actif {
		e.Depuis = b.depuis.Unix()
	}
	b.mu.Unlock()
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return ecrireAtomique(chemin, append(data, '\n'), 0600)
}
