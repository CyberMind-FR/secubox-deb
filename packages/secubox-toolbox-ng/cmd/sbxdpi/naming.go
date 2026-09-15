// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxdpi :: NOMMAGE DES INTERLOCUTEURS
//
// Les talkers étaient des paires d'adresses — « 192.168.1.254 → 192.168.1.200 ».
// L'interface les réduisait aux derniers octets, « ·254 → ·200 », ce qui ne
// désigne rien. Ce fichier donne un NOM à chaque adresse, et dit D'OÙ il vient.
//
// ── LE NOM OBSERVÉ BAT LE DNS INVERSE, et c'est la décision centrale ─────────
//
// Le moteur voit déjà passer le nom que le client a DEMANDÉ (SNI, requête DNS).
// Interroger un résolveur pour redécouvrir ce nom serait payer un aller-retour
// réseau pour une information qu'on tient déjà. Et les deux ne disent pas la
// même chose : le PTR nomme le PROPRIÉTAIRE de l'adresse, le SNI nomme ce que
// l'utilisateur voulait joindre. Pour 82.67.100.75, le PTR rend
// « maegia.hd.free.fr » ; le SNI rend « www.maegia.tv ». C'est le second qu'on
// reconnaît.
//
// Le PTR reste utile en DERNIER RECOURS, pour les adresses qu'aucun flux n'a
// nommées — mais il est résolu HORS DU CHEMIN CHAUD, dans une file bornée, et
// JAMAIS pour une adresse privée : demander à un résolveur externe le nom de
// 192.168.1.61, c'est lui décrire le plan du réseau interne.
//
// ── ORDRE DE PRIORITÉ ───────────────────────────────────────────────────────
//
//	alias    table de l'opérateur            il a toujours raison
//	soi      une adresse de la box            elle se reconnaît
//	observé  SNI/DNS vu dans un flux          ce que le client a demandé
//	voisin   table ARP → constructeur (OUI)   « Apple ·61 » vaut mieux que « ·61 »
//	ptr      DNS inverse                      dernier recours, public uniquement
//
// Chaque identité porte sa source : une interface qui affiche « Apple » doit
// pouvoir dire que c'est déduit d'une adresse MAC, pas lu sur l'appareil.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Bornes. Toutes les tables sont plafonnées : un balayage qui touche des
// milliers d'adresses ne doit pas faire enfler le démon.
const (
	nomsCap      = 4000            // adresses nommées gardées en mémoire
	ptrCap       = 1500            // résultats de DNS inverse mémorisés
	ptrFileCap   = 256             // file d'attente de résolution
	ptrTimeout   = 2 * time.Second // au-delà, l'adresse reste anonyme
	ouiPath      = "/usr/share/ieee-data/oui.txt"
	voisinsEvery = 90 * time.Second
)

// identite : un nom, et d'où il vient. La source n'est pas décorative — c'est
// ce qui distingue un nom CONSTATÉ d'un nom DÉDUIT.
type identite struct {
	Nom    string `json:"nom"`
	Source string `json:"source,omitempty"` // alias · soi · observé · voisin · ptr
	Portee string `json:"portee,omitempty"` // soi · local · public
}

type nommeur struct {
	mu sync.RWMutex

	alias   map[string]string // /etc/secubox/dpi/ip-names.json
	soi     map[string]bool   // adresses des interfaces de la box
	observe map[string]string // IP → nom vu dans un flux (SNI/DNS)
	voisins map[string]string // IP → constructeur, via ARP + OUI
	ptr     map[string]string // IP → nom inverse ("" = résolu, sans résultat)

	aliasPath  string
	aliasMtime int64

	file    chan string
	ptrOnce sync.Once
	oui     map[string]string
	ouiOnce sync.Once
}

func newNommeur(aliasPath string) *nommeur {
	n := &nommeur{
		alias:     map[string]string{},
		soi:       map[string]bool{},
		observe:   map[string]string{},
		voisins:   map[string]string{},
		ptr:       map[string]string{},
		aliasPath: aliasPath,
		file:      make(chan string, ptrFileCap),
	}
	n.relitAlias()
	n.relitSoi()
	n.relitVoisins()
	return n
}

// --- sources ---------------------------------------------------------------

// relitAlias charge la table de l'opérateur. Absente ou illisible → table vide,
// jamais d'erreur : le nommage est un confort, pas une dépendance.
func (n *nommeur) relitAlias() {
	if n.aliasPath == "" {
		return
	}
	st, err := os.Stat(n.aliasPath)
	if err != nil {
		return
	}
	if mt := st.ModTime().Unix(); mt == n.aliasMtime {
		return
	} else {
		n.aliasMtime = mt
	}
	buf, err := os.ReadFile(n.aliasPath)
	if err != nil {
		return
	}
	var brut map[string]string
	if err := json.Unmarshal(buf, &brut); err != nil {
		return
	}
	m := make(map[string]string, len(brut))
	for k, v := range brut {
		// Les clés « __ » sont de la documentation dans le fichier, pas des
		// adresses — même convention que device-names.json.
		if strings.HasPrefix(k, "__") || v == "" {
			continue
		}
		m[k] = v
	}
	n.mu.Lock()
	n.alias = m
	n.mu.Unlock()
}

// relitSoi relève les adresses portées par les interfaces de la box.
func (n *nommeur) relitSoi() {
	adrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	m := map[string]bool{}
	for _, a := range adrs {
		if ipn, ok := a.(*net.IPNet); ok {
			m[ipn.IP.String()] = true
		}
	}
	n.mu.Lock()
	n.soi = m
	n.mu.Unlock()
}

// chargeOUI lit la base IEEE une seule fois, à la première adresse MAC vue.
// ~35 000 entrées : on ne relit pas le fichier par appareil.
func (n *nommeur) chargeOUI() {
	n.ouiOnce.Do(func() {
		m := map[string]string{}
		f, err := os.Open(ouiPath)
		if err != nil {
			n.oui = m
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			// Format : "AC-DE-48   (hex)\t\tPRIVATE"
			l := sc.Text()
			i := strings.Index(l, "(hex)")
			if i < 8 {
				continue
			}
			pref := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(l[:i]), "-", ""))
			if len(pref) != 6 {
				continue
			}
			nom := strings.TrimSpace(l[i+len("(hex)"):])
			if nom == "" {
				continue
			}
			m[pref] = abrege(nom)
		}
		n.oui = m
	})
}

// abrege raccourcit une raison sociale en marque. « Apple, Inc. » → « Apple ».
// La forme juridique n'apprend rien à qui lit un tableau de trafic.
func abrege(s string) string {
	s = strings.TrimSpace(s)
	for _, coupe := range []string{",", " Inc", " Corp", " Ltd", " LLC", " GmbH",
		" Co.", " Company", " Technologies", " Technology", " Electronics"} {
		if i := strings.Index(s, coupe); i > 0 {
			s = s[:i]
		}
	}
	if len(s) > 22 {
		s = s[:22]
	}
	return strings.TrimSpace(s)
}

// relitVoisins relève la table ARP/NDP et traduit chaque MAC en constructeur.
// C'est la seule source qui nomme un appareil du réseau local quand le serveur
// DHCP n'est pas la box — ici la Freebox distribue les baux, et
// /var/lib/misc/dnsmasq.leases reste donc vide.
func (n *nommeur) relitVoisins() {
	ctx, annule := context.WithTimeout(context.Background(), 3*time.Second)
	defer annule()
	sortie, err := exec.CommandContext(ctx, "ip", "neigh").Output()
	if err != nil {
		return
	}
	n.chargeOUI()
	m := map[string]string{}
	for _, l := range strings.Split(string(sortie), "\n") {
		ch := strings.Fields(l)
		if len(ch) < 5 {
			continue
		}
		ip := ch[0]
		var mac string
		for i, c := range ch {
			if c == "lladdr" && i+1 < len(ch) {
				mac = ch[i+1]
				break
			}
		}
		if mac == "" {
			continue
		}
		pref := strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
		if len(pref) < 6 {
			continue
		}
		if v := n.oui[pref[:6]]; v != "" {
			m[ip] = v
		}
	}
	if len(m) == 0 {
		return
	}
	n.mu.Lock()
	n.voisins = m
	n.mu.Unlock()
}

// Observe enregistre le nom qu'un flux a révélé. Appelé sur le chemin chaud :
// une écriture de map sous verrou court, rien de plus.
func (n *nommeur) Observe(ip, host string) {
	if ip == "" || host == "" || ip == host {
		return
	}
	n.mu.Lock()
	if _, vu := n.observe[ip]; !vu && len(n.observe) < nomsCap {
		n.observe[ip] = host
	}
	n.mu.Unlock()
}

// --- résolution inverse, hors du chemin chaud ------------------------------

// demandePTR met une adresse en file. Non bloquant : si la file est pleine,
// l'adresse reste anonyme ce tour-ci plutôt que de retarder un flux.
func (n *nommeur) demandePTR(ip string) {
	select {
	case n.file <- ip:
	default:
	}
}

// BoucleInverse résout les adresses en attente. Un seul travailleur : le DNS
// inverse est un confort d'affichage, il ne mérite pas d'ouvrir une rafale de
// requêtes sortantes à chaque rafraîchissement du tableau.
func (n *nommeur) BoucleInverse(ctx context.Context) {
	rafraichi := time.NewTicker(voisinsEvery)
	defer rafraichi.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-rafraichi.C:
			// La table ARP vieillit : un appareil éteint en sort, un nouveau y
			// entre. On la relit périodiquement, avec les alias.
			n.relitVoisins()
			n.relitAlias()
		case ip := <-n.file:
			c, annule := context.WithTimeout(ctx, ptrTimeout)
			noms, err := net.DefaultResolver.LookupAddr(c, ip)
			annule()
			nom := ""
			if err == nil && len(noms) > 0 {
				nom = strings.TrimSuffix(noms[0], ".")
			}
			n.mu.Lock()
			if len(n.ptr) < ptrCap {
				// On mémorise même l'ÉCHEC (chaîne vide) : sans cela, une
				// adresse sans PTR serait redemandée à chaque snapshot.
				n.ptr[ip] = nom
			}
			n.mu.Unlock()
		}
	}
}

// --- résolution ------------------------------------------------------------

// Nomme rend l'identité d'une adresse. Ne bloque jamais : si seul le DNS
// inverse pourrait répondre, l'adresse est mise en file et rendue telle quelle,
// puis nommée au snapshot suivant.
func (n *nommeur) Nomme(ip string) identite {
	if ip == "" {
		return identite{}
	}
	prive := isLocalIP(ip)
	portee := "public"
	if prive {
		portee = "local"
	}

	n.mu.RLock()
	alias, aAlias := n.alias[ip]
	estSoi := n.soi[ip]
	obs := n.observe[ip]
	vois := n.voisins[ip]
	rev, aPTR := n.ptr[ip]
	n.mu.RUnlock()

	switch {
	case aAlias:
		return identite{Nom: alias, Source: "alias", Portee: portee}
	case estSoi:
		return identite{Nom: "cette box", Source: "soi", Portee: "soi"}
	case obs != "":
		return identite{Nom: obs, Source: "observé", Portee: portee}
	case vois != "":
		// « Apple ·61 » : le constructeur ne suffit pas à distinguer deux
		// appareils de la même marque, le dernier octet si.
		return identite{Nom: vois + " " + dernierOctet(ip), Source: "voisin", Portee: portee}
	case aPTR && rev != "":
		return identite{Nom: rev, Source: "ptr", Portee: portee}
	}

	// Rien pour l'instant. On ne demande un PTR que pour le PUBLIC : résoudre
	// une adresse privée auprès d'un résolveur externe lui décrirait le réseau
	// interne — et n'obtiendrait rien.
	if !prive && !aPTR {
		n.demandePTR(ip)
	}
	return identite{Nom: ip, Portee: portee}
}

// dernierOctet rend « ·61 » pour 192.168.1.61. Pour IPv6, le dernier groupe.
func dernierOctet(ip string) string {
	if i := strings.LastIndex(ip, "."); i >= 0 {
		return "·" + ip[i+1:]
	}
	if i := strings.LastIndex(ip, ":"); i >= 0 {
		return "·" + ip[i+1:]
	}
	return ""
}
