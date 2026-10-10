// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
)

// Capteur DPI d'Actor Intelligence (#2240, phase 2).
//
// nDPI marque chaque flux de « risques ». La plupart sont du BRUIT sur un réseau réel (mesuré sur gk2 : 12 millions de « Known Proto on Non Std Port »,
// 11 millions de « Error Code ») : ils ne produisent AUCUN signal. Seuls quelques risques parlent d'une intention hostile — empreinte TLS malveillante,
// sonde, User-Agent suspect, tentative d'exploitation, hôte à logiciel malveillant. Chacun porte un poids ; une adresse PUBLIQUE dont les flux cumulent au
// moins `seuil` points en 10 minutes devient une enveloppe `dpi` envoyée à actord, qui la corrèle avec le WAF, le pare-feu et le DNS.
//
// Garde-fous : jamais d'adresse privée, locale, lien-local, CGNAT ou multicast (les appareils du réseau ne sont pas jugés ici) ; un même flux ne compte
// qu'une fois par risque (un flux émet plusieurs événements : détecté, mis à jour, terminé) ; pas de répétition d'un même acteur sauf si son score double ;
// mémoire bornée (4 096 sources, 1 024 couples flux/risque par source) ; sans émetteur, le capteur ne fait rien et ne coûte rien.
const (
	fenetreCapteur     = 10 * time.Minute
	seuilCapteurDefaut = 6
	maxSourcesCapteur  = 4096
	maxCouplesParSrc   = 1024
)

// risquesCapteurDefaut : nom nDPI → poids. Tout risque absent d'ici pèse 0. Surchargeable par DPI_ACTOR_RISQUES (« Nom=poids, Nom=poids »).
var risquesCapteurDefaut = map[string]int{
	"Malicious Fingerprint":    3,
	"Possible Exploit Attempt": 5,
	"Malware Host Contacted":   5,
	"HTTP Susp User-Agent":     2,
	"Probing Attempt":          1,
	"TLS Susp Extn":            1,
}

func parseRisquesCapteur(spec string) map[string]int {
	out := map[string]int{}
	spec = strings.TrimSpace(spec)
	if spec == "" {
		for k, v := range risquesCapteurDefaut {
			out[k] = v
		}
		return out
	}
	for _, part := range strings.Split(spec, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		if w, err := strconv.Atoi(strings.TrimSpace(kv[1])); err == nil && w > 0 {
			out[strings.TrimSpace(kv[0])] = w
		}
	}
	return out
}

type dpiEmetteur interface{ Emit(*envelope.Envelope) bool }

type srcCapteur struct {
	debut     time.Time
	score     int
	emis      int // score au moment de la dernière émission (0 = jamais)
	couples   map[string]bool
	ports     map[int]bool
	risques   map[string]int
	ja4       string
	proto     string
	transport string
}

type ActorSensor struct {
	emetteur dpiEmetteur
	poids    map[string]int
	seuil    int
	now      func() time.Time
	// muet : liste de l'opérateur (DPI_RISK_MUTE) — un risque qu'il a réduit au silence ne compte jamais, ici non plus. Posé avant le démarrage.
	muet func(risque string) bool

	mu  sync.Mutex
	acc map[string]*srcCapteur
}

func NewActorSensor(e dpiEmetteur, poids map[string]int) *ActorSensor {
	return &ActorSensor{emetteur: e, poids: poids, seuil: seuilCapteurDefaut, now: time.Now, acc: map[string]*srcCapteur{}}
}

func (s *ActorSensor) suivies() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.acc)
}

// adressePublique : une adresse routable. Le reste (privé, local, lien-local, multicast, CGNAT) n'est jamais un acteur DPI.
func adressePublique(ip string) bool {
	a := net.ParseIP(ip)
	if a == nil || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	if v4 := a.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xC0 == 64 { // 100.64.0.0/10 (CGNAT)
		return false
	}
	return true
}

func slugRisque(r string) string {
	b := make([]byte, 0, len(r))
	for _, c := range strings.ToLower(r) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b = append(b, byte(c))
		} else if len(b) > 0 && b[len(b)-1] != '_' {
			b = append(b, '_')
		}
	}
	return strings.Trim(string(b), "_")
}

// Observe est appelé pour chaque événement de flux déjà filtré ; sans risque pondéré ou sans émetteur, il ne fait rien.
func (s *ActorSensor) Observe(ev *dpiEvent) {
	if s == nil || s.emetteur == nil || len(ev.NDPI.FlowRisk) == 0 || !adressePublique(ev.SrcIP) {
		return
	}
	var gagnes []string
	for _, r := range ev.NDPI.FlowRisk {
		if s.poids[r.Risk] > 0 && (s.muet == nil || !s.muet(r.Risk)) {
			gagnes = append(gagnes, r.Risk)
		}
	}
	if len(gagnes) == 0 {
		return
	}
	now := s.now()
	s.mu.Lock()
	a := s.acc[ev.SrcIP]
	if a != nil && now.Sub(a.debut) > fenetreCapteur {
		delete(s.acc, ev.SrcIP) // fenêtre échue : le compte repart de zéro
		a = nil
	}
	if a == nil {
		if len(s.acc) >= maxSourcesCapteur {
			s.evincer(now)
		}
		a = &srcCapteur{debut: now, couples: map[string]bool{}, ports: map[int]bool{}, risques: map[string]int{}}
		s.acc[ev.SrcIP] = a
	}
	for _, r := range gagnes {
		cle := strconv.FormatUint(ev.FlowID, 10) + "|" + r
		if a.couples[cle] || len(a.couples) >= maxCouplesParSrc {
			continue
		}
		a.couples[cle] = true
		a.score += s.poids[r]
		a.risques[r] += s.poids[r]
	}
	if ev.DstPort > 0 {
		a.ports[ev.DstPort] = true
	}
	if j := ev.ja4(); j != "" {
		a.ja4 = j
	}
	a.proto, a.transport = strings.ToLower(ev.master()), strings.ToLower(ev.L4Proto)
	emettre := a.score >= s.seuil && (a.emis == 0 || a.score >= 2*a.emis)
	var env *envelope.Envelope
	if emettre {
		a.emis = a.score
		env = s.enveloppe(ev.SrcIP, a, now)
	}
	s.mu.Unlock()
	if env != nil {
		s.emetteur.Emit(env)
	}
}

// evincer retire la source la plus ancienne (verrou tenu).
func (s *ActorSensor) evincer(now time.Time) {
	var pire string
	var t time.Time
	for ip, a := range s.acc {
		if pire == "" || a.debut.Before(t) {
			pire, t = ip, a.debut
		}
	}
	delete(s.acc, pire)
}

func (s *ActorSensor) enveloppe(ip string, a *srcCapteur, now time.Time) *envelope.Envelope {
	noms := make([]string, 0, len(a.risques))
	for r := range a.risques {
		noms = append(noms, r)
	}
	sort.Slice(noms, func(i, j int) bool {
		if a.risques[noms[i]] != a.risques[noms[j]] {
			return a.risques[noms[i]] > a.risques[noms[j]]
		}
		return noms[i] < noms[j]
	})
	tags := []string{"dpi_risk"}
	for i, r := range noms {
		if i >= 6 {
			break
		}
		tags = append(tags, slugRisque(r))
	}
	sev := 35 + 4*a.score
	if sev > 100 {
		sev = 100
	}
	return &envelope.Envelope{EventID: envelope.NewEventID(), Timestamp: now.Unix(), Sensor: envelope.SensorDPI, SrcIP: ip,
		DstService: fmt.Sprintf("ports:%d", len(a.ports)), Transport: a.transport, Protocol: a.proto, Action: envelope.ActionObserve,
		RuleID: "dpi.risk." + slugRisque(noms[0]), Severity: sev, TLSFingerprint: a.ja4, BehaviorTags: tags}
}
