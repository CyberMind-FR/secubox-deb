// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// MÉMOIRE DES NAVIGATEURS (#3919). Une adresse qui a donné UNE preuve de navigateur (ressource, cookie, référent, requête conditionnelle…) n'est plus
// jugée pendant 7 jours : un visiteur qui revient avec ses ressources en cache n'en recharge aucune, son silence ne prouve rien. Indépendante de la
// signature et du navigateur déclaré, nourrie par TOUTE requête non privée, relue au redémarrage.
//
// DONNÉE PERSONNELLE : jamais l'adresse, seulement un condensé de 64 bits salé (sel aléatoire gardé avec les données). Une collision épargne : sans
// danger. IPv6 : la clé est le /64 (les adresses temporaires d'un même poste changent chaque jour).
//
// BORNÉE : au plus `max` entrées, la plus ancienne sort. Sortir une entrée encore valable, c'est oublier un vrai navigateur : la mémoire se déclare
// alors SATURÉE jusqu'à l'échéance de l'entrée sortie, et le détecteur ne bannit plus.

const (
	rotationMemoireTTL   = 7 * 24 * time.Hour
	rotationMemoireMax   = 200000
	rotationMemoirePas   = 2 * time.Minute  // réécrite au plus toutes les 2 min si elle a changé…
	rotationMemoireRepos = 15 * time.Minute // … et au moins toutes les 15 min (date du fichier)
	rotationMemoireTrou  = time.Hour        // fichier plus vieux : la mémoire est trouée, on repart comme sans fichier
	memoireGrain         = 60               // s : une preuve plus récente que cela n'est pas réécrite (chemin chaud)
	memoireTranche       = 4096             // entrées copiées par section critique
)

var memoireMagie = []byte("SBXNAV1\n")

type noeudMemoire struct {
	cle        uint64
	vu         uint32 // Unix (s)
	prec, suiv int32
}

type memoireAdresses struct {
	mu           sync.Mutex
	max          int
	ttl          int64 // s
	idx          map[uint64]int32
	noeuds       []noeudMemoire
	tete, queue  int32 // tête = plus récente
	satureJusqua int64 // Unix (s)
	sale         bool
}

func nouvelleMemoire(max int, ttl time.Duration) *memoireAdresses {
	return &memoireAdresses{max: max, ttl: int64(ttl / time.Second), idx: map[uint64]int32{}, tete: -1, queue: -1}
}

func (m *memoireAdresses) detacher(i int32) {
	n := &m.noeuds[i]
	if n.prec >= 0 {
		m.noeuds[n.prec].suiv = n.suiv
	} else {
		m.tete = n.suiv
	}
	if n.suiv >= 0 {
		m.noeuds[n.suiv].prec = n.prec
	} else {
		m.queue = n.prec
	}
}

func (m *memoireAdresses) enTete(i int32) {
	n := &m.noeuds[i]
	n.prec, n.suiv = -1, m.tete
	if m.tete >= 0 {
		m.noeuds[m.tete].prec = i
	}
	m.tete = i
	if m.queue < 0 {
		m.queue = i
	}
}

// noter enregistre une preuve. O(1).
func (m *memoireAdresses) noter(cle uint64, s int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if i, ok := m.idx[cle]; ok {
		if s < int64(m.noeuds[i].vu)+memoireGrain {
			return
		}
		m.noeuds[i].vu = uint32(s)
		m.detacher(i)
		m.enTete(i)
		m.sale = true
		return
	}
	var i int32
	if len(m.noeuds) >= m.max {
		i = m.queue
		if fin := int64(m.noeuds[i].vu) + m.ttl; fin > s && fin > m.satureJusqua {
			m.satureJusqua = fin
		}
		m.detacher(i)
		delete(m.idx, m.noeuds[i].cle)
	} else {
		m.noeuds = append(m.noeuds, noeudMemoire{})
		i = int32(len(m.noeuds) - 1)
	}
	m.noeuds[i].cle, m.noeuds[i].vu = cle, uint32(s)
	m.idx[cle] = i
	m.enTete(i)
	m.sale = true
}

func (m *memoireAdresses) contient(cle uint64, s int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	i, ok := m.idx[cle]
	return ok && s-int64(m.noeuds[i].vu) < m.ttl
}

func (m *memoireAdresses) saturee(s int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return s < m.satureJusqua
}

func (m *memoireAdresses) nb() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.noeuds)
}

type entreeMemoire struct {
	cle uint64
	vu  uint32
}

// instantane copie les entrées par tranches (jamais toute la table sous le verrou), de la plus ancienne à la plus récente.
func (m *memoireAdresses) instantane() ([]entreeMemoire, int64) {
	var out []entreeMemoire
	for deb := 0; ; deb += memoireTranche {
		m.mu.Lock()
		if deb == 0 {
			m.sale = false
			out = make([]entreeMemoire, 0, len(m.noeuds)+memoireTranche)
		}
		fin := min(deb+memoireTranche, len(m.noeuds))
		for i := deb; i < fin; i++ {
			out = append(out, entreeMemoire{m.noeuds[i].cle, m.noeuds[i].vu})
		}
		reste, sat := fin < len(m.noeuds), m.satureJusqua
		m.mu.Unlock()
		if !reste {
			sort.Slice(out, func(i, j int) bool { return out[i].vu < out[j].vu })
			return out, sat
		}
	}
}

func (m *memoireAdresses) estSale() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sale
}

// ── Adresses ─────────────────────────────────────────────────────────────────────────────────────────────────────────

// origine ramène une adresse à ce qui compte pour UNE source : l'adresse en IPv4, le /64 en IPv6 (un seul poste en tient 2^64).
func origine(a netip.Addr) netip.Addr {
	if a.Is4() {
		return a
	}
	b := a.As16()
	for i := 8; i < 16; i++ {
		b[i] = 0
	}
	return netip.AddrFrom16(b)
}

// cleAdresse : condensé salé de 64 bits de l'origine (aucune allocation).
func cleAdresse(sel *[32]byte, a netip.Addr) uint64 {
	var b [48]byte
	copy(b[:32], sel[:])
	o := origine(a).As16()
	copy(b[32:], o[:])
	c := sha256.Sum256(b[:])
	return binary.LittleEndian.Uint64(c[:8])
}

func nouveauSel() (sel [32]byte) {
	if _, err := rand.Read(sel[:]); err != nil {
		panic("sbxwaf: générateur aléatoire indisponible : " + err.Error())
	}
	return sel
}

// ── Fichier ──────────────────────────────────────────────────────────────────────────────────────────────────────────
//
// magie | sel (32) | depuis (i64 : la mémoire est continue depuis) | écrit_le (i64) | par mémoire : saturé_jusqu'à (i64), nombre (u32), {clé u64, vu u32}… | SHA-256 de tout ce qui précède.

var errMemoire = errors.New("mémoire des navigateurs illisible")

func ecrireMemoires(chemin string, sel [32]byte, depuis int64, t time.Time, ms ...*memoireAdresses) error {
	var b bytes.Buffer
	var u [12]byte
	i64 := func(v int64) {
		binary.LittleEndian.PutUint64(u[:8], uint64(v))
		b.Write(u[:8])
	}
	b.Write(memoireMagie)
	b.Write(sel[:])
	i64(depuis)
	i64(t.Unix())
	for _, m := range ms {
		es, sat := m.instantane()
		i64(sat)
		binary.LittleEndian.PutUint32(u[:4], uint32(len(es)))
		b.Write(u[:4])
		for _, e := range es {
			binary.LittleEndian.PutUint64(u[:8], e.cle)
			binary.LittleEndian.PutUint32(u[8:], e.vu)
			b.Write(u[:])
		}
	}
	som := sha256.Sum256(b.Bytes())
	b.Write(som[:])

	_ = os.MkdirAll(filepath.Dir(chemin), 0o755)
	tmp := chemin + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	_, err = f.Write(b.Bytes())
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err == nil {
		err = os.Rename(tmp, chemin)
	}
	if err != nil {
		for _, m := range ms { // l'écriture est à refaire
			m.mu.Lock()
			m.sale = true
			m.mu.Unlock()
		}
	}
	return err
}

// lireMemoires remplit des mémoires VIDES ; sur erreur rien n'est repris. Une date du futur est ramenée à `t`.
func lireMemoires(chemin string, t time.Time, ms ...*memoireAdresses) (sel [32]byte, depuis, ecritLe int64, err error) {
	fi, err := os.Stat(chemin)
	if err != nil {
		return sel, 0, 0, err
	}
	if fi.Size() > 16<<20 || !fi.Mode().IsRegular() {
		return sel, 0, 0, errMemoire
	}
	b, err := os.ReadFile(chemin)
	if err != nil {
		return sel, 0, 0, err
	}
	tete := len(memoireMagie) + 32 + 16
	if len(b) < tete+32 || !bytes.HasPrefix(b, memoireMagie) {
		return sel, 0, 0, errMemoire
	}
	corps, som := b[:len(b)-32], sha256.Sum256(b[:len(b)-32])
	if !bytes.Equal(som[:], b[len(b)-32:]) {
		return sel, 0, 0, errMemoire
	}
	copy(sel[:], corps[len(memoireMagie):])
	depuis = int64(binary.LittleEndian.Uint64(corps[tete-16:]))
	ecritLe = int64(binary.LittleEndian.Uint64(corps[tete-8:]))
	corps = corps[tete:]
	type section struct {
		sat int64
		es  []byte
	}
	var secs []section
	for range ms {
		if len(corps) < 12 {
			return sel, 0, 0, errMemoire
		}
		s := section{sat: int64(binary.LittleEndian.Uint64(corps))}
		n := int(binary.LittleEndian.Uint32(corps[8:]))
		corps = corps[12:]
		if n < 0 || n > len(corps)/12 {
			return sel, 0, 0, errMemoire
		}
		s.es, corps = corps[:n*12], corps[n*12:]
		secs = append(secs, s)
	}
	if len(corps) != 0 {
		return sel, 0, 0, errMemoire
	}
	s := t.Unix()
	for i, m := range ms {
		for es := secs[i].es; len(es) > 0; es = es[12:] {
			vu := int64(binary.LittleEndian.Uint32(es[8:]))
			if vu > s {
				vu = s
			}
			if s-vu < m.ttl {
				m.noter(binary.LittleEndian.Uint64(es), vu)
			}
		}
		sat := secs[i].sat
		if sat > s+m.ttl {
			sat = s + m.ttl
		}
		m.satureJusqua = max(m.satureJusqua, sat)
		m.sale = false
	}
	return sel, depuis, ecritLe, nil
}
