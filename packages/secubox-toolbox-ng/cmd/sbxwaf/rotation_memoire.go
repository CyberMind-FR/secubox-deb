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
// DONNÉE PERSONNELLE PSEUDONYMISÉE, pas anonyme : jamais l'adresse, seulement un condensé de 64 bits salé. Le sel est gardé avec les données : qui lit le
// fichier peut retrouver une adresse IPv4 en les essayant toutes. D'où 0640, 7 jours au plus, et les entrées expirées purgées à chaque écriture. Une
// collision épargne : sans danger. IPv6 : la clé est le /64 (les adresses temporaires d'un même poste changent chaque jour).
//
// BORNÉE : au plus `max` entrées, la plus ancienne sort. Sortir une entrée encore valable, c'est oublier un vrai navigateur : la mémoire se déclare
// alors SATURÉE jusqu'à l'échéance de l'entrée sortie, et le détecteur ne bannit plus. Une entrée rattachée à un GROUPE (source d'établissement d'une
// campagne) ne sature que son groupe ; partagée entre plusieurs, elle sature tout.

const (
	rotationMemoireTTL   = 7 * 24 * time.Hour
	rotationMemoireMax   = 200000
	rotationMemoirePas   = 2 * time.Minute  // réécrite au plus toutes les 2 min si elle a changé…
	rotationMemoireRepos = 15 * time.Minute // … et au moins toutes les 15 min (date du fichier)
	rotationMemoireTrou  = time.Hour        // fichier plus vieux : la mémoire est trouée, on repart comme sans fichier
	memoireGrain         = 60               // s : une preuve plus récente que cela n'est pas réécrite (chemin chaud)
	memoireTranche       = 4096             // entrées copiées ou purgées par section critique
	memoireGroupesMax    = 5000             // groupes saturés retenus
)

var memoireMagie = []byte("SBXNAV1\n")

type noeudMemoire struct {
	cle        uint64
	vu         uint32 // Unix (s)
	prec, suiv int32
	groupe     uint32 // 0 : aucun, ou plusieurs
}

type memoireAdresses struct {
	mu           sync.Mutex
	max          int
	ttl          int64 // s
	idx          map[uint64]int32
	noeuds       []noeudMemoire
	tete, queue  int32            // tête = plus récente
	satureJusqua int64            // Unix (s)
	groupesSat   map[uint32]int64 // groupe → saturé jusqu'à (Unix, s)
	sale         bool
}

func nouvelleMemoire(max int, ttl time.Duration) *memoireAdresses {
	return &memoireAdresses{max: max, ttl: int64(ttl / time.Second), idx: map[uint64]int32{}, groupesSat: map[uint32]int64{}, tete: -1, queue: -1}
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
func (m *memoireAdresses) noter(cle uint64, s int64) { m.noterGroupe(cle, s, 0) }

func (m *memoireAdresses) noterGroupe(cle uint64, s int64, groupe uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if i, ok := m.idx[cle]; ok {
		n := &m.noeuds[i]
		if n.groupe != groupe {
			n.groupe, m.sale = 0, true
		}
		if s < int64(n.vu)+memoireGrain {
			return
		}
		n.vu = uint32(s)
		m.detacher(i)
		m.enTete(i)
		m.sale = true
		return
	}
	var i int32
	if len(m.noeuds) >= m.max {
		i = m.queue
		if fin := int64(m.noeuds[i].vu) + m.ttl; fin > s {
			m.saturer(m.noeuds[i].groupe, fin)
		}
		m.detacher(i)
		delete(m.idx, m.noeuds[i].cle)
	} else {
		m.noeuds = append(m.noeuds, noeudMemoire{})
		i = int32(len(m.noeuds) - 1)
	}
	m.noeuds[i].cle, m.noeuds[i].vu, m.noeuds[i].groupe = cle, uint32(s), groupe
	m.idx[cle] = i
	m.enTete(i)
	m.sale = true
}

// saturer (sous verrou) : une entrée valable jusqu'à `fin` est perdue ; trop de groupes saturés : tout l'est.
func (m *memoireAdresses) saturer(groupe uint32, fin int64) {
	if _, ok := m.groupesSat[groupe]; groupe == 0 || !ok && len(m.groupesSat) >= memoireGroupesMax {
		m.satureJusqua = max(m.satureJusqua, fin)
		return
	}
	m.groupesSat[groupe] = max(m.groupesSat[groupe], fin)
}

func (m *memoireAdresses) groupeSature(groupe uint32, s int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return s < m.satureJusqua || s < m.groupesSat[groupe]
}

// purger oublie les entrées expirées, par tranches (jamais toute la table sous le verrou).
func (m *memoireAdresses) purger(s int64) {
	for {
		m.mu.Lock()
		k := 0
		for ; k < memoireTranche && m.queue >= 0 && s-int64(m.noeuds[m.queue].vu) >= m.ttl; k++ {
			m.retirer(m.queue)
		}
		if k < memoireTranche {
			for g, fin := range m.groupesSat {
				if fin <= s {
					delete(m.groupesSat, g)
				}
			}
		}
		m.mu.Unlock()
		if k < memoireTranche {
			return
		}
	}
}

// retirer (sous verrou) : la dernière case prend la place libérée, la table reste compacte.
func (m *memoireAdresses) retirer(i int32) {
	m.detacher(i)
	delete(m.idx, m.noeuds[i].cle)
	d := int32(len(m.noeuds) - 1)
	if i != d {
		n := m.noeuds[d]
		m.noeuds[i] = n
		m.idx[n.cle] = i
		if n.prec >= 0 {
			m.noeuds[n.prec].suiv = i
		} else {
			m.tete = i
		}
		if n.suiv >= 0 {
			m.noeuds[n.suiv].prec = i
		} else {
			m.queue = i
		}
	}
	m.noeuds = m.noeuds[:d]
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
	cle    uint64
	vu     uint32
	groupe uint32
}

// instantane copie les entrées encore valables par tranches (jamais toute la table sous le verrou), de la plus ancienne à la plus récente.
func (m *memoireAdresses) instantane(s int64) (es []entreeMemoire, sat int64, groupes map[uint32]int64) {
	for deb := 0; ; deb += memoireTranche {
		m.mu.Lock()
		if deb == 0 {
			m.sale = false
			es = make([]entreeMemoire, 0, len(m.noeuds)+memoireTranche)
		}
		fin := min(deb+memoireTranche, len(m.noeuds))
		for i := deb; i < fin; i++ {
			if n := &m.noeuds[i]; s-int64(n.vu) < m.ttl {
				es = append(es, entreeMemoire{n.cle, n.vu, n.groupe})
			}
		}
		if fin >= len(m.noeuds) {
			sat, groupes = m.satureJusqua, make(map[uint32]int64, len(m.groupesSat))
			for g, f := range m.groupesSat {
				groupes[g] = f
			}
			m.mu.Unlock()
			sort.Slice(es, func(i, j int) bool { return es[i].vu < es[j].vu })
			return es, sat, groupes
		}
		m.mu.Unlock()
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
// magie | sel (32) | depuis (i64 : la mémoire est continue depuis) | écrit_le (i64) | par mémoire : saturé_jusqu'à (i64), nombre (u32),
// {clé u64, vu u32, groupe u32}…, groupes saturés (u32), {groupe u32, jusqu'à i64}… | SHA-256 de tout ce qui précède.

var errMemoire = errors.New("mémoire des navigateurs illisible")

func ecrireMemoires(chemin string, sel [32]byte, depuis int64, t time.Time, ms ...*memoireAdresses) error {
	var b bytes.Buffer
	var u [8]byte
	i64 := func(v int64) {
		binary.LittleEndian.PutUint64(u[:], uint64(v))
		b.Write(u[:])
	}
	u32 := func(v uint32) {
		binary.LittleEndian.PutUint32(u[:4], v)
		b.Write(u[:4])
	}
	b.Write(memoireMagie)
	b.Write(sel[:])
	i64(depuis)
	i64(t.Unix())
	for _, m := range ms {
		m.purger(t.Unix())
		es, sat, groupes := m.instantane(t.Unix())
		i64(sat)
		u32(uint32(len(es)))
		for _, e := range es {
			i64(int64(e.cle))
			u32(e.vu)
			u32(e.groupe)
		}
		u32(uint32(len(groupes)))
		for g, fin := range groupes {
			u32(g)
			i64(fin)
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
		sat    int64
		es, gs []byte
	}
	// prendre détache `n` enregistrements de `taille` octets, précédés de leur nombre.
	prendre := func(taille int) ([]byte, bool) {
		if len(corps) < 4 {
			return nil, false
		}
		n := int(binary.LittleEndian.Uint32(corps))
		corps = corps[4:]
		if n > len(corps)/taille {
			return nil, false
		}
		v := corps[:n*taille]
		corps = corps[n*taille:]
		return v, true
	}
	var secs []section
	for range ms {
		if len(corps) < 8 {
			return sel, 0, 0, errMemoire
		}
		x := section{sat: int64(binary.LittleEndian.Uint64(corps))}
		corps = corps[8:]
		var ok1, ok2 bool
		x.es, ok1 = prendre(16)
		x.gs, ok2 = prendre(12)
		if !ok1 || !ok2 {
			return sel, 0, 0, errMemoire
		}
		secs = append(secs, x)
	}
	if len(corps) != 0 {
		return sel, 0, 0, errMemoire
	}
	s := t.Unix()
	for i, m := range ms {
		borne := func(fin int64) int64 {
			if fin > s+m.ttl {
				return s + m.ttl
			}
			return fin
		}
		for es := secs[i].es; len(es) > 0; es = es[16:] {
			vu := int64(binary.LittleEndian.Uint32(es[8:]))
			if vu > s {
				vu = s
			}
			if s-vu < m.ttl {
				m.noterGroupe(binary.LittleEndian.Uint64(es), vu, binary.LittleEndian.Uint32(es[12:]))
			}
		}
		m.mu.Lock()
		for gs := secs[i].gs; len(gs) > 0; gs = gs[12:] {
			m.saturer(binary.LittleEndian.Uint32(gs), borne(int64(binary.LittleEndian.Uint64(gs[4:]))))
		}
		m.satureJusqua = max(m.satureJusqua, borne(secs[i].sat))
		m.sale = false
		m.mu.Unlock()
	}
	return sel, depuis, ecritLe, nil
}
