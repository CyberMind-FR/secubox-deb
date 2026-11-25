// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Journal de bans persistant (#1070, phase B).
//
// Le compteur de ban en mémoire est perdu au redémarrage : un scanner banni
// repartait à zéro. BanStore journalise chaque ban/unban en JSONL append-only ;
// au démarrage on relit les bans encore actifs et on les ré-injecte dans nft.
// C'est ce qui rend le WAF AUTONOME : les bans survivent au restart, sans
// dépendre d'un relais externe.

// BanRecord est une ligne du journal.
type BanRecord struct {
	IP       string `json:"ip"`
	Category string `json:"cat"`
	Severity string `json:"sev"`
	At       int64  `json:"at"`     // unix : quand la décision a été prise
	Expires  int64  `json:"exp"`    // unix : échéance du ban (0 = via unban explicite)
	Action   string `json:"action"` // "ban" | "unban"
}

// BanStore sérialise l'accès à un fichier JSONL append-only, compacté par Compacter (#3816,
// banstore_compactage.go) : mu sérialise les ajouts, les relectures et le rename du compactage ;
// compactMu, les passes de compactage entre elles.
type BanStore struct {
	path      string
	mu        sync.Mutex
	compactMu sync.Mutex
	idx       *indexBans // dernier état par adresse, relu au fil du fichier (#3930) ; sous mu
}

func NewBanStore(path string) *BanStore {
	if path == "" {
		return nil
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	return &BanStore{path: path}
}

// Append ajoute une ligne au journal (best-effort : une erreur d'écriture ne
// doit pas casser le chemin de requête, elle est seulement journalisée par
// l'appelant s'il le souhaite).
func (s *BanStore) Append(rec BanRecord) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

// ActiveBans relit le journal et renvoie, par IP, les bans ENCORE actifs à
// l'instant `now` : le dernier « ban » l'emporte sauf s'il est suivi d'un
// « unban » ou si son échéance est dépassée. C'est ce que le démarrage
// ré-injecte dans nft, et ce que le balayage réconcilie.
func (s *BanStore) ActiveBans(now int64) []BanRecord {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.path)
	if err != nil {
		s.idx = nil
		return nil // journal absent = aucun ban
	}
	defer f.Close()
	s.suivre(f, now)
	var actifs []BanRecord
	if n := len(s.idx.dernier); n > 0 {
		actifs = make([]BanRecord, 0, n)
	}
	for ip, r := range s.idx.dernier {
		if r.Expires != 0 && r.Expires <= now {
			if r.Expires <= now-margeIndex {
				delete(s.idx.dernier, ip)
			}
			continue // échu
		}
		actifs = append(actifs, r)
	}
	return actifs
}

// Actif rend le ban actif de l'adresse au journal.
func (s *BanStore) Actif(ip string, now int64) (BanRecord, bool) {
	if s == nil {
		return BanRecord{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.path)
	if err != nil {
		s.idx = nil
		return BanRecord{}, false
	}
	defer f.Close()
	s.suivre(f, now)
	r, ok := s.idx.dernier[cleBan(ip)]
	return r, ok && (r.Expires == 0 || r.Expires > now)
}

// Levees rend, parmi `adresses` (clés de cleBan), celles dont la dernière ligne au journal est un « unban ». Relit tout le journal ; toute erreur
// de lecture, absence comprise, est rendue : elle ne dit jamais « levé ».
func (s *BanStore) Levees(adresses map[string]netip.Addr) (map[string]struct{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	levees := map[string]struct{}{}
	r := bufio.NewReaderSize(f, 256*1024)
	var long []byte
	var taille int
	for {
		morceau, err := r.ReadSlice('\n')
		if err != nil && err != io.EOF && !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
		if taille += len(morceau); taille <= ligneMaxLectures { // sinon : ligne démesurée, ignorée comme par l'index
			long = append(long, morceau...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		var rec BanRecord
		if taille <= ligneMaxLectures && json.Unmarshal(long, &rec) == nil && rec.IP != "" {
			cle := cleBan(rec.IP)
			if _, ok := adresses[cle]; ok {
				if rec.Action == "unban" {
					levees[cle] = struct{}{}
				} else {
					delete(levees, cle)
				}
			}
		}
		if err == io.EOF {
			return levees, nil
		}
		long, taille = long[:0], 0
	}
}

// cleBan : une adresse, une clé, quelle que soit son écriture au journal (IPv6 non abrégée, IPv4 en ::ffff:). Un unban
// écrit sous la forme normalisée lève ainsi un ban écrit autrement.
func cleBan(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	return a.Unmap().String()
}

// INDEX DU JOURNAL (#3930). À 1 000 bans par heure et 31 jours gardés, le journal compte des centaines de milliers de
// lignes (~80 Mo) ; la réévaluation (30 s), la repose (2 min) et les campagnes (5 min) le relisaient chaque fois en
// entier, sous le verrou qu'Append attend. L'index garde le dernier ban de chaque adresse et ne relit que les octets
// ajoutés. Il repart de zéro si le fichier a changé d'inode, raccourci ou été réécrit (empreinte des derniers octets lus).
type indexBans struct {
	fichier   os.FileInfo
	lu        int64  // octets consommés : fin d'une ligne complète
	empreinte []byte // derniers octets avant lu
	dernier   map[string]BanRecord
	horizon   int64 // plus grand `now` servi : les échus d'avant horizon-margeIndex sont oubliés
}

const (
	margeIndex       = 3600
	tailleEmpreinte  = 64
	ligneMaxLectures = 1024 * 1024
)

// suivre met l'index à jour depuis f (mu tenu).
func (s *BanStore) suivre(f *os.File, now int64) {
	st, err := f.Stat()
	x := s.idx
	if err != nil || x == nil || !os.SameFile(st, x.fichier) || st.Size() < x.lu || now < x.horizon-margeIndex || !x.memeDebut(f) {
		x = &indexBans{dernier: map[string]BanRecord{}}
		s.idx = x
	}
	x.fichier = st
	if now > x.horizon {
		x.horizon = now
	}
	if _, err := f.Seek(x.lu, io.SeekStart); err != nil {
		return
	}
	r := bufio.NewReaderSize(f, 256*1024)
	var long []byte
	var taille int64 // octets de la ligne en cours
	for {
		morceau, err := r.ReadSlice('\n')
		taille += int64(len(morceau))
		if errors.Is(err, bufio.ErrBufferFull) {
			if taille <= ligneMaxLectures {
				long = append(long, morceau...)
			}
			continue
		}
		ligne := morceau
		if len(long) > 0 {
			ligne = append(long, morceau...)
		}
		if taille <= ligneMaxLectures {
			x.appliquer(ligne, now)
		} // sinon : ligne démesurée, ignorée comme une ligne corrompue
		if err != nil {
			break // fin de fichier ; une fin sans « \n » est lue mais non consommée (écriture en cours)
		}
		x.lu += taille
		long, taille = long[:0], 0
	}
	x.marquer(f)
}

func (x *indexBans) appliquer(ligne []byte, now int64) {
	var r BanRecord
	if json.Unmarshal(ligne, &r) != nil || r.IP == "" {
		return // ligne corrompue : on l'ignore, on ne casse pas la relecture
	}
	r.IP = cleBan(r.IP)
	if r.Action != "ban" || (r.Expires != 0 && r.Expires <= now-margeIndex) {
		delete(x.dernier, r.IP)
		return
	}
	x.dernier[r.IP] = r
}

func (x *indexBans) lireEmpreinte(f *os.File) []byte {
	n := x.lu
	if n > tailleEmpreinte {
		n = tailleEmpreinte
	}
	b := make([]byte, n)
	if _, err := f.ReadAt(b, x.lu-n); err != nil {
		return nil
	}
	return b
}

func (x *indexBans) marquer(f *os.File) { x.empreinte = x.lireEmpreinte(f) }

func (x *indexBans) memeDebut(f *os.File) bool {
	b := x.lireEmpreinte(f)
	return b != nil && bytes.Equal(b, x.empreinte)
}

// deplacer suit le compactage (mu tenu) : `fin` octets recopiés tels quels depuis l'octet n de l'ancien fichier terminent
// le nouveau, et le reste rend le même état (banstore_compactage.go) : l'index vaut toujours, seule sa position change.
func (s *BanStore) deplacer(nouveau os.FileInfo, n, fin int64) {
	x := s.idx
	if x == nil {
		return
	}
	s.idx = nil // relu en entier si quoi que ce soit ne colle pas
	f, err := os.Open(s.path)
	if err != nil {
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !os.SameFile(st, nouveau) || x.lu < n {
		return
	}
	x.fichier, x.lu = st, nouveau.Size()-fin+(x.lu-n)
	x.marquer(f)
	s.idx = x
}

// CompteCategorie compte les bans de `ip` dont la catégorie commence par `prefixe`, posés depuis `depuis` (secondes Unix). Sert à graduer la durée
// d'un ban à la récidive (leurre, campagnes) : le journal append-only est la seule mémoire, elle survit aux redémarrages.
func (s *BanStore) CompteCategorie(ip, prefixe string, depuis int64) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	ip = cleBan(ip)
	motif := []byte(ip + `"`) // l'essentiel du coût est le décodage : seules les lignes de l'adresse le méritent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if !bytes.Contains(sc.Bytes(), motif) {
			continue
		}
		var r BanRecord
		if json.Unmarshal(sc.Bytes(), &r) == nil && r.Action == "ban" && cleBan(r.IP) == ip && r.At >= depuis && strings.HasPrefix(r.Category, prefixe) {
			n++
		}
	}
	return n
}

// DepuisChaine rend depuis combien de temps l'adresse est bannie SANS INTERRUPTION : on remonte les bans de `ip` tant que chacun commence avant la fin du
// précédent (à 5 min près). Une pause plus longue casse la chaîne : l'adresse a été libre, et un nouveau ban repart de zéro.
func (s *BanStore) DepuisChaine(ip string, maintenant int64) time.Duration {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.path)
	if err != nil {
		return 0
	}
	defer f.Close()
	debut, fin := int64(0), int64(0)
	ip = cleBan(ip)
	motif := []byte(ip + `"`)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if !bytes.Contains(sc.Bytes(), motif) {
			continue
		}
		var r BanRecord
		if json.Unmarshal(sc.Bytes(), &r) != nil || cleBan(r.IP) != ip || r.Action != "ban" {
			continue
		}
		if debut == 0 || r.At > fin+300 {
			debut = r.At // pause : nouvelle chaîne
		}
		if r.Expires > fin {
			fin = r.Expires
		}
	}
	if debut == 0 || debut > maintenant {
		return 0
	}
	return time.Duration(maintenant-debut) * time.Second
}
