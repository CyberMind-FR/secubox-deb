// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// Compactage des journaux de preuves mesures.jsonl et reevaluations.jsonl (#3820).
//
// Les deux journaux (une ligne JSON par décision, champ `ts` en secondes) étaient append-only et jamais tournés : 84 Mo
// et 9 Mo sur gk2 en six semaines. Contrairement à bans.jsonl, aucun lecteur ne les relit par adresse : le seul lecteur
// est l'API du WAF, qui les lit PAR LA FIN —
//
//   - `/mesures` (`lire_fin_jsonl`) : 8 Mio au plus depuis la fin (`_MESURES_OCTETS`), curseur `ts` de la veille V2
//     (rattrapage 24 h) ;
//   - `/reevaluations` : les 5 000 dernières lignes (`_REEVAL_LIGNES_MAX`), totaux compris.
//
// Le compactage garde donc un SUFFIXE du fichier (octets identiques, ordre identique) qui commence à la première ligne
// de `ts >= maintenant − Fenetre`, reculé autant qu'il faut pour garder strictement plus de `MinOctets` octets et au
// moins `MinLignes` lignes : toute lecture par la fin dans ces bornes rend exactement la même chose qu'avant (prouvé par
// test). Ce qui précède part, dans l'ordre, dans une archive mensuelle gzip <préfixe>-AAAAMM.jsonl.gz (mois de `ts`,
// UTC), purgée au-delà de `ArchivesMois` mois — mêmes aides que bans.jsonl (archive avant journal : au pire des
// doublons, jamais de perte).
//
// Verrou : les écrivains (MesuresWAF.ecrireLigne, Reeval.ecrire) rouvrent le fichier par son chemin à chaque ligne,
// sous verrouAjout(chemin). Le tri et la recopie se font sans ce verrou (octets [0, N) figés) ; seule la fin (octets
// ajoutés depuis N, puis rename) le prend. Pas de chown (seccomp) : un fichier d'un autre propriétaire n'est pas touché.

// Bornes des lecteurs de l'API (packages/secubox-waf-ng/composants/waf/api/main.py) ; un test vérifie qu'elles
// n'ont pas bougé.
const (
	octetsLusMesures        = 8 * 1024 * 1024 // _MESURES_OCTETS
	lignesLuesReevaluations = 5000            // _REEVAL_LIGNES_MAX
)

// fenetreMinimalePreuves : le rattrapage de la veille V2 (curseur absent) remonte à 24 h.
const fenetreMinimalePreuves = 24 * time.Hour

// CompactageJournal règle le compactage d'un journal de preuves.
type CompactageJournal struct {
	Fenetre      time.Duration // lignes de ts plus récent gardées telles quelles (24 h au moins)
	MinOctets    int64         // la fin gardée fait STRICTEMENT plus que ceci (lecture par la fin bornée en octets)
	MinLignes    int           // au moins ces dernières lignes complètes gardées (lecture des N dernières lignes)
	ArchivesMois int           // archives mensuelles gardées
	Seuil        int64         // octets archivables en dessous desquels rien n'est réécrit
}

type verrousJournal struct {
	ajout, compact sync.Mutex
}

var (
	verrousMu sync.Mutex
	verrous   = map[string]*verrousJournal{}
)

func verrousDe(chemin string) *verrousJournal {
	verrousMu.Lock()
	defer verrousMu.Unlock()
	v := verrous[chemin]
	if v == nil {
		v = &verrousJournal{}
		verrous[chemin] = v
	}
	return v
}

// verrouAjout : tenu par chaque écrivain le temps d'ouvrir, écrire et fermer une ligne ; le compactage le prend pour
// recopier la fin et renommer.
func verrouAjout(chemin string) *sync.Mutex { return &verrousDe(chemin).ajout }

// ligneJournal : ce que le tri retient d'une ligne.
type ligneJournal struct {
	ts     int64
	lu     bool // ts lisible
	taille int32
}

// horodatageLigne lit `ts` (entier, flottant ou RFC 3339, comme `_horodatage_epoque` de l'API).
func horodatageLigne(ligne []byte) (int64, bool) {
	var r struct {
		Ts json.RawMessage `json:"ts"`
	}
	if json.Unmarshal(ligne, &r) != nil || len(r.Ts) == 0 {
		return 0, false
	}
	var f float64
	if json.Unmarshal(r.Ts, &f) == nil {
		return int64(f), true
	}
	var s string
	if json.Unmarshal(r.Ts, &s) == nil && s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.Unix(), true
		}
	}
	return 0, false
}

// lireLignesJournal lit les octets [0, taille) : une entrée par ligne terminée par « \n », et la fin n de la dernière
// ligne complète (une fin sans « \n » est une écriture en cours : recopiée telle quelle).
func lireLignesJournal(f *os.File, taille int64) ([]ligneJournal, int64, error) {
	var lignes []ligneJournal
	r := bufio.NewReaderSize(io.LimitReader(f, taille), 256*1024)
	var n int64
	var long []byte
	for {
		morceau, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			long = append(long, morceau...)
			if len(long) > ligneMaxBans {
				return nil, 0, fmt.Errorf("ligne de plus de %d octets à l'octet %d : non compacté", ligneMaxBans, n)
			}
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, 0, err
		}
		ligne := morceau
		if long != nil {
			ligne = append(long, morceau...)
			long = nil
		}
		if len(ligne) == 0 || ligne[len(ligne)-1] != '\n' {
			break
		}
		if len(ligne)-1 > ligneMaxBans {
			return nil, 0, fmt.Errorf("ligne de plus de %d octets à l'octet %d : non compacté", ligneMaxBans, n)
		}
		ts, lu := horodatageLigne(ligne)
		lignes = append(lignes, ligneJournal{ts: ts, lu: lu, taille: int32(len(ligne))})
		n += int64(len(ligne))
		if errors.Is(err, io.EOF) {
			break
		}
	}
	return lignes, n, nil
}

// debutSuffixe rend l'index de la première ligne gardée : première ligne de ts >= coupure, reculée pour garder au moins
// minLignes lignes et, si minOctets > 0, strictement plus de minOctets octets (queue, `reste`, comprise : octets après la dernière ligne
// complète). Toute ligne de ts >= coupure est donc gardée, et le fichier gardé est un suffixe de l'ancien.
func debutSuffixe(lignes []ligneJournal, reste int64, coupure int64, minLignes int, minOctets int64) int {
	k := len(lignes)
	for i, l := range lignes {
		if l.lu && l.ts >= coupure {
			k = i
			break
		}
	}
	if m := len(lignes) - minLignes; m < k {
		k = max(m, 0)
	}
	garde := reste
	for _, l := range lignes[k:] {
		garde += int64(l.taille)
	}
	for minOctets > 0 && k > 0 && garde <= minOctets {
		k--
		garde += int64(lignes[k].taille)
	}
	return k
}

// CompacterJournal fait une passe sur `chemin` à l'instant `now` ; archives <prefixe>-AAAAMM.jsonl.gz.
func CompacterJournal(chemin, prefixe string, now time.Time, cfg CompactageJournal) (bilan BilanCompactage, err error) {
	if chemin == "" {
		return bilan, nil
	}
	if cfg.Fenetre < fenetreMinimalePreuves {
		cfg.Fenetre = fenetreMinimalePreuves
	}
	v := verrousDe(chemin)
	v.compact.Lock()
	defer v.compact.Unlock()
	dir := filepath.Dir(chemin)
	nettoyerTemporaires(dir, filepath.Base(chemin), prefixe)
	defer func() { bilan.ArchivesSupprimees = purgerArchives(dir, prefixe, now, cfg.ArchivesMois) }()

	// 1. Taille figée N sous le verrou d'ajout : tout ce qui est avant N est écrit en entier.
	v.ajout.Lock()
	f, err := os.OpenFile(chemin, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		v.ajout.Unlock()
		if errors.Is(err, os.ErrNotExist) {
			return bilan, nil
		}
		return bilan, err
	}
	st, err := f.Stat()
	v.ajout.Unlock()
	if err != nil {
		f.Close()
		return bilan, err
	}
	defer f.Close()
	if !st.Mode().IsRegular() {
		return bilan, fmt.Errorf("%s n'est pas un fichier ordinaire", chemin)
	}
	if sys, _ := st.Sys().(*syscall.Stat_t); sys != nil && int(sys.Uid) != os.Geteuid() {
		return bilan, fmt.Errorf("%s appartient à l'uid %d, pas à %d : non compacté", chemin, sys.Uid, os.Geteuid())
	}
	bilan.OctetsAvant = st.Size()

	// 2. Premier passage : début du suffixe gardé.
	lignes, n, err := lireLignesJournal(f, st.Size())
	if err != nil {
		return bilan, err
	}
	bilan.Lignes = len(lignes)
	k := debutSuffixe(lignes, st.Size()-n, now.Add(-cfg.Fenetre).Unix(), cfg.MinLignes, cfg.MinOctets)
	var archivables int64
	for _, l := range lignes[:k] {
		archivables += int64(l.taille)
	}
	if k == 0 || archivables < cfg.Seuil {
		bilan.Gardees = bilan.Lignes
		bilan.OctetsApres = bilan.OctetsAvant
		return bilan, nil
	}
	bilan.Gardees, bilan.Archivees = len(lignes)-k, k

	// 3. Lignes [0, k) vers les archives (mois de leur ts ; une ligne illisible suit le mois de la précédente lisible),
	// puis [k, N) vers le temporaire.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return bilan, err
	}
	archives := map[string]*archiveMensuelle{}
	defer func() {
		for _, a := range archives {
			a.abandonner()
		}
	}()
	r := bufio.NewReaderSize(f, 256*1024)
	mois := now.UTC().Format("200601")
	var tampon []byte
	for _, l := range lignes[:k] {
		if cap(tampon) < int(l.taille) {
			tampon = make([]byte, l.taille)
		}
		brut := tampon[:l.taille]
		if _, err := io.ReadFull(r, brut); err != nil {
			return bilan, fmt.Errorf("relecture : %w", err)
		}
		if l.lu && l.ts > 0 {
			mois = time.Unix(l.ts, 0).UTC().Format("200601")
		}
		a := archives[mois]
		if a == nil {
			if a, err = ouvrirArchive(dir, prefixe, mois); err != nil {
				return bilan, err
			}
			archives[mois] = a
		}
		if _, err := a.gz.Write(brut); err != nil {
			return bilan, err
		}
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(chemin)+".tmp-*")
	if err != nil {
		return bilan, err
	}
	tmpNom := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmpNom)
		}
	}()
	w := bufio.NewWriterSize(tmp, 256*1024)
	if _, err := io.CopyN(w, r, sommeTailles(lignes[k:])); err != nil {
		return bilan, err
	}
	for _, a := range archives {
		if err := a.valider(); err != nil {
			return bilan, err
		}
	}
	if err := syncDossier(dir); err != nil {
		return bilan, err
	}

	// 4. Fin sous le verrou d'ajout : octets ajoutés depuis N, puis rename.
	v.ajout.Lock()
	defer v.ajout.Unlock()
	actuel, err := os.Lstat(chemin)
	if err != nil {
		return bilan, err
	}
	if !os.SameFile(st, actuel) {
		return bilan, fmt.Errorf("%s remplacé pendant le compactage : abandon", chemin)
	}
	if _, err := f.Seek(n, io.SeekStart); err != nil {
		return bilan, err
	}
	if _, err := io.Copy(w, f); err != nil {
		return bilan, err
	}
	if err := w.Flush(); err != nil {
		return bilan, err
	}
	if err := tmp.Chmod(st.Mode().Perm()); err != nil {
		return bilan, err
	}
	alignerACL(chemin, tmpNom)
	if err := tmp.Sync(); err != nil {
		return bilan, err
	}
	fin, err := tmp.Stat()
	if err != nil {
		return bilan, err
	}
	if err := tmp.Close(); err != nil {
		return bilan, err
	}
	if err := os.Rename(tmpNom, chemin); err != nil {
		return bilan, err
	}
	ok = true
	if err := syncDossier(dir); err != nil {
		return bilan, err
	}
	bilan.Reecrit = true
	bilan.OctetsApres = fin.Size()
	return bilan, nil
}

func sommeTailles(lignes []ligneJournal) int64 {
	var s int64
	for _, l := range lignes {
		s += int64(l.taille)
	}
	return s
}

// alignerACL donne au nouveau fichier l'ACL d'accès de l'ancien : recopiée s'il en a une, retirée sinon (le
// temporaire hérite de l'ACL par défaut du dossier — lecture de secubox-live — que l'ancien journal n'avait pas).
func alignerACL(source, cible string) {
	const nom = "system.posix_acl_access"
	buf := make([]byte, 4096)
	n, err := syscall.Getxattr(source, nom, buf)
	if err == nil && n > 0 {
		if err := syscall.Setxattr(cible, nom, buf[:n], 0); err != nil {
			log.Printf("sbxwaf: ACL de %s non recopiée : %v", source, err)
		}
		return
	}
	if err := syscall.Removexattr(cible, nom); err != nil && !errors.Is(err, syscall.ENODATA) && !errors.Is(err, syscall.EOPNOTSUPP) {
		log.Printf("sbxwaf: ACL héritée de %s non retirée : %v", cible, err)
	}
}

// JournalPreuves : un journal de preuves à compacter, avec ses bornes de lecture.
type JournalPreuves struct {
	Chemin, Prefixe string
	MinOctets       int64
	MinLignes       int
}

// VeillerCompactageJournaux compacte tout de suite, puis toutes les `intervalle` (0 : une seule passe).
func VeillerCompactageJournaux(journaux []JournalPreuves, cfg CompactageJournal, intervalle time.Duration) {
	passe := func() {
		for _, j := range journaux {
			c := cfg
			c.MinOctets, c.MinLignes = j.MinOctets, j.MinLignes
			debut := time.Now()
			b, err := CompacterJournal(j.Chemin, j.Prefixe, debut, c)
			switch {
			case err != nil:
				log.Printf("sbxwaf: compactage de %s : %v", j.Chemin, err)
			case b.Reecrit:
				log.Printf("sbxwaf: compactage de %s : %d lignes, %d gardées, %d archivées, %s → %s octets, %d archive(s) supprimée(s), %s",
					j.Chemin, b.Lignes, b.Gardees, b.Archivees, strconv.FormatInt(b.OctetsAvant, 10), strconv.FormatInt(b.OctetsApres, 10),
					b.ArchivesSupprimees, time.Since(debut).Round(time.Millisecond))
			}
		}
	}
	passe()
	if intervalle <= 0 {
		return
	}
	t := time.NewTicker(intervalle)
	defer t.Stop()
	for range t.C {
		passe()
	}
}
