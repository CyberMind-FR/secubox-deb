// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Compactage du journal de bans (#3816).
//
// bans.jsonl était append-only et jamais tourné : 11 Mo et 105 000 lignes sur gk2 depuis août, relus en entier à chaque
// démarrage et par chaque lecteur. Le compactage réécrit le journal de façon ATOMIQUE (fichier temporaire dans le même
// dossier, fsync, rename, fsync du dossier) en gardant :
//
//   - toutes les lignes de moins de `Fenetre` (31 j d'office : les lecteurs les plus exigeants regardent 30 j, voir
//     fenetreMinimaleBans) ;
//   - pour chaque adresse, son dernier état s'il est un ban actif (exp > maintenant, ou exp = 0) ;
//   - pour chaque adresse, toute la CHAÎNE de bans (DepuisChaine) qui atteint la fenêtre, pour que la durée d'un ban
//     ininterrompu reste exacte (plafond de 30 j de la réévaluation).
//
// Par adresse, on garde un SUFFIXE de ses lignes (dans l'ordre du fichier, bans et unbans compris) : la relecture du
// journal compacté rend exactement ce que rendait le journal complet, maintenant et pour toute ligne ajoutée ensuite :
// ActiveBans, CompteCategorie et sanctions sur ≤ 30 j, et DepuisChaine de toute adresse bannie (son seul usage : la
// réévaluation d'un ban actif ; pour une adresse libre depuis plus que la fenêtre, la chaîne passée est archivée). Ce qui sort est ajouté à une archive mensuelle gzip
// bans-AAAAMM.jsonl.gz (mois de `at`, UTC) dans le même dossier ; les archives de plus de `ArchivesMois` mois sont
// supprimées. Archive écrite et renommée AVANT le journal : un arrêt brutal entre les deux laisse au pire des doublons
// dans l'archive, jamais une ligne perdue.
//
// Verrou : la lecture et le tri se font SANS bloquer les ajouts (le fichier est append-only : les octets [0, N) ne
// bougent plus) ; seule la fin (octets ajoutés depuis N, puis rename) se fait sous le verrou d'Append. Append rouvre le
// fichier par son chemin à chaque ligne : après le rename il écrit dans le nouveau fichier, sans poignée à rouvrir.

// fenetreMinimaleBans : la plus longue fenêtre de lecture du journal (récidive leurre et campagne, réévaluation
// plafondChaine, vue /enforcement de l'API) ; une fenêtre plus courte fausserait ces comptes.
const fenetreMinimaleBans = 30 * 24 * time.Hour

// Lignes plus longues que ceci : la relecture (bufio.Scanner à 1 Mio) s'arrête dessus ; le compactage ne touche alors
// à rien plutôt que de changer ce que relit le WAF.
const ligneMaxBans = 1024 * 1024

// CompactageBans règle le compactage.
type CompactageBans struct {
	Fenetre      time.Duration // lignes plus récentes gardées telles quelles
	ArchivesMois int           // archives mensuelles gardées (mois courant moins ArchivesMois et après)
	Seuil        int64         // octets archivables en dessous desquels on ne réécrit rien (évite une rotation par heure)
}

// BilanCompactage décrit une passe.
type BilanCompactage struct {
	Lignes, Gardees, Archivees int
	OctetsAvant, OctetsApres   int64
	Reecrit                    bool
	ArchivesSupprimees         int
}

var motifArchiveBans = regexp.MustCompile(`^bans-([0-9]{6})\.jsonl\.gz$`)

// ligneBan : ce que le tri retient d'une ligne (pas la ligne elle-même : mémoire ~32 o/ligne).
type ligneBan struct {
	ip     int32 // index de l'adresse, -1 si ligne illisible
	at     int64
	exp    int64
	ban    bool
	taille int32
}

// Compacter fait une passe à l'instant `now`.
func (s *BanStore) Compacter(now time.Time, cfg CompactageBans) (bilan BilanCompactage, err error) {
	if s == nil {
		return bilan, nil
	}
	if cfg.Fenetre < fenetreMinimaleBans {
		cfg.Fenetre = fenetreMinimaleBans
	}
	s.compactMu.Lock()
	defer s.compactMu.Unlock()
	dir := filepath.Dir(s.path)
	nettoyerTemporairesBans(dir, filepath.Base(s.path))
	defer func() { bilan.ArchivesSupprimees = purgerArchivesBans(dir, now, cfg.ArchivesMois) }()

	// 1. Taille figée N sous le verrou : tout ce qui est avant N est écrit en entier et ne bougera plus.
	s.mu.Lock()
	f, err := os.Open(s.path)
	if err != nil {
		s.mu.Unlock()
		if errors.Is(err, os.ErrNotExist) {
			return bilan, nil
		}
		return bilan, err
	}
	st, err := f.Stat()
	s.mu.Unlock()
	if err != nil {
		f.Close()
		return bilan, err
	}
	defer f.Close()
	if !st.Mode().IsRegular() {
		return bilan, fmt.Errorf("%s n'est pas un fichier ordinaire", s.path)
	}
	sys, _ := st.Sys().(*syscall.Stat_t)
	if sys != nil && int(sys.Uid) != os.Geteuid() {
		// Le WAF n'a pas le droit de changer de propriétaire (seccomp ~@privileged tue le processus sur chown) : on ne
		// réécrit pas un fichier qui n'est pas le sien.
		return bilan, fmt.Errorf("%s appartient à l'uid %d, pas à %d : non compacté", s.path, sys.Uid, os.Geteuid())
	}
	bilan.OctetsAvant = st.Size()

	// 2. Premier passage : tri par adresse.
	lignes, n, err := lireLignesBans(f, st.Size())
	if err != nil {
		return bilan, err
	}
	bilan.Lignes = len(lignes)
	garder := planCompactage(lignes, now.Unix(), now.Add(-cfg.Fenetre).Unix())
	var archivables int64
	for i, l := range lignes {
		if garder[i] {
			bilan.Gardees++
		} else {
			bilan.Archivees++
			archivables += int64(l.taille)
		}
	}
	if bilan.Archivees == 0 || archivables < cfg.Seuil {
		bilan.Gardees, bilan.Archivees = bilan.Lignes, 0
		bilan.OctetsApres = bilan.OctetsAvant
		return bilan, nil
	}

	// 3. Second passage : lignes gardées vers le temporaire, les autres vers les archives (temporaires elles aussi).
	tmp, err := os.CreateTemp(dir, filepath.Base(s.path)+".tmp-*")
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
	archives := map[string]*archiveBans{}
	defer func() {
		for _, a := range archives {
			a.abandonner()
		}
	}()
	w := bufio.NewWriterSize(tmp, 256*1024)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return bilan, err
	}
	r := bufio.NewReaderSize(io.LimitReader(f, n), 256*1024)
	var tampon []byte
	for i, l := range lignes {
		if cap(tampon) < int(l.taille) {
			tampon = make([]byte, l.taille)
		}
		brut := tampon[:l.taille]
		if _, err := io.ReadFull(r, brut); err != nil {
			return bilan, fmt.Errorf("relecture : %w", err)
		}
		if garder[i] {
			if _, err := w.Write(brut); err != nil {
				return bilan, err
			}
			continue
		}
		mois := now.UTC().Format("200601")
		if l.ip >= 0 && l.at > 0 {
			mois = time.Unix(l.at, 0).UTC().Format("200601")
		}
		a := archives[mois]
		if a == nil {
			if a, err = ouvrirArchiveBans(dir, mois); err != nil {
				return bilan, err
			}
			archives[mois] = a
		}
		if _, err := a.gz.Write(brut); err != nil {
			return bilan, err
		}
	}
	for _, a := range archives {
		if err := a.valider(); err != nil {
			return bilan, err
		}
	}
	if err := syncDossier(dir); err != nil {
		return bilan, err
	}

	// 4. Fin sous le verrou d'Append : octets ajoutés depuis N, puis rename.
	s.mu.Lock()
	defer s.mu.Unlock()
	actuel, err := os.Lstat(s.path)
	if err != nil {
		return bilan, err
	}
	if !os.SameFile(st, actuel) {
		return bilan, fmt.Errorf("%s remplacé pendant le compactage : abandon", s.path)
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
	copierACL(s.path, tmpNom)
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
	if err := os.Rename(tmpNom, s.path); err != nil {
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

// lireLignesBans lit les octets [0, taille) et rend une entrée par ligne terminée par « \n », et la fin n de la
// dernière ligne complète (une fin sans « \n » est une écriture en cours ou interrompue : recopiée telle quelle).
func lireLignesBans(f *os.File, taille int64) ([]ligneBan, int64, error) {
	var lignes []ligneBan
	ips := map[string]int32{}
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
			break // EOF : fin sans « \n » (ou rien)
		}
		if len(ligne)-1 > ligneMaxBans {
			return nil, 0, fmt.Errorf("ligne de plus de %d octets à l'octet %d : non compacté", ligneMaxBans, n)
		}
		l := ligneBan{ip: -1, taille: int32(len(ligne))}
		var rec BanRecord
		if json.Unmarshal(ligne, &rec) == nil && rec.IP != "" {
			idx, vu := ips[rec.IP]
			if !vu {
				idx = int32(len(ips))
				ips[rec.IP] = idx
			}
			l.ip, l.at, l.exp, l.ban = idx, rec.At, rec.Expires, rec.Action == "ban"
		}
		lignes = append(lignes, l)
		n += int64(len(ligne))
		if errors.Is(err, io.EOF) {
			break
		}
	}
	return lignes, n, nil
}

// planCompactage rend, pour chaque ligne, si elle reste dans le journal. Pour chaque adresse : suffixe de ses lignes
// à partir du plus petit des index suivants — première ligne de `at >= coupure` ; dernière ligne si c'est un ban actif ;
// début de la première chaîne de bans (au sens de DepuisChaine) dont l'échéance atteint la coupure. Si l'état de chaîne
// (début, fin) du suffixe diffère de celui de toutes les lignes, l'adresse garde tout. Les lignes illisibles sortent.
func planCompactage(lignes []ligneBan, now, coupure int64) []bool {
	parIP := map[int32][]int{}
	for i, l := range lignes {
		if l.ip >= 0 {
			parIP[l.ip] = append(parIP[l.ip], i)
		}
	}
	garder := make([]bool, len(lignes))
	for _, L := range parIP {
		k := debutGarde(lignes, L, now, coupure)
		for _, i := range L[k:] {
			garder[i] = true
		}
	}
	return garder
}

func debutGarde(lignes []ligneBan, L []int, now, coupure int64) int {
	n := len(L)
	k := n
	for j, i := range L {
		if lignes[i].at >= coupure {
			k = j
			break
		}
	}
	if d := lignes[L[n-1]]; d.ban && (d.exp == 0 || d.exp > now) && n-1 < k {
		k = n - 1
	}
	// Chaînes, exactement comme DepuisChaine (début, fin glissante, pause > 300 s). La fin glissante ne fait que croître :
	// dès qu'une chaîne l'amène à la coupure, toutes les suivantes aussi.
	debut, fin, cur := int64(0), int64(0), -1
	for j, i := range L {
		l := lignes[i]
		if !l.ban {
			continue
		}
		if debut == 0 || l.at > fin+300 {
			if cur >= 0 && fin+300 >= coupure {
				break // la chaîne précédente atteint la coupure
			}
			cur, debut = j, l.at
		}
		if l.exp > fin {
			fin = l.exp
		}
	}
	if cur >= 0 && fin+300 >= coupure && cur < k {
		k = cur
	}
	// État de chaîne (début, fin) du suffixe ≠ celui de toutes les lignes : on garde tout, sauf si l'adresse est libre
	// et sa chaîne close avant la coupure (tout ban ajouté ensuite, at ≥ maintenant, ouvre une chaîne neuve des deux
	// côtés, avec la même fin).
	if k > 0 && k < n {
		complet := etatChaine(lignes, L)
		d := lignes[L[n-1]]
		actif := d.ban && (d.exp == 0 || d.exp > now)
		if complet != etatChaine(lignes, L[k:]) && (actif || complet.fin+300 >= coupure) {
			return 0
		}
	}
	return k
}

type chaine struct{ debut, fin int64 }

func etatChaine(lignes []ligneBan, L []int) chaine {
	var c chaine
	for _, i := range L {
		l := lignes[i]
		if !l.ban {
			continue
		}
		if c.debut == 0 || l.at > c.fin+300 {
			c.debut = l.at
		}
		if l.exp > c.fin {
			c.fin = l.exp
		}
	}
	return c
}

// archiveBans : copie d'une archive mensuelle en cours d'écriture (anciens octets + un membre gzip de plus).
type archiveBans struct {
	final, tmp string
	f          *os.File
	gz         *gzip.Writer
	fait       bool
}

func ouvrirArchiveBans(dir, mois string) (*archiveBans, error) {
	final := filepath.Join(dir, "bans-"+mois+".jsonl.gz")
	f, err := os.CreateTemp(dir, "bans-"+mois+".jsonl.gz.tmp-*")
	if err != nil {
		return nil, err
	}
	a := &archiveBans{final: final, tmp: f.Name(), f: f}
	if st, err := os.Lstat(final); err == nil {
		if !st.Mode().IsRegular() {
			a.abandonner()
			return nil, fmt.Errorf("%s n'est pas un fichier ordinaire", final)
		}
		src, err := os.OpenFile(final, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			a.abandonner()
			return nil, err
		}
		_, err = io.Copy(f, src) // gzip multi-membres : l'ancien contenu reste lisible tel quel
		src.Close()
		if err != nil {
			a.abandonner()
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		a.abandonner()
		return nil, err
	}
	a.gz = gzip.NewWriter(f)
	return a, nil
}

func (a *archiveBans) valider() error {
	if err := a.gz.Close(); err != nil {
		return err
	}
	if err := a.f.Chmod(0o640); err != nil {
		return err
	}
	if err := a.f.Sync(); err != nil {
		return err
	}
	if err := a.f.Close(); err != nil {
		return err
	}
	if err := os.Rename(a.tmp, a.final); err != nil {
		return err
	}
	a.fait = true
	return nil
}

func (a *archiveBans) abandonner() {
	if a.fait {
		return
	}
	a.f.Close()
	os.Remove(a.tmp)
	a.fait = true
}

// purgerArchivesBans supprime les archives d'un mois antérieur à (mois courant − mois).
func purgerArchivesBans(dir string, now time.Time, mois int) int {
	if mois < 0 {
		return 0
	}
	u := now.UTC()
	limite := time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -mois, 0).Format("200601")
	entrees, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entrees {
		m := motifArchiveBans.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() || m[1] >= limite {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err == nil {
			n++
		} else {
			log.Printf("sbxwaf: archive de bans %s non supprimée : %v", e.Name(), err)
		}
	}
	return n
}

// nettoyerTemporairesBans retire les temporaires d'une passe interrompue (arrêt brutal) : seul le compactage en crée,
// et il tient compactMu.
func nettoyerTemporairesBans(dir, base string) {
	entrees, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entrees {
		nom := e.Name()
		if !e.Type().IsRegular() {
			continue
		}
		if strings.HasPrefix(nom, base+".tmp-") || (strings.HasPrefix(nom, "bans-") && strings.Contains(nom, ".jsonl.gz.tmp-")) {
			os.Remove(filepath.Join(dir, nom))
		}
	}
}

func syncDossier(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// copierACL recopie l'ACL POSIX d'accès (lecture de secubox-live, #3351) sur le nouveau fichier. Sans elle, l'ACL par
// défaut du dossier s'applique déjà ; un échec est seulement journalisé.
func copierACL(source, cible string) {
	const nom = "system.posix_acl_access"
	buf := make([]byte, 4096)
	n, err := syscall.Getxattr(source, nom, buf)
	if err != nil || n <= 0 {
		return // pas d'ACL (ou système sans ACL) : rien à recopier
	}
	if err := syscall.Setxattr(cible, nom, buf[:n], 0); err != nil {
		log.Printf("sbxwaf: ACL de %s non recopiée : %v", source, err)
	}
}

// VeillerCompactage compacte tout de suite, puis toutes les `intervalle` (0 : une seule passe).
func (s *BanStore) VeillerCompactage(cfg CompactageBans, intervalle time.Duration) {
	if s == nil {
		return
	}
	passe := func() {
		debut := time.Now()
		b, err := s.Compacter(debut, cfg)
		switch {
		case err != nil:
			log.Printf("sbxwaf: compactage de %s : %v", s.path, err)
		case b.Reecrit:
			log.Printf("sbxwaf: compactage de %s : %d lignes, %d gardées, %d archivées, %s → %s octets, %d archive(s) supprimée(s), %s",
				s.path, b.Lignes, b.Gardees, b.Archivees, strconv.FormatInt(b.OctetsAvant, 10), strconv.FormatInt(b.OctetsApres, 10),
				b.ArchivesSupprimees, time.Since(debut).Round(time.Millisecond))
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
