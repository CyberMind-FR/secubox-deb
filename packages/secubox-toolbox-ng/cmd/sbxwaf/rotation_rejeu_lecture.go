// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"container/heap"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Lecture des journaux nginx pour le rejeu hors ligne du détecteur de rotation (#3919, rotation_rejeu.go) : une ligne à la fois, plusieurs fichiers
// fusionnés dans l'ordre du temps. Mémoire bornée : un fichier n'est ouvert que lorsque son tour vient et fermé à sa fin (32 Kio par fichier ouvert,
// plus la fenêtre gzip). LECTURE SEULE.

const rejeuLigneMax = 32 << 10 // ligne plus longue : malformée

// rejeuLigne : ce que le rejeu retient d'une ligne de journal. `hote` vide : le nom du fichier fait foi.
type rejeuLigne struct {
	t                     int64 // Unix (s)
	hote, ip              string
	methode, chemin, ua   string // vides : la requête est illisible (sonde TLS, ligne vide)
	statut                int
	referent, authentifie bool
}

// preuve : ce que le journal laisse voir d'un vrai navigateur ; mêmes règles que preuveNavigateur, moins ce qui n'est pas journalisé. Un 304 répond à
// une requête conditionnelle (If-None-Match, If-Modified-Since).
func (l *rejeuLigne) preuve() bool { return l.naturePreuve() != "" }

func (l *rejeuLigne) naturePreuve() string {
	switch {
	case l.referent:
		return "referent"
	case l.authentifie:
		return "authentification"
	case l.statut == 304:
		return "revalidation"
	case l.methode != "" && ressourceDePage(l.chemin):
		return "ressource"
	}
	return ""
}

func (l *rejeuLigne) navigation() bool {
	return l.methode != "" && estNavigation(l.methode, l.chemin, nil)
}

// pageServie : la réponse ressemble à une page HTML complète (le journal ne dit ni le type ni le corps).
func (l *rejeuLigne) pageServie() bool {
	return l.statut >= 200 && l.statut < 300 && l.statut != 204 && l.statut != 206 && pageProbable(l.chemin)
}

// extensionsSansPage : téléchargements, données et textes bruts (les ressources de page sont dans extensionsRessource).
var extensionsSansPage = map[string]struct{}{}

func init() {
	for _, e := range strings.Fields(".zip .gz .tgz .tar .bz2 .xz .zst .7z .rar .deb .rpm .apk .iso .img .exe .msi .dmg .bin .jar .whl .crate .pdf .doc .docx .xls .xlsx .odt .ods " +
		".json .ndjson .xml .rss .atom .ics .csv .txt .log .yml .yaml .toml .sql .bak .patch .diff .bundle .raw .asc .sig .pem .crt .sha256 .gpg") {
		extensionsSansPage[e] = struct{}{}
	}
}

// pageProbable : chemin sans extension de ressource, de téléchargement ni de texte brut. Les vues de code d'une forge (vueDeForge) sont des pages, quelle
// que soit l'extension du fichier montré.
func pageProbable(chemin string) bool {
	if ressourceDePage(chemin) {
		return false
	}
	i := strings.LastIndexByte(chemin, '.')
	if i < 0 || strings.IndexByte(chemin[i:], '/') >= 0 {
		return true
	}
	if _, non := extensionsSansPage[strings.ToLower(chemin[i:])]; !non {
		return true
	}
	return vueDeForge(chemin)
}

// analyserLigne lit le format combiné de nginx, précédé ou non de l'hôte (« $host » ou « $host:$port », formats sbx_host, sbx_masque, vhost_combined).
// Les champs entre guillemets sont déjà échappés par nginx (« \x22 ») : ils sont gardés tels quels.
func analyserLigne(s string) (l rejeuLigne, ok bool) {
	i := strings.IndexByte(s, '[')
	if i < 1 {
		return l, false
	}
	tete := strings.Fields(s[:i])
	if len(tete) == 4 {
		l.hote, tete = tete[0], tete[1:]
	}
	if len(tete) != 3 {
		return l, false
	}
	if _, err := netip.ParseAddr(tete[0]); err != nil {
		return l, false
	}
	l.ip, l.authentifie = tete[0], tete[2] != "-"
	s = s[i+1:]
	if i = strings.IndexByte(s, ']'); i < 0 {
		return l, false
	}
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", s[:i])
	if err != nil || t.Unix() < 0 || t.Unix() > 1<<32-1 {
		return l, false
	}
	l.t = t.Unix()
	requete, s, ok := champCite(s[i+1:])
	if !ok {
		return l, false
	}
	apres := strings.Fields(avantGuillemet(s))
	if len(apres) < 2 {
		return l, false
	}
	if l.statut, err = strconv.Atoi(apres[0]); err != nil {
		return l, false
	}
	referent, s, ok := champCite(s)
	if !ok {
		return l, false
	}
	ua, _, ok := champCite(s)
	if !ok {
		return l, false
	}
	l.referent = referent != "" && referent != "-"
	if ua != "-" {
		l.ua = ua
	}
	if p := strings.Split(requete, " "); len(p) == 3 && strings.HasPrefix(p[2], "HTTP/") {
		l.methode, l.chemin = p[0], cheminDeCible(p[1])
	}
	return l, true
}

func avantGuillemet(s string) string {
	if i := strings.IndexByte(s, '"'); i >= 0 {
		return s[:i]
	}
	return s
}

// champCite rend le prochain champ entre guillemets et le reste.
func champCite(s string) (champ, reste string, ok bool) {
	i := strings.IndexByte(s, '"')
	if i < 0 {
		return "", "", false
	}
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '"':
			return s[i+1 : j], s[j+1:], true
		}
	}
	return "", "", false
}

// cheminDeCible : le chemin d'une cible de requête, sans paramètres ni « https://hôte ».
func cheminDeCible(c string) string {
	if i := strings.IndexAny(c, "?#"); i >= 0 {
		c = c[:i]
	}
	if !strings.HasPrefix(c, "/") {
		if i := strings.Index(c, "://"); i >= 0 {
			c = c[i+3:]
			if i = strings.IndexByte(c, '/'); i < 0 {
				return "/"
			}
			c = c[i:]
		}
	}
	return c
}

var (
	rejeuSuffixeRotation = regexp.MustCompile(`(\.gz|\.\d+|-\d{8}(-\d+)?)$`)
	rejeuSuffixeAcces    = regexp.MustCompile(`[._-]access\.log$`)
)

// hoteDuFichier : « <vhost>_access.log[.N][.gz] » → vhost ; un journal commun garde son nom (le même pour toutes ses rotations).
func hoteDuFichier(chemin string) string {
	n := filepath.Base(chemin)
	for {
		c := rejeuSuffixeRotation.ReplaceAllString(n, "")
		if c == n || c == "" {
			break
		}
		n = c
	}
	if h := rejeuSuffixeAcces.ReplaceAllString(n, ""); h != "" {
		n = h
	}
	return hoteRotation(n)
}

// ── Fichiers ─────────────────────────────────────────────────────────────────────────────────────────────────────────

type rejeuFlux struct {
	chemin, hote string
	rang         int
	dev, ino     uint64
	premier      int64 // date de la première ligne lisible

	f        *os.File
	br       *bufio.Reader
	ligne    rejeuLigne
	lues     int
	malForme int
}

type rejeuErreur struct {
	Fichier string `json:"fichier"`
	Erreur  string `json:"erreur"`
}

func inode(f os.FileInfo) (dev, ino uint64) {
	if s, ok := f.Sys().(*syscall.Stat_t); ok {
		return uint64(s.Dev), s.Ino
	}
	return 0, 0
}

func (x *rejeuFlux) ouvrir() error {
	i, err := os.Stat(x.chemin)
	if err != nil {
		return err
	}
	if !i.Mode().IsRegular() {
		return errors.New("pas un fichier ordinaire")
	}
	f, err := os.Open(x.chemin)
	if err != nil {
		return err
	}
	if i, err = f.Stat(); err != nil {
		f.Close()
		return err
	}
	dev, ino := inode(i)
	if x.ino != 0 && (dev != x.dev || ino != x.ino) {
		f.Close()
		return errors.New("remplacé pendant le rejeu (rotation du journal) : travailler sur une copie")
	}
	x.dev, x.ino, x.f, x.br = dev, ino, f, bufio.NewReaderSize(f, rejeuLigneMax)
	if m, _ := x.br.Peek(2); bytes.Equal(m, []byte{0x1f, 0x8b}) {
		z, err := gzip.NewReader(x.br)
		if err != nil {
			x.fermer()
			return err
		}
		x.br = bufio.NewReaderSize(z, rejeuLigneMax)
	}
	return nil
}

func (x *rejeuFlux) fermer() {
	if x.f != nil {
		x.f.Close()
	}
	x.f, x.br = nil, nil
}

// suivante lit la prochaine ligne lisible dans x.ligne ; io.EOF à la fin.
func (x *rejeuFlux) suivante() error {
	for {
		b, err := x.br.ReadSlice('\n')
		if err == bufio.ErrBufferFull { // trop longue : sautée
			for err == bufio.ErrBufferFull {
				_, err = x.br.ReadSlice('\n')
			}
			x.lues++
			x.malForme++
			if err != nil {
				return err
			}
			continue
		}
		if len(b) > 0 && (err == nil || err == io.EOF) {
			x.lues++
			l, ok := analyserLigne(string(bytes.TrimRight(b, "\r\n")))
			if ok {
				x.ligne = l
				return nil // une éventuelle fin de fichier reviendra à l'appel suivant
			}
			x.malForme++
		}
		if err != nil {
			return err
		}
	}
}

// reperer cherche la date de la première ligne lisible de chaque fichier. Illisibles, absents, doublons : dans les erreurs ; sans aucune ligne
// lisible : comptés dans `lues` et `malformees` tout de suite.
func reperer(fichiers []string) (flux []*rejeuFlux, lues, malformees, sansLigne int, erreurs []rejeuErreur) {
	vus := map[[2]uint64]bool{}
	for k, c := range fichiers {
		x := &rejeuFlux{chemin: c, hote: hoteDuFichier(c), rang: k}
		err := x.ouvrir()
		if err == nil && vus[[2]uint64{x.dev, x.ino}] {
			err = errors.New("déjà donné")
			x.fermer()
		}
		if err == nil {
			vus[[2]uint64{x.dev, x.ino}] = true
			err = x.suivante()
			x.fermer()
		}
		switch {
		case err == io.EOF:
			sansLigne++
			lues, malformees = lues+x.lues, malformees+x.malForme
		case err != nil:
			erreurs = append(erreurs, rejeuErreur{c, err.Error()})
		default:
			x.premier, x.lues, x.malForme = x.ligne.t, 0, 0
			flux = append(flux, x)
		}
	}
	sort.SliceStable(flux, func(i, j int) bool { return flux[i].premier < flux[j].premier })
	return
}

type rejeuTas []*rejeuFlux

func (h rejeuTas) Len() int { return len(h) }
func (h rejeuTas) Less(i, j int) bool {
	if h[i].ligne.t != h[j].ligne.t {
		return h[i].ligne.t < h[j].ligne.t
	}
	return h[i].rang < h[j].rang
}
func (h rejeuTas) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *rejeuTas) Push(x any)   { *h = append(*h, x.(*rejeuFlux)) }
func (h *rejeuTas) Pop() any {
	v := *h
	x := v[len(v)-1]
	*h = v[:len(v)-1]
	return x
}

// fusionner donne à `f` toutes les lignes lisibles, du plus ancien au plus récent (à ordre égal : le rang du fichier). Rend les lignes lues et
// malformées, et les erreurs de lecture : ce qui précède une erreur est gardé.
func fusionner(flux []*rejeuFlux, f func(hote string, l *rejeuLigne)) (lues, malformees int, erreurs []rejeuErreur) {
	var tas rejeuTas
	finir := func(x *rejeuFlux, err error) {
		x.fermer()
		lues, malformees = lues+x.lues, malformees+x.malForme
		if err != io.EOF {
			erreurs = append(erreurs, rejeuErreur{x.chemin, fmt.Sprintf("lecture interrompue : %v", err)})
		}
	}
	defer func() {
		for _, x := range tas {
			x.fermer()
		}
	}()
	for len(flux) > 0 || len(tas) > 0 {
		for len(flux) > 0 && (len(tas) == 0 || flux[0].premier <= tas[0].ligne.t) {
			x := flux[0]
			flux = flux[1:]
			x.lues, x.malForme = 0, 0
			err := x.ouvrir()
			if err == nil {
				err = x.suivante()
			}
			if err != nil {
				finir(x, err)
				continue
			}
			heap.Push(&tas, x)
		}
		if len(tas) == 0 {
			continue
		}
		x := tas[0]
		hote := x.ligne.hote
		if hote != "" {
			hote = hoteRotation(hote)
		} else {
			hote = x.hote
		}
		f(hote, &x.ligne)
		if err := x.suivante(); err != nil {
			finir(x, err)
			heap.Pop(&tas)
			continue
		}
		heap.Fix(&tas, 0)
	}
	return
}
