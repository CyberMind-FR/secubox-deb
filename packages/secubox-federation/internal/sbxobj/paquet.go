// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sbxobj

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/canon"
	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/sbxcert"
)

// Membres admis dans un .sbx — rien d'autre n'est extrait.
const (
	membreManifeste = "manifest.json"
	membreContenu   = "content.tar"
	membreDepot     = "repo.bundle"
)

// TailleMax : un paquet, décompressé, ne dépasse pas cette taille.
const TailleMax = 512 << 20

// Emballage : ce que l'éditeur fournit.
type Emballage struct {
	SiteDir    string // /srv/metablogizer/sites/<nom>
	Objet      Objet
	Domaine    string // domaine d'origine (information, pour l'import metablogizer)
	Cle        ed25519.PrivateKey
	Certificat string   // YAML du certificat SBX de l'éditeur (vide : non certifié)
	Sortie     string   // chemin du .sbx produit
	Apercus    []string // captures (PNG/JPEG), réduites et embarquées — 4 au plus
	Maintenant time.Time
}

// Emballe produit un .sbx signé, compatible avec l'import du metablogizer.
func Emballe(e Emballage) (map[string]any, error) {
	if err := e.Objet.Valide(); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(e.SiteDir, "public")); err != nil {
		if _, err2 := os.Stat(filepath.Join(e.SiteDir, ".git")); err2 != nil {
			return nil, fmt.Errorf("%s : ni public/ ni dépôt git — rien à emballer", e.SiteDir)
		}
	}
	tmp, err := os.MkdirTemp("", "sbx-emballe-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	aGit := dirExiste(filepath.Join(e.SiteDir, ".git"))
	membre := membreContenu
	if aGit {
		// L'HISTOIRE COMPLÈTE, comme l'export du metablogizer.
		membre = membreDepot
		// safe.directory LIMITÉ À CE DÉPÔT : lancé en root, git refuse un dépôt
		// qui appartient au compte `secubox` (« dubious ownership »). On ne
		// fait que LIRE ce dépôt, le temps du bundle.
		// Git compare au chemin RÉEL : /srv → /data sur gk2.
		reel, err := filepath.EvalSymlinks(e.SiteDir)
		if err != nil {
			return nil, err
		}
		if out, err := exec.Command("git", "-c", "safe.directory="+reel, "-C", reel, "bundle", "create",
			filepath.Join(tmp, membre), "--all").CombinedOutput(); err != nil {
			return nil, fmt.Errorf("git bundle : %v : %s", err, out)
		}
	} else if err := tarDossier(filepath.Join(e.SiteDir, "public"), "public", filepath.Join(tmp, membre)); err != nil {
		return nil, err
	}
	somme, err := sha256Fichier(filepath.Join(tmp, membre))
	if err != nil {
		return nil, err
	}
	if len(e.Apercus) > ApercusMax {
		return nil, fmt.Errorf("%d aperçus : %d au plus", len(e.Apercus), ApercusMax)
	}
	integ := map[string]any{membre: "sha256:" + somme}
	membres := []string{membre}
	apercus := []any{}
	for i, src := range e.Apercus {
		jpg, l, h, err := Vignette(src)
		if err != nil {
			return nil, err
		}
		nom := membreApercu(i + 1)
		if err := os.WriteFile(filepath.Join(tmp, nom), jpg, 0o644); err != nil {
			return nil, err
		}
		s, _ := sha256Fichier(filepath.Join(tmp, nom))
		integ[nom] = "sha256:" + s
		membres = append(membres, nom)
		apercus = append(apercus, map[string]any{"fichier": nom, "largeur": l, "hauteur": h})
	}
	pub := e.Cle.Public().(ed25519.PublicKey)
	man := map[string]any{
		// Champs lus par l'import du metablogizer — inchangés.
		"name": e.Objet.Name, "domain": e.Domaine, "has_git": aGit,
		// Ce que la fédération y ajoute.
		"objet":     e.Objet.carte(),
		"integrite": integ,
		"editeur": map[string]any{"did": sbxcert.DID(pub), "pubkey": sbxcert.FormatPub(pub),
			"certificat": e.Certificat},
		"cree": e.Maintenant.UTC().Format(time.RFC3339),
	}
	if len(apercus) > 0 {
		man["apercus"] = apercus
	}
	msg, err := canon.Encode(man)
	if err != nil {
		return nil, err
	}
	man["signature"] = sbxcert.Signe(e.Cle, msg)
	jm, _ := json.MarshalIndent(man, "", "  ")
	if err := os.WriteFile(filepath.Join(tmp, membreManifeste), jm, 0o644); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(e.Sortie), 0o755); err != nil {
		return nil, err
	}
	return man, tarGz(e.Sortie+".tmp", tmp, append(membres, membreManifeste), func() error {
		return os.Rename(e.Sortie+".tmp", e.Sortie)
	})
}

// Paquet : un .sbx OUVERT et VÉRIFIÉ.
type Paquet struct {
	Manifeste map[string]any
	Objet     Objet
	Editeur   string   // DID
	Certifie  bool     // l'éditeur tient un certificat valide de la CA donnée
	Motif     string   // pourquoi il ne l'est pas
	Membre    string   // content.tar | repo.bundle
	Apercus   []string // chemins des aperçus extraits et vérifiés, dans l'ordre
	dir       string
}

func (p *Paquet) Ferme() { os.RemoveAll(p.dir) }

// Ouvre extrait et VÉRIFIE : membres admis seulement, intégrité de chacun,
// signature de l'éditeur, puis — si caPub est fourni — son certificat.
// Une erreur ici signifie : ne rien installer.
func Ouvre(chemin string, caPub ed25519.PublicKey, revoques map[string]bool, maintenant time.Time) (*Paquet, error) {
	dir, err := os.MkdirTemp("", "sbx-ouvre-")
	if err != nil {
		return nil, err
	}
	p := &Paquet{dir: dir}
	if err := extraitMembres(chemin, dir); err != nil {
		p.Ferme()
		return nil, err
	}
	if err := p.verifie(caPub, revoques, maintenant); err != nil {
		p.Ferme()
		return nil, err
	}
	return p, nil
}

func (p *Paquet) verifie(caPub ed25519.PublicKey, revoques map[string]bool, maintenant time.Time) error {
	b, err := os.ReadFile(filepath.Join(p.dir, membreManifeste))
	if err != nil {
		return errors.New("manifest.json absent")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var man map[string]any
	if err := d.Decode(&man); err != nil {
		return fmt.Errorf("manifeste illisible : %w", err)
	}
	sig, _ := man["signature"].(string)
	delete(man, "signature")
	ed, _ := man["editeur"].(map[string]any)
	if ed == nil {
		return errors.New("paquet sans éditeur : non signé")
	}
	did, _ := ed["did"].(string)
	pubS, _ := ed["pubkey"].(string)
	pub, err := sbxcert.LitPub(pubS)
	if err != nil || sbxcert.DID(pub) != did {
		return errors.New("éditeur : la clé ne correspond pas au DID")
	}
	msg, err := canon.Encode(man)
	if err != nil {
		return err
	}
	if !sbxcert.Verifie(pub, msg, sig) {
		return errors.New("signature de l'éditeur invalide — paquet modifié ou forgé")
	}
	// INTÉGRITÉ : chaque membre présent est listé, et chaque listé est intact.
	integ, _ := man["integrite"].(map[string]any)
	nContenu := 0
	for membre, attendu := range integ {
		apercu := reApercu.MatchString(membre)
		if membre != membreContenu && membre != membreDepot && !apercu {
			return fmt.Errorf("membre inattendu : %s", membre)
		}
		somme, err := sha256Fichier(filepath.Join(p.dir, membre))
		if err != nil {
			return fmt.Errorf("membre %s absent", membre)
		}
		if attendu != "sha256:"+somme {
			return fmt.Errorf("membre %s altéré (SHA-256)", membre)
		}
		if !apercu {
			p.Membre = membre
			nContenu++
		}
	}
	if nContenu != 1 {
		return errors.New("intégrité : exactement un membre de contenu attendu")
	}
	for _, autre := range []string{membreContenu, membreDepot} {
		if autre != p.Membre && fichierExiste(filepath.Join(p.dir, autre)) {
			return fmt.Errorf("membre %s non couvert par la signature", autre)
		}
	}
	// APERÇUS : la liste signée dit lesquels, dans quel ordre ; tout aperçu
	// présent y figure ; chacun est un JPEG borné (il finira dans un <img>).
	liste, _ := man["apercus"].([]any)
	if len(liste) > ApercusMax {
		return errors.New("trop d'aperçus")
	}
	declares := map[string]bool{}
	for _, x := range liste {
		a, _ := x.(map[string]any)
		f, _ := a["fichier"].(string)
		if !reApercu.MatchString(f) || declares[f] {
			return fmt.Errorf("aperçu mal déclaré : %q", f)
		}
		if _, ok := integ[f]; !ok {
			return fmt.Errorf("aperçu %s non couvert par la signature", f)
		}
		if err := verifieApercu(filepath.Join(p.dir, f)); err != nil {
			return fmt.Errorf("%s : %v", f, err)
		}
		declares[f] = true
		p.Apercus = append(p.Apercus, filepath.Join(p.dir, f))
	}
	for i := 1; i <= ApercusMax; i++ {
		if f := membreApercu(i); !declares[f] && fichierExiste(filepath.Join(p.dir, f)) {
			return fmt.Errorf("aperçu %s non déclaré", f)
		}
	}
	ob, _ := json.Marshal(man["objet"])
	if err := json.Unmarshal(ob, &p.Objet); err != nil {
		return errors.New("fiche d'objet illisible")
	}
	if err := p.Objet.Valide(); err != nil {
		return err
	}
	if n, _ := man["name"].(string); n != p.Objet.Name {
		return errors.New("le nom du site ne correspond pas à la fiche")
	}
	p.Manifeste, p.Editeur = man, did
	p.Motif = "aucune CA pour vérifier l'éditeur"
	if caPub != nil {
		certY, _ := ed["certificat"].(string)
		switch c, err := sbxcert.Lit([]byte(certY)); {
		case certY == "":
			p.Motif = "éditeur sans certificat SBX"
		case err != nil:
			p.Motif = "certificat de l'éditeur illisible"
		case c.BoxID != did:
			p.Motif = "le certificat joint est celui d'une autre box"
		default:
			if e := c.Verification(caPub, maintenant, revoques); !e.Valide {
				p.Motif = "certificat de l'éditeur : " + e.Motif
			} else if !c.Rights["metapack"] && p.Objet.Type == "metablog" {
				p.Motif = "l'éditeur n'a pas le droit metapack"
			} else {
				p.Certifie, p.Motif = true, ""
			}
		}
	}
	return nil
}

// Installe crée le site `nom` — JAMAIS par-dessus un site existant.
// Le site arrive NON PUBLIÉ : la publication (vhost, WAF, certificat, DNS)
// reste un geste du metablogizer, fait en connaissance de cause.
func (p *Paquet) Installe(sitesRoot, nom string, maintenant time.Time) (string, error) {
	if !reNom.MatchString(nom) {
		return "", fmt.Errorf("nom de site invalide : %q", nom)
	}
	cible := filepath.Join(sitesRoot, nom)
	if _, err := os.Lstat(cible); err == nil {
		return "", fmt.Errorf("le site %q existe déjà — rien n'est écrasé ; choisir un autre nom", nom)
	}
	if p.Membre == membreDepot {
		if out, err := exec.Command("git", "clone", "-q", filepath.Join(p.dir, membreDepot), cible).CombinedOutput(); err != nil {
			os.RemoveAll(cible)
			return "", fmt.Errorf("git clone : %v : %s", err, out)
		}
	} else {
		if err := os.MkdirAll(cible, 0o755); err != nil {
			return "", err
		}
		if err := extraitContenu(filepath.Join(p.dir, membreContenu), cible); err != nil {
			os.RemoveAll(cible)
			return "", err
		}
	}
	domaine := ""
	if d, _ := p.Manifeste["domain"].(string); d != "" {
		if i := strings.Index(d, "."); i > 0 {
			domaine = nom + d[i:]
		}
	}
	site := map[string]any{"name": nom, "domain": domaine, "published": false,
		"version": p.Objet.Version, "objet": p.Objet.ID,
		"installe_depuis": p.Objet.ID + "@" + p.Objet.Version, "editeur": p.Editeur,
		"installe_le": maintenant.UTC().Format(time.RFC3339)}
	b, _ := json.MarshalIndent(site, "", "  ")
	if err := os.WriteFile(filepath.Join(cible, "site.json"), b, 0o644); err != nil {
		os.RemoveAll(cible)
		return "", err
	}
	return cible, nil
}

// ── tar ─────────────────────────────────────────────────────────────────────

func tarDossier(src, prefixe, sortie string) error {
	f, err := os.Create(sortie)
	if err != nil {
		return err
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	err = filepath.WalkDir(src, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		nom := filepath.ToSlash(filepath.Join(prefixe, rel))
		info, err := de.Info()
		if err != nil {
			return err
		}
		// Ni liens, ni fichiers spéciaux : ils ne voyagent pas (et ne
		// s'extrairaient pas de l'autre côté).
		if !info.Mode().IsRegular() && !info.IsDir() {
			return nil
		}
		h, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		h.Name, h.Uname, h.Gname, h.Uid, h.Gid = nom, "", "", 0, 0
		if info.IsDir() {
			h.Name += "/"
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			r, err := os.Open(p)
			if err != nil {
				return err
			}
			defer r.Close()
			_, err = io.Copy(tw, r)
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

func tarGz(sortie, dir string, membres []string, apres func() error) error {
	f, err := os.Create(sortie)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, m := range membres {
		info, err := os.Stat(filepath.Join(dir, m))
		if err != nil {
			f.Close()
			return err
		}
		h := &tar.Header{Name: m, Mode: 0o644, Size: info.Size(), ModTime: info.ModTime(), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(h); err != nil {
			f.Close()
			return err
		}
		r, _ := os.Open(filepath.Join(dir, m))
		_, err = io.Copy(tw, r)
		r.Close()
		if err != nil {
			f.Close()
			return err
		}
	}
	if err := tw.Close(); err != nil {
		f.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return apres()
}

// extraitMembres : seulement les membres admis (dont les aperçus), fichiers réguliers,
// taille bornée.
func extraitMembres(chemin, dir string) error {
	f, err := os.Open(chemin)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return errors.New("paquet illisible (gzip)")
	}
	tr := tar.NewReader(gz)
	vus, total := map[string]bool{}, int64(0)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("paquet illisible (tar)")
		}
		if h.Typeflag != tar.TypeReg {
			return fmt.Errorf("membre %q : fichier ordinaire attendu", h.Name)
		}
		if h.Name != membreManifeste && h.Name != membreContenu && h.Name != membreDepot && !reApercu.MatchString(h.Name) {
			return fmt.Errorf("membre inattendu : %q", h.Name)
		}
		if vus[h.Name] {
			return fmt.Errorf("membre en double : %q", h.Name)
		}
		vus[h.Name] = true
		total += h.Size
		if total > TailleMax {
			return errors.New("paquet trop grand")
		}
		w, err := os.Create(filepath.Join(dir, h.Name))
		if err != nil {
			return err
		}
		_, err = io.Copy(w, io.LimitReader(tr, TailleMax))
		w.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// extraitContenu : content.tar dans `cible`, SOUS public/ uniquement, sans
// traversée ni lien — la même règle que _safe_extractall du metablogizer.
func extraitContenu(tarPath, cible string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	base, _ := filepath.Abs(cible)
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errors.New("contenu illisible")
		}
		nom := filepath.Clean(h.Name)
		if nom != "public" && !strings.HasPrefix(nom, "public/") {
			return fmt.Errorf("entrée hors de public/ : %q", h.Name)
		}
		dest := filepath.Join(base, nom)
		if dest != base && !strings.HasPrefix(dest, base+string(os.PathSeparator)) {
			return fmt.Errorf("entrée qui sort du site : %q", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dest, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			total += h.Size
			if total > TailleMax {
				return errors.New("contenu trop grand")
			}
			if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
				return err
			}
			w, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
			if err != nil {
				return err
			}
			_, err = io.Copy(w, io.LimitReader(tr, h.Size))
			w.Close()
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("entrée %q : ni fichier ni dossier", h.Name)
		}
	}
}

func sha256Fichier(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func dirExiste(p string) bool     { st, err := os.Stat(p); return err == nil && st.IsDir() }
func fichierExiste(p string) bool { st, err := os.Stat(p); return err == nil && st.Mode().IsRegular() }
