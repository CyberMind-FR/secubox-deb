package store

// Sauvegarde.
//
// CE QUE CETTE FONCTION EST, ET CE QU'ELLE N'EST PAS
//
// Elle produit une archive du CONTENU : content/ et files/. Elle n'emporte ni
// la base, ni les secrets.
//
//   - Pas la base, parce qu'elle se reconstruit (Reindex) et qu'une base copiee
//     a chaud est un fichier a moitie ecrit. C'est precisement pour ne pas
//     avoir a l'arreter qu'on ne la sauvegarde pas.
//
//   - Pas les secrets, parce qu'une archive de contenu CIRCULE : disque
//     externe, autre machine, transmission pour depannage. Les hashes de mots
//     de passe se sauvegardent separement, avec les precautions qui vont avec.
//
// Elle ne remplace donc pas un rsync du repertoire entier : elle en est la
// version transportable, celle qu'on peut poser quelque part sans y reflechir
// a deux fois.

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// LA PROTECTION DES SECRETS N'EST PAS `exclus` : c'est la LISTE BLANCHE des
// sous-repertoires parcourus (content, files). secrets/ vit a cote d'eux et
// n'est jamais atteint. Une liste noire protege de ce qu'on a pense a y mettre ;
// une liste blanche protege aussi de ce a quoi on n'a pas pense.
//
// `exclus` est la seconde barriere : elle attrape un secrets/ ou un cache/
// place A L'INTERIEUR de content/ ou files/, ou la liste blanche ne dit plus
// rien. Ce cas parait improbable jusqu'a ce qu'un module y depose son cache.
var exclus = []string{"secrets", "tmp", "cache"}

func (s *Store) Backup(dest string) error {
	// Ecriture sous nom temporaire puis renommage : une archive interrompue ne
	// doit pas prendre la place de la precedente, qui elle etait complete.
	tmp := dest + ".partiel"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	echec := func(e error) error {
		tw.Close()
		gz.Close()
		f.Close()
		os.Remove(tmp)
		return e
	}

	for _, sous := range []string{"content", "files"} {
		racine := filepath.Join(s.root, sous)
		if _, err := os.Stat(racine); os.IsNotExist(err) {
			continue
		}
		err := filepath.Walk(racine, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(s.root, p)
			if err != nil {
				return err
			}
			if estExclu(rel) {
				if fi.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			// Ni lien symbolique ni fichier special : un lien pointant hors de
			// l'arborescence ferait sortir de l'archive des fichiers que
			// personne n'a decide d'y mettre.
			if !fi.Mode().IsRegular() && !fi.IsDir() {
				return nil
			}
			h, err := tar.FileInfoHeader(fi, "")
			if err != nil {
				return err
			}
			h.Name = filepath.ToSlash(rel)
			// Ni proprietaire ni horodatage d'acces : deux sauvegardes du meme
			// contenu doivent donner deux archives comparables.
			h.Uid, h.Gid, h.Uname, h.Gname = 0, 0, "", ""
			if err := tw.WriteHeader(h); err != nil {
				return err
			}
			if fi.IsDir() {
				return nil
			}
			src, err := os.Open(p)
			if err != nil {
				return err
			}
			defer src.Close()
			_, err = io.Copy(tw, src)
			return err
		})
		if err != nil {
			return echec(fmt.Errorf("sauvegarde de %s : %w", sous, err))
		}
	}

	if err := tw.Close(); err != nil {
		return echec(err)
	}
	if err := gz.Close(); err != nil {
		return echec(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

func estExclu(rel string) bool {
	for _, p := range strings.Split(filepath.ToSlash(rel), "/") {
		for _, x := range exclus {
			if p == x {
				return true
			}
		}
	}
	return false
}

// Integrity compare le disque et l'index, sans rien modifier.
//
// Rendue par la console sysop. Un ecart doit se voir AVANT qu'on en ait besoin,
// pas le jour de la restauration.
type Integrity struct {
	OnDisk, Indexed, Diverging, Missing int
	// Unreadable est distinct de Diverging. « Divergent » veut dire que le
	// contenu ne correspond plus a l'index ; un fichier qu'on ne peut pas
	// OUVRIR est un probleme de droits. Confondre les deux envoie chercher une
	// corruption la ou il n'y a qu'un droit manquant — ce qui est arrive : la
	// console annoncait 252 divergents pour 252 fichiers illisibles.
	Unreadable int
	Details    []string
}

func (s *Store) Integrity() (Integrity, error) {
	var r Integrity
	rows, err := s.db.Query(`SELECT id, body_path FROM posts WHERE deleted_at IS NULL`)
	if err != nil {
		return r, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var rel string
		if err := rows.Scan(&id, &rel); err != nil {
			return r, err
		}
		r.Indexed++
		p := Post{ID: id, BodyPath: rel}
		if _, err := os.Stat(filepath.Join(s.root, rel)); os.IsNotExist(err) {
			r.Missing++
			r.Details = append(r.Details, "absent du disque : "+rel)
			continue
		}
		r.OnDisk++
		if _, err := s.Body(p); err != nil {
			if os.IsPermission(err) {
				r.Unreadable++
				r.Details = append(r.Details,
					"illisible (droits) : "+rel+" — verifiez le proprietaire")
				continue
			}
			r.Diverging++
			r.Details = append(r.Details, err.Error())
		}
	}
	return r, rows.Err()
}
