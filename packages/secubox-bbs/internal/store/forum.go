package store

// Fils et messages.
//
// LE CORPS DES MESSAGES N'EST PAS EN BASE. Chaque message est un fichier
// Markdown sous content/, precede d'un entete qui porte ses metadonnees. La
// base n'est qu'un index de ces fichiers.
//
// Cette contrainte parait lourde jusqu'au jour ou elle sert. Elle donne :
//
//   - une sauvegarde par simple rsync, a chaud, sans arreter le service ;
//   - des messages lisibles avec `less` dans dix ans, sans ce logiciel ;
//   - une base entierement reconstructible — donc jetable, donc jamais un
//     point de perte unique.
//
// Elle a un cout : l'entete doit rester complet, sinon la reconstruction perd
// ce qu'il ne porte pas. C'est pourquoi Reindex est teste comme une garantie
// du projet et non comme une commodite.

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Visibility string

const (
	VisLocal  Visibility = "local"  // ne sort pas de la maison
	VisPublic Visibility = "public" // eligible a l'export statique
)

type Post struct {
	ID         int64
	ThreadID   int64
	AuthorID   int64
	BodyPath   string
	Visibility Visibility
	CreatedAt  int64
	// EditedAt/EditedBy : 0 si jamais edite. EditedBy != AuthorID signale une
	// CORRECTION DE MODERATION (un sysop a touche au texte d'un autre), a
	// afficher distinctement d'une retouche de l'auteur (#1091).
	EditedAt int64
	EditedBy int64
}

// ── ecriture ────────────────────────────────────────────────────────────────

// NewThread ouvre un fil et ecrit son premier message.
func (s *Store) NewThread(catID, authorID int64, title, body string, vis Visibility) (int64, error) {
	if strings.TrimSpace(title) == "" {
		return 0, errors.New("titre vide")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	slug, err := slugLibre(tx, catID, slugify(title))
	if err != nil {
		return 0, err
	}
	res, err := tx.Exec(`INSERT INTO threads(category_id,author_id,slug,title,visibility,
		created_at,last_post_at) VALUES(?,?,?,?,?,unixepoch(),unixepoch())`,
		catID, authorID, slug, title, string(vis))
	if err != nil {
		return 0, err
	}
	th, _ := res.LastInsertId()
	if _, err := s.insertPost(tx, th, authorID, body, vis); err != nil {
		return 0, err
	}
	return th, tx.Commit()
}

// MarquerSource pose le TYPE de source d'un fil (#1056 stage 2 : video /
// podcast / film / livre / conference / web). La rédaction s'en sert pour
// classer le dossier ; l'adresse elle-même vit dans le premier message.
func (s *Store) MarquerSource(threadID int64, source string) error {
	_, err := s.db.Exec(`UPDATE threads SET source = ? WHERE id = ?`, source, threadID)
	return err
}

// MarquerSourceMedia pose type + média (#1056 stage 3) : une source vidéo
// déposée garde son adresse dans media_url et media_kind="video", ce qui la
// rend embarquable dans la rédaction ET fournit l'URL au raccord ytsas.
func (s *Store) MarquerSourceMedia(threadID int64, source, mediaURL, mediaKind string) error {
	_, err := s.db.Exec(
		`UPDATE threads SET source = ?, media_url = ?, media_kind = ? WHERE id = ?`,
		source, mediaURL, mediaKind, threadID)
	return err
}

// SourceMediaFil rend l'adresse média enregistrée d'un fil (pour le raccord
// ytsas / l'archivage PeerTube). Vide si le fil n'en a pas.
func (s *Store) SourceMediaFil(threadID int64) (string, error) {
	var u string
	err := s.db.QueryRow(`SELECT COALESCE(media_url,'') FROM threads WHERE id = ?`, threadID).Scan(&u)
	return u, err
}

// Reply ajoute un message a un fil existant.
func (s *Store) Reply(threadID, authorID int64, body string, vis Visibility) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	id, err := s.insertPost(tx, threadID, authorID, body, vis)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(
		`UPDATE threads SET last_post_at = unixepoch() WHERE id = ?`, threadID); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// insertPost ecrit la ligne d'index PUIS le fichier.
//
// Cet ordre est delibere : le chemin du fichier est derive de l'identifiant que
// SQLite vient d'attribuer. Il n'est JAMAIS derive du titre ni d'aucun texte
// fourni par un utilisateur — un titre « ../../etc/passwd » ne doit pas pouvoir
// designer un chemin. C'est la seule garantie qui tienne : assainir un texte
// libre pour en faire un chemin est un exercice qu'on finit toujours par
// perdre.
func (s *Store) insertPost(tx *sql.Tx, threadID, authorID int64, body string, vis Visibility) (int64, error) {
	res, err := tx.Exec(`INSERT INTO posts(thread_id,author_id,body_path,body_sha256,
		visibility,created_at) VALUES(?,?,'',x'',?,unixepoch())`,
		threadID, authorID, string(vis))
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()

	rel := filepath.Join("content", strconv.FormatInt(threadID, 10), strconv.FormatInt(id, 10)+".md")
	var handle, catSlug, title, source, ref, media, kind string
	var created int64
	if err := tx.QueryRow(`SELECT u.handle, c.slug, t.title, p.created_at,
		COALESCE(t.source,''), COALESCE(t.source_ref,''),
		COALESCE(t.media_url,''), COALESCE(t.media_kind,'')
		FROM posts p JOIN threads t ON t.id = p.thread_id
		JOIN categories c ON c.id = t.category_id
		JOIN users u ON u.id = p.author_id WHERE p.id = ?`, id).
		Scan(&handle, &catSlug, &title, &created, &source, &ref, &media, &kind); err != nil {
		return 0, err
	}

	if err := writeBody(filepath.Join(s.root, rel), entete{
		Thread: threadID, Category: catSlug, Author: handle,
		Visibility: vis, Created: created, Title: title,
		Source: source, Ref: ref, Media: media, Kind: kind,
	}, body); err != nil {
		return 0, err
	}
	sum := sha256.Sum256([]byte(normaliseCorps(body)))
	if _, err := tx.Exec(`UPDATE posts SET body_path = ?, body_sha256 = ? WHERE id = ?`,
		rel, sum[:], id); err != nil {
		return 0, err
	}
	return id, nil
}

// ── lecture ─────────────────────────────────────────────────────────────────

func (s *Store) PostsOf(threadID int64) ([]Post, error) { return s.posts(threadID, false) }

// PublicPostsOf rend ce qui peut sortir de la maison — et RIEN d'autre.
//
// La condition porte sur le fil ET sur le message. Un fil local n'expose aucun
// message, meme marque public : le contenant prime. L'inverse — un message
// public suffisant a lui seul — rendrait un fil public par inadvertance, un
// message a la fois, sans que personne ne l'ait decide.
func (s *Store) PublicPostsOf(threadID int64) ([]Post, error) { return s.posts(threadID, true) }

func (s *Store) posts(threadID int64, publicOnly bool) ([]Post, error) {
	q := `SELECT p.id,p.thread_id,p.author_id,p.body_path,p.visibility,p.created_at,
	             COALESCE(p.edited_at,0),COALESCE(p.edited_by,0)
	      FROM posts p JOIN threads t ON t.id = p.thread_id
	      WHERE p.thread_id = ? AND p.deleted_at IS NULL`
	if publicOnly {
		q += ` AND t.visibility = 'public' AND p.visibility = 'public'`
	}
	q += ` ORDER BY p.created_at, p.id`
	rows, err := s.db.Query(q, threadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Post
	for rows.Next() {
		var p Post
		var vis string
		if err := rows.Scan(&p.ID, &p.ThreadID, &p.AuthorID, &p.BodyPath, &vis,
			&p.CreatedAt, &p.EditedAt, &p.EditedBy); err != nil {
			return nil, err
		}
		p.Visibility = Visibility(vis)
		out = append(out, p)
	}
	return out, rows.Err()
}

// Body lit le corps depuis le disque et VERIFIE qu'il correspond a l'index.
//
// Servir un contenu divergent sans le dire serait pire que de refuser : le
// lecteur n'aurait aucun moyen de savoir que ce qu'il lit a ete modifie hors
// du BBS. Une restauration partielle, une edition a la main, une corruption
// silencieuse — tous se manifestent ici plutot que de passer inapercus.
func (s *Store) Body(p Post) (string, error) {
	_, body, err := readBody(filepath.Join(s.root, p.BodyPath))
	if err != nil {
		return "", err
	}
	var want []byte
	if err := s.db.QueryRow(`SELECT body_sha256 FROM posts WHERE id = ?`, p.ID).Scan(&want); err != nil {
		return "", err
	}
	got := sha256.Sum256([]byte(body))
	if len(want) == sha256.Size && string(got[:]) != string(want) {
		return "", fmt.Errorf("message %d : le fichier diverge de l'index (%s)", p.ID, p.BodyPath)
	}
	return body, nil
}

// ── entete des fichiers ─────────────────────────────────────────────────────

type entete struct {
	Thread     int64
	Category   string
	Author     string
	Visibility Visibility
	Created    int64
	Title      string
	// Source et Ref identifient un fil venu d'un module. SANS EUX SUR LE
	// DISQUE, une reconstruction les perd : les fils redeviennent « humains »
	// et le prochain import, ne les reconnaissant plus, les recree en double.
	// « Le disque fait foi » n'est vrai que si le disque porte tout.
	Source string
	Ref    string
	// Media et Kind : meme raison que Source/Ref. La reconstruction lit le
	// DISQUE ; ce qui n'y figure pas est perdu. L'origine avait deja ete
	// perdue une fois faute d'etre ecrite ici.
	Media string
	Kind  string
}

// normaliseCorps est la SEULE definition de ce qu'est un corps.
//
// L'empreinte etait calculee sur le texte recu, mais la lecture retirait le
// saut de ligne final — les passerelles, qui ajoutent un lien en fin de corps,
// produisaient donc 186 messages annonces « divergents » sans que rien n'ait
// diverge. Une alerte d'integrite qui crie au loup est pire qu'une absence
// d'alerte : on cesse de la lire, et le jour ou elle a raison, personne ne
// regarde.
//
// Ecriture, lecture et empreinte passent desormais toutes par ici.
func normaliseCorps(s string) string {
	return strings.TrimRight(strings.ReplaceAll(s, "\r\n", "\n"), "\n \t")
}

func writeBody(abs string, h entete, body string) error {
	body = normaliseCorps(body)
	if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("---\n")
	fmt.Fprintf(&b, "thread: %d\ncategory: %s\nauthor: %s\nvisibility: %s\ncreated: %d\n",
		h.Thread, h.Category, h.Author, h.Visibility, h.Created)
	// Le titre est echappe en une ligne : un titre multi-ligne casserait
	// l'entete, et avec lui la reconstruction.
	fmt.Fprintf(&b, "title: %s\n", strings.NewReplacer("\n", " ", "\r", " ").Replace(h.Title))
	if h.Source != "" {
		fmt.Fprintf(&b, "source: %s\nsource_ref: %s\n", h.Source, h.Ref)
	}
	if h.Media != "" {
		fmt.Fprintf(&b, "media: %s\nmedia_kind: %s\n", h.Media, h.Kind)
	}
	b.WriteString("---\n")
	b.WriteString(body)
	// Ecriture atomique : un fichier a moitie ecrit serait indexe comme
	// divergent au prochain demarrage, sans qu'on sache si c'est une attaque
	// ou une coupure de courant.
	tmp := abs + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp, abs); err != nil {
		return err
	}
	// MEME CAUSE QUE POUR LA BASE ET LES HASHES : l'outil d'administration
	// tourne en root, le service sous son propre compte. `bbsctl ingest` a
	// ainsi ecrit 252 corps de messages appartenant a root, que le service ne
	// pouvait plus lire — la console signalait « 252 divergents » alors que
	// rien n'avait diverge : les fichiers etaient simplement illisibles.
	//
	// Le repertoire, lui, appartient deja au bon compte ; on s'aligne sur lui.
	return adopteProprietaireDuDossier(abs)
}

func readBody(abs string) (entete, string, error) {
	f, err := os.Open(abs)
	if err != nil {
		return entete{}, "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var h entete
	var body strings.Builder
	state := 0 // 0 avant l'entete, 1 dedans, 2 dans le corps
	for sc.Scan() {
		line := sc.Text()
		switch state {
		case 0:
			if line != "---" {
				return h, "", fmt.Errorf("%s : entete absente", filepath.Base(abs))
			}
			state = 1
		case 1:
			if line == "---" {
				state = 2
				continue
			}
			k, v, _ := strings.Cut(line, ":")
			v = strings.TrimSpace(v)
			switch strings.TrimSpace(k) {
			case "thread":
				h.Thread, _ = strconv.ParseInt(v, 10, 64)
			case "category":
				h.Category = v
			case "author":
				h.Author = v
			case "visibility":
				h.Visibility = Visibility(v)
			case "created":
				h.Created, _ = strconv.ParseInt(v, 10, 64)
			case "title":
				h.Title = v
			case "source":
				h.Source = v
			case "source_ref":
				h.Ref = v
			case "media":
				h.Media = v
			case "media_kind":
				h.Kind = v
			}
		default:
			body.WriteString(line)
			body.WriteByte('\n')
		}
	}
	if err := sc.Err(); err != nil {
		return h, "", err
	}
	if state != 2 {
		return h, "", fmt.Errorf("%s : entete non terminee", filepath.Base(abs))
	}
	return h, normaliseCorps(body.String()), nil
}

// ── reconstruction ──────────────────────────────────────────────────────────

// Reindex rebatit l'index a partir de content/ seul.
//
// C'EST LA GARANTIE CENTRALE DU PROJET. Tant qu'elle tient, la base est
// jetable : perdue, corrompue, ou simplement d'une version anterieure du
// schema, elle se refait. Si elle cesse de tenir, « sauvegarde par rsync »
// devient un mensonge, et il faudrait des copies a froid, donc des arrets de
// service.
//
// Les identifiants sont conserves : ils sont portes par les NOMS de fichiers,
// pas par un compteur. Les permaliens survivent donc a une reconstruction —
// sans quoi tout lien externe vers un fil serait rompu a la premiere.
func (s *Store) Reindex() error {
	type found struct {
		h    entete
		post int64
		rel  string
		body string
	}
	var all []found
	contentDir := filepath.Join(s.root, "content")
	err := filepath.WalkDir(contentDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".md") {
			return nil // un repertoire illisible n'interrompt pas le reste
		}
		h, body, err := readBody(p)
		if err != nil {
			return fmt.Errorf("%s : %w", p, err)
		}
		id, err := strconv.ParseInt(strings.TrimSuffix(filepath.Base(p), ".md"), 10, 64)
		if err != nil {
			return fmt.Errorf("%s : nom de fichier sans identifiant", p)
		}
		rel, _ := filepath.Rel(s.root, p)
		all = append(all, found{h, id, rel, body})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(all, func(i, j int) bool { return all[i].post < all[j].post })

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// On vide l'index, pas le disque. Si quelque chose tourne mal ici, la
	// transaction annule tout et les fichiers n'ont pas ete touches.
	if _, err := tx.Exec(`DELETE FROM posts`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM threads`); err != nil {
		return err
	}

	for _, f := range all {
		cat, err := upsertID(tx, `SELECT id FROM categories WHERE slug = ?`,
			`INSERT INTO categories(slug,title) VALUES(?,?)`, f.h.Category, f.h.Category)
		if err != nil {
			return err
		}
		// Un auteur absent de la base est RECREE, desactive. Le fichier de
		// hashes vit ailleurs : ce compte ne peut pas se connecter. Mais
		// l'attribution des ecrits est preservee — l'alternative serait de
		// perdre la signature de messages qui existent bel et bien.
		au, err := upsertID(tx, `SELECT id FROM users WHERE handle = ?`,
			`INSERT INTO users(handle,display_name,role,created_at,disabled_at)
			 VALUES(?,?,'member',unixepoch(),unixepoch())`, f.h.Author, f.h.Author)
		if err != nil {
			return err
		}
		// PAS d'`INSERT OR IGNORE` ICI.
		//
		// Le slug est unique par salon. Des fils importes partagent souvent un
		// titre — 186 sur cette board — donc le meme slug. `OR IGNORE` sautait
		// alors le fil EN SILENCE, et le message qui suivait referencait un fil
		// inexistant : la reconstruction echouait sur une clef etrangere, en
		// annoncant un probleme d'integrite la ou il n'y avait qu'une collision
		// de nom.
		//
		// On demande un slug libre, comme a la creation. Et on n'ignore rien :
		// une erreur ici doit remonter.
		if deja := 0; tx.QueryRow(`SELECT count(*) FROM threads WHERE id = ?`,
			f.h.Thread).Scan(&deja) == nil && deja == 0 {
			slug, err := slugLibre(tx, cat, slugify(f.h.Title))
			if err != nil {
				return err
			}
			var src, ref any
			if f.h.Source != "" {
				src, ref = f.h.Source, f.h.Ref
			}
			var med, knd any
			if f.h.Media != "" {
				med, knd = f.h.Media, f.h.Kind
			}
			if _, err := tx.Exec(`INSERT INTO threads(id,category_id,author_id,slug,
				title,visibility,source,source_ref,media_url,media_kind,created_at,last_post_at)
				VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
				f.h.Thread, cat, au, slug, f.h.Title,
				string(visOr(f.h.Visibility)), src, ref, med, knd,
				f.h.Created, f.h.Created); err != nil {
				return fmt.Errorf("fil %d (%s) : %w", f.h.Thread, bref(f.h.Title), err)
			}
		}
		sum := sha256.Sum256([]byte(normaliseCorps(f.body)))
		if _, err := tx.Exec(`INSERT INTO posts(id,thread_id,author_id,body_path,
			body_sha256,visibility,created_at) VALUES(?,?,?,?,?,?,?)`,
			f.post, f.h.Thread, au, f.rel, sum[:], string(visOr(f.h.Visibility)),
			f.h.Created); err != nil {
			return err
		}
		if _, err := tx.Exec(
			`UPDATE threads SET last_post_at = max(last_post_at, ?) WHERE id = ?`,
			f.h.Created, f.h.Thread); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// visOr : au moindre doute, LOCAL. Un entete abime ne doit pas rendre public
// ce qui ne l'etait pas — l'erreur dans ce sens est irrattrapable.
func visOr(v Visibility) Visibility {
	if v == VisPublic {
		return VisPublic
	}
	return VisLocal
}

func upsertID(tx *sql.Tx, sel, ins string, key string, args ...any) (int64, error) {
	var id int64
	err := tx.QueryRow(sel, key).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	all := append([]any{key}, args...)
	res, err := tx.Exec(ins, all...)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// slugLibre rend un slug encore disponible dans ce salon, en suffixant.
//
// Le slug est UNIQUE par salon (contrainte du schema). Or « Question du jour »
// sera ecrit dix fois : refuser le second fil parce que son slug existe deja
// serait une regle du programme, pas du forum. On suffixe donc plutot que de
// refuser.
//
// La boucle est bornee : au-dela, on laisse la contrainte parler. Chercher
// indefiniment transformerait un salon charge en attente sans fin.
func slugLibre(tx *sql.Tx, catID int64, base string) (string, error) {
	if base == "" {
		base = "fil"
	}
	for i := 0; i < 200; i++ {
		essai := base
		if i > 0 {
			essai = base + "-" + strconv.Itoa(i+1)
		}
		var n int
		err := tx.QueryRow(`SELECT count(*) FROM threads WHERE category_id = ? AND slug = ?`,
			catID, essai).Scan(&n)
		if err != nil {
			return "", err
		}
		if n == 0 {
			return essai, nil
		}
	}
	return "", errors.New("aucun slug libre pour ce titre dans ce salon")
}

func slugify(s string) string {
	var b strings.Builder
	prev := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prev = false
		default:
			if !prev && b.Len() > 0 {
				b.WriteByte('-')
				prev = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func nowUnix() int64 { return time.Now().Unix() }

func bref(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}
