package store

// Listes affichees : salons, fils, statistiques.
//
// Chaque requete de liste existe en DEUX versions, publique et interne. Ce
// n'est pas une commodite : la version publique alimente les pages vues depuis
// internet, et un fil local qui y apparaitrait divulguerait deja son TITRE —
// souvent l'essentiel de l'information.

import "database/sql"

type Category struct {
	ID      int64
	Slug    string
	Title   string
	Desc    string
	Threads int
	Public  bool
}

type Thread struct {
	ID         int64
	CategoryID int64
	Slug       string
	Title      string
	Author     string
	Visibility Visibility
	Source     string
	Posts      int
	LastPostAt int64
	MediaURL   string
	MediaKind  string
	Published  string // adresse du billet tire de ce fil, vide sinon
}

// Categories rend les salons. publicOnly : ceux qui sortent de la maison.
func (s *Store) Categories(publicOnly bool) ([]Category, error) {
	q := `SELECT c.id, c.slug, c.title, COALESCE(c.description,''),
	        (SELECT count(*) FROM threads t WHERE t.category_id = c.id` + visClause(publicOnly, "t") + `)
	      FROM categories c ORDER BY c.id`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Category
	for rows.Next() {
		var c Category
		if err := rows.Scan(&c.ID, &c.Slug, &c.Title, &c.Desc, &c.Threads); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Threads rend les fils d'un salon, les epingles d'abord.
func (s *Store) Threads(catID int64, publicOnly bool) ([]Thread, error) {
	q := `SELECT t.id, t.category_id, t.slug, t.title, u.handle, t.visibility,
	        COALESCE(t.source,''), t.last_post_at,
	        (SELECT count(*) FROM posts p
	          WHERE p.thread_id = t.id AND p.deleted_at IS NULL` + visClause(publicOnly, "p") + `),
	        COALESCE((SELECT b.url FROM billets b WHERE b.thread_id = t.id),''),
	        COALESCE(t.media_url,''), COALESCE(t.media_kind,'')
	      FROM threads t JOIN users u ON u.id = t.author_id
	      WHERE t.category_id = ?` + visClause(publicOnly, "t") + `
	      ORDER BY t.pinned DESC, t.last_post_at DESC, t.id DESC`
	return s.scanThreads(q, catID)
}

// Recent rend les derniers fils, tous salons confondus.
func (s *Store) Recent(limit int, publicOnly bool) ([]Thread, error) {
	q := `SELECT t.id, t.category_id, t.slug, t.title, u.handle, t.visibility,
	        COALESCE(t.source,''), t.last_post_at,
	        (SELECT count(*) FROM posts p
	          WHERE p.thread_id = t.id AND p.deleted_at IS NULL` + visClause(publicOnly, "p") + `),
	        COALESCE((SELECT b.url FROM billets b WHERE b.thread_id = t.id),''),
	        COALESCE(t.media_url,''), COALESCE(t.media_kind,'')
	      FROM threads t JOIN users u ON u.id = t.author_id
	      WHERE 1=1` + visClause(publicOnly, "t") + `
	      ORDER BY t.last_post_at DESC, t.id DESC LIMIT ?`
	return s.scanThreads(q, limit)
}

// visClause : la garde est ECRITE UNE FOIS et reutilisee partout.
//
// La recopier a chaque requete garantit qu'un jour l'une d'elles sera oubliee,
// et cet oubli-la ne se voit pas : la page s'affiche, simplement elle montre un
// fil de trop.
func visClause(publicOnly bool, alias string) string {
	if !publicOnly {
		return ""
	}
	return " AND " + alias + ".visibility = 'public'"
}

func (s *Store) scanThreads(q string, arg any) ([]Thread, error) {
	rows, err := s.db.Query(q, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Thread
	for rows.Next() {
		var t Thread
		var vis string
		if err := rows.Scan(&t.ID, &t.CategoryID, &t.Slug, &t.Title, &t.Author, &vis,
			&t.Source, &t.LastPostAt, &t.Posts, &t.Published,
			&t.MediaURL, &t.MediaKind); err != nil {
			return nil, err
		}
		t.Visibility = Visibility(vis)
		out = append(out, t)
	}
	return out, rows.Err()
}

// ThreadByID rend un fil seul.
func (s *Store) ThreadByID(id int64) (Thread, error) {
	var t Thread
	var vis string
	err := s.db.QueryRow(`SELECT t.id,t.category_id,t.slug,t.title,u.handle,t.visibility,
		COALESCE(t.source,''),t.last_post_at,0,
		COALESCE((SELECT b.url FROM billets b WHERE b.thread_id = t.id),''),
		COALESCE(t.media_url,''), COALESCE(t.media_kind,'')
		FROM threads t JOIN users u ON u.id = t.author_id WHERE t.id = ?`, id).
		Scan(&t.ID, &t.CategoryID, &t.Slug, &t.Title, &t.Author, &vis,
			&t.Source, &t.LastPostAt, &t.Posts, &t.Published,
			&t.MediaURL, &t.MediaKind)
	t.Visibility = Visibility(vis)
	if err == sql.ErrNoRows {
		return t, err
	}
	return t, err
}

// Author rend le pseudonyme d'un auteur.
func (s *Store) Author(id int64) string {
	var h string
	s.db.QueryRow(`SELECT handle FROM users WHERE id = ?`, id).Scan(&h)
	return h
}

type Stats struct{ Threads, Posts, Files, Members, Billets int }

func (s *Store) Stats() (Stats, error) {
	var st Stats
	err := s.db.QueryRow(`SELECT
		(SELECT count(*) FROM threads),
		(SELECT count(*) FROM posts WHERE deleted_at IS NULL),
		(SELECT count(*) FROM files),
		(SELECT count(*) FROM users WHERE disabled_at IS NULL),
		(SELECT count(*) FROM billets)`).
		Scan(&st.Threads, &st.Posts, &st.Files, &st.Members, &st.Billets)
	return st, err
}

// MarkPublished enregistre le lien fil -> billet.
//
// N'est appelee QU'APRES une reponse favorable de billets. L'ecrire avant
// afficherait un lien vers une page qui n'existe pas, et personne ne s'en
// apercevrait avant qu'un lecteur ne clique.
func (s *Store) MarkPublished(threadID int64, billetID, url string, pris, retenus int) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO billets
		(thread_id,billet_id,url,published_at,taken,held)
		VALUES(?,?,?,unixepoch(),?,?)`, threadID, billetID, url, pris, retenus)
	return err
}

// CreateCategory cree un salon, ou rend l'existant s'il porte deja ce slug.
func (s *Store) CreateCategory(slug, title, desc string) (int64, error) {
	var id int64
	if err := s.db.QueryRow(`SELECT id FROM categories WHERE slug = ?`, slug).
		Scan(&id); err == nil {
		return id, nil
	}
	res, err := s.db.Exec(
		`INSERT INTO categories(slug,title,description) VALUES(?,?,?)`, slug, title, desc)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// slugSource derive le slug d'un fil importe de sa REFERENCE, pas seulement de
// son titre.
//
// Trois episodes titres « Hors-serie » produiraient sinon le meme slug, et le
// schema n'en accepte qu'un par salon. Suffixer par la reference donne une
// adresse stable — elle ne change pas si l'episode est renomme chez la source.
func slugSource(titre, ref string) string {
	s := slugify(titre)
	r := slugify(ref)
	switch {
	case s == "" && r == "":
		return "import"
	case s == "":
		return r
	case r == "":
		return s
	}
	return s + "-" + r
}

// NewSourcedThread cree un fil venu d'un module. Rend false s'il existait deja.
//
// L'UNICITE EST PORTEE PAR LA BASE (index unique sur source, source_ref), pas
// par un SELECT prealable. Un SELECT puis un INSERT laisse une fenetre entre
// les deux : deux imports simultanes — la minuterie et une relance manuelle —
// verraient tous deux « absent » et inserreraient tous deux.
func (s *Store) NewSourcedThread(catID, authorID int64, title, body string,
	vis Visibility, source, ref string, date int64) (bool, error) {
	cree, _, err := s.upsertSourced(catID, authorID, title, body, vis, source, ref, date)
	return cree, err
}

// UpsertSourced cree le fil, ou met a jour son TITRE s'il a change a la source.
//
// Idempotent ne veut pas dire fige : une source qui corrige un titre doit etre
// suivie, sans quoi il faudrait tout supprimer pour reimporter — et perdre les
// reponses des membres.
//
// SEUL LE TITRE suit. Le corps du premier message n'est jamais reecrit : un
// membre a pu y repondre en le citant, et le remplacer sous ses pieds rendrait
// la conversation incomprehensible.
func (s *Store) UpsertSourced(catID, authorID int64, title, body string,
	vis Visibility, source, ref string, date int64) (cree, misAJour bool, err error) {
	return s.upsertSourced(catID, authorID, title, body, vis, source, ref, date)
}

// UpsertSourcedMedia : comme UpsertSourced, en attachant un media jouable.
func (s *Store) UpsertSourcedMedia(catID, authorID int64, title, body string,
	vis Visibility, source, ref string, date int64, media, kind string) (bool, bool, error) {
	cree, maj, err := s.upsertSourced(catID, authorID, title, body, vis, source, ref, date)
	if err != nil {
		return cree, maj, err
	}
	if media != "" {
		_, err = s.db.Exec(`UPDATE threads SET media_url = ?, media_kind = ?
			WHERE source = ? AND source_ref = ?`, media, kind, source, ref)
	}
	return cree, maj, err
}

func (s *Store) upsertSourced(catID, authorID int64, title, body string,
	vis Visibility, source, ref string, date int64) (bool, bool, error) {

	if date <= 0 {
		date = nowUnix()
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, false, err
	}
	defer tx.Rollback()

	// `ON CONFLICT (source, source_ref) DO NOTHING` et NON `INSERT OR IGNORE`.
	//
	// `OR IGNORE` avale TOUTES les contraintes, pas seulement celle qu'on vise :
	// une cle etrangere invalide, un CHECK viole, un index oublie deviennent des
	// « rien a faire » silencieux. Le premier jet utilisait `OR IGNORE` et
	// n'importait qu'un fil sur trois sans lever la moindre erreur.
	//
	// Cette forme n'ignore QUE le doublon attendu ; tout le reste remonte.
	//
	// La clause WHERE est REPETEE dans la cible : l'index est PARTIEL, et
	// SQLite refuse un ON CONFLICT qui ne reproduit pas exactement sa
	// condition — « does not match any UNIQUE constraint ».
	res, err := tx.Exec(`INSERT INTO threads(category_id,author_id,slug,title,
		visibility,source,source_ref,created_at,last_post_at)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(source, source_ref) WHERE source IS NOT NULL AND source_ref IS NOT NULL
		DO UPDATE SET title = excluded.title, slug = excluded.slug
		  WHERE threads.title <> excluded.title`,
		catID, authorID, slugSource(title, ref), title, string(vis), source, ref, date, date)
	if err != nil {
		return false, false, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, false, nil // deja connu, titre inchange : le cas normal
	}
	th, _ := res.LastInsertId()
	// Un UPDATE compte aussi comme « ligne affectee ». On distingue les deux en
	// regardant si le fil vient d'etre cree : un fil mis a jour a deja son
	// premier message, et le REECRIRE serait une faute — un membre a pu
	// repondre en citant ce qu'il a lu.
	var messages int
	if err := tx.QueryRow(`SELECT count(*) FROM posts WHERE thread_id =
		(SELECT id FROM threads WHERE source = ? AND source_ref = ?)`,
		source, ref).Scan(&messages); err == nil && messages > 0 {
		return false, true, tx.Commit()
	}
	if _, err := s.insertPost(tx, th, authorID, body, vis); err != nil {
		return false, false, err
	}
	return true, false, tx.Commit()
}

type IngestRun struct {
	Source        string
	RanAt         int64
	Seen, Created int
	Skipped       int
	Error         string
}

func (s *Store) LogIngest(source string, seen, created, skipped int, erreur string) error {
	_, err := s.db.Exec(`INSERT INTO ingest_runs(source,ran_at,seen,created,skipped,error)
		VALUES(?,unixepoch(),?,?,?,?)`, source, seen, created, skipped, erreur)
	return err
}

func (s *Store) IngestRuns(limit int) ([]IngestRun, error) {
	rows, err := s.db.Query(`SELECT source,ran_at,seen,created,skipped,COALESCE(error,'')
		FROM ingest_runs ORDER BY ran_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IngestRun
	for rows.Next() {
		var r IngestRun
		if err := rows.Scan(&r.Source, &r.RanAt, &r.Seen, &r.Created, &r.Skipped, &r.Error); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
