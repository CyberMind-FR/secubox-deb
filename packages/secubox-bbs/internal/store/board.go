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
	        COALESCE((SELECT b.url FROM billets b WHERE b.thread_id = t.id),'')
	      FROM threads t JOIN users u ON u.id = t.author_id
	      WHERE t.category_id = ?` + visClause(publicOnly, "t") + `
	      ORDER BY t.pinned DESC, t.last_post_at DESC`
	return s.scanThreads(q, catID)
}

// Recent rend les derniers fils, tous salons confondus.
func (s *Store) Recent(limit int, publicOnly bool) ([]Thread, error) {
	q := `SELECT t.id, t.category_id, t.slug, t.title, u.handle, t.visibility,
	        COALESCE(t.source,''), t.last_post_at,
	        (SELECT count(*) FROM posts p
	          WHERE p.thread_id = t.id AND p.deleted_at IS NULL` + visClause(publicOnly, "p") + `),
	        COALESCE((SELECT b.url FROM billets b WHERE b.thread_id = t.id),'')
	      FROM threads t JOIN users u ON u.id = t.author_id
	      WHERE 1=1` + visClause(publicOnly, "t") + `
	      ORDER BY t.last_post_at DESC LIMIT ?`
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
			&t.Source, &t.LastPostAt, &t.Posts, &t.Published); err != nil {
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
		COALESCE((SELECT b.url FROM billets b WHERE b.thread_id = t.id),'')
		FROM threads t JOIN users u ON u.id = t.author_id WHERE t.id = ?`, id).
		Scan(&t.ID, &t.CategoryID, &t.Slug, &t.Title, &t.Author, &vis,
			&t.Source, &t.LastPostAt, &t.Posts, &t.Published)
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
