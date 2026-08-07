package store

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// Ce test lève le risque le plus cher du projet, et il le fait EN PREMIER.
//
// `modernc.org/sqlite` est SQLite retranscrit en Go — pas un binding. FTS5 y est
// annoncé, mais rien ne garantit qu'il soit compilé dans cette version ni qu'il
// se comporte comme l'original sur les accents. Or toute la recherche interne en
// dépend.
//
// S'il échoue, la bascule (mattn/go-sqlite3 en cgo, ou recherche dégradée) coûte
// dix minutes aujourd'hui, et une réécriture après trois modules.
func TestFTS5EstDisponibleEtGereLesAccents(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("ouverture: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE VIRTUAL TABLE recherche USING fts5(
		titre, corps, tokenize = "unicode61 remove_diacritics 2")`)
	if err != nil {
		t.Fatalf("FTS5 indisponible dans modernc.org/sqlite : %v", err)
	}

	if _, err := db.Exec(
		`INSERT INTO recherche(titre, corps) VALUES (?, ?)`,
		"Fermentation à 18 °C", "Le barboteur n'est pas un débitmètre",
	); err != nil {
		t.Fatalf("insertion: %v", err)
	}

	// Le point qui compte : chercher sans accent doit trouver le mot accenté.
	// Un forum francophone où « debitmetre » ne trouve pas « débitmètre » a une
	// recherche qui ne sert à rien.
	for _, q := range []string{"debitmetre", "débitmètre", "fermentation"} {
		var n int
		if err := db.QueryRow(
			`SELECT count(*) FROM recherche WHERE recherche MATCH ?`, q,
		).Scan(&n); err != nil {
			t.Fatalf("requête %q: %v", q, err)
		}
		if n != 1 {
			t.Errorf("recherche %q : %d résultat(s), attendu 1", q, n)
		}
	}
}
