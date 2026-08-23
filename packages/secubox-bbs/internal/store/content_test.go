package store

import "testing"

func TestContentMigrationCreeLesTables(t *testing.T) {
	s := ouvre(t) // helper existant (migrate_test.go) : ouvre un Store neuf en tempdir (migrations jouées)
	for _, tbl := range []string{"content_object", "content_provenance",
		"content_representation", "content_event", "content_timeline"} {
		var n int
		err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&n)
		if err != nil || n != 1 {
			t.Fatalf("table %s absente (n=%d, err=%v)", tbl, n, err)
		}
	}
}
