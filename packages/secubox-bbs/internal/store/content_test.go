package store

import "testing"

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreerContenuIdempotentParProvenanceOriginale(t *testing.T) {
	s := ouvre(t)
	prov := []Provenance{{SourceURL: "https://youtu.be/X", SourceType: "youtube", Original: true}}
	id1, err := s.CreerContenu(ContentObject{Type: "video", Title: "Clip"}, prov, 1000)
	if err != nil || id1 == "" {
		t.Fatalf("create 1: id=%q err=%v", id1, err)
	}
	id2, err := s.CreerContenu(ContentObject{Type: "video", Title: "Clip (revu)"}, prov, 1001)
	if err != nil {
		t.Fatal(err)
	}
	if id2 != id1 {
		t.Fatalf("re-création avec la même source originale devrait renvoyer %q, obtenu %q", id1, id2)
	}
}

func TestCreerContenuExigeUneOriginale(t *testing.T) {
	s := ouvre(t)
	_, err := s.CreerContenu(ContentObject{Type: "video", Title: "X"},
		[]Provenance{{SourceURL: "u", SourceType: "rss", Original: false}}, 1)
	if err == nil {
		t.Fatal("attendu une erreur : aucune provenance originale")
	}
}

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
