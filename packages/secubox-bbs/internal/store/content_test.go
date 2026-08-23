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

func TestRepresentationIdempotenteEtResoluble(t *testing.T) {
	s := ouvre(t)
	id, _ := s.CreerContenu(ContentObject{Type: "audio", Title: "T"},
		[]Provenance{{SourceURL: "u", SourceType: "youtube", Original: true}}, 1)
	must(t, s.AjouterRepresentation(id, "radio", "secubox-radio", "248", true, "", 2))
	must(t, s.AjouterRepresentation(id, "radio", "secubox-radio", "248", true, "", 3)) // re-appel
	got, ok := s.ContenuParRef("secubox-radio", "248")
	if !ok || got != id {
		t.Fatalf("ContenuParRef = %q,%v ; attendu %q", got, ok, id)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM content_representation WHERE content_id=?`, id).Scan(&n)
	if n != 1 {
		t.Fatalf("doublon de représentation : n=%d", n)
	}
}

func TestAjouterEventAppendOnly(t *testing.T) {
	s := ouvre(t)
	id, _ := s.CreerContenu(ContentObject{Type: "audio", Title: "T"},
		[]Provenance{{SourceURL: "u2", SourceType: "youtube", Original: true}}, 1)
	must(t, s.AjouterEvent(id, "created", "collector", `{}`, 2))
	must(t, s.AjouterEvent(id, "published", "collector", `{}`, 3))
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM content_event WHERE content_id=?`, id).Scan(&n)
	if n != 2 {
		t.Fatalf("attendu 2 événements, obtenu %d", n)
	}
}

func TestLierTopic(t *testing.T) {
	s := ouvre(t)
	id, _ := s.CreerContenu(ContentObject{Type: "audio", Title: "T"},
		[]Provenance{{SourceURL: "u3", SourceType: "youtube", Original: true}}, 1)
	must(t, s.LierTopic(id, 42))
	o, err := s.ContenuParID(id)
	must(t, err)
	if o.BBSTopicID != 42 {
		t.Fatalf("bbs_topic_id = %d, attendu 42", o.BBSTopicID)
	}
}

func TestTimelineRejetteAnonyme(t *testing.T) {
	s := ouvre(t)
	id, _ := s.CreerContenu(ContentObject{Type: "audio", Title: "T"},
		[]Provenance{{SourceURL: "u4", SourceType: "youtube", Original: true}}, 1)
	if _, err := s.AjouterTimeline(id, TimelineComment{Author: "anon", AuthorID: 0, OffsetMS: 1000, Body: "hi"}); err == nil {
		t.Fatal("un message anonyme (author_id=0) ne doit JAMAIS être persisté")
	}
}

func TestTimelineMembreOrdreParOffset(t *testing.T) {
	s := ouvre(t)
	id, _ := s.CreerContenu(ContentObject{Type: "audio", Title: "T"},
		[]Provenance{{SourceURL: "u5", SourceType: "youtube", Original: true}}, 1)
	s.AjouterTimeline(id, TimelineComment{Author: "Koda", AuthorID: 7, OffsetMS: 80000, Body: "b"})
	s.AjouterTimeline(id, TimelineComment{Author: "Lyra", AuthorID: 5, OffsetMS: 64000, Body: "a"})
	got, err := s.TimelineDe(id, 0, 0)
	if err != nil || len(got) != 2 {
		t.Fatalf("len=%d err=%v", len(got), err)
	}
	if got[0].OffsetMS != 64000 || got[1].OffsetMS != 80000 {
		t.Fatalf("ordre par offset non respecté : %d puis %d", got[0].OffsetMS, got[1].OffsetMS)
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
