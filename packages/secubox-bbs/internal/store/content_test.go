package store

import (
	"fmt"
	"sync"
	"testing"
)

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

// TestIndexPartielRejetteDoublonOriginal pin le backstop DB : deux objets
// distincts ne peuvent JAMAIS porter chacun une provenance is_original=1
// pour la même source_url. C'est ce qui rattrape la fenêtre de course entre
// le SELECT de pré-vérification de CreerContenu et son INSERT — le check
// applicatif seul ("check-then-act") ne suffit pas.
func TestIndexPartielRejetteDoublonOriginal(t *testing.T) {
	s := ouvre(t)
	if _, err := s.db.Exec(
		`INSERT INTO content_object(id,type,title,created_at,updated_at) VALUES('co_a','video','A',1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO content_object(id,type,title,created_at,updated_at) VALUES('co_b','video','B',1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO content_provenance(content_id,source_url,source_type,is_original,noted_at)
		 VALUES('co_a','https://x','youtube',1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO content_provenance(content_id,source_url,source_type,is_original,noted_at)
		 VALUES('co_b','https://x','youtube',1,1)`); err == nil {
		t.Fatal("idx_prov_original doit refuser une seconde provenance originale pour la même source_url")
	}
}

// TestCreerContenuConcurrentNeDuplicePasEtNeLockPasCommeErreur reproduit le
// défaut réel : des appels VRAIMENT concurrents pour la même provenance
// originale. La SELECT de pré-vérification de CreerContenu peut laisser
// passer les deux (aucune n'a encore rien inséré) ; le backstop DB
// (idx_prov_original) doit alors garantir qu'un seul content_object survit
// et que l'appel perdant se RÉSOUT sur l'id gagnant — jamais une erreur
// "database is locked" brute renvoyée à l'appelant.
func TestCreerContenuConcurrentNeDuplicePasEtNeLockPasCommeErreur(t *testing.T) {
	s := ouvre(t)
	const n = 5
	prov := []Provenance{{SourceURL: "https://youtu.be/concurrent", SourceType: "youtube", Original: true}}

	var wg sync.WaitGroup
	ids := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ids[i], errs[i] = s.CreerContenu(
				ContentObject{Type: "video", Title: fmt.Sprintf("Clip %d", i)}, prov, int64(1000+i))
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("appel %d : erreur inattendue (doit se résoudre, jamais une erreur de verrou) : %v", i, err)
		}
	}
	for i := 1; i < n; i++ {
		if ids[i] != ids[0] {
			t.Fatalf("ids divergents sous course : %q (0) vs %q (%d)", ids[0], ids[i], i)
		}
	}

	var nObjets int
	must(t, s.db.QueryRow(`SELECT COUNT(*) FROM content_object`).Scan(&nObjets))
	if nObjets != 1 {
		t.Fatalf("attendu 1 seul content_object malgré %d appels concurrents, obtenu %d", n, nObjets)
	}
	var nOriginales int
	must(t, s.db.QueryRow(
		`SELECT COUNT(*) FROM content_provenance WHERE source_url=? AND is_original=1`,
		prov[0].SourceURL).Scan(&nOriginales))
	if nOriginales != 1 {
		t.Fatalf("attendu 1 seule provenance originale, obtenu %d", nOriginales)
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
