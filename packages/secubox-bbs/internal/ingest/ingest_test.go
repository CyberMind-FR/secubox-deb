package ingest

import (
	"path/filepath"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

func banc(t *testing.T) (*store.Store, int64, int64) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "bbs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	cat, err := s.CreateCategory("emissions", "Emissions", "")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := s.CreateUser("module", "Module", store.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	return s, cat, uid
}

func items(n int) []Item {
	var out []Item
	for i := 0; i < n; i++ {
		out = append(out, Item{Ref: string(rune('a' + i)), Titre: "Episode", Corps: "corps"})
	}
	return out
}

func TestUnDeuxiemeImportNeCreeAucunDoublon(t *testing.T) {
	// LA propriete de ce paquet. Un import tourne en boucle : minuterie,
	// redemarrage, relance manuelle apres un doute. S'il duplique, il duplique
	// a chaque fois — et sur cette board un import de podcast avait deja
	// produit 34 flux en double et 2,3 Go de media inutiles.
	s, cat, uid := banc(t)
	src := Source{Nom: "podcaster", Categorie: cat, Auteur: uid, Visibilite: store.VisLocal}

	r1, err := Importer(s, src, items(3))
	if err != nil {
		t.Fatal(err)
	}
	if r1.Crees != 3 {
		t.Fatalf("premier import : %d crees, attendu 3", r1.Crees)
	}

	r2, err := Importer(s, src, items(3))
	if err != nil {
		t.Fatal(err)
	}
	if r2.Crees != 0 {
		t.Errorf("second import : %d fils crees — doublons", r2.Crees)
	}
	if r2.Ignores != 3 {
		t.Errorf("second import : %d ignores, attendu 3", r2.Ignores)
	}

	th, _ := s.Recent(100, false)
	if len(th) != 3 {
		t.Errorf("%d fils au total apres deux imports, attendu 3", len(th))
	}
}

func TestUnTitreIdentiqueMaisUneReferenceDifferenteDonneDeuxFils(t *testing.T) {
	// L'identite est la REFERENCE, jamais le titre. Deux episodes peuvent
	// s'appeler « Hors-serie » sans etre le meme.
	s, cat, uid := banc(t)
	src := Source{Nom: "podcaster", Categorie: cat, Auteur: uid}
	Importer(s, src, []Item{{Ref: "ep-1", Titre: "Hors-serie", Corps: "a"}})
	Importer(s, src, []Item{{Ref: "ep-2", Titre: "Hors-serie", Corps: "b"}})
	th, _ := s.Recent(100, false)
	if len(th) != 2 {
		t.Errorf("%d fils, attendu 2 — l'identite s'appuie sur le titre", len(th))
	}
}

func TestDeuxSourcesPeuventPartagerUneReference(t *testing.T) {
	// « ep-1 » chez le podcaster et « ep-1 » chez PeerTube ne sont pas le meme
	// objet : l'identite est le COUPLE (source, reference).
	s, cat, uid := banc(t)
	Importer(s, Source{Nom: "podcaster", Categorie: cat, Auteur: uid},
		[]Item{{Ref: "ep-1", Titre: "A", Corps: "a"}})
	Importer(s, Source{Nom: "peertube", Categorie: cat, Auteur: uid},
		[]Item{{Ref: "ep-1", Titre: "B", Corps: "b"}})
	th, _ := s.Recent(100, false)
	if len(th) != 2 {
		t.Errorf("%d fils, attendu 2", len(th))
	}
}

func TestLaVisibiliteImporteeParDefautEstLocale(t *testing.T) {
	// Une passerelle publie sans relecture humaine. Si elle se trompe vers
	// « public », elle met sur internet une liste de titres que personne n'a
	// decide de publier — et l'erreur ne se rattrape pas.
	s, cat, uid := banc(t)
	Importer(s, Source{Nom: "peertube", Categorie: cat, Auteur: uid},
		[]Item{{Ref: "v1", Titre: "Video", Corps: "c"}})
	th, _ := s.Recent(100, false)
	if th[0].Visibility != store.VisLocal {
		t.Errorf("visibilite par defaut : %q, attendu local", th[0].Visibility)
	}
}

func TestUneVisibilitePubliqueDoitEtreDemandeeExplicitement(t *testing.T) {
	s, cat, uid := banc(t)
	Importer(s, Source{Nom: "billets", Categorie: cat, Auteur: uid,
		Visibilite: store.VisPublic}, []Item{{Ref: "b1", Titre: "Billet", Corps: "c"}})
	th, _ := s.Recent(100, false)
	if th[0].Visibility != store.VisPublic {
		t.Errorf("visibilite : %q, attendu public", th[0].Visibility)
	}
}

func TestUnItemSansReferenceEstIgnore(t *testing.T) {
	// Sans reference, aucune identite : l'item serait re-cree a chaque import.
	// Mieux vaut le laisser de cote et le signaler.
	s, cat, uid := banc(t)
	r, err := Importer(s, Source{Nom: "peertube", Categorie: cat, Auteur: uid},
		[]Item{{Ref: "", Titre: "Sans reference", Corps: "c"}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Crees != 0 {
		t.Error("un item sans reference a ete importe")
	}
	if r.Ignores != 1 {
		t.Errorf("%d ignores, attendu 1", r.Ignores)
	}
}

func TestUnItemDefectueuxNInterromptPasLesAutres(t *testing.T) {
	// Un import qui s'arrete au premier defaut laisse la moitie du catalogue
	// dehors, et il faut deviner laquelle.
	s, cat, uid := banc(t)
	r, _ := Importer(s, Source{Nom: "peertube", Categorie: cat, Auteur: uid}, []Item{
		{Ref: "v1", Titre: "Bonne", Corps: "a"},
		{Ref: "", Titre: "Cassee", Corps: "b"},
		{Ref: "v3", Titre: "Bonne aussi", Corps: "c"},
	})
	if r.Crees != 2 {
		t.Errorf("%d crees, attendu 2 — un defaut a interrompu l'import", r.Crees)
	}
}

func TestLeJournalDImportEstEcrit(t *testing.T) {
	s, cat, uid := banc(t)
	Importer(s, Source{Nom: "podcaster", Categorie: cat, Auteur: uid}, items(2))
	runs, err := s.IngestRuns(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].Created != 2 {
		t.Errorf("journal : %+v", runs)
	}
}

func TestDesTitresIdentiquesSontDesambiguisParLAdresse(t *testing.T) {
	// Cas REEL : 30 billets auto-publies portent tous le meme titre
	// (« Retrouvez l'integralite du podcast… »), seul leur lien differe. Une
	// liste de trente lignes identiques est inutilisable, meme si chaque fil
	// est bien distinct en base.
	//
	// On ne touche qu'aux titres EN DOUBLE : un titre unique est celui que
	// l'auteur a voulu, et le remplacer serait presomptueux.
	items := []Item{
		{Ref: "1", Titre: "Retrouvez le podcast", Lien: "https://b/b/les-ovnis-existent-ils"},
		{Ref: "2", Titre: "Retrouvez le podcast", Lien: "https://b/b/le-rechauffement"},
		{Ref: "3", Titre: "Un titre bien a lui", Lien: "https://b/b/autre-chose"},
	}
	out := Desambiguiser(items)
	if out[0].Titre == out[1].Titre {
		t.Errorf("titres toujours identiques : %q", out[0].Titre)
	}
	if !contient(out[0].Titre, "ovnis") {
		t.Errorf("le titre ne reprend pas l'adresse : %q", out[0].Titre)
	}
	if out[2].Titre != "Un titre bien a lui" {
		t.Errorf("un titre UNIQUE a ete reecrit : %q", out[2].Titre)
	}
}

func TestSansAdresseExploitableLeTitreEstConserve(t *testing.T) {
	// Ne pas inventer : si l'adresse n'apporte rien, on garde ce qu'on a
	// plutot que de produire un titre vide ou absurde.
	items := []Item{
		{Ref: "1", Titre: "Meme titre", Lien: ""},
		{Ref: "2", Titre: "Meme titre", Lien: "https://b/"},
	}
	out := Desambiguiser(items)
	for i, it := range out {
		if it.Titre == "" {
			t.Errorf("item %d : titre vide", i)
		}
	}
}

func contient(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}

func TestUnTitreCorrigeALaSourceEstRepercute(t *testing.T) {
	// Idempotent ne veut pas dire figé. Si la source corrige un titre — ou si
	// notre desambiguisation s'ameliore — le fil doit suivre, sans quoi il
	// faudrait tout supprimer pour reimporter, en perdant les reponses des
	// membres.
	//
	// SEUL LE TITRE suit. Le corps n'est PAS reecrit : un membre a pu repondre
	// en citant ce qu'il a lu, et le remplacer sous ses pieds rendrait la
	// conversation incomprehensible.
	s, cat, uid := banc(t)
	src := Source{Nom: "billets", Categorie: cat, Auteur: uid}

	Importer(s, src, []Item{{Ref: "b1", Titre: "Titre repete", Corps: "corps d origine"}})
	r, err := Importer(s, src, []Item{{Ref: "b1", Titre: "Les ovnis existent ils", Corps: "corps modifie"}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Crees != 0 {
		t.Errorf("%d fils crees — le doublon n'a pas ete reconnu", r.Crees)
	}
	if r.MisAJour != 1 {
		t.Errorf("%d titres mis a jour, attendu 1", r.MisAJour)
	}

	th, _ := s.Recent(10, false)
	if th[0].Title != "Les ovnis existent ils" {
		t.Errorf("titre non repercute : %q", th[0].Title)
	}
	posts, _ := s.PostsOf(th[0].ID)
	corps, _ := s.Body(posts[0])
	if !contient(corps, "corps d origine") {
		t.Errorf("le corps a ete reecrit sous les pieds des lecteurs : %q", corps)
	}
}

func TestLaDesambiguisationPrefereLeTexteALAdresse(t *testing.T) {
	// L'adresse est ASCII : billets a deja retire les accents en fabriquant son
	// slug, et « Les ovnis phénomènes » y devient « les-ovnis-ph-nom-nes ».
	// Le CORPS, lui, a garde son texte.
	//
	// On saute le paragraphe d'entete commun a tous les items — c'est
	// justement lui qui rend les titres identiques — et on prend la premiere
	// phrase qui distingue vraiment.
	items := []Item{
		{Ref: "1", Titre: "Retrouvez le podcast",
			Corps: "Retrouvez le podcast sur RTBF\n\nSoucoupes et sphères dans le ciel, l'enquête.",
			Lien:  "https://b/b/les-ovnis-ph-nom-nes"},
		{Ref: "2", Titre: "Retrouvez le podcast",
			Corps: "Retrouvez le podcast sur RTBF\n\nLe réchauffement climatique en question.",
			Lien:  "https://b/b/le-r-chauffement"},
	}
	out := Desambiguiser(items)
	if !contient(out[0].Titre, "Soucoupes") {
		t.Errorf("titre 0 : %q — le texte du corps n'a pas ete utilise", out[0].Titre)
	}
	if !contient(out[1].Titre, "réchauffement") {
		t.Errorf("titre 1 : %q — les accents sont perdus", out[1].Titre)
	}
	if out[0].Titre == out[1].Titre {
		t.Error("titres toujours identiques")
	}
}

func TestSansCorpsDistinctifOnRetombeSurLAdresse(t *testing.T) {
	items := []Item{
		{Ref: "1", Titre: "Meme", Corps: "texte commun", Lien: "https://b/b/premier-sujet"},
		{Ref: "2", Titre: "Meme", Corps: "texte commun", Lien: "https://b/b/second-sujet"},
	}
	out := Desambiguiser(items)
	if out[0].Titre == out[1].Titre {
		t.Errorf("titres identiques : %q", out[0].Titre)
	}
	if !contient(out[0].Titre, "remier") {
		t.Errorf("repli sur l'adresse non applique : %q", out[0].Titre)
	}
}
