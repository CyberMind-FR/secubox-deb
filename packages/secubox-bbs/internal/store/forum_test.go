package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func salon(t *testing.T, s *Store) (int64, int64) {
	t.Helper()
	if _, err := s.db.Exec(
		`INSERT INTO categories(slug,title) VALUES('atelier','Atelier')`); err != nil {
		t.Fatal(err)
	}
	uid, err := s.CreateUser("gk2", "Gandalf", RoleSysop)
	if err != nil {
		t.Fatal(err)
	}
	return 1, uid
}

func TestLeCorpsVaSurLeDisquePasEnBase(t *testing.T) {
	// Toute la promesse « un repertoire copiable » repose la-dessus. Si le
	// texte vit en base, perdre la base perd les messages — et la sauvegarde
	// par rsync ne veut plus rien dire.
	s := ouvre(t)
	cat, uid := salon(t, s)
	th, err := s.NewThread(cat, uid, "Fermentation a 18 degres", "Le barboteur ne bouge pas.", VisPublic)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(dumpAll(t, s), "barboteur") {
		t.Error("le corps du message est present dans l'index")
	}

	posts, err := s.PostsOf(th)
	if err != nil || len(posts) != 1 {
		t.Fatalf("PostsOf: %v (%d)", err, len(posts))
	}
	body, err := s.Body(posts[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "barboteur") {
		t.Errorf("corps illisible depuis le disque : %q", body)
	}
}

func TestUneDivergenceDisqueIndexEstDetectee(t *testing.T) {
	// L'empreinte n'est pas decorative : si un fichier est modifie hors du
	// BBS — edition manuelle, restauration partielle, corruption — il faut le
	// SAVOIR plutot que servir un contenu qui ne correspond plus a l'index.
	s := ouvre(t)
	cat, uid := salon(t, s)
	th, _ := s.NewThread(cat, uid, "Titre", "corps d'origine", VisLocal)
	posts, _ := s.PostsOf(th)

	p := filepath.Join(s.root, posts[0].BodyPath)
	if err := os.WriteFile(p, []byte("corps remplace a la main"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Body(posts[0]); err == nil {
		t.Error("un corps divergent est servi sans avertissement")
	}
}

func TestUnFilPublicPeutContenirUneReponseLocale(t *testing.T) {
	// Le cas difficile de tout le systeme, et celui qui decide de ce qui sort
	// de la maison.
	s := ouvre(t)
	cat, uid := salon(t, s)
	th, _ := s.NewThread(cat, uid, "Fil public", "premier message", VisPublic)
	if _, err := s.Reply(th, uid, "reponse gardee locale", VisLocal); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reply(th, uid, "reponse publique", VisPublic); err != nil {
		t.Fatal(err)
	}

	pub, err := s.PublicPostsOf(th)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 2 {
		t.Fatalf("%d messages publics, attendu 2", len(pub))
	}
	for _, p := range pub {
		if p.Visibility != VisPublic {
			t.Errorf("un message local est sorti : %d", p.ID)
		}
	}
}

func TestUnFilLocalNExposeAucunMessageMemePublic(t *testing.T) {
	// Un message marque public dans un fil local ne doit PAS fuir : le fil est
	// le contenant, sa discretion prime. L'inverse serait une fuite par
	// inadvertance — on rend public un fil sans s'en rendre compte, message
	// par message.
	s := ouvre(t)
	cat, uid := salon(t, s)
	th, _ := s.NewThread(cat, uid, "Fil local", "premier", VisLocal)
	s.Reply(th, uid, "marque public par erreur", VisPublic)

	pub, err := s.PublicPostsOf(th)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 0 {
		t.Errorf("%d message(s) exposes depuis un fil local", len(pub))
	}
}

func TestLIndexSeReconstruitDepuisLeDisque(t *testing.T) {
	// LA garantie du projet. Si ce test tombe, « sauvegarde par simple rsync »
	// devient un mensonge : on aurait besoin de la base, donc d'une copie a
	// froid, donc d'un arret du service.
	s := ouvre(t)
	cat, uid := salon(t, s)
	th, _ := s.NewThread(cat, uid, "Un titre qui compte", "un corps qui compte", VisPublic)
	s.Reply(th, uid, "une reponse locale", VisLocal)

	before, _ := s.PostsOf(th)
	if len(before) != 2 {
		t.Fatalf("%d messages avant", len(before))
	}

	if err := s.Reindex(); err != nil {
		t.Fatalf("Reindex: %v", err)
	}

	after, err := s.PostsOf(th)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("%d messages apres reconstruction, attendu %d", len(after), len(before))
	}
	for i := range after {
		if after[i].Visibility != before[i].Visibility {
			t.Errorf("visibilite perdue a la reconstruction : %v -> %v",
				before[i].Visibility, after[i].Visibility)
		}
	}
	body, err := s.Body(after[0])
	if err != nil || !strings.Contains(body, "un corps qui compte") {
		t.Errorf("corps perdu a la reconstruction : %v %q", err, body)
	}
}

func TestLeCheminDuCorpsResteDansLArborescence(t *testing.T) {
	// Les chemins sont derives d'identifiants, jamais de texte fourni. Ce test
	// fige la propriete : aucun corps ne doit pouvoir etre ecrit hors de
	// content/.
	s := ouvre(t)
	cat, uid := salon(t, s)
	th, _ := s.NewThread(cat, uid, "../../etc/passwd", "essai de traversee", VisLocal)
	posts, _ := s.PostsOf(th)
	if strings.Contains(posts[0].BodyPath, "..") {
		t.Errorf("chemin echappant a l'arborescence : %s", posts[0].BodyPath)
	}
	abs := filepath.Join(s.root, posts[0].BodyPath)
	if !strings.HasPrefix(filepath.Clean(abs), filepath.Clean(s.root)) {
		t.Errorf("chemin hors racine : %s", abs)
	}
}

func TestUneEnteteAbimeeRetombeSurLocal(t *testing.T) {
	// Le seul defaut acceptable est le silence. Une entete tronquee, une
	// valeur inconnue, un fichier restaure a moitie : dans tous ces cas le
	// message doit revenir LOCAL.
	//
	// Se tromper vers « local » cache un message a des lecteurs legitimes —
	// desagreable, et rattrapable en une commande. Se tromper vers « public »
	// publie sur internet quelque chose que personne n'a decide de publier, et
	// ne se rattrape plus : c'est lu, indexe, archive.
	//
	// Ce test manquait au premier jet ; la mutation « au doute, PUBLIC »
	// passait sans rien casser.
	s := ouvre(t)
	cat, uid := salon(t, s)
	th, _ := s.NewThread(cat, uid, "Un fil", "corps", VisPublic)
	posts, _ := s.PostsOf(th)

	raw, err := os.ReadFile(filepath.Join(s.root, posts[0].BodyPath))
	if err != nil {
		t.Fatal(err)
	}
	abime := strings.Replace(string(raw), "visibility: public", "visibility: pubIic", 1)
	if abime == string(raw) {
		t.Fatal("l'entete ne portait pas la visibilite attendue")
	}
	if err := os.WriteFile(filepath.Join(s.root, posts[0].BodyPath), []byte(abime), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := s.Reindex(); err != nil {
		t.Fatal(err)
	}
	after, _ := s.PostsOf(th)
	if len(after) != 1 {
		t.Fatalf("%d messages", len(after))
	}
	if after[0].Visibility != VisLocal {
		t.Errorf("entete abimee -> %q, attendu local", after[0].Visibility)
	}
	pub, _ := s.PublicPostsOf(th)
	if len(pub) != 0 {
		t.Errorf("%d message(s) exposes depuis une entete illisible", len(pub))
	}
}

func TestUnCorpsTerminantParUneLigneVideNeDivergePas(t *testing.T) {
	s := ouvre(t)
	cat, uid := salon(t, s)
	// Les passerelles ajoutent un lien en fin de corps, donc un saut de ligne
	// final. La lecture le retirait alors que l'empreinte avait ete calculee
	// AVEC : 186 messages importes etaient annonces « divergents » sans que
	// rien n'ait diverge. Une alerte d'integrite qui crie au loup est pire
	// qu'une absence d'alerte — on cesse de la lire.
	th, err := s.NewThread(cat, uid, "Fil", "un corps\n\n[Voir chez billets](https://b/x)\n", VisPublic)
	if err != nil {
		t.Fatal(err)
	}
	posts, _ := s.PostsOf(th)
	if _, err := s.Body(posts[0]); err != nil {
		t.Errorf("corps declare divergent alors qu'il ne l'est pas : %v", err)
	}
	in, _ := s.Integrity()
	if in.Diverging != 0 {
		t.Errorf("%d divergents", in.Diverging)
	}
}

func TestLaReconstructionSurvitAuxTitresEnDouble(t *testing.T) {
	// LA GARANTIE CENTRALE DU PROJET tombait sur la vraie base : 186 fils
	// importes partageant un titre entraient en collision de slug, le fil etait
	// SILENCIEUSEMENT ignore par un `INSERT OR IGNORE`, puis son message
	// referencait un fil inexistant — « FOREIGN KEY constraint failed ».
	//
	// Le test d'origine reconstruisait deux fils aux titres distincts : il ne
	// pouvait pas voir le probleme. Troisieme fois qu'`INSERT OR IGNORE` cache
	// un echec dans ce paquet.
	s := ouvre(t)
	cat, uid := salon(t, s)
	for i, ref := range []string{"a", "b", "c"} {
		if _, _, err := s.UpsertSourced(cat, uid, "Retrouvez le podcast",
			"corps "+ref, VisPublic, "billets", ref, int64(1700000000+i)); err != nil {
			t.Fatal(err)
		}
	}
	avant, _ := s.Recent(50, false)
	if len(avant) != 3 {
		t.Fatalf("%d fils avant", len(avant))
	}

	if err := s.Reindex(); err != nil {
		t.Fatalf("reconstruction impossible : %v", err)
	}
	apres, _ := s.Recent(50, false)
	if len(apres) != 3 {
		t.Fatalf("%d fils apres reconstruction, attendu 3", len(apres))
	}
	in, _ := s.Integrity()
	if in.Diverging != 0 || in.Missing != 0 {
		t.Errorf("apres reconstruction : %d divergents, %d absents", in.Diverging, in.Missing)
	}
}

func TestLaReconstructionPreserveLOrigineDesFilsImportes(t *testing.T) {
	// « LE DISQUE FAIT FOI » n'est vrai que si le disque porte TOUT. L'entete
	// ne contenait ni `source` ni `source_ref` : apres une reconstruction, 253
	// fils importes redevenaient des fils « humains » — et le prochain import,
	// ne les reconnaissant plus, en aurait recree 252 en double.
	//
	// C'est precisement le scenario que l'index unique devait empecher, rendu
	// possible par une reconstruction qui perdait la clef.
	s := ouvre(t)
	cat, uid := salon(t, s)
	if _, _, err := s.UpsertSourced(cat, uid, "Episode 42", "corps", VisLocal,
		"podcaster", "guid-42", 1700000000); err != nil {
		t.Fatal(err)
	}
	if err := s.Reindex(); err != nil {
		t.Fatal(err)
	}
	th, _ := s.Recent(10, false)
	if len(th) != 1 {
		t.Fatalf("%d fils", len(th))
	}
	if th[0].Source != "podcaster" {
		t.Errorf("source perdue a la reconstruction : %q", th[0].Source)
	}
	// La preuve qui compte : un import ulterieur ne doit PAS creer de doublon.
	cree, _, err := s.UpsertSourced(cat, uid, "Episode 42", "corps", VisLocal,
		"podcaster", "guid-42", 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	if cree {
		t.Error("l'import a recree le fil : la reference n'a pas survecu")
	}
}
