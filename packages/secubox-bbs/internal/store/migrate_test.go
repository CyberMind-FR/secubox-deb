package store

import (
	"path/filepath"
	"testing"
)

func ouvre(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "bbs.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMigrateEstIdempotent(t *testing.T) {
	s := ouvre(t)
	v1, err := s.Version()
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if v1 == 0 {
		t.Fatal("aucune migration appliquée")
	}
	// Rejouer ne doit RIEN changer : une unité systemd redémarre, un paquet se
	// réinstalle — la migration s'exécutera bien plus souvent qu'une fois.
	if err := s.Migrate(); err != nil {
		t.Fatalf("seconde migration: %v", err)
	}
	v2, _ := s.Version()
	if v1 != v2 {
		t.Errorf("version %d -> %d : la migration n'est pas idempotente", v1, v2)
	}
}

func TestMigrationEchoueeNeLaissePasDeVersionPartielle(t *testing.T) {
	// Une migration a moitie appliquee est pire qu'une migration refusee : le
	// schema ne correspond plus au code, et rien ne le signale.
	//
	// La migration d'epreuve cree D'ABORD une table VALIDE, puis echoue. Sans
	// transaction, la table survit a l'echec — et c'est exactement ce qu'on
	// veut interdire. Un premier jet de ce test utilisait du SQL invalide des
	// la premiere instruction : rien n'etait ecrit dans les deux cas, et la
	// mutation « migration non transactionnelle » passait tranquillement.
	s := ouvre(t)
	before, _ := s.Version()

	const partielle = `
		CREATE TABLE epreuve_atomicite (id INTEGER PRIMARY KEY);
		CECI N'EST PAS DU SQL;`

	if err := s.applyOne(99, partielle); err == nil {
		t.Fatal("une migration invalide doit echouer")
	}

	after, _ := s.Version()
	if before != after {
		t.Errorf("version passee de %d a %d malgre l'echec", before, after)
	}

	// Le vrai controle : la table creee par la premiere instruction ne doit
	// PAS avoir survecu.
	var n int
	if err := s.db.QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='epreuve_atomicite'`,
	).Scan(&n); err != nil {
		t.Fatalf("sqlite_master: %v", err)
	}
	if n != 0 {
		t.Error("la table creee avant l'echec a survecu : la migration n'est pas atomique")
	}
}

func TestRolesEtVisibilitesSontContraintsParLeSchema(t *testing.T) {
	// Ces contraintes ne sont pas décoratives : un rôle inventé ou une
	// visibilité inconnue déciderait de qui lit quoi, et de ce qui sort de la
	// maison. La base doit refuser, pas le code applicatif seul.
	s := ouvre(t)
	if _, err := s.db.Exec(
		`INSERT INTO users(handle,display_name,role,created_at) VALUES('x','X','archonte',1)`,
	); err == nil {
		t.Error("un rôle inconnu doit être refusé par le schéma")
	}
	if _, err := s.db.Exec(
		`INSERT INTO categories(slug,title) VALUES('c','C')`); err != nil {
		t.Fatalf("catégorie: %v", err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO users(handle,display_name,role,created_at) VALUES('u','U','member',1)`); err != nil {
		t.Fatalf("membre: %v", err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO threads(category_id,author_id,slug,title,visibility,created_at,last_post_at)
		 VALUES(1,1,'t','T','secret',1,1)`,
	); err == nil {
		t.Error("une visibilité inconnue doit être refusée par le schéma")
	}
}

func TestCleEtrangereRefuseUnFilOrphelin(t *testing.T) {
	// Sans PRAGMA foreign_keys=ON, SQLite ACCEPTE les clés étrangères
	// invalides en silence — c'est désactivé par défaut, et c'est le piège
	// classique. Un fil rattaché à une catégorie inexistante deviendrait
	// invisible sans erreur.
	s := ouvre(t)
	if _, err := s.db.Exec(
		`INSERT INTO threads(category_id,author_id,slug,title,created_at,last_post_at)
		 VALUES(4242,4242,'t','T',1,1)`,
	); err == nil {
		t.Error("clé étrangère invalide acceptée : PRAGMA foreign_keys est-il activé ?")
	}
}
