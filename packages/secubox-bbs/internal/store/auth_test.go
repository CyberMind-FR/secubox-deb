package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func authDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "secrets")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestLeHashNeVaJamaisEnBase(t *testing.T) {
	// Toute la raison d'etre du fichier separe. Si un hash atterrit dans
	// l'index, un `rsync` du repertoire de contenu vers un support externe
	// emporte les identifiants — et l'index est cense etre jetable.
	s, dir := ouvre(t), authDir(t)
	a, err := OpenAuth(filepath.Join(dir, "users.auth"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.CreateUser("gk2", "Gandalf", RoleSysop)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SetPassword(id, "un mot de passe qui tient"); err != nil {
		t.Fatal(err)
	}

	dump := dumpAll(t, s)
	if strings.Contains(dump, "argon2") || strings.Contains(dump, "$") {
		t.Errorf("un hash semble present dans l'index :\n%s", dump)
	}
}

func TestLeFichierAuthEstIllisibleParLesAutres(t *testing.T) {
	// 0600 : un fichier de hashes lisible par le groupe ou par tous annule
	// l'interet de l'avoir sorti de la base.
	dir := authDir(t)
	p := filepath.Join(dir, "users.auth")
	a, err := OpenAuth(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SetPassword(1, "secret"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("permissions %o, attendu 600", perm)
	}
}

func TestMotDePasseVerifieEtRefuse(t *testing.T) {
	a, _ := OpenAuth(filepath.Join(authDir(t), "users.auth"))
	if err := a.SetPassword(7, "le bon"); err != nil {
		t.Fatal(err)
	}
	if !a.Verify(7, "le bon") {
		t.Error("le bon mot de passe est refuse")
	}
	if a.Verify(7, "le mauvais") {
		t.Error("un mauvais mot de passe est accepte")
	}
	if a.Verify(8, "le bon") {
		t.Error("un compte inconnu est accepte")
	}
}

func TestDeuxHashesDuMemeMotDePasseDifferent(t *testing.T) {
	// Sans sel par compte, deux membres avec le meme mot de passe ont le meme
	// hash : la fuite d'un fichier revele instantanement qui partage quoi.
	a, _ := OpenAuth(filepath.Join(authDir(t), "users.auth"))
	a.SetPassword(1, "identique")
	a.SetPassword(2, "identique")
	if a.raw(1) == a.raw(2) {
		t.Error("meme hash pour deux comptes : le sel n'est pas par compte")
	}
}

func TestSessionNeStockeQueLEmpreinteDuJeton(t *testing.T) {
	// Le jeton en clair vit dans le cookie du membre, jamais chez nous. Une
	// base lue par un tiers ne doit pas lui permettre de se faire passer pour
	// quelqu'un.
	s := ouvre(t)
	id, _ := s.CreateUser("nono", "Nono", RoleMember)
	token, err := s.NewSession(id, "10.0.0.2", "curl")
	if err != nil {
		t.Fatal(err)
	}
	if len(token) < 32 {
		t.Errorf("jeton trop court (%d caracteres)", len(token))
	}
	if strings.Contains(dumpAll(t, s), token) {
		t.Error("le jeton en clair est present dans la base")
	}
	got, err := s.UserBySession(token)
	if err != nil || got != id {
		t.Errorf("session non retrouvee : %v %d", err, got)
	}
}

func TestSessionExpireeEstRefusee(t *testing.T) {
	s := ouvre(t)
	id, _ := s.CreateUser("klm", "Klm", RoleMember)
	token, _ := s.NewSession(id, "", "")
	if _, err := s.db.Exec(
		`UPDATE sessions SET expires_at = unixepoch() - 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserBySession(token); err == nil {
		t.Error("une session expiree est acceptee")
	}
}

func TestCompteDesactiveNeSeConnectePlus(t *testing.T) {
	// Desactiver, jamais supprimer : les ecrits gardent leur auteur. Encore
	// faut-il que la desactivation coupe reellement l'acces.
	s := ouvre(t)
	id, _ := s.CreateUser("spam01", "Spam", RoleMember)
	token, _ := s.NewSession(id, "", "")
	if err := s.DisableUser(id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserBySession(token); err == nil {
		t.Error("un compte desactive garde sa session ouverte")
	}
}

func TestInvitationEstAUsageUnique(t *testing.T) {
	// L'inscription est sur invitation. Une invitation rejouable serait une
	// inscription ouverte qui s'ignore.
	s := ouvre(t)
	sysop, _ := s.CreateUser("gk2", "Gandalf", RoleSysop)
	code, err := s.NewInvite(sysop)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemInvite(code, "brassin", "Brassin"); err != nil {
		t.Fatalf("premiere utilisation refusee : %v", err)
	}
	if _, err := s.RedeemInvite(code, "autre", "Autre"); err == nil {
		t.Error("invitation rejouable")
	}
}

func TestInvitationInconnueEstRefusee(t *testing.T) {
	s := ouvre(t)
	if _, err := s.RedeemInvite("code-invente", "x", "X"); err == nil {
		t.Error("une invitation inconnue est acceptee")
	}
}

func TestHandleEstUniqueSansEgardALaCasse(t *testing.T) {
	// « Gandalf » et « gandalf » qui coexistent, c'est une usurpation offerte.
	s := ouvre(t)
	if _, err := s.CreateUser("Gandalf", "G", RoleMember); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser("gandalf", "G2", RoleMember); err == nil {
		t.Error("deux comptes ne differant que par la casse ont ete acceptes")
	}
}

func dumpAll(t *testing.T, s *Store) string {
	t.Helper()
	var b strings.Builder
	rows, err := s.db.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		tables = append(tables, n)
	}
	rows.Close()
	for _, tb := range tables {
		r, err := s.db.Query(`SELECT * FROM "` + tb + `"`)
		if err != nil {
			continue
		}
		cols, _ := r.Columns()
		for r.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			r.Scan(ptrs...)
			for _, v := range vals {
				switch x := v.(type) {
				case string:
					b.WriteString(x + "\n")
				case []byte:
					b.WriteString(string(x) + "\n")
				}
			}
		}
		r.Close()
	}
	return b.String()
}

func TestSessionCreeeApresDesactivationEstRefusee(t *testing.T) {
	// DisableUser supprime les sessions en cours — c'est la premiere barriere.
	// Celle-ci teste la SECONDE : la verification de `disabled_at` a chaque
	// requete.
	//
	// Sans elle, une session creee apres la desactivation (course entre deux
	// requetes, ou reconnexion pendant la transaction) rouvrirait l'acces a un
	// compte coupe. Le premier jet de ce fichier ne testait que la premiere
	// barriere : retirer la seconde ne cassait aucun test.
	s := ouvre(t)
	id, _ := s.CreateUser("spam02", "Spam", RoleMember)
	if err := s.DisableUser(id); err != nil {
		t.Fatal(err)
	}
	// Session posee directement, en contournant DisableUser.
	token, err := s.NewSession(id, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserBySession(token); err == nil {
		t.Error("une session creee apres desactivation ouvre l'acces")
	}
}
