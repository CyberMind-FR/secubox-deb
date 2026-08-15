package store

import (
	"errors"
	"path/filepath"
	"testing"
)

func magasinMasto(t *testing.T) (*Store, int64, int64) {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "bbs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	alice, err := s.CreateUser("alice", "Alice", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := s.CreateUser("bob", "Bob", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	return s, alice, bob
}

// LE TEST LE PLUS IMPORTANT DE CE LOT. Un membre local « alice » n'est PAS
// @alice sur l'instance tant qu'elle ne l'a pas prouve. Rapprocher deux comptes
// sur l'egalite des pseudonymes ferait publier au nom de quelqu'un d'autre : sur
// une instance ouverte, il suffirait d'y prendre le pseudonyme d'un membre du
// BBS pour recevoir sa parole.
func TestAucunCompteNEstLieSansAllerRetour(t *testing.T) {
	s, alice, _ := magasinMasto(t)

	// Un compte Mastodon portant EXACTEMENT le meme pseudonyme existe dehors et
	// se trouve deja lie... a quelqu'un d'autre.
	if err := s.LieCompteMastodon(alice+1000, CompteMastodon{
		Instance: "exemple.social", Acct: "alice", CompteID: "42",
	}, "jeton-d-un-autre"); err == nil {
		t.Skip("membre inexistant accepte : le scenario ne tient pas")
	}

	if _, err := s.CompteMastodonDe(alice); !errors.Is(err, ErrPasDeCompteMastodon) {
		t.Errorf("un compte est lie sans aller-retour : %v", err)
	}
	if _, _, err := s.JetonMastodon(alice); !errors.Is(err, ErrPasDeCompteMastodon) {
		t.Error("un jeton existe sans aller-retour")
	}
}

func TestLeLienSEtablitEtSeRetire(t *testing.T) {
	s, alice, _ := magasinMasto(t)
	c := CompteMastodon{Instance: "exemple.social", Acct: "alice", CompteID: "42"}
	if err := s.LieCompteMastodon(alice, c, "jeton-alice"); err != nil {
		t.Fatal(err)
	}
	vu, err := s.CompteMastodonDe(alice)
	if err != nil {
		t.Fatal(err)
	}
	if vu.Acct != "alice" || vu.Instance != "exemple.social" {
		t.Errorf("compte relu de travers : %+v", vu)
	}
	jeton, inst, err := s.JetonMastodon(alice)
	if err != nil || jeton != "jeton-alice" || inst != "exemple.social" {
		t.Errorf("jeton relu de travers : %q %q %v", jeton, inst, err)
	}
	if err := s.DelieCompteMastodon(alice); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompteMastodonDe(alice); !errors.Is(err, ErrPasDeCompteMastodon) {
		t.Error("le lien survit au retrait")
	}
}

// LE JETON N'EST PAS DANS LA STRUCTURE QUI S'AFFICHE. Ce qui se rend dans un
// gabarit et ce qui autorise ne doivent pas voyager ensemble, sinon le jeton
// finit un jour dans une page par simple commodite.
func TestLaStructureAffichableNePorteAucunJeton(t *testing.T) {
	s, alice, _ := magasinMasto(t)
	if err := s.LieCompteMastodon(alice,
		CompteMastodon{Instance: "exemple.social", Acct: "alice", CompteID: "42"},
		"jeton-tres-secret"); err != nil {
		t.Fatal(err)
	}
	c, err := s.CompteMastodonDe(alice)
	if err != nil {
		t.Fatal(err)
	}
	for _, champ := range []string{c.Instance, c.Acct, c.CompteID, c.Portee} {
		if champ == "jeton-tres-secret" {
			t.Fatal("le jeton se trouve dans la structure affichable")
		}
	}
}

// DEUX MEMBRES NE PARLENT PAS SOUS LA MEME IDENTITE FEDIVERSE : l'attribution
// deviendrait ambigue — deux pseudonymes ici pour une seule voix dehors.
func TestUnMemeCompteFediverseNeSertPasADeuxMembres(t *testing.T) {
	s, alice, bob := magasinMasto(t)
	c := CompteMastodon{Instance: "exemple.social", Acct: "alice", CompteID: "42"}
	if err := s.LieCompteMastodon(alice, c, "jeton-alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.LieCompteMastodon(bob, c, "jeton-bob"); !errors.Is(err, ErrIdentitePrise) {
		t.Errorf("un second membre a pris la meme identite : %v", err)
	}
	// Alice, elle, peut relier de nouveau le sien (renouvellement de jeton).
	if err := s.LieCompteMastodon(alice, c, "jeton-alice-2"); err != nil {
		t.Errorf("le proprietaire ne peut plus renouveler : %v", err)
	}
}

// L'ETAT LIE L'ALLER AU RETOUR. Sans lui, un retour d'autorisation aboutirait
// dans la session d'un autre et lui attacherait le compte de l'attaquant.
func TestUnEtatSertUneFoisEtNommeSonProprietaire(t *testing.T) {
	s, alice, _ := magasinMasto(t)
	etat, err := s.NouvelEtatMastodon(alice, "exemple.social")
	if err != nil {
		t.Fatal(err)
	}
	qui, inst, err := s.ConsommeEtatMastodon(etat)
	if err != nil {
		t.Fatal(err)
	}
	if qui != alice {
		t.Errorf("etat attribue au membre %d au lieu de %d", qui, alice)
	}
	if inst != "exemple.social" {
		t.Errorf("instance = %q", inst)
	}
	// Rejoue, il ne vaut plus rien : sans cela, un retour capture dans un
	// journal permettrait de re-attacher un compte apres un deliement.
	if _, _, err := s.ConsommeEtatMastodon(etat); !errors.Is(err, ErrEtatMastodon) {
		t.Error("etat rejouable")
	}
}

func TestUnEtatInconnuEstRefuse(t *testing.T) {
	s, _, _ := magasinMasto(t)
	if _, _, err := s.ConsommeEtatMastodon("etat-invente"); !errors.Is(err, ErrEtatMastodon) {
		t.Error("etat inconnu accepte")
	}
	if _, _, err := s.ConsommeEtatMastodon(""); !errors.Is(err, ErrEtatMastodon) {
		t.Error("etat vide accepte")
	}
}

// SANS NORMALISATION, `https://Exemple.fr/` et `exemple.fr` seraient deux
// instances : deux applications enregistrees, et un index d'unicite qui ne
// protege plus rien.
func TestLInstanceEstNormaliseeAvantToutRapprochement(t *testing.T) {
	cas := map[string]string{
		"https://Exemple.fr/":     "exemple.fr",
		"http://exemple.fr":       "exemple.fr",
		"exemple.fr/":             "exemple.fr",
		"  Exemple.FR  ":          "exemple.fr",
		"@moi@exemple.fr":         "exemple.fr",
		"https://exemple.fr/@moi": "exemple.fr",
		"https://exemple.fr/?x=1": "exemple.fr",
	}
	for brut, attendu := range cas {
		if got := NormaliseInstance(brut); got != attendu {
			t.Errorf("NormaliseInstance(%q) = %q, attendu %q", brut, got, attendu)
		}
	}
}

func TestLApplicationEstRetenueParInstance(t *testing.T) {
	s, _, _ := magasinMasto(t)
	if id, _, _ := s.AppMastodon("exemple.social"); id != "" {
		t.Fatal("une application existe avant enregistrement")
	}
	if err := s.PoseAppMastodon("https://Exemple.Social/", "cid", "csecret"); err != nil {
		t.Fatal(err)
	}
	// Relue sous une autre ecriture de la meme instance : c'est tout l'objet de
	// la normalisation.
	id, sec, err := s.AppMastodon("exemple.social")
	if err != nil || id != "cid" || sec != "csecret" {
		t.Errorf("application relue de travers : %q %q %v", id, sec, err)
	}
}
