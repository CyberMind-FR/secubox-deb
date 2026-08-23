package store

import (
	"path/filepath"
	"testing"
	"time"
)

var t0 = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

func banc(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "radio.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// ── NORMALISATION DE LA SOURCE ──────────────────────────────────────────────
//
// Sans elle, la meme chanson entre trois fois et la playlist se remplit de
// doublons que personne ne comprend — le desaccord ne se voit qu'a l'ecoute.
func TestLaMemeChansonNeRentrePasDeuxFois(t *testing.T) {
	memes := []string{
		"https://www.youtube.com/watch?v=ABC123",
		"https://youtu.be/ABC123",
		"https://youtube.com/watch?v=ABC123&t=42s",
		"https://m.youtube.com/watch?v=ABC123",
		"https://music.youtube.com/watch?v=ABC123&list=XYZ",
		"https://www.youtube.com/shorts/ABC123",
	}
	ref := CleSource(memes[0])
	for _, m := range memes[1:] {
		if got := CleSource(m); got != ref {
			t.Errorf("CleSource(%q) = %q, attendu %q", m, got, ref)
		}
	}
	// ...et deux chansons differentes restent differentes.
	if CleSource("https://youtu.be/ABC123") == CleSource("https://youtu.be/XYZ789") {
		t.Error("deux videos distinctes partagent la meme cle")
	}
}

// ON NE REND JAMAIS UNE CLE VIDE POUR UNE ENTREE NON VIDE : deux adresses
// inconnues deviendraient « egales » et la seconde ecraserait la premiere.
func TestUneAdresseInconnueGardeUneCleDistincte(t *testing.T) {
	a := CleSource("https://exemple.fr/piste/1")
	b := CleSource("https://exemple.fr/piste/2")
	if a == "" || b == "" {
		t.Fatal("cle vide pour une adresse non vide")
	}
	if a == b {
		t.Error("deux adresses distinctes partagent la meme cle")
	}
	// Les parametres de suivi ne creent pas de doublon.
	if CleSource("https://exemple.fr/p?utm_source=x") != CleSource("https://exemple.fr/p") {
		t.Error("un parametre de suivi cree un doublon")
	}
}

func TestAjouterDeuxFoisRendLaMemePiste(t *testing.T) {
	s := banc(t)
	a, neuf, err := s.Ajoute("https://youtu.be/ABC", "Un titre", 1, t0)
	if err != nil || !neuf {
		t.Fatalf("premier ajout : %v neuf=%v", err, neuf)
	}
	b, neuf, err := s.Ajoute("https://www.youtube.com/watch?v=ABC&t=9", "", 2, t0)
	if err != nil {
		t.Fatal(err)
	}
	if neuf {
		t.Error("le doublon a ete traite comme une piste neuve")
	}
	if a.ID != b.ID {
		t.Errorf("deux identifiants pour la meme chanson : %d et %d", a.ID, b.ID)
	}
}

// REPROPOSER UNE PISTE INDISPONIBLE LA REMET EN JEU : c'est souvent ce que
// veut dire le geste — « reessaie celle-la ».
func TestReproposerUnePisteIndisponibleLaRemetEnJeu(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Ajoute("https://youtu.be/ABC", "", 1, t0)
	if err := s.MarqueIndisponible(p.ID, "geo-bloque"); err != nil {
		t.Fatal(err)
	}
	if q, _ := s.ParID(p.ID); !q.Indisponible {
		t.Fatal("la piste n'est pas marquee indisponible")
	}
	q, neuf, err := s.Ajoute("https://youtu.be/ABC", "", 2, t0)
	if err != nil || neuf {
		t.Fatalf("re-ajout : %v neuf=%v", err, neuf)
	}
	if q.Indisponible {
		t.Error("la piste reste ecartee alors qu'on la repropose")
	}
}

// ── COEURS ──────────────────────────────────────────────────────────────────
//
// UNE TABLE, PAS UN COMPTEUR : un entier ne saurait ni empecher le double
// vote, ni dire QUI a aime.
func TestUnCoeurNeCompteQuUneFoisParPersonne(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Ajoute("https://youtu.be/ABC", "", 1, t0)
	for i := 0; i < 3; i++ {
		if err := s.PoseCoeur(p.ID, 7, "u", t0); err != nil {
			t.Fatalf("pose %d : %v", i, err)
		}
	}
	if q, _ := s.ParID(p.ID); q.Coeurs != 1 {
		t.Errorf("%d coeurs pour une seule personne", q.Coeurs)
	}
	_ = s.PoseCoeur(p.ID, 8, "u", t0)
	if q, _ := s.ParID(p.ID); q.Coeurs != 2 {
		t.Errorf("%d coeurs pour deux personnes", q.Coeurs)
	}
}

func TestOnPeutRetirerSonCoeurEtLuiSeul(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Ajoute("https://youtu.be/ABC", "", 1, t0)
	_ = s.PoseCoeur(p.ID, 7, "u", t0)
	_ = s.PoseCoeur(p.ID, 8, "u", t0)
	if err := s.RetireCoeur(p.ID, 7); err != nil {
		t.Fatal(err)
	}
	q, _ := s.ParID(p.ID)
	if q.Coeurs != 1 {
		t.Errorf("%d coeurs apres retrait", q.Coeurs)
	}
	if a, _ := s.ACoeur(p.ID, 7); a {
		t.Error("le coeur retire est toujours la")
	}
	if a, _ := s.ACoeur(p.ID, 8); !a {
		t.Error("le retrait a emporte le coeur d'un autre")
	}
}

// ── LECTURES ────────────────────────────────────────────────────────────────

func TestLaDerniereLectureAlimenteLeRepos(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Ajoute("https://youtu.be/ABC", "", 1, t0)
	if q, _ := s.ParID(p.ID); q.JoueeLe != 0 {
		t.Fatal("une piste neuve porte deja une lecture")
	}
	_ = s.NoteLecture(p.ID, t0.Add(-2*time.Hour), 111)
	_ = s.NoteLecture(p.ID, t0.Add(-30*time.Minute), 222)
	q, _ := s.ParID(p.ID)
	if q.JoueeLe != t0.Add(-30*time.Minute).Unix() {
		t.Errorf("derniere lecture = %d, attendue la plus recente", q.JoueeLe)
	}
}

// LES « PRÉCÉDENTS » VIENNENT DU JOURNAL, PAS DE LA PLAYLIST. On diffuse dans
// un ordre (B, C, A) différent de l'ordre d'ajout (A, B, C) ; Historique doit
// rendre l'ordre de DIFFUSION, le plus récent d'abord.
func TestHistoriqueRendLOrdreDeDiffusionReel(t *testing.T) {
	s := banc(t)
	a, _, _ := s.Ajoute("https://youtu.be/AAA", "A", 1, t0)
	b, _, _ := s.Ajoute("https://youtu.be/BBB", "B", 1, t0)
	c, _, _ := s.Ajoute("https://youtu.be/CCC", "C", 1, t0)
	_ = s.NoteLecture(b.ID, t0.Add(1*time.Minute), 1)
	_ = s.NoteLecture(c.ID, t0.Add(2*time.Minute), 2)
	_ = s.NoteLecture(a.ID, t0.Add(3*time.Minute), 3)
	h, err := s.Historique(10)
	if err != nil {
		t.Fatal(err)
	}
	want := []int64{a.ID, c.ID, b.ID}
	if len(h) != len(want) {
		t.Fatalf("Historique a rendu %d pistes, attendu %d", len(h), len(want))
	}
	for i, w := range want {
		if h[i].ID != w {
			t.Fatalf("Historique[%d].ID = %d, attendu %d (ordre de diffusion, plus récent d'abord)", i, h[i].ID, w)
		}
	}
}

// LE JOURNAL EST APPEND-ONLY : c'est lui qui rend le tirage explicable.
func TestLHistoriqueDesLecturesEstConserve(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Ajoute("https://youtu.be/ABC", "", 1, t0)
	for i := 0; i < 3; i++ {
		_ = s.NoteLecture(p.ID, t0.Add(time.Duration(i)*time.Hour), int64(100+i))
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM lectures WHERE piste_id = ?`, p.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("%d lectures conservees sur 3", n)
	}
}

// ── TIRAGE ──────────────────────────────────────────────────────────────────
//
// UNE PISTE PAS ENCORE EN CACHE EST ECARTEE : la tirer donnerait un silence.
// Elle reste dans la file, visible, avec son etat.
func TestUnePisteSansCacheNestPasTirable(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Ajoute("https://youtu.be/ABC", "", 1, t0)
	tp, _, err := s.PourTirage()
	if err != nil {
		t.Fatal(err)
	}
	if len(tp) != 1 {
		t.Fatalf("%d pistes", len(tp))
	}
	if !tp[0].Indisponible {
		t.Error("une piste non recuperee est proposee au tirage : elle donnerait un silence")
	}
	// ...et elle le devient une fois en cache.
	if err := s.PoseCache(p.ID, "/data/1.opus", "audio/ogg", 4096, 210000, "Titre", "Auteur"); err != nil {
		t.Fatal(err)
	}
	tp, _, _ = s.PourTirage()
	if tp[0].Indisponible {
		t.Error("une piste en cache reste ecartee du tirage")
	}
	q, _ := s.ParID(p.ID)
	if !q.EnCache() || q.Titre != "Titre" || q.DureeMS != 210000 {
		t.Errorf("cache mal enregistre : %+v", q)
	}
}

// La file reste dans l'ordre d'ajout : c'est ce que l'interface affiche.
func TestLaFileGardeLOrdreDAjout(t *testing.T) {
	s := banc(t)
	for i, u := range []string{"https://youtu.be/A", "https://youtu.be/B", "https://youtu.be/C"} {
		if _, _, err := s.Ajoute(u, "", 1, t0.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	l, err := s.Toutes()
	if err != nil || len(l) != 3 {
		t.Fatalf("%d pistes, %v", len(l), err)
	}
	if l[0].Source != "yt:A" || l[2].Source != "yt:C" {
		t.Errorf("ordre casse : %s, %s, %s", l[0].Source, l[1].Source, l[2].Source)
	}
}

// Le depart d'un membre ne retire pas sa musique de l'antenne.
func TestUneAdresseVideEstRefusee(t *testing.T) {
	s := banc(t)
	if _, _, err := s.Ajoute("   ", "", 1, t0); err == nil {
		t.Error("une adresse vide a ete acceptee")
	}
}

// ── BORNES DU CACHE ─────────────────────────────────────────────────────────
//
// L'eMMC pleine a deja provoque des 502 sur cette machine : un cache sans borne
// n'est pas une imprudence theorique.

func enCache(t *testing.T, s *Store, source string, octets int64, joueeIlYA time.Duration) Piste {
	t.Helper()
	p, _, err := s.Ajoute(source, "", 1, t0.Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PoseCache(p.ID, "/data/"+source, "audio/ogg", octets, 180000, "", ""); err != nil {
		t.Fatal(err)
	}
	if joueeIlYA > 0 {
		if err := s.NoteLecture(p.ID, t0.Add(-joueeIlYA), 1); err != nil {
			t.Fatal(err)
		}
	}
	q, _ := s.ParID(p.ID)
	return q
}

// LA MOINS RECEMMENT JOUEE PART EN PREMIER, et non la plus ancienne : une
// piste de 2019 qui passe chaque semaine doit rester ; une nouveaute que
// personne n'ecoute peut partir.
func TestLaPurgeEvinceLaMoinsRecemmentJouee(t *testing.T) {
	s := banc(t)
	vieilleMaisEcoutee := enCache(t, s, "https://youtu.be/A", 100, time.Hour)
	jamaisEcoutee := enCache(t, s, "https://youtu.be/B", 100, 0)
	ecouteeHier := enCache(t, s, "https://youtu.be/C", 100, 24*time.Hour)

	tot, _ := s.OctetsEnCache()
	if tot != 300 {
		t.Fatalf("total = %d", tot)
	}
	l, err := s.APurger(150, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 2 {
		t.Fatalf("%d pistes a purger pour passer de 300 a 150", len(l))
	}
	if l[0].ID != jamaisEcoutee.ID {
		t.Errorf("la premiere evincee est %d, attendue la jamais ecoutee %d",
			l[0].ID, jamaisEcoutee.ID)
	}
	if l[1].ID != ecouteeHier.ID {
		t.Errorf("la seconde evincee est %d, attendue celle d'hier %d", l[1].ID, ecouteeHier.ID)
	}
	for _, p := range l {
		if p.ID == vieilleMaisEcoutee.ID {
			t.Error("la piste ecoutee il y a une heure a ete evincee")
		}
	}
}

// ON NE RETIRE JAMAIS CE QUI PASSE OU VA PASSER : le programme est fige sur
// quelques titres, les evincer couperait l'antenne.
func TestLaPurgeEpargneLesPistesProtegees(t *testing.T) {
	s := banc(t)
	a := enCache(t, s, "https://youtu.be/A", 100, 0) // la plus evincable
	_ = enCache(t, s, "https://youtu.be/B", 100, 24*time.Hour)
	_ = enCache(t, s, "https://youtu.be/C", 100, time.Hour)

	l, err := s.APurger(150, map[int64]bool{a.ID: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range l {
		if p.ID == a.ID {
			t.Fatal("une piste protegee a ete evincee : l'antenne se couperait")
		}
	}
}

// SOUS LA BORNE, ON NE PURGE RIEN. Un menage qui tourne a vide use le disque
// pour rien.
func TestSousLaBorneAucunePurge(t *testing.T) {
	s := banc(t)
	_ = enCache(t, s, "https://youtu.be/A", 100, 0)
	l, err := s.APurger(1000, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 0 {
		t.Errorf("%d pistes purgees alors qu'on est sous la borne", len(l))
	}
}

// LA PISTE SURVIT A SON FICHIER : elle reste au repertoire et sera reprise si
// elle ressort au tirage. L'evincer aurait fait disparaitre des titres a chaque
// menage.
func TestOublierLeCacheNeSupprimePasLaPiste(t *testing.T) {
	s := banc(t)
	p := enCache(t, s, "https://youtu.be/A", 100, 0)
	if err := s.OublieCache(p.ID); err != nil {
		t.Fatal(err)
	}
	q, err := s.ParID(p.ID)
	if err != nil {
		t.Fatalf("la piste a disparu : %v", err)
	}
	if q.EnCache() {
		t.Error("le fichier est toujours la")
	}
	if q.Etat != EtatValide {
		t.Errorf("l'etat a change : %q", q.Etat)
	}
	if n, _ := s.OctetsEnCache(); n != 0 {
		t.Errorf("le total du cache reste a %d", n)
	}
}

// ── LES COEURS SONT PUBLICS ─────────────────────────────────────────────────
//
// Un coeur anonyme se compte ; un coeur signe se discute — « c'est toi qui as
// mis ca ? » est une conversation, et c'est le propre d'une radio collective.
func TestOnVoitQuiAAimeUnePiste(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Ajoute("https://youtu.be/ABC", "", 1, t0)
	if err := s.PoseCoeur(p.ID, 7, "alice", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.PoseCoeur(p.ID, 8, "bob", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	l, err := s.QuiAime(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 2 {
		t.Fatalf("%d aimeurs", len(l))
	}
	// DANS L'ORDRE DU GESTE : qui a lance le mouvement se lit en premier.
	if l[0].Pseudo != "alice" || l[1].Pseudo != "bob" {
		t.Errorf("ordre = %s, %s", l[0].Pseudo, l[1].Pseudo)
	}
	if l[0].MisLe != t0.Unix() {
		t.Errorf("date du premier coeur = %d", l[0].MisLe)
	}
}

// LE PSEUDONYME SE MET A JOUR, la date du geste non : si quelqu'un a change de
// nom, la liste montre celui sous lequel on le connait aujourd'hui — sans
// reecrire quand il a aime.
func TestUnChangementDePseudoNeReecritPasLaDate(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Ajoute("https://youtu.be/ABC", "", 1, t0)
	_ = s.PoseCoeur(p.ID, 7, "alice", t0)
	_ = s.PoseCoeur(p.ID, 7, "alice-nouveau-nom", t0.Add(time.Hour))

	l, _ := s.QuiAime(p.ID)
	if len(l) != 1 {
		t.Fatalf("%d aimeurs apres renommage : le coeur a ete double", len(l))
	}
	if l[0].Pseudo != "alice-nouveau-nom" {
		t.Errorf("pseudo = %q, attendu le plus recent", l[0].Pseudo)
	}
	if l[0].MisLe != t0.Unix() {
		t.Errorf("la date du geste a ete reecrite : %d", l[0].MisLe)
	}
}

func TestRetirerSonCoeurLeRetireDeLaListePublique(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Ajoute("https://youtu.be/ABC", "", 1, t0)
	_ = s.PoseCoeur(p.ID, 7, "alice", t0)
	_ = s.PoseCoeur(p.ID, 8, "bob", t0)
	if err := s.RetireCoeur(p.ID, 7); err != nil {
		t.Fatal(err)
	}
	l, _ := s.QuiAime(p.ID)
	if len(l) != 1 || l[0].Pseudo != "bob" {
		t.Errorf("liste apres retrait : %+v", l)
	}
}

// Les coeurs poses AVANT que la liste devienne publique n'ont pas de nom : la
// migration ne doit pas les faire disparaitre du compte pour autant.
func TestUnCoeurSansPseudoResteCompte(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Ajoute("https://youtu.be/ABC", "", 1, t0)
	if _, err := s.db.Exec(
		`INSERT INTO coeurs (piste_id, user_id, mis_le) VALUES (?,?,?)`,
		p.ID, 9, t0.Unix()); err != nil {
		t.Fatal(err)
	}
	if q, _ := s.ParID(p.ID); q.Coeurs != 1 {
		t.Errorf("%d coeurs : un coeur ancien a disparu du compte", q.Coeurs)
	}
	l, _ := s.QuiAime(p.ID)
	if len(l) != 1 {
		t.Fatalf("%d aimeurs", len(l))
	}
	if l[0].Pseudo != "" {
		t.Errorf("pseudo invente pour un coeur ancien : %q", l[0].Pseudo)
	}
}

// ── PLAYLISTS ───────────────────────────────────────────────────────────────
//
// UNE ADRESSE `watch?v=X&list=Y` DESIGNE UN MORCEAU, pas la playlist qui
// l'entoure : c'est ainsi que YouTube partage un titre pris dans une liste.
// Ne regarder que `list` ferait entrer deux cents morceaux a chaque fois qu'on
// colle un lien — c'est-a-dire presque toujours.
func TestUnLienPrisDansUnePlaylistResteUnSeulMorceau(t *testing.T) {
	cle := CleSource("https://www.youtube.com/watch?v=ABC&list=PL123&index=4")
	if cle != "yt:ABC" {
		t.Errorf("cle = %q, attendu yt:ABC", cle)
	}
}

// ...ET UNE VRAIE ADRESSE DE PLAYLIST EN EST UNE.
func TestUneAdresseDePlaylistEstReconnue(t *testing.T) {
	for _, u := range []string{
		"https://www.youtube.com/playlist?list=PL123",
		"https://m.youtube.com/playlist?list=PL123",
		"https://music.youtube.com/playlist?list=PL123",
	} {
		if cle := CleSource(u); cle != "ytpl:PL123" {
			t.Errorf("CleSource(%q) = %q, attendu ytpl:PL123", u, cle)
		}
	}
}

// UNE PLAYLIST NE SE JOUE PAS, ELLE SE DEPLIE. Tant qu'elle ne l'est pas, elle
// ne doit jamais atteindre le tirage — sinon l'antenne « joue » une liste.
func TestUnePlaylistNestJamaisJouable(t *testing.T) {
	s := banc(t)
	p, _, err := s.Ajoute("https://www.youtube.com/playlist?list=PL123", "Ma liste", 1, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !p.EstPlaylist() {
		t.Fatal("la playlist n'est pas reconnue comme telle")
	}
	// Meme marquee « en cache », elle reste hors du tirage.
	_ = s.PoseCache(p.ID, "/x", "video/mp4", 1, 1000, "", "")
	q, _ := s.ParID(p.ID)
	if q.EnCache() {
		t.Error("une playlist est declaree jouable")
	}
	tp, _, _ := s.PourTirage()
	for _, t2 := range tp {
		if t2.ID == p.ID && !t2.Indisponible {
			t.Error("une playlist est proposee au tirage")
		}
	}
}

// DEPLIER, C'EST HERITER DE LA DECISION DEJA PRISE : le sysop a valide LA
// PLAYLIST, il n'a pas a revalider chacun de ses titres.
func TestDeplierUnePlaylistLaTransformeEnPropositions(t *testing.T) {
	s := banc(t)
	pl, _, _ := s.Ajoute("https://www.youtube.com/playlist?list=PL1", "Ma liste", 7, t0)
	n, err := s.Deplie(pl.ID, []MorceauPlaylist{
		{URL: "https://youtu.be/A", Titre: "Un"},
		{URL: "https://youtu.be/B", Titre: "Deux"},
	}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("%d morceaux deplies", n)
	}
	// ILS ARRIVENT EN PROPOSITIONS, pas a l'antenne : on ne connait pas une
	// liste avant de l'avoir vue.
	if l, _ := s.Toutes(); len(l) != 0 {
		t.Errorf("%d pistes sont entrees a l'antenne sans etre regardees", len(l))
	}
	pr, _ := s.Propositions()
	if len(pr) != 2 {
		t.Fatalf("%d propositions", len(pr))
	}
	for _, p := range pr {
		if p.Etat != EtatPropose {
			t.Errorf("%s est en %q", p.Source, p.Etat)
		}
		if p.AjoutePar != 7 {
			t.Errorf("l'auteur de la proposition est perdu : %d", p.AjoutePar)
		}
		// GROUPES PAR LOT : cinquante lignes melees au reste seraient illisibles.
		if p.Lot != "ytpl:PL1" {
			t.Errorf("lot = %q", p.Lot)
		}
		if p.LotTitre != "Ma liste" {
			t.Errorf("titre du lot = %q", p.LotTitre)
		}
	}
	// LA PLAYLIST A JOUE SON ROLE et disparait : la garder laisserait une
	// entree qui ne se joue jamais.
	if _, err := s.ParID(pl.ID); err == nil {
		t.Error("la playlist subsiste apres depliage")
	}
}

// UN MORCEAU DEJA REFUSE NE REVIENT PAS PAR LA PLAYLIST : ce serait la porte de
// derriere exacte que le refus est cense fermer.
//
// CE TEST FIGE LA PROPRIETE, il ne discrimine pas la ligne qui la porte :
// verifie par mutation, neutraliser le test sur `EtatRefuse` ne le fait pas
// tomber, parce que le rejet des morceaux DEJA CONNUS suffit. Le dire evite
// qu'on prete a ce test une precision qu'il n'a pas.
func TestDeplierNeRessuscitePasUnMorceauRefuse(t *testing.T) {
	s := banc(t)
	refuse, _, _ := s.Propose("https://youtu.be/NON", "", 7, t0)
	_ = s.Refuse(refuse.ID, 1, t0, "hors sujet")

	pl, _, _ := s.Ajoute("https://www.youtube.com/playlist?list=PL1", "", 7, t0)
	n, err := s.Deplie(pl.ID, []MorceauPlaylist{
		{URL: "https://youtu.be/NON", Titre: "Le refuse"},
		{URL: "https://youtu.be/OUI", Titre: "L'autre"},
	}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d morceaux entres, attendu 1 (le refuse doit rester dehors)", n)
	}
	q, _ := s.ParSource("yt:NON")
	if q.Etat != EtatRefuse {
		t.Errorf("le morceau refuse est revenu en %q", q.Etat)
	}
}

// LA BORNE EXISTE PARCE QU'UNE PLAYLIST PEUT EN PORTER CINQ CENTS : les faire
// entrer d'un coup noierait le repertoire, et le tirage ne parlerait plus que
// d'elle pendant des semaines.
func TestUnDepliageEstBorne(t *testing.T) {
	s := banc(t)
	pl, _, _ := s.Ajoute("https://www.youtube.com/playlist?list=PL1", "", 7, t0)
	var m []MorceauPlaylist
	for i := 0; i < MaxParPlaylist+20; i++ {
		m = append(m, MorceauPlaylist{URL: "https://youtu.be/x" + itoa(i), Titre: "t"})
	}
	n, err := s.Deplie(pl.ID, m, t0)
	if err != nil {
		t.Fatal(err)
	}
	if n != MaxParPlaylist {
		t.Errorf("%d morceaux entres, borne a %d", n, MaxParPlaylist)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
