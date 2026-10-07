package tirage

import (
	"math"
	"math/rand"
	"testing"
	"time"
)

var t0 = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

func piste(id int64, ajout, jouee time.Time, coeurs int) Piste {
	return Piste{ID: id, AjouteLe: ajout, JoueeLe: jouee, Coeurs: coeurs}
}

// ── LE DEFAUT QUE CE PAQUET EXISTE POUR CORRIGER ────────────────────────────
//
// Sur une playlist qui grandit, un tirage uniforme donne a une nouveaute
// 1/N de chance : personne n'entend jamais ce qu'il vient de deposer.
func TestUneNouveauteEstFavoriseeFaceAUnFondAncien(t *testing.T) {
	r := Defaut()
	vieux := piste(1, t0.Add(-90*24*time.Hour), time.Time{}, 0)
	neuf := piste(2, t0, time.Time{}, 0)

	pv, pn := Poids(vieux, r, t0), Poids(neuf, r, t0)
	if pn <= pv {
		t.Fatalf("la nouveaute (%.3f) ne passe pas devant l'ancien (%.3f)", pn, pv)
	}
	if rapport := pn / pv; rapport < 2 {
		t.Errorf("l'avantage de nouveaute est de ×%.2f, attendu ~×2,4", rapport)
	}
}

// LA DECROISSANCE EST CONTINUE. Un seuil ferme ferait chuter une piste d'un
// coup au huitieme jour : on entendrait la marche.
func TestLaNouveauteDecroitSansMarche(t *testing.T) {
	r := Defaut()
	var prec float64 = math.Inf(1)
	for h := 0; h <= 24*21; h += 6 {
		p := piste(1, t0.Add(-time.Duration(h)*time.Hour), time.Time{}, 0)
		w := Poids(p, r, t0)
		if w > prec+1e-9 {
			t.Fatalf("le poids remonte a %d h : %.4f > %.4f", h, w, prec)
		}
		// Aucun pas ne doit faire chuter de plus de 5 % : ce serait une marche.
		if prec != math.Inf(1) && w < prec*0.95 {
			t.Errorf("chute brutale a %d h : %.4f -> %.4f", h, prec, w)
		}
		prec = w
	}
	// Et elle tend vers 1, sans jamais passer dessous.
	tres := piste(1, t0.Add(-365*24*time.Hour), time.Time{}, 0)
	if w := Poids(tres, r, t0); w < 1 || w > 1.05 {
		t.Errorf("apres un an, poids = %.4f, attendu ~1", w)
	}
}

// ── SOUS-LINEARITE DES COEURS ───────────────────────────────────────────────
//
// LE POINT LE PLUS IMPORTANT DU PAQUET. Avec une ponderation lineaire, un
// titre a 50 coeurs passerait 50 fois plus qu'un titre a 1 : trois succes
// monopoliseraient l'antenne et la radio cesserait d'etre collective.
func TestLesCoeursNeSontPasLineaires(t *testing.T) {
	r := Defaut()
	vieux := t0.Add(-365 * 24 * time.Hour) // nouveaute neutralisee
	un := Poids(piste(1, vieux, time.Time{}, 1), r, t0)
	cinquante := Poids(piste(2, vieux, time.Time{}, 50), r, t0)

	rapport := cinquante / un
	if rapport >= 10 {
		t.Errorf("50 coeurs valent ×%.1f un seul coeur : la ponderation est trop forte", rapport)
	}
	if rapport <= 1 {
		t.Errorf("les coeurs ne pesent pas (×%.2f)", rapport)
	}
	// Doubler les coeurs ne doit jamais doubler le poids.
	dix := Poids(piste(3, vieux, time.Time{}, 10), r, t0)
	vingt := Poids(piste(4, vieux, time.Time{}, 20), r, t0)
	if vingt >= dix*1.5 {
		t.Errorf("de 10 a 20 coeurs le poids fait ×%.2f : trop proche du lineaire", vingt/dix)
	}
}

// ── LE REPOS, ET NON L'ALEATOIRE, EMPECHE LE RESSASSEMENT ───────────────────
func TestUnePisteQuiVientDePasserNeRepasserPas(t *testing.T) {
	r := Defaut()
	juste := piste(1, t0.Add(-30*24*time.Hour), t0, 0)
	if w := Poids(juste, r, t0); w > PoidsMin {
		t.Errorf("une piste jouee a l'instant garde un poids de %.4f", w)
	}
	// ...et elle revient progressivement.
	moitie := Poids(piste(1, t0.Add(-30*24*time.Hour), t0.Add(-time.Hour), 0), r, t0)
	pleine := Poids(piste(1, t0.Add(-30*24*time.Hour), t0.Add(-3*time.Hour), 0), r, t0)
	if !(moitie > PoidsMin && moitie < pleine) {
		t.Errorf("le retour n'est pas progressif : mi-repos %.3f, repose %.3f", moitie, pleine)
	}
}

// UNE PISTE JAMAIS JOUEE N'EST PAS AU REPOS — c'est au contraire ce qu'on
// cherche a faire passer.
//
// CE TEST FIGE LA PROPRIETE, IL NE DISCRIMINE PAS LA GARDE `IsZero`. Verifie
// par mutation : en retirant cette garde, le test passe encore, parce que
// `maintenant.Sub(zero)` depasse de loin la duree de repos et rend le meme
// resultat. Le dire evite qu'on lui prete une portee qu'il n'a pas.
func TestUnePisteJamaisJoueeNestPasAuRepos(t *testing.T) {
	r := Defaut()
	if w := Poids(piste(1, t0, time.Time{}, 0), r, t0); w <= PoidsMin {
		t.Fatalf("une piste jamais jouee est traitee comme au repos (%.4f)", w)
	}
}

// ── GARANTIES ───────────────────────────────────────────────────────────────

// Aucune piste n'atteint zero DEFINITIVEMENT : elle disparaitrait de la radio
// sans que personne ne l'ait retiree.
func TestAucunePisteNeDisparaitDefinitivement(t *testing.T) {
	r := Defaut()
	// Le pire cas : tres ancienne, aucun coeur, et jouee il y a longtemps.
	p := piste(1, t0.Add(-10*365*24*time.Hour), t0.Add(-365*24*time.Hour), 0)
	if w := Poids(p, r, t0); w < PoidsMin {
		t.Errorf("poids %.6g sous le plancher", w)
	}
}

func TestUnePisteIndisponibleEstEcartee(t *testing.T) {
	r := Defaut()
	p := piste(1, t0, time.Time{}, 99)
	p.Indisponible = true
	if w := Poids(p, r, t0); w != 0 {
		t.Errorf("une piste indisponible garde un poids de %.4f", w)
	}
	if _, err := Suivante([]Piste{p}, r, t0, rand.New(rand.NewSource(1))); err != ErrAucunePiste {
		t.Errorf("une piste indisponible a ete tiree : %v", err)
	}
}

// LE TIRAGE EST REJOUABLE DEPUIS SA GRAINE : on doit pouvoir expliquer apres
// coup pourquoi tel titre est passe.
func TestLeTirageEstRejouable(t *testing.T) {
	r := Defaut()
	var ps []Piste
	for i := int64(1); i <= 20; i++ {
		ps = append(ps, piste(i, t0.Add(-time.Duration(i)*24*time.Hour), time.Time{}, int(i%7)))
	}
	a := Programme(ps, r, t0, 5, rand.New(rand.NewSource(42)))
	b := Programme(ps, r, t0, 5, rand.New(rand.NewSource(42)))
	if len(a) != 5 || len(b) != 5 {
		t.Fatalf("programme tronque : %d / %d", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Fatalf("meme graine, programmes differents en position %d", i)
		}
	}
}

// LE PROGRAMME NE REPETE PAS : sans mise au repos entre deux tirages, le meme
// titre sortirait trois fois de suite s'il porte un poids fort.
func TestLeProgrammeNeRepetePasUnMemeTitre(t *testing.T) {
	r := Defaut()
	var ps []Piste
	// Une piste tres favorisee, et quatre banales.
	ps = append(ps, piste(1, t0, time.Time{}, 500))
	for i := int64(2); i <= 5; i++ {
		ps = append(ps, piste(i, t0.Add(-200*24*time.Hour), time.Time{}, 0))
	}
	prog := Programme(ps, r, t0, 4, rand.New(rand.NewSource(7)))
	vus := map[int64]int{}
	for _, p := range prog {
		vus[p.ID]++
	}
	for id, n := range vus {
		if n > 1 {
			t.Errorf("la piste %d apparait %d fois dans le programme", id, n)
		}
	}
}

// ── DISTRIBUTION ────────────────────────────────────────────────────────────
//
// Les proprietes ci-dessus portent sur les POIDS ; celle-ci verifie que le
// tirage les respecte reellement.
func TestLeTirageSuitLesPoids(t *testing.T) {
	r := Defaut()
	vieux := t0.Add(-365 * 24 * time.Hour)
	ps := []Piste{
		piste(1, vieux, time.Time{}, 0), // banale
		piste(2, t0, time.Time{}, 0),    // nouveaute
	}
	alea := rand.New(rand.NewSource(1))
	compte := map[int64]int{}
	const n = 20000
	for i := 0; i < n; i++ {
		p, err := Suivante(ps, r, t0, alea)
		if err != nil {
			t.Fatal(err)
		}
		compte[p.ID]++
	}
	pr := Probabilites(ps, r, t0)
	for id, attendu := range pr {
		obtenu := float64(compte[id]) / n
		if math.Abs(obtenu-attendu) > 0.02 {
			t.Errorf("piste %d : tiree %.3f du temps, probabilite annoncee %.3f", id, obtenu, attendu)
		}
	}
}

func TestLesProbabilitesFontUn(t *testing.T) {
	r := Defaut()
	ps := []Piste{
		piste(1, t0, time.Time{}, 3),
		piste(2, t0.Add(-48*time.Hour), t0.Add(-30*time.Minute), 12),
		piste(3, t0.Add(-300*24*time.Hour), time.Time{}, 0),
	}
	var somme float64
	for _, v := range Probabilites(ps, r, t0) {
		somme += v
	}
	if math.Abs(somme-1) > 1e-9 {
		t.Errorf("somme des probabilites = %.9f", somme)
	}
}

// Une horloge de travers ne doit pas recompenser une piste datee du futur.
func TestUneDateFutureNeDonnePasDAvantage(t *testing.T) {
	r := Defaut()
	futur := Poids(piste(1, t0.Add(48*time.Hour), time.Time{}, 0), r, t0)
	maintenant := Poids(piste(2, t0, time.Time{}, 0), r, t0)
	if futur > maintenant+1e-9 {
		t.Errorf("une piste datee du futur pese plus (%.4f > %.4f)", futur, maintenant)
	}
}

func TestUneListeVideNeFaitPasPaniquer(t *testing.T) {
	if _, err := Suivante(nil, Defaut(), t0, rand.New(rand.NewSource(1))); err != ErrAucunePiste {
		t.Errorf("liste vide : %v", err)
	}
	if p := Programme(nil, Defaut(), t0, 3, rand.New(rand.NewSource(1))); len(p) != 0 {
		t.Errorf("programme non vide sur une liste vide")
	}
}

// ── « MOINS SOUVENT » : le contraire du coeur ────────────────────────────────
//
// Un titre poussé vers le bas reste dans la radio (jamais supprimé, jamais à zéro) mais passe beaucoup plus rarement.
func TestUnePistePousseeVersLeBasPasseBeaucoupMoinsSouvent(t *testing.T) {
	r := Defaut()
	normal := piste(1, t0.Add(-90*24*time.Hour), time.Time{}, 0)
	bas := normal
	bas.ID, bas.Bas = 2, true
	if rapport := Poids(bas, r, t0) / Poids(normal, r, t0); rapport > 0.12 {
		t.Fatalf("poussée vers le bas : poids ×%.3f, attendu au plus ×0,12", rapport)
	}
}

func TestPousseeVersLeBasNeFaitJamaisDisparaitre(t *testing.T) {
	r := Defaut()
	p := piste(1, t0.Add(-365*24*time.Hour), t0.Add(-time.Minute), 0)
	p.Bas = true
	if w := Poids(p, r, t0); w < PoidsMin {
		t.Fatalf("le plancher %.0e doit tenir, poids %.2e", PoidsMin, w)
	}
}

func TestDesReglagesSansCurseurBasUtilisentLeDefaut(t *testing.T) {
	r := Reglages{Nouveaute: 1, Repos: 0} // un Reglages construit sans le curseur : le geste doit quand même agir
	p := piste(1, t0, time.Time{}, 0)
	b := p
	b.Bas = true
	if Poids(b, r, t0) >= Poids(p, r, t0) {
		t.Fatal("sans curseur Bas, le geste n'a eu aucun effet")
	}
}

func TestSurLongueDureeLeTitrePousseVersLeBasPasseRarement(t *testing.T) {
	r := Defaut()
	pistes := []Piste{piste(1, t0.Add(-90*24*time.Hour), time.Time{}, 0), piste(2, t0.Add(-90*24*time.Hour), time.Time{}, 0), piste(3, t0.Add(-90*24*time.Hour), time.Time{}, 0)}
	pistes[2].Bas = true
	alea := rand.New(rand.NewSource(42))
	n3 := 0
	const tirages = 6000
	for i := 0; i < tirages; i++ {
		p, err := Suivante(pistes, r, t0, alea)
		if err != nil {
			t.Fatal(err)
		}
		if p.ID == 3 {
			n3++
		}
	}
	if part := float64(n3) / tirages; part > 0.06 || n3 == 0 {
		t.Fatalf("le titre poussé vers le bas passe %.1f %% du temps (attendu 0 < part ≤ 6 %%, un tiers sans le geste)", part*100)
	}
}
