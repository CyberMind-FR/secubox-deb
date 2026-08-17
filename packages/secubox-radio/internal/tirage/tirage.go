// Package tirage choisit la piste suivante d'une radio collaborative.
//
// LE PROBLEME QU'IL RESOUT. Un tirage uniforme rejoue les memes titres et noie
// ce qu'on vient d'ajouter : sur une playlist qui grandit, une nouveaute a
// 1/200 de chance de passer, donc personne n'entend jamais ce qu'il vient de
// deposer. C'est le defaut qui fait abandonner une radio collective.
//
// TROIS FACTEURS SE MULTIPLIENT, et chacun repond a un defaut precis :
//
//	poids = 1 × nouveaute(age) × aime(coeurs) × repos(derniere lecture)
//
// Le produit, et non la somme : un facteur nul doit pouvoir annuler le tirage
// d'une piste (c'est le role du repos), ce qu'une somme ne permet pas.
package tirage

import (
	"errors"
	"math"
	"math/rand"
	"sort"
	"time"
)

// Piste : ce que le tirage a besoin de savoir, et rien de plus.
type Piste struct {
	ID       int64
	AjouteLe time.Time
	Coeurs   int
	// JoueeLe : zero si jamais jouee. Une piste jamais jouee n'est PAS au
	// repos — elle est au contraire ce qu'on cherche a faire passer.
	JoueeLe time.Time
	// Indisponible : telechargement en echec. Ecartee du tirage sans etre
	// supprimee — elle peut redevenir disponible, et un titre qui disparait
	// sans trace fait chercher la panne ailleurs.
	Indisponible bool
}

// Reglages : les trois curseurs du panneau.
type Reglages struct {
	// Nouveaute : facteur applique a une piste ajoutee a l'instant. 1 = pas de
	// faveur. Retombe vers 1 sur DemiVieNouveaute.
	Nouveaute        float64
	DemiVieNouveaute time.Duration
	// Coeurs : k dans `1 + k·ln(1+coeurs)`. SOUS-LINEAIRE A DESSEIN — avec une
	// ponderation lineaire, un titre a 50 coeurs passerait 50 fois plus qu'un
	// titre a 1, trois succes monopoliseraient l'antenne, et la radio cesserait
	// d'etre collective.
	Coeurs float64
	// Repos : duree pendant laquelle une piste qui vient de passer reste ecartee.
	// C'EST CE FACTEUR, ET NON L'ALEATOIRE, qui empeche le ressassement : un
	// tirage pondere FAVORISE la repetition, puisque ce qui a un poids fort sort
	// souvent et revient donc vite.
	Repos time.Duration
}

// Defaut : des reglages qui donnent une radio ecoutable sans rien regler.
func Defaut() Reglages {
	return Reglages{
		Nouveaute:        2.4,
		DemiVieNouveaute: 7 * 24 * time.Hour,
		Coeurs:           0.45,
		Repos:            2 * time.Hour,
	}
}

// PoidsMin : aucune piste n'atteint jamais zero DEFINITIVEMENT.
//
// Sans ce plancher, une piste sortie du repos mais sans coeur ni nouveaute
// pourrait tomber si bas qu'elle ne repasserait plus jamais — elle aurait
// disparu de la radio sans que personne ne l'ait retiree.
const PoidsMin = 1e-4

var ErrAucunePiste = errors.New("aucune piste jouable")

// Poids evalue une piste a l'instant donne.
func Poids(p Piste, r Reglages, maintenant time.Time) float64 {
	if p.Indisponible {
		return 0
	}
	return math.Max(PoidsMin,
		facteurNouveaute(p, r, maintenant)*
			facteurCoeurs(p, r)*
			facteurRepos(p, r, maintenant))
}

// facteurNouveaute decroit CONTINUMENT vers 1.
//
// Un seuil ferme (« nouveau pendant 7 jours ») ferait chuter une piste d'un
// coup au huitieme jour : on entendrait la marche, et le reglage deviendrait
// une falaise plutot qu'une pente.
func facteurNouveaute(p Piste, r Reglages, maintenant time.Time) float64 {
	if r.Nouveaute <= 1 || p.AjouteLe.IsZero() || r.DemiVieNouveaute <= 0 {
		return 1
	}
	age := maintenant.Sub(p.AjouteLe)
	if age < 0 {
		age = 0 // horloge de travers : on ne recompense pas le futur
	}
	// Decroissance exponentielle de (Nouveaute-1) vers 0.
	return 1 + (r.Nouveaute-1)*math.Exp2(-float64(age)/float64(r.DemiVieNouveaute))
}

func facteurCoeurs(p Piste, r Reglages) float64 {
	if r.Coeurs <= 0 || p.Coeurs <= 0 {
		return 1
	}
	return 1 + r.Coeurs*math.Log1p(float64(p.Coeurs))
}

// facteurRepos remonte de 0 a 1 sur la duree de repos.
//
// LINEAIRE, et non brutal : une piste qui redevient jouable d'un coup a la
// seconde pres produirait un pic de probabilite juste apres l'echeance.
func facteurRepos(p Piste, r Reglages, maintenant time.Time) float64 {
	// UNE PISTE JAMAIS JOUEE N'EST PAS AU REPOS — c'est au contraire ce qu'on
	// cherche a faire passer.
	//
	// LE TEST `IsZero` EST REDONDANT AVEC L'ARITHMETIQUE, et c'est verifie :
	// sans lui, `maintenant.Sub(zero)` vaut environ deux mille ans, donc
	// depasse le repos, donc rend 1 — le meme resultat. Il est garde pour dire
	// l'intention, pas pour corriger un defaut. Le supprimer ne casse aucun
	// test, et il ne faut pas croire le contraire.
	if r.Repos <= 0 || p.JoueeLe.IsZero() {
		return 1
	}
	depuis := maintenant.Sub(p.JoueeLe)
	if depuis <= 0 {
		return 0
	}
	if depuis >= r.Repos {
		return 1
	}
	return float64(depuis) / float64(r.Repos)
}

// Suivante tire une piste, ponderee.
//
// `alea` est fourni par l'appelant pour que le tirage soit REJOUABLE depuis sa
// graine : on doit pouvoir expliquer apres coup pourquoi tel titre est passe.
func Suivante(pistes []Piste, r Reglages, maintenant time.Time, alea *rand.Rand) (Piste, error) {
	var total float64
	poids := make([]float64, len(pistes))
	for i, p := range pistes {
		poids[i] = Poids(p, r, maintenant)
		total += poids[i]
	}
	if total <= 0 {
		return Piste{}, ErrAucunePiste
	}
	seuil := alea.Float64() * total
	for i, w := range poids {
		seuil -= w
		if seuil <= 0 {
			return pistes[i], nil
		}
	}
	// Les arrondis flottants peuvent laisser un residu positif : on rend la
	// derniere piste JOUABLE plutot que de repondre « aucune », ce qui serait
	// faux puisque le total est strictement positif.
	for i := len(pistes) - 1; i >= 0; i-- {
		if poids[i] > 0 {
			return pistes[i], nil
		}
	}
	return Piste{}, ErrAucunePiste
}

// Probabilites rend la chance de chaque piste au prochain tirage.
//
// Le panneau les affiche AVANT qu'on bouge un curseur : un reglage dont on ne
// voit pas l'effet se regle a l'aveugle.
func Probabilites(pistes []Piste, r Reglages, maintenant time.Time) map[int64]float64 {
	out := make(map[int64]float64, len(pistes))
	var total float64
	for _, p := range pistes {
		w := Poids(p, r, maintenant)
		out[p.ID] = w
		total += w
	}
	if total <= 0 {
		return out
	}
	for id, w := range out {
		out[id] = w / total
	}
	return out
}

// Programme tire les `n` prochaines pistes SANS remise, en tenant compte du
// repos que chaque passage impose aux suivantes.
//
// POURQUOI FIGER LES PROCHAINES. Une file qui change a chaque rafraichissement
// donne l'impression d'un bug — on regarde ce qui vient, on recharge, ce n'est
// plus la meme chose. On en fige donc quelques-unes, et l'on ne decide de la
// suite qu'au fur et a mesure.
func Programme(pistes []Piste, r Reglages, depuis time.Time, n int, alea *rand.Rand) []Piste {
	etat := make([]Piste, len(pistes))
	copy(etat, pistes)
	out := make([]Piste, 0, n)
	t := depuis
	for len(out) < n {
		p, err := Suivante(etat, r, t, alea)
		if err != nil {
			break
		}
		out = append(out, p)
		// La piste tiree passe au repos pour les tirages suivants, sinon le
		// programme repeterait le meme titre trois fois de suite.
		for i := range etat {
			if etat[i].ID == p.ID {
				etat[i].JoueeLe = t
			}
		}
		t = t.Add(time.Second) // le temps avance : le repos se relache
	}
	return out
}

// ParPoidsDecroissant : l'ordre d'affichage du panneau.
func ParPoidsDecroissant(pistes []Piste, r Reglages, maintenant time.Time) []Piste {
	out := make([]Piste, len(pistes))
	copy(out, pistes)
	sort.SliceStable(out, func(i, j int) bool {
		return Poids(out[i], r, maintenant) > Poids(out[j], r, maintenant)
	})
	return out
}
