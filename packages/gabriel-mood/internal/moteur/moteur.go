// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package moteur — la chaîne d'analyse d'UNE session.
//
// Une session = une personne devant son navigateur. Tout y est local à la
// session : le plancher de bruit du VAD (ce n'est pas la même pièce), l'étalon
// prosodique (ce n'est pas la même voix), l'historique. Rien n'est partagé —
// mélanger deux locuteurs dans le même ordinaire produirait un ordinaire qui
// n'est celui de personne.
package moteur

import (
	"math"
	"sync"
	"time"

	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/audio"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/fft"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/mfcc"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/pitch"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/ser"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/vad"
)

// Réglages de la chaîne. Ils se tiennent : la trame fixe la plus basse
// fréquence analysable, le pas fixe la latence, et le rapport des deux fixe le
// coût processeur.
const (
	// 2048 échantillons = 42,7 ms. Il en faut au moins deux périodes pour que
	// YIN voie la fondamentale : à 55 Hz, une période dure 18 ms, donc 2048
	// est le minimum viable. 1024 plafonnerait la détection à 94 Hz — au-dessus
	// de beaucoup de voix d'hommes.
	TailleTrame = 2048
	// 512 échantillons = 10,7 ms. C'est LA latence d'analyse : on ne peut rien
	// dire d'un son avant d'avoir accumulé un pas.
	PasTrame = 512
	// Le spectre envoyé à l'écran est réduit à ce nombre de bandes. 1025 raies
	// à vingt images par seconde feraient 150 ko/s de JSON pour un affichage
	// large de quelques centaines de pixels : on enverrait dix fois plus de
	// chiffres que l'écran ne peut en montrer.
	BandesAffichees = 128
	// YIN coûte cinq fois une FFT. Le lancer une trame sur deux suffit
	// largement — la hauteur d'une voix ne change pas en dix millisecondes —
	// et divise par deux le poste le plus cher de la chaîne.
	PasPitch = 2
	// Fenêtre d'agrégation des traits : une seconde de voix. Plus court, les
	// indices sautent à chaque syllabe ; plus long, ils ne suivent plus la
	// conversation.
	FenetreTraits = 100
)

// Image : ce qui part vers l'écran, vingt fois par seconde.
//
// Les noms JSON suivent le contrat annoncé (`calm`, `joy`, `stress`, `anger`)
// et l'étendent : l'interface montre aussi fatigue et concentration, et il
// vaut mieux les nommer que les faire deviner.
type Image struct {
	Horodatage int64     `json:"timestamp"` // ms depuis le début de la session
	FFT        []float64 `json:"fft"`       // dBFS, BandesAffichees valeurs
	Pitch      float64   `json:"pitch"`     // Hz, 0 si non voisé
	Energie    float64   `json:"energy"`    // RMS 0..1

	Calme     float64 `json:"calm"`
	Joie      float64 `json:"joy"`
	Tension   float64 `json:"stress"`
	Colere    float64 `json:"anger"`
	Fatigue   float64 `json:"fatigue"`
	Concentre float64 `json:"focus"`

	Etat       string  `json:"state"`
	Motif      string  `json:"motif,omitempty"`
	Reference  string  `json:"reference,omitempty"`
	Confiance  float64 `json:"confidence"`
	Activation float64 `json:"activation"`

	// TENDANCES : où va chaque indice, et pas seulement où il est. Un calme à
	// 0,55 qui MONTE et un calme à 0,55 qui descend ne racontent pas la même
	// chose, et c'est souvent la pente qui intéresse — pas la valeur.
	// Différence entre l'indice courant et sa moyenne sur la mémoire courte.
	Tendances map[string]float64 `json:"trends"`

	Voix    bool    `json:"vad"`
	Debit   float64 `json:"speech_rate"` // syllabes/minute
	Jitter  float64 `json:"jitter"`      // %
	Shimmer float64 `json:"shimmer"`     // dB
	Clarte  float64 `json:"clarity"`     // 0..1, qualité de la mesure de hauteur

	LatenceMs float64 `json:"latency_ms"`
	ChargeCPU float64 `json:"cpu"` // part d'un cœur, 0..1
	// Fiabilite REMPLACE « calibration » : ce n'était pas une progression vers
	// un achèvement, et l'afficher comme telle promettait une fin qui n'arrive
	// jamais. Le champ JSON garde son nom pour les consommateurs existants.
	Fiabilite    float64 `json:"calibration"` // 0..1
	Observations int     `json:"observations"`

	SourceReelle bool   `json:"source_reelle"`
	Reserve      string `json:"reserve"`
}

// Analyseur : la chaîne d'une session.
type Analyseur struct {
	mu sync.RWMutex

	plan    *fft.Plan
	banc    *mfcc.Banc
	yin     *pitch.Estimateur
	vad     *vad.Detecteur
	pert    *pitch.Perturbation
	ref     *ser.Reference
	classif ser.Classifieur

	anneau *audio.Anneau
	source audio.Source
	debut  time.Time

	// tampons réutilisés — voir les commentaires d'allocation dans fft/pitch
	mag       []float64
	puissance []float64
	bandes    []float64

	nTrame      int
	derniere    Image
	derniereLec ser.Lecture
	traits      ser.Traits

	// agrégation sur la fenêtre
	fenEnergies  []float64
	fenVoisees   int
	fenTotal     int
	cpuCumul     time.Duration
	cpuFenetre   time.Time
	derniereF0   float64
	derniereClar float64

	// Mémoire courte des indices, pour les tendances. Vingt secondes : assez
	// pour qu'une pente veuille dire quelque chose, assez court pour qu'elle
	// suive la conversation.
	memoire []map[string]float64

	partage *ser.EtalonPartage
	session string
}

// MemoireTendance : combien de lectures on garde pour calculer une pente. Une
// lecture par fenêtre de traits, soit environ une par seconde.
const MemoireTendance = 20

// Nouveau prépare la chaîne pour une source donnée.
func Nouveau(src audio.Source) *Analyseur { return NouveauAvecPartage(src, nil, "") }

// NouveauAvecPartage relie la chaîne à l'ordinaire du GROUPE : elle s'en sert
// comme repère tant que l'ordinaire personnel n'existe pas, et y contribue le
// sien une fois qu'il est complet.
func NouveauAvecPartage(src audio.Source, partage *ser.EtalonPartage, session string) *Analyseur {
	plan := fft.NouveauPlan(TailleTrame)
	raies := TailleTrame/2 + 1
	// RÉFÉRENCE EN LIGNE : utilisable dès la première mesure, et de plus en
	// plus sûre. Il n'y a plus de phase d'apprentissage à attendre.
	ref := ser.NouvelleReference()
	a := &Analyseur{
		plan:       plan,
		banc:       mfcc.NouveauBanc(26, raies, audio.Echantillonnage, 50, 8000),
		yin:        pitch.NouvelEstimateur(TailleTrame, audio.Echantillonnage),
		vad:        vad.Nouveau(raies, audio.Echantillonnage, vad.Normal, 12),
		pert:       pitch.NouvellePerturbation(80),
		ref:        ref,
		classif:    ser.NouvelleHeuristique(ref).AvecEtalonPartage(partage),
		anneau:     audio.NouvelAnneau(TailleTrame, PasTrame),
		source:     src,
		debut:      time.Now(),
		puissance:  make([]float64, raies),
		bandes:     make([]float64, BandesAffichees),
		cpuFenetre: time.Now(),
	}
	a.derniereLec = ser.LectureIndeterminee(ser.MotifPeuDeVoix, "session qui démarre", false)
	return a
}

// RemplaceClassifieur permet de brancher l'inférence externe. Le secours reste
// l'heuristique : un modèle absent ne doit pas faire taire le module.
func (a *Analyseur) RemplaceClassifieur(c ser.Classifieur) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.classif = c
}

// Source décrit d'où viennent les échantillons.
func (a *Analyseur) Source() audio.Description { return a.source.Decrit() }

// Tourne consomme la source jusqu'à épuisement ou fermeture. `surImage` est
// appelée au rythme demandé, pas à chaque trame : l'analyse tourne à ~94 Hz,
// l'écran n'a besoin que de 20.
func (a *Analyseur) Tourne(parSeconde int, surImage func(Image)) error {
	if parSeconde <= 0 {
		parSeconde = 20
	}
	intervalle := time.Second / time.Duration(parSeconde)
	dernierEnvoi := time.Now()
	bloc := make([]float64, PasTrame)

	for {
		n, err := a.source.Lis(bloc)
		if err != nil {
			return err
		}
		a.anneau.Ecris(bloc[:n], a.analyseTrame)
		if time.Since(dernierEnvoi) >= intervalle {
			dernierEnvoi = time.Now()
			if surImage != nil {
				surImage(a.Derniere())
			}
		}
	}
}

// analyseTrame : le cœur. Une trame, toutes les mesures.
//
// LE CHRONOMÈTRE EST ICI, ET PAS CHEZ L'APPELANT. Il y était, et la charge
// affichée tombait à zéro dès qu'on pilotait la chaîne autrement que par la
// boucle temps réel — ce que fait l'ingestion WebSocket. Une mesure qui dépend
// de QUI appelle n'est pas une mesure du travail, c'est une mesure d'un chemin.
func (a *Analyseur) analyseTrame(trame []float64) {
	chrono := time.Now()
	defer func() { a.cpuCumul += time.Since(chrono) }()
	a.nTrame++

	a.mag = a.plan.Spectre(trame, a.mag)
	for i, m := range a.mag {
		a.puissance[i] = m * m
	}

	v := a.vad.Analyse(a.puissance)

	// RMS sur la trame : l'énergie perçue, pas le maximum, qui sauterait à
	// chaque claquement.
	var somme float64
	for _, s := range trame {
		somme += s * s
	}
	rms := math.Sqrt(somme / float64(len(trame)))

	// LA HAUTEUR NE SE MESURE QUE SUR DE LA VOIX. La chercher dans du bruit
	// donne un nombre — YIN en rend toujours un — qui n'a aucun référent.
	if v.Parole && a.nTrame%PasPitch == 0 {
		r := a.yin.Estime(trame)
		a.derniereF0, a.derniereClar = r.Hz, r.Clarte
		if r.Voise {
			a.pert.Ajoute(r.Periode, rms)
		}
	} else if !v.Parole {
		a.derniereF0, a.derniereClar = 0, 0
	}

	a.fenEnergies = append(a.fenEnergies, rms)
	a.fenTotal++
	if v.Parole {
		a.fenVoisees++
	}
	if len(a.fenEnergies) > FenetreTraits {
		a.fenEnergies = a.fenEnergies[1:]
	}

	// SILENCE PROLONGÉ : on oublie les périodes. Sans cela, les deux côtés
	// d'une pause de dix secondes seraient comparés comme deux cycles
	// consécutifs, et le jitter exploserait sans raison.
	if !v.Parole && a.fenVoisees == 0 {
		a.pert.Oublie()
	}

	a.reduitSpectre()

	if a.nTrame%FenetreTraits == 0 {
		a.majTraits()
	}
	a.majImage(v, rms)
}

// reduitSpectre ramène les 1025 raies aux bandes affichées, en ÉCHELLE
// LOGARITHMIQUE : une bande linéaire donnerait quatre-vingts pour cent des
// pixels aux aigus, où la voix n'a presque rien, et écraserait la région
// 100–1000 Hz qui porte tout.
func (a *Analyseur) reduitSpectre() {
	n := len(a.mag)
	fmin, fmax := 50.0, 8000.0
	pas := audio.Echantillonnage / float64(2*(n-1))
	for b := 0; b < BandesAffichees; b++ {
		f0 := fmin * math.Pow(fmax/fmin, float64(b)/BandesAffichees)
		f1 := fmin * math.Pow(fmax/fmin, float64(b+1)/BandesAffichees)
		k0, k1 := int(f0/pas), int(f1/pas)
		if k1 <= k0 {
			k1 = k0 + 1
		}
		if k1 >= n {
			k1 = n - 1
		}
		if k0 >= n {
			k0 = n - 1
		}
		// Maximum et non moyenne : une raie fine (une harmonique) doit rester
		// visible même quand la bande qui la contient est large.
		crete := 0.0
		for k := k0; k <= k1; k++ {
			if a.mag[k] > crete {
				crete = a.mag[k]
			}
		}
		a.bandes[b] = math.Round(fft.Decibels(crete, -100)*10) / 10
	}
}

// majTraits recalcule les traits agrégés et la lecture, une fois par fenêtre.
func (a *Analyseur) majTraits() {
	var moy, moy2 float64
	for _, e := range a.fenEnergies {
		moy += e
	}
	if len(a.fenEnergies) > 0 {
		moy /= float64(len(a.fenEnergies))
		for _, e := range a.fenEnergies {
			moy2 += (e - moy) * (e - moy)
		}
		moy2 = math.Sqrt(moy2 / float64(len(a.fenEnergies)))
	}
	part := 0.0
	if a.fenTotal > 0 {
		part = float64(a.fenVoisees) / float64(a.fenTotal)
	}

	t := ser.Traits{
		F0Median:      a.pert.MedianeF0(audio.Echantillonnage),
		F0Etendue:     a.pert.EtendueF0(audio.Echantillonnage),
		Energie:       moy,
		EnergieVar:    moy2,
		Debit:         a.debitSyllabique(),
		Jitter:        a.pert.Jitter(),
		Shimmer:       a.pert.Shimmer(),
		Centre:        mfcc.CentreDeGravite(a.puissance, audio.Echantillonnage),
		Platitude:     mfcc.PlatitudeSpectrale(a.puissance),
		Pente:         mfcc.PenteSpectrale(a.puissance, audio.Echantillonnage),
		PartVoisee:    part,
		TramesVoisees: a.fenVoisees,
	}

	a.mu.Lock()
	a.traits = t
	a.mu.Unlock()

	a.ref.Observe(t)
	// ON NE PARTAGE QUE CE QUI EST ÉTABLI (le seuil de fiabilité est dans
	// Contribue) : un ordinaire approximatif mis en commun donnerait un
	// à-peu-près commun, et personne n'y gagnerait.
	if a.partage != nil {
		a.partage.Contribue(a.session, a.ref)
	}
	lec := a.classif.Evalue(t)

	a.mu.Lock()
	a.derniereLec = lec
	// ON NE MÉMORISE QUE LES LECTURES QUI EN SONT. Empiler les indices d'un
	// refus — tous à zéro — ferait plonger toutes les tendances à chaque
	// silence, et l'on lirait « le calme s'effondre » alors que personne ne
	// parlait.
	if lec.Etat != ser.Indetermine && lec.Indices != nil {
		c := make(map[string]float64, len(lec.Indices))
		for k, v := range lec.Indices {
			c[k] = v
		}
		a.memoire = append(a.memoire, c)
		if len(a.memoire) > MemoireTendance {
			a.memoire = a.memoire[1:]
		}
	}
	a.mu.Unlock()

	a.fenVoisees, a.fenTotal = 0, 0
}

// debitSyllabique compte les NOYAUX de syllabe : les sommets de l'enveloppe
// d'énergie, espacés d'au moins cent millisecondes.
//
// CE N'EST PAS UNE TRANSCRIPTION. On ne reconnaît pas des syllabes, on compte
// des bosses d'énergie — ce qui les surestime sur une voix hachée et les
// sous-estime sur une parole liée. L'ordre de grandeur est juste (une parole
// ordinaire tourne autour de 200 à 300 syllabes/minute) ; le chiffre exact ne
// l'est pas, et rien dans le module ne le traite comme tel.
func (a *Analyseur) debitSyllabique() float64 {
	n := len(a.fenEnergies)
	if n < 10 {
		return 0
	}
	// Lissage court : sans lui, chaque micro-variation compte pour une syllabe.
	lisse := make([]float64, n)
	const demi = 2
	for i := range lisse {
		var s float64
		var c int
		for j := i - demi; j <= i+demi; j++ {
			if j >= 0 && j < n {
				s += a.fenEnergies[j]
				c++
			}
		}
		lisse[i] = s / float64(c)
	}
	var moy float64
	for _, v := range lisse {
		moy += v
	}
	moy /= float64(n)
	seuil := moy * 0.6

	// Espacement minimal : 100 ms, soit une syllabe toutes les ~9 trames au
	// pas de 10,7 ms. Au-delà de dix syllabes par seconde, ce n'est plus de la
	// parole humaine.
	const ecartMin = 9
	compte, dernier := 0, -ecartMin
	for i := 1; i < n-1; i++ {
		if lisse[i] > seuil && lisse[i] >= lisse[i-1] && lisse[i] > lisse[i+1] &&
			i-dernier >= ecartMin {
			compte++
			dernier = i
		}
	}
	duree := float64(n) * float64(PasTrame) / audio.Echantillonnage
	if duree <= 0 {
		return 0
	}
	return float64(compte) / duree * 60
}

// tendances : l'écart de chaque indice à sa moyenne récente.
//
// UN INDICE QUI MONTE ET UN INDICE QUI DESCEND NE DISENT PAS LA MÊME CHOSE à
// valeur égale, et c'est souvent la pente qui intéresse plutôt que le niveau.
//
// Il faut quelques lectures pour qu'une moyenne existe : en-dessous on rend
// une carte VIDE plutôt que des zéros, qui se liraient comme « stable » alors
// qu'on ne sait encore rien.
func (a *Analyseur) tendances() map[string]float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if len(a.memoire) < 4 {
		return nil
	}
	courant := a.memoire[len(a.memoire)-1]
	out := make(map[string]float64, len(courant))
	for _, k := range ser.Etats {
		var somme float64
		for _, m := range a.memoire {
			somme += m[k]
		}
		moy := somme / float64(len(a.memoire))
		out[k] = math.Round((courant[k]-moy)*1000) / 1000
	}
	return out
}

func (a *Analyseur) majImage(v vad.Verdict, rms float64) {
	a.mu.RLock()
	lec := a.derniereLec
	a.mu.RUnlock()

	ind := lec.Indices
	get := func(k string) float64 {
		if ind == nil {
			return 0
		}
		return ind[k]
	}

	// Charge : le temps passé à analyser rapporté au temps écoulé. C'est une
	// mesure, pas une estimation — et elle inclut tout ce que fait la chaîne.
	charge := 0.0
	if d := time.Since(a.cpuFenetre); d > 0 {
		charge = float64(a.cpuCumul) / float64(d)
	}
	if time.Since(a.cpuFenetre) > time.Second {
		a.cpuCumul, a.cpuFenetre = 0, time.Now()
	}

	// Latence : le pas d'analyse, plus ce qui attend dans la source.
	lat := float64(PasTrame) / audio.Echantillonnage * 1000
	if n, ok := a.source.(interface{ Retard() time.Duration }); ok {
		lat += float64(n.Retard().Microseconds()) / 1000
	}

	img := Image{
		Horodatage: time.Since(a.debut).Milliseconds(),
		FFT:        append([]float64(nil), a.bandes...),
		Pitch:      math.Round(a.derniereF0*10) / 10,
		Energie:    math.Round(rms*1000) / 1000,
		Calme:      get(ser.Calme), Joie: get(ser.Joie),
		Tension: get(ser.Tension), Colere: get(ser.Colere),
		Fatigue: get(ser.Fatigue), Concentre: get(ser.Concentre),
		Etat: lec.Etat, Motif: lec.Motif, Reference: lec.Reference,
		Confiance:  lec.Confiance,
		Activation: lec.Activation, Tendances: a.tendances(),
		Voix:         v.Parole,
		Clarte:       math.Round(a.derniereClar*100) / 100,
		LatenceMs:    math.Round(lat*10) / 10,
		ChargeCPU:    math.Round(charge*1000) / 1000,
		Fiabilite:    math.Round(lec.Fiabilite*100) / 100,
		Observations: lec.Observations,
		SourceReelle: a.source.Decrit().Reelle,
		Reserve:      lec.Reserve,
	}
	a.mu.RLock()
	img.Debit = math.Round(a.traits.Debit)
	img.Jitter = math.Round(a.traits.Jitter*100) / 100
	img.Shimmer = math.Round(a.traits.Shimmer*100) / 100
	a.mu.RUnlock()

	a.mu.Lock()
	a.derniere = img
	a.mu.Unlock()
}

// Derniere rend la dernière image calculée — sûre en accès concurrent.
func (a *Analyseur) Derniere() Image {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.derniere
}

// Lecture rend la dernière lecture, avec ses justifications et sa réserve.
func (a *Analyseur) Lecture() ser.Lecture {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.derniereLec
}

// Traits rend les mesures brutes de la dernière fenêtre.
func (a *Analyseur) Traits() ser.Traits {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.traits
}
