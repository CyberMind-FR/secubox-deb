// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package ser

import "testing"

func etalonDe(f0, energie, debit float64) *Etalon {
	e := NouvelEtalon(600)
	for i := 0; i < MinimumEtalon+10; i++ {
		d := float64(i%20-10) / 10
		e.Observe(Traits{
			F0Median: f0 + d*18, Energie: energie + d*0.08, Debit: debit + d*30,
			Jitter: 0.8 + d*0.3, Centre: 1400 + d*300, TramesVoisees: 60,
		})
	}
	return e
}

// ── LE SEUIL EST LA PROMESSE ───────────────────────────────────────────────
//
// À UN contributeur, l'« ordinaire du groupe » EST la signature vocale de
// cette personne, sous un autre nom. À DEUX, celui qui connaît la sienne
// retrouve l'autre par soustraction. Ces tests gardent la règle.

func TestUnSeulContributeurNeFaitPasUneBaseCommune(t *testing.T) {
	p := NouvelEtalonPartage()
	p.Contribue("a", etalonDe(130, .3, 150))
	if p.Utilisable() {
		t.Fatal("la base est déclarée utilisable avec UNE voix : c'est cette voix, pas un groupe")
	}
	if p.Ecarts(Traits{F0Median: 180}) != nil {
		t.Fatal("des écarts sont rendus depuis une base d'une seule personne")
	}
}

func TestDeuxContributeursNonPlus(t *testing.T) {
	p := NouvelEtalonPartage()
	p.Contribue("a", etalonDe(130, .3, 150))
	p.Contribue("b", etalonDe(190, .4, 190))
	if p.Utilisable() {
		t.Fatal("à deux, qui connaît son propre ordinaire obtient l'autre par soustraction")
	}
}

func TestATroisLaBaseSert(t *testing.T) {
	p := NouvelEtalonPartage()
	p.Contribue("a", etalonDe(120, .25, 140))
	p.Contribue("b", etalonDe(150, .32, 165))
	p.Contribue("c", etalonDe(185, .40, 195))
	if !p.Utilisable() || p.Contributeurs() != 3 {
		t.Fatalf("base inutilisable à %d contributeurs", p.Contributeurs())
	}
	e := p.Ecarts(Traits{F0Median: 260, Energie: .7, Debit: 300, Jitter: 3, Centre: 3000})
	if e == nil || e["f0"] <= 0 {
		t.Fatalf("une voix nettement plus haute que le groupe doit donner un écart positif : %v", e)
	}
}

// UN DÉPART EFFACE LA CONTRIBUTION. Rien ne doit subsister de quelqu'un qui a
// fermé son onglet — et surtout pas son ordinaire vocal, qui l'identifie mieux
// qu'on ne le croit.
func TestUnDepartEffaceLaContribution(t *testing.T) {
	p := NouvelEtalonPartage()
	p.Contribue("a", etalonDe(120, .25, 140))
	p.Contribue("b", etalonDe(150, .32, 165))
	p.Contribue("c", etalonDe(185, .40, 195))
	p.Retire("b")
	if p.Contributeurs() != 2 {
		t.Fatalf("%d contributeurs après un départ", p.Contributeurs())
	}
	if p.Utilisable() {
		t.Fatal("la base reste utilisable en repassant sous le seuil")
	}
}

// UN ORDINAIRE INCOMPLET NE SE PARTAGE PAS : un à-peu-part commun ne sert
// personne, et il embarque du bruit dans la référence de tout le monde.
func TestUnEtalonIncompletNeContribuePas(t *testing.T) {
	p := NouvelEtalonPartage()
	partiel := NouvelEtalon(600)
	for i := 0; i < MinimumEtalonProvisoire+5; i++ {
		partiel.Observe(Traits{F0Median: 130, Energie: .3, TramesVoisees: 60})
	}
	if partiel.Pret() {
		t.Skip("fixture invalide")
	}
	p.Contribue("a", partiel)
	if p.Contributeurs() != 0 {
		t.Fatal("un étalon incomplet a été mis en commun")
	}
}

// ── LA LECTURE DIT SUR QUOI ELLE S'APPUIE ─────────────────────────────────
//
// Lire « tension » sans savoir qu'on est comparé à d'AUTRES voix, ce serait
// croire à une mesure personnelle. La référence doit être dans la réponse.

func TestUneLectureDeSecoursSeDeclareEtSeBride(t *testing.T) {
	p := NouvelEtalonPartage()
	p.Contribue("a", etalonDe(120, .25, 140))
	p.Contribue("b", etalonDe(150, .32, 165))
	p.Contribue("c", etalonDe(185, .40, 195))

	// Quelqu'un qui arrive : son propre étalon est vide.
	h := NouvelleHeuristique(NouvelEtalon(600)).AvecEtalonPartage(p)
	l := h.Evalue(Traits{F0Median: 240, F0Etendue: 6, Energie: .62, Debit: 260,
		Jitter: 1.4, Shimmer: .7, Centre: 2600, Platitude: .2,
		PartVoisee: .6, TramesVoisees: 60})

	if l.Etat == Indetermine {
		t.Fatal("sans base commune on se taisait ; avec elle on doit pouvoir répondre")
	}
	if l.Reference != "groupe" {
		t.Errorf("référence %q : la lecture ne dit pas qu'elle compare à d'autres voix", l.Reference)
	}
	if l.Confiance > PlafondGroupe {
		t.Errorf("confiance %.3f au-dessus du plafond de groupe %.2f", l.Confiance, PlafondGroupe)
	}
	if l.Etalonne {
		t.Error("prétend avoir un étalon personnel")
	}
}

func TestSansBaseCommuneNiPersonnelleOnSeTait(t *testing.T) {
	h := NouvelleHeuristique(NouvelEtalon(600)).AvecEtalonPartage(NouvelEtalonPartage())
	l := h.Evalue(Traits{F0Median: 240, Energie: .6, Platitude: .2,
		PartVoisee: .6, TramesVoisees: 60})
	if l.Etat != Indetermine || l.Motif != MotifEtalonnage {
		t.Fatalf("état %q motif %q", l.Etat, l.Motif)
	}
}

// L'ordinaire PERSONNEL l'emporte dès qu'il existe : la base commune est un
// secours, jamais une norme qui s'imposerait à quelqu'un.
func TestLOrdinairePersonnelLEmporte(t *testing.T) {
	p := NouvelEtalonPartage()
	p.Contribue("a", etalonDe(120, .25, 140))
	p.Contribue("b", etalonDe(150, .32, 165))
	p.Contribue("c", etalonDe(185, .40, 195))

	h := NouvelleHeuristique(etalonDe(240, .6, 260)).AvecEtalonPartage(p)
	l := h.Evalue(Traits{F0Median: 240, F0Etendue: 4, Energie: .6, Debit: 260,
		Jitter: .8, Shimmer: .5, Centre: 1400, Platitude: .2,
		PartVoisee: .6, TramesVoisees: 60})
	if l.Reference != "vous" {
		t.Fatalf("référence %q : l'ordinaire personnel doit primer", l.Reference)
	}
	// Une voix naturellement haute, à SON ordinaire, ne doit pas être lue
	// comme activée sous prétexte qu'elle est plus haute que le groupe.
	if l.Activation > 0.3 {
		t.Errorf("activation %+.2f : la voix est pourtant à son propre ordinaire", l.Activation)
	}
}
