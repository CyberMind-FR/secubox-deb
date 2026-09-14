// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package similarity

import "testing"

func TestSimilarite_FortsSignaux(t *testing.T) {
	base := Signature{
		CredentialHash: "hmac-abc", PathSig: "sig-1", UAFamily: "nuclei",
		TLSFingerprint: "ja4-x", CadenceBucket: "6-30", IP: "203.0.113.7",
		ASN: 13335, Country: "US", SeenAt: 1000,
	}
	b := base
	b.SeenAt = 1000 // même instant → IP à pleine contribution
	s := Similarity(base, b)
	// 30+18+12+12+8+10+5+1 = 96
	if s.Value < 85 {
		t.Fatalf("continuité forte attendue, obtenu %d", s.Value)
	}
	if Band(s.Value) != BandVeryStrong {
		t.Errorf("bande = %q", Band(s.Value))
	}
}

func TestSimilarite_PaysSeulNonDecisif(t *testing.T) {
	a := Signature{Country: "FR"}
	b := Signature{Country: "FR"}
	s := Similarity(a, b)
	if s.Value != WCountry { // 1
		t.Errorf("pays seul = %d, attendu %d", s.Value, WCountry)
	}
	if Band(s.Value) != BandNonRelated {
		t.Errorf("le pays seul ne doit jamais franchir un seuil : bande %q", Band(s.Value))
	}
}

func TestSimilarite_CredentialSeul(t *testing.T) {
	a := Signature{CredentialHash: "h"}
	b := Signature{CredentialHash: "h"}
	if v := Similarity(a, b).Value; v != WCredential {
		t.Errorf("credential réutilisé seul = %d, attendu %d", v, WCredential)
	}
}

func TestSimilarite_DecroissanceIP(t *testing.T) {
	a := Signature{IP: "1.2.3.4", SeenAt: 0}
	proche := Signature{IP: "1.2.3.4", SeenAt: 60}         // 1 min
	loin := Signature{IP: "1.2.3.4", SeenAt: 6 * 3600 * 8} // 8 demi-vies
	if Similarity(a, proche).Value < 9 {
		t.Error("IP identique récente devrait contribuer ~10")
	}
	if Similarity(a, loin).Value != 0 {
		t.Errorf("IP identique très ancienne devrait décroître vers 0, obtenu %d", Similarity(a, loin).Value)
	}
}

func TestSimilarite_Vides(t *testing.T) {
	if v := Similarity(Signature{}, Signature{}).Value; v != 0 {
		t.Errorf("signatures vides = %d, attendu 0 (pas de faux pivot)", v)
	}
	// Champs vides identiques ne doivent pas matcher.
	a := Signature{CredentialHash: "", TLSFingerprint: ""}
	if v := Similarity(a, a).Value; v != 0 {
		t.Errorf("champs vides identiques = %d, attendu 0", v)
	}
}

// ── Seuil adapte aux capteurs presents (2026-09-14) ──────────────────────────

func TestSeuilEffectif_SeDetendQuandPeuDeCapteurs(t *testing.T) {
	// Cas reel de la box : seuls chemin (18), outil (12) et IP (10) sont
	// alimentes. Avec le seuil nominal de 50, le plafond atteignable etait 40 —
	// aucun rattachement n'etait possible, d'ou un acteur par evenement.
	const comparableReel = WPathSeq + WTool + WIP
	s := SeuilEffectif(50, comparableReel)
	if s >= comparableReel {
		t.Fatalf("seuil %d >= plafond atteignable %d : le rattachement reste impossible", s, comparableReel)
	}
	if s < MasseMin {
		t.Fatalf("seuil %d sous le plancher de masse %d", s, MasseMin)
	}
}

func TestSeuilEffectif_NeDescendJamaisSousLePlancher(t *testing.T) {
	// Un deploiement qui ne partagerait qu'un pays (poids 1) ne doit pas
	// rattacher pour autant : le plancher tient.
	if s := SeuilEffectif(50, WCountry); s != MasseMin {
		t.Fatalf("pays seul : seuil %d, attendu le plancher %d", s, MasseMin)
	}
}

func TestSeuilEffectif_TousCapteursRendLeSeuilNominal(t *testing.T) {
	if s := SeuilEffectif(50, PoidsTotal); s != 50 {
		t.Fatalf("tous capteurs : seuil %d, attendu le nominal 50", s)
	}
}

func TestComparable_IgnoreLesAxesQueLUnDesDeuxNePortePas(t *testing.T) {
	a := Signature{UAFamily: "nuclei", PathSig: "p1"}
	b := Signature{UAFamily: "nuclei"} // pas de PathSig : axe non comparable
	if got := Comparable(a, b); got != WTool {
		t.Fatalf("comparable = %d, attendu %d (l'outil seul)", got, WTool)
	}
}
