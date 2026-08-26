// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbx-authwatch — alimentation du set nft (#1220)
//
// On alimente L'ENSEMBLE DEJA EXISTANT du WAF, `inet secubox waf_ban{,6}`, et
// non un ensemble a nous. C'est le point de la demande : un seul endroit ou
// regarder qui est banni, une seule chaine qui applique, quelle que soit la
// surface qui a leve l'alerte — HTTP, SSH ou SMTP.
//
// LA GARDE, tiree de #1218. Ce jour-la on a decouvert que le WAF remplissait
// depuis des mois un set que RIEN ne consultait : ni chaine, ni regle, zero
// reference a @waf_ban dans tout le jeu de regles. Quatre-vingt-onze adresses
// « bannies » qui passaient toutes. On ne refera pas la meme erreur en silence :
// au demarrage, ce programme VERIFIE qu'une regle consulte reellement le set,
// et refuse de demarrer sinon. Mieux vaut un service qui ne demarre pas et le
// dit qu'un service qui compte des bannissements sans effet.
package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// executeur execute « nft <args…> ». Injectable : les tests observent les
// commandes sans toucher au pare-feu de la machine qui les fait tourner.
type executeur func(ctx context.Context, args ...string) ([]byte, error)

type Banneur struct {
	nftPath string
	table   string
	set4    string
	set6    string
	duree   time.Duration
	simule  bool
	exec    executeur
}

func NewBanneur(nftPath, table, set4, set6 string, duree time.Duration, simule bool) *Banneur {
	if nftPath == "" {
		nftPath = "nft"
	}
	b := &Banneur{nftPath: nftPath, table: table, set4: set4, set6: set6, duree: duree, simule: simule}
	b.exec = b.execReel
	return b
}

func (b *Banneur) execReel(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, b.nftPath, args...).CombinedOutput()
}

func (b *Banneur) run(ctx context.Context, args ...string) ([]byte, error) {
	return b.exec(ctx, args...)
}

// Verifie s'assure que les ensembles existent ET qu'une regle les consulte.
// Rend une erreur PARLANTE : le message doit suffire a savoir quoi reparer.
func (b *Banneur) Verifie(ctx context.Context) error {
	sortie, err := b.run(ctx, "list", "ruleset")
	if err != nil {
		return fmt.Errorf("lecture du jeu de regles nft impossible (droits ?) : %v", err)
	}
	texte := string(sortie)

	for _, set := range []string{b.set4, b.set6} {
		if !strings.Contains(texte, "set "+set+" ") && !strings.Contains(texte, "set "+set+" {") {
			return fmt.Errorf("l'ensemble %s n'existe pas dans la table %s — "+
				"sbxwaf doit tourner au moins une fois pour le creer", set, b.table)
		}
	}
	// La verification qui compte : une REGLE doit consulter l'ensemble.
	if !strings.Contains(texte, "@"+b.set4) {
		return fmt.Errorf("aucune regle ne consulte @%s : les bannissements seraient "+
			"comptes sans effet (c'est exactement le defaut #1218). "+
			"Verifier la chaine waf_drop de sbxwaf", b.set4)
	}
	return nil
}

// Bannit ajoute l'adresse a l'ensemble correspondant a sa famille.
//
// GARDE-FOU identique a celui du WAF : jamais une adresse privee. Le drop est
// reel ; une seule erreur en amont couperait l'administration de la box depuis
// la box. Le refus est ici, au dernier moment, ou rien ne peut le contourner.
func (b *Banneur) Bannit(ctx context.Context, ip string) error {
	p := net.ParseIP(ip)
	if p == nil {
		return fmt.Errorf("adresse invalide : %q", ip)
	}
	if p.IsLoopback() || p.IsPrivate() || p.IsLinkLocalUnicast() || p.IsUnspecified() {
		return fmt.Errorf("adresse privee refusee : %s", ip)
	}
	set := b.set6
	if p.To4() != nil {
		set = b.set4
	}
	elem := fmt.Sprintf("{ %s timeout %ds }", ip, int(b.duree.Seconds()))
	if b.simule {
		return nil
	}
	if out, err := b.run(ctx, "add", "element", "inet", b.table, set, elem); err != nil {
		return fmt.Errorf("nft add element %s : %v : %s", set, err, strings.TrimSpace(string(out)))
	}
	return nil
}
