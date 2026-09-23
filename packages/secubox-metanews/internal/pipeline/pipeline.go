// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package pipeline : la chaîne MetaNews — sonder les flux, normaliser, regrouper
// en événements, résumer. Colle store + linker + cluster + resume.
package pipeline

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/cluster"
	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/linker"
	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/resume"
	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/store"
)

// Pipe orchestre un tour de MetaNews.
type Pipe struct {
	st  *store.Store
	rss *linker.RSS
	jr  *log.Logger
}

// New crée le pipeline.
func New(st *store.Store, rss *linker.RSS, jr *log.Logger) *Pipe {
	return &Pipe{st: st, rss: rss, jr: jr}
}

// Tour exécute un sondage puis un regroupement. Retourne (articles neufs,
// sujets touchés).
func (p *Pipe) Tour(now int64) (int, int, error) {
	neufs, err := p.Sonder(now)
	if err != nil {
		return neufs, 0, err
	}
	touches, err := p.Regrouper(now)
	// Complète les vignettes des sujets dont les images d'articles viennent
	// d'être renseignées (re-sondage).
	_ = p.st.BackfillVignettes()
	return neufs, touches, err
}

// TesterURL récupère un flux et retourne le nombre d'articles lisibles (pour le
// bouton « tester » de la gestion des sources).
func (p *Pipe) TesterURL(u string) (int, error) {
	items, err := p.rss.Flux(u)
	if err != nil {
		return 0, err
	}
	return len(items), nil
}

// Sonder récupère les flux dus et insère les articles neufs.
func (p *Pipe) Sonder(now int64) (int, error) {
	srcs, err := p.st.SourcesDues(now)
	if err != nil {
		return 0, err
	}
	neufs := 0
	for _, src := range srcs {
		items, err := p.rss.Flux(src.URL)
		if err != nil {
			_ = p.st.MarquerSync(src.ID, now, err.Error())
			if p.jr != nil {
				p.jr.Printf("flux %q : %v", src.Slug, err)
			}
			continue
		}
		for _, it := range items {
			pub := it.PublieLe
			if pub == 0 {
				pub = now
			}
			a := store.Article{
				SourceID:    src.ID,
				Ref:         refOu(it.Ref, it.URL, it.Titre),
				Title:       it.Titre,
				URL:         it.URL,
				Summary:     tronquer(it.Corps, 500),
				Author:      it.Auteur,
				Lang:        it.Langue,
				PublishedAt: pub,
				FetchedAt:   now,
				Fingerprint: linker.Empreinte(it.Titre, it.Corps),
				Image:       it.Vignette,
				Entities:    cluster.Entites(it.Titre + " " + it.Corps),
				Tags:        nil,
			}
			if _, neuf, err := p.st.UpsertArticle(a); err == nil && neuf {
				neufs++
			}
		}
		_ = p.st.MarquerSync(src.ID, now, "")
	}
	return neufs, nil
}

// Regrouper affecte chaque article non regroupé au meilleur sujet récent
// (score ≥ seuil) ou en ouvre un nouveau, puis met à jour le sujet.
func (p *Pipe) Regrouper(now int64) (int, error) {
	arts, err := p.st.ArticlesSansSujet(500)
	if err != nil {
		return 0, err
	}
	touches := map[string]bool{}
	for _, a := range arts {
		sujets, err := p.st.SujetsRecents(now - cluster.FenetreSec)
		if err != nil {
			return len(touches), err
		}
		meilleur := ""
		var meilleurScore float64
		for _, t := range sujets {
			sc := cluster.Score(a.Title, a.Entities, a.PublishedAt, t.Title, t.Entities, t.UpdatedAt)
			if sc > meilleurScore {
				meilleurScore, meilleur = sc, t.ID
			}
		}
		if meilleur != "" && meilleurScore >= cluster.Seuil {
			_ = p.st.SetArticleSujet(a.ID, meilleur)
			_ = p.st.AjouterEvenement(meilleur, now, "source", a.URL)
			touches[meilleur] = true
		} else {
			id := nouvelID(now)
			t := store.Topic{
				ID: id, Title: a.Title, Lang: a.Lang,
				CreatedAt: now, UpdatedAt: now,
				Entities: a.Entities, SourcesCount: 1, Confidence: 1,
			}
			if err := p.st.CreerSujet(t); err != nil {
				if p.jr != nil {
					p.jr.Printf("créer sujet : %v", err)
				}
				continue
			}
			_ = p.st.SetArticleSujet(a.ID, id)
			_ = p.st.AjouterEvenement(id, now, "detected", a.Title)
			touches[id] = true
		}
	}
	for id := range touches {
		p.recomposer(id, now)
	}
	return len(touches), nil
}

// Reclasser NETTOIE LES SUJETS DEJA FUSIONNES A TORT (#1362b). Les regles de
// regroupement ont ete durcies, mais les sujets composes AVANT ne se defont pas
// seuls (tornade + preservatif restent colles). Cette passe reevalue chaque
// article de chaque sujet : s'il ne ressemble a AUCUN autre article du meme
// sujet (score < seuil pour tous), il n'y a pas sa place — on le detache. Les
// detaches sont re-groupes ensuite (par leur ressemblance reelle), et un sujet
// vide de tout sauf un article isole redevient un sujet a une source.
//
// Idempotente : apres un premier nettoyage, plus rien a detacher.
func (p *Pipe) Reclasser(now int64) (int, error) {
	sujets, err := p.st.SujetsRecents(now - cluster.FenetreSec*8)
	if err != nil {
		return 0, err
	}
	detaches := 0
	touches := map[string]bool{}
	for _, t := range sujets {
		arts, err := p.st.ArticlesDuSujet(t.ID)
		if err != nil || len(arts) < 2 {
			continue
		}
		for _, a := range arts {
			meilleur := 0.0
			for _, b := range arts {
				if b.ID == a.ID {
					continue
				}
				sc := cluster.Score(a.Title, a.Entities, a.PublishedAt,
					b.Title, b.Entities, b.PublishedAt)
				if sc > meilleur {
					meilleur = sc
				}
			}
			// Ne colle a AUCUN autre article du sujet : il n'a rien a y faire.
			if meilleur < cluster.Seuil {
				_ = p.st.SetArticleSujet(a.ID, "")
				detaches++
			}
		}
		touches[t.ID] = true
	}
	for id := range touches {
		p.recomposer(id, now)
	}
	if detaches > 0 && p.jr != nil {
		p.jr.Printf("reclasser : %d articles detaches des mauvais sujets", detaches)
	}
	// Les orphelins retrouvent (ou fondent) un sujet par leur ressemblance reelle.
	if detaches > 0 {
		_, _ = p.Regrouper(now)
	}
	return detaches, nil
}

// Rafraichir RECOMPOSE TOUS LES SUJETS RÉCENTS, une fois (#1323).
//
// POURQUOI UNE PASSE À PART. `recomposer` n'est appelé que sur un sujet TOUCHÉ
// — un sujet qui reçoit un article. Un sujet intact garde donc éternellement
// ce que la version précédente avait calculé, titre compris : après le
// correctif « le titre suit le plus récent », les sujets déjà en base
// continuaient d'afficher celui de leur article fondateur, et rien ne les en
// aurait sortis tant qu'aucune nouvelle dépêche ne les rejoignait.
//
// Idempotente : recomposer relit les articles et recalcule ; deux passages
// donnent le même résultat. DOUBLEMENT bornée — par la fenêtre de temps, et
// par `MaxRafraichis`. La seconde borne a été ajoutée après coup : la fenêtre
// seule laissait près de trente mille sujets, et la passe n'aboutissait jamais
// avant le redémarrage suivant. Les archives, elles, n'ont pas besoin d'être
// réécrites pour un titre que plus personne ne lit.
// ReparerTitres réécrit les titres déjà en base qui ne sont qu'un gabarit.
//
// POURQUOI UNE PASSE, ET PAS SEULEMENT LE CORRECTIF À L'INGESTION. Un article
// n'est lu qu'une fois : réparer `TitreLisible` ne touche que ce qui arrivera
// APRÈS. Les soixante-dix-neuf dépêches déjà enregistrées — un mois de
// publications du Dauphiné — garderaient « $content.TitleNoTags » pour
// toujours, et c'est précisément ce qu'on voit à l'écran.
//
// Idempotente : un titre réparé ne porte plus de gabarit, la passe suivante
// l'ignore. Bornée comme Rafraichir — on ne réécrit pas les archives.
//
// ELLE RECOMPOSE CE QU'ELLE TOUCHE, et c'est le point qui m'a manqué d'abord.
// J'avais laissé ce soin à Rafraichir, qui passe juste après — mais Rafraichir
// balaie TOUS les sujets de la fenêtre, soit près de trente mille : il n'en
// avait recomposé qu'une partie avant qu'un redémarrage ne l'interrompe, et
// onze sujets gardaient leur gabarit sans que rien ne l'explique. Réparer
// quatre-vingts articles ne touche qu'une vingtaine de sujets : on les reprend
// ici, tout de suite, au lieu d'espérer qu'un balayage y arrive.
func (p *Pipe) ReparerTitres(depuis int64) (int, error) {
	arts, err := p.st.ArticlesSuspectsDeGabarit(depuis)
	if err != nil {
		return 0, err
	}
	n := 0
	touches := map[string]bool{}
	for _, a := range arts {
		if !linker.PorteUnGabarit(a.Title) {
			continue
		}
		neuf := linker.TitreLisible(a.Title, a.Summary)
		if neuf == a.Title {
			continue
		}
		if err := p.st.RenommerArticle(a.ID, neuf); err != nil {
			return n, err
		}
		if a.TopicID != "" {
			touches[a.TopicID] = true
		}
		n++
	}
	// LES SUJETS ABÎMÉS QUE PLUS AUCUN ARTICLE NE DÉSIGNE. Un sujet prend le
	// titre de son article le plus récent, donc réparer les articles DEVRAIT
	// suffire — sauf que les deux écritures sont distinctes. Une interruption
	// entre elles laisse des sujets au gabarit que rien ne reprendra jamais :
	// leurs articles, eux, sont devenus propres. On les cherche donc aussi
	// pour eux-mêmes ; recomposer y remettra le bon titre.
	for _, t := range p.sujetsAGabarit(depuis) {
		touches[t] = true
	}
	maintenant := time.Now().Unix()
	for id := range touches {
		p.recomposer(id, maintenant)
	}
	return n, nil
}

func (p *Pipe) sujetsAGabarit(depuis int64) []string {
	sujets, err := p.st.SujetsSuspectsDeGabarit(depuis, MaxRafraichis)
	if err != nil {
		return nil
	}
	var out []string
	for _, t := range sujets {
		if linker.PorteUnGabarit(t.Title) {
			out = append(out, t.ID)
		}
	}
	return out
}

// MaxRafraichis borne le balayage de démarrage. Sans borne il portait sur
// 29 324 sujets — des heures de carte pour des titres que plus personne ne
// regarde, et jamais terminé. Le haut de la pile est ce qu'un lecteur voit.
const MaxRafraichis = 400

func (p *Pipe) Rafraichir(now int64, depuis int64) (int, error) {
	sujets, err := p.st.SujetsDerniers(depuis, MaxRafraichis)
	if err != nil {
		return 0, err
	}
	for _, t := range sujets {
		p.recomposer(t.ID, t.UpdatedAt)
	}
	return len(sujets), nil
}

// recomposer recalcule résumé, compteur d'ORIGINES (clones fondus), entités,
// tags et importance d'un sujet.
func (p *Pipe) recomposer(topicID string, now int64) {
	arts, err := p.st.ArticlesDuSujet(topicID)
	if err != nil || len(arts) == 0 {
		return
	}
	t, err := p.st.SujetParID(topicID)
	if err != nil {
		return
	}
	origines := map[string]bool{}   // clones fondus par empreinte
	distinctSrc := map[int64]bool{} // diversité par flux
	ent := []string{}
	var items []resume.Item
	var recent int64
	vignette := ""
	for _, a := range arts {
		origines[a.Fingerprint] = true
		distinctSrc[a.SourceID] = true
		ent = cluster.Fusion(ent, a.Entities)
		items = append(items, resume.Item{Titre: a.Title, Corps: a.Summary})
		if vignette == "" && a.Image != "" {
			vignette = a.Image // 1ère image disponible = illustration du sujet
		}
		if a.PublishedAt > recent {
			recent = a.PublishedAt
		}
	}
	// LE TITRE SUIT LE PLUS RÉCENT (#1323). `ArticlesDuSujet` rend les articles
	// du plus récent au plus ancien ; le sujet, lui, gardait le titre de
	// l'article FONDATEUR. Un sujet nourri pendant des semaines s'annonçait
	// donc sous le titre du premier jour — « JOURNAL DE 7H du 26 août » en tête
	// d'un fil alimenté jusqu'au 14 septembre. La vignette et le résumé
	// suivaient déjà la fraîcheur ; le titre restait en arrière, et c'est lui
	// qu'on lit en premier.
	if arts[0].Title != "" {
		t.Title = arts[0].Title
	}
	t.Vignette = vignette
	t.SourcesCount = int64(len(origines))
	t.Entities = ent
	t.Tags = ent // MVP : les tags = entités marquantes (dièse côté UI)
	t.Summary = resume.Resume(items, 3)
	t.UpdatedAt = now
	// importance = diversité des flux + nb d'origines + fraîcheur
	frais := cluster.Recence(now - recent)
	t.Importance = float64(len(distinctSrc)) + 0.5*float64(len(origines)) + 2*frais
	_ = p.st.MajSujet(t)
	_ = p.st.AjouterEvenement(topicID, now, "resume", "")
}

func nouvelID(now int64) string {
	var b [3]byte
	_, _ = rand.Read(b[:])
	return "mn_" + time.Unix(now, 0).UTC().Format("20060102") + "_" + hex.EncodeToString(b[:])
}

func refOu(refs ...string) string {
	for _, r := range refs {
		if r != "" {
			return r
		}
	}
	return ""
}

func tronquer(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
