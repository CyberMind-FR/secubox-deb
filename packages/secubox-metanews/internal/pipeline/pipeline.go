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
	origines := map[string]bool{}  // clones fondus par empreinte
	distinctSrc := map[int64]bool{} // diversité par flux
	ent := []string{}
	var items []resume.Item
	var recent int64
	for _, a := range arts {
		origines[a.Fingerprint] = true
		distinctSrc[a.SourceID] = true
		ent = cluster.Fusion(ent, a.Entities)
		items = append(items, resume.Item{Titre: a.Title, Corps: a.Summary})
		if a.PublishedAt > recent {
			recent = a.PublishedAt
		}
	}
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
