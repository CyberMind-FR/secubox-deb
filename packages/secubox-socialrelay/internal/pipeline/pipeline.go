// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package pipeline : la chaîne SocialRelay — sonder les sources sociales, cacher
// les médias en local, relayer chaque post en fil BBS.
package pipeline

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-socialrelay/internal/linker"
	"github.com/CyberMind-FR/secubox-deb/secubox-socialrelay/internal/mediacache"
	"github.com/CyberMind-FR/secubox-deb/secubox-socialrelay/internal/store"
)

// Pipe orchestre un tour de SocialRelay.
type Pipe struct {
	st        *store.Store
	reg       *linker.Registre
	cache     *mediacache.Cache
	jr        *log.Logger
	bbsSock   string
	jwtSecret string
	relayer   bool // créer des fils BBS ?
}

// New crée le pipeline.
func New(st *store.Store, reg *linker.Registre, cache *mediacache.Cache, jr *log.Logger, bbsSock, jwtSecret string, relayer bool) *Pipe {
	return &Pipe{st: st, reg: reg, cache: cache, jr: jr, bbsSock: bbsSock, jwtSecret: jwtSecret, relayer: relayer}
}

type mediaLocal struct {
	Hash string `json:"hash"`
	Kind string `json:"kind"`
	Orig string `json:"orig"`
}

// Tour : sonde puis relaie. Retourne (posts neufs, fils créés).
func (p *Pipe) Tour(now int64) (int, int, error) {
	neufs, err := p.Sonder(now)
	if err != nil {
		return neufs, 0, err
	}
	fils, err := p.Passerelle(now)
	return neufs, fils, err
}

// Sonder récupère les sources dues, cache leurs médias, insère les posts neufs.
func (p *Pipe) Sonder(now int64) (int, error) {
	srcs, err := p.st.SourcesDues(now)
	if err != nil {
		return 0, err
	}
	neufs := 0
	for _, src := range srcs {
		posts, err := p.reg.Peek(src.Kind, src.Handle, src.URL)
		if err != nil {
			_ = p.st.MarquerSync(src.ID, now, err.Error())
			if p.jr != nil {
				p.jr.Printf("source %q : %v", src.Slug, err)
			}
			continue
		}
		for _, c := range posts {
			var ml []mediaLocal
			for _, m := range c.Medias {
				if h := p.cache.Cacher(m); h != "" {
					ml = append(ml, mediaLocal{Hash: h, Kind: m.Kind, Orig: m.URL})
				}
			}
			mj, _ := json.Marshal(ml)
			pub := c.PublieLe
			if pub == 0 {
				pub = now
			}
			if _, neuf, err := p.st.UpsertPost(store.Post{
				SourceID: src.ID, Ref: c.Ref, Author: c.Auteur, URL: c.URL,
				Text: c.Texte, PublishedAt: pub, FetchedAt: now, Media: string(mj),
			}); err == nil && neuf {
				neufs++
			}
		}
		_ = p.st.MarquerSync(src.ID, now, "")
	}
	return neufs, nil
}

// Passerelle relaie les posts neufs en fils BBS (si activé).
func (p *Pipe) Passerelle(now int64) (int, error) {
	if !p.relayer || p.jwtSecret == "" {
		return 0, nil
	}
	posts, err := p.st.PostsSansFil(50)
	if err != nil {
		return 0, err
	}
	srcs, _ := p.st.Sources()
	salon := map[int64]string{}
	for _, s := range srcs {
		salon[s.ID] = s.Salon
	}
	fils := 0
	for _, po := range posts {
		titre := titreDe(po.Author, po.Text)
		corps := corpsDe(po)
		tid, err := p.pokeBBS(titre, corps, salon[po.SourceID], po.URL)
		if err != nil {
			if p.jr != nil {
				p.jr.Printf("poke BBS : %v", err)
			}
			continue // on réessaiera au prochain tour
		}
		_ = p.st.FixerFilBBS(po.ID, tid)
		fils++
	}
	return fils, nil
}

func titreDe(auteur, texte string) string {
	t := strings.TrimSpace(strings.SplitN(texte, "\n", 2)[0])
	if r := []rune(t); len(r) > 90 {
		t = string(r[:90]) + "…"
	}
	if t == "" {
		t = "Publication"
	}
	if auteur != "" {
		return auteur + " — " + t
	}
	return t
}

func corpsDe(po store.Post) string {
	var b strings.Builder
	b.WriteString(po.Text)
	b.WriteString("\n\n")
	if po.Author != "" {
		fmt.Fprintf(&b, "— %s\n", po.Author)
	}
	fmt.Fprintf(&b, "Source : %s\n", po.URL)
	return b.String()
}

// pokeBBS crée le fil BBS via POST /api/v1/bbs/threads (socket unix + JWT).
func (p *Pipe) pokeBBS(titre, corps, salon, srcURL string) (int64, error) {
	if salon == "" {
		salon = "reseaux"
	}
	body, _ := json.Marshal(map[string]any{
		"title": titre, "body": corps, "category": salon,
		"source_url": srcURL, "visibility": "local",
	})
	cli := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", p.bbsSock)
		}}}
	req, _ := http.NewRequest("POST", "http://bbs/api/v1/bbs/threads", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+signerJeton(p.jwtSecret, "socialrelay", 2*time.Minute))
	resp, err := cli.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var out struct {
		ThreadID int64 `json:"thread_id"`
	}
	_ = json.Unmarshal(rb, &out)
	return out.ThreadID, nil
}

func signerJeton(secret, sub string, ttl time.Duration) string {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	hdr := b64([]byte(`{"alg":"HS256","typ":"JWT"}`))
	now := time.Now()
	cl, _ := json.Marshal(map[string]any{"sub": sub, "iss": "socialrelay", "iat": now.Unix(), "exp": now.Add(ttl).Unix()})
	pl := b64(cl)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(hdr + "." + pl))
	return hdr + "." + pl + "." + b64(mac.Sum(nil))
}
