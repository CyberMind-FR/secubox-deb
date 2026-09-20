// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package api expose la surface REST decrite dans docs/openapi.yaml.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-signal/internal/config"
	"github.com/CyberMind-FR/secubox-deb/secubox-signal/internal/pairing"
	"github.com/CyberMind-FR/secubox-deb/secubox-signal/internal/signalcli"
	"github.com/CyberMind-FR/secubox-deb/secubox-signal/internal/store"
	"github.com/CyberMind-FR/secubox-deb/secubox-signal/internal/web"
	"github.com/CyberMind-FR/secubox-deb/secubox-signal/internal/ws"
)

const Version = "0.1.0"

type API struct {
	cfg  config.Config
	cli  *signalcli.Client
	st   *store.Store
	hub  *ws.Hub
	jwt  Verificateur
	lien etatLien
}

// Verificateur decouple l'API du mecanisme de jeton. Le parc verifie le JWT
// en amont (nginx + Hall) ; le demon revalide, parce qu'une socket Unix
// lisible par un autre service du parc n'est pas une frontiere de confiance.
type Verificateur interface {
	Valide(jeton string) bool
}

type etatLien struct {
	ID     string
	Etat   string // pending | linked | expired | failed
	Expire time.Time
	Detail string
	Compte string
}

func New(cfg config.Config, cli *signalcli.Client, st *store.Store, hub *ws.Hub, v Verificateur) *API {
	return &API{cfg: cfg, cli: cli, st: st, hub: hub, jwt: v, lien: etatLien{Etat: "expired"}}
}

func (a *API) Routes() http.Handler {
	m := http.NewServeMux()
	const p = "/api/v1/signal"

	// Sans authentification : vivacite et cardlet. Le cardlet est encadre par
	// le Hall, qui porte deja la session ; lui demander un JWT le rendrait
	// blanc pour tout le monde.
	m.HandleFunc(p+"/healthz", a.healthz)
	m.HandleFunc(p+"/micro", a.micro)

	m.Handle(p+"/status", a.protege(a.status))
	m.Handle(p+"/link/start", a.protege(a.linkStart))
	m.Handle(p+"/link/status", a.protege(a.linkStatus))
	m.Handle(p+"/link", a.protege(a.linkDelete))
	m.Handle(p+"/contacts", a.protege(a.contacts))
	m.Handle(p+"/groups", a.protege(a.groups))
	m.Handle(p+"/messages", a.protege(a.messages))
	m.Handle(p+"/ws", a.protege(a.websocket))
	return m
}

func (a *API) protege(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jeton := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if a.jwt == nil || !a.jwt.Valide(jeton) {
			probleme(w, http.StatusUnauthorized, "Jeton absent, expire ou invalide")
			return
		}
		h(w, r)
	})
}

func ecrire(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// probleme rend un RFC 9457, comme l'annonce l'OpenAPI.
func probleme(w http.ResponseWriter, code int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"title": http.StatusText(code), "status": code, "detail": detail,
	})
}

func (a *API) backendEtat() string {
	if a.lien.Etat != "linked" {
		return "unlinked"
	}
	return "up"
}

func (a *API) healthz(w http.ResponseWriter, _ *http.Request) {
	ecrire(w, http.StatusOK, map[string]any{
		"status": "ok", "version": Version, "backend": a.backendEtat(),
	})
}

func (a *API) status(w http.ResponseWriter, _ *http.Request) {
	ecrire(w, http.StatusOK, map[string]any{
		"linked":          a.lien.Etat == "linked",
		"account":         nilSiVide(a.lien.Compte),
		"backend":         a.backendEtat(),
		"queue_depth":     a.hub.Nombre(),
		"store_body":      a.cfg.StoreBody,
		"retention_hours": a.cfg.RetentionHours,
	})
}

func nilSiVide(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (a *API) linkStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		probleme(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	if a.lien.Etat == "linked" {
		probleme(w, http.StatusConflict, "Un compte est deja lie — le delier d'abord")
		return
	}
	brut, err := a.cli.Call(r.Context(), "startLink", map[string]any{"deviceName": "SecuBox"})
	if err != nil {
		probleme(w, http.StatusBadGateway, err.Error())
		return
	}
	var rep struct {
		URI string `json:"deviceLinkUri"`
	}
	if err := json.Unmarshal(brut, &rep); err != nil || rep.URI == "" {
		probleme(w, http.StatusBadGateway, "reponse d'appairage illisible")
		return
	}
	svg, err := pairing.SVG(rep.URI, 320)
	if err != nil {
		probleme(w, http.StatusInternalServerError, err.Error())
		return
	}
	// L'URI elle-meme ne quitte JAMAIS le processus : seul le SVG sort.
	a.lien = etatLien{ID: strconv.FormatInt(time.Now().Unix(), 36), Etat: "pending",
		Expire: time.Now().Add(10 * time.Minute)}
	a.hub.Diffuser("link.progress", map[string]any{"state": "pending"})
	ecrire(w, http.StatusCreated, map[string]any{
		"link_id": a.lien.ID, "qr_svg": svg,
		"expires_at": a.lien.Expire.UTC().Format(time.RFC3339),
	})
}

func (a *API) linkStatus(w http.ResponseWriter, _ *http.Request) {
	if a.lien.Etat == "pending" && time.Now().After(a.lien.Expire) {
		a.lien.Etat = "expired"
	}
	ecrire(w, http.StatusOK, map[string]any{
		"state": a.lien.Etat, "detail": nilSiVide(a.lien.Detail),
	})
}

func (a *API) linkDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		probleme(w, http.StatusMethodNotAllowed, "DELETE attendu")
		return
	}
	if _, err := a.cli.Call(r.Context(), "unregister", nil); err != nil {
		probleme(w, http.StatusBadGateway, err.Error())
		return
	}
	// Journalisation d'audit : delier est une decision de securite.
	log.Printf("[audit] compte Signal delie")
	a.lien = etatLien{Etat: "expired"}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) contacts(w http.ResponseWriter, r *http.Request) { a.passePlat(w, r, "listContacts") }
func (a *API) groups(w http.ResponseWriter, r *http.Request)   { a.passePlat(w, r, "listGroups") }

func (a *API) passePlat(w http.ResponseWriter, r *http.Request, methode string) {
	brut, err := a.cli.Call(r.Context(), methode, nil)
	if err != nil {
		if errors.Is(err, signalcli.ErrNonLie) {
			probleme(w, http.StatusConflict, "aucun compte lie")
			return
		}
		probleme(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(brut)
}

func (a *API) messages(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		limite, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		avant, _ := strconv.ParseInt(r.URL.Query().Get("cursor"), 10, 64)
		items, err := a.st.List(r.URL.Query().Get("peer"), limite, avant)
		if err != nil {
			probleme(w, http.StatusInternalServerError, err.Error())
			return
		}
		var suivant any
		if n := len(items); n > 0 {
			suivant = strconv.FormatInt(items[n-1].TS.Unix(), 10)
		}
		ecrire(w, http.StatusOK, map[string]any{"items": items, "next_cursor": suivant})
	case http.MethodPost:
		var env struct {
			To      string `json:"to"`
			GroupID string `json:"group_id"`
			Body    string `json:"body"`
		}
		if json.NewDecoder(r.Body).Decode(&env) != nil || (env.To == "" && env.GroupID == "") {
			probleme(w, http.StatusBadRequest, "`to` ou `group_id` est requis")
			return
		}
		dest := env.To
		if dest == "" {
			dest = env.GroupID
		}
		if err := a.Envoyer(r.Context(), dest, env.Body); err != nil {
			probleme(w, http.StatusBadGateway, err.Error())
			return
		}
		ecrire(w, http.StatusAccepted, map[string]any{
			"id": strconv.FormatInt(time.Now().UnixNano(), 36), "state": "queued",
		})
	default:
		probleme(w, http.StatusMethodNotAllowed, "GET ou POST attendu")
	}
}

// Envoyer satisfait sentinel.Envoyeur : le relais d'alertes emprunte le meme
// chemin que l'UI, donc les memes garde-fous et le meme journal.
func (a *API) Envoyer(ctx context.Context, dest, corps string) error {
	_, err := a.cli.Call(ctx, "send", map[string]any{"recipient": dest, "message": corps})
	if err == nil {
		a.hub.Diffuser("message.sent", map[string]any{"peer": dest, "size": len(corps)})
		_ = a.st.Add(store.Message{
			ID: strconv.FormatInt(time.Now().UnixNano(), 36), TS: time.Now(),
			Direction: "out", Peer: dest, Size: len(corps), Body: corps,
		})
	}
	return err
}

func (a *API) websocket(w http.ResponseWriter, r *http.Request) {
	if err := a.hub.Upgrade(w, r); err != nil {
		probleme(w, http.StatusBadRequest, err.Error())
	}
}

func (a *API) micro(w http.ResponseWriter, _ *http.Request) {
	b, err := fs.ReadFile(web.Static(), "micro.html")
	if err != nil {
		probleme(w, http.StatusInternalServerError, "cardlet absente")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}
