// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"context"
	"encoding/base64"
	"html"
	"net/http"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/CyberMind-FR/secubox-deb/secubox-socialrelay/internal/fbauth"
)

// brancherFB enregistre les routes du wizard OAuth Facebook (consent).
func (s *Serveur) BrancherFB(fb *fbauth.Store) {
	const p = "/api/v1/socialrelay"
	s.fb = fb
	s.mux.HandleFunc("GET "+p+"/fb/status", s.jwt(s.fbStatus))
	s.mux.HandleFunc("POST "+p+"/fb/start", s.jwt(s.fbStart))
	s.mux.HandleFunc("GET "+p+"/fb/callback", s.fbCallback) // Meta redirige le navigateur (validé par state)
}

func (s *Serveur) fbStatus(w http.ResponseWriter, _ *http.Request) {
	if s.fb == nil {
		ecrire(w, 200, map[string]any{"ok": true, "configured": false, "connected": false})
		return
	}
	st := s.fb.Statut()
	ecrire(w, 200, map[string]any{"ok": true, "configured": st.Configured, "connected": st.Connected,
		"expires_at": st.ExpiresAt, "redirect_uri": st.Redirect})
}

// fbStart génère un état CSRF + l'URL d'autorisation Meta et son QR (PNG data-URI).
func (s *Serveur) fbStart(w http.ResponseWriter, _ *http.Request) {
	if s.fb == nil || !s.fb.Configured() {
		ecrire(w, 400, map[string]any{"ok": false, "erreur": "app Meta non configurée — déposez App ID/Secret dans /etc/secubox/secrets/socialrelay-facebook-app"})
		return
	}
	st, err := s.fb.NouvelÉtat()
	if err != nil {
		ecrire(w, 500, map[string]any{"ok": false, "erreur": err.Error()})
		return
	}
	u, err := s.fb.URLAutorisation(st)
	if err != nil {
		ecrire(w, 500, map[string]any{"ok": false, "erreur": err.Error()})
		return
	}
	qr := ""
	if png, e := qrcode.Encode(u, qrcode.Medium, 320); e == nil {
		qr = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	}
	ecrire(w, 200, map[string]any{"ok": true, "url": u, "qr": qr})
}

// fbCallback reçoit la redirection de Meta, échange le code, met le jeton en cache.
func (s *Serveur) fbCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		fbPage(w, false, "Autorisation refusée : "+html.EscapeString(q.Get("error_description")))
		return
	}
	if s.fb == nil || !s.fb.ConsommerÉtat(q.Get("state")) {
		fbPage(w, false, "État invalide ou expiré. Relancez la connexion depuis le panel.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	if err := s.fb.Échanger(ctx, q.Get("code"), time.Now()); err != nil {
		fbPage(w, false, "Échec de l'échange du jeton : "+html.EscapeString(err.Error()))
		return
	}
	fbPage(w, true, "Facebook est connecté. Le relais utilisera ce jeton pour lire vos pages/groupes autorisés.")
}

// fbPage rend une page de retour minimale (fenêtre OAuth).
func fbPage(w http.ResponseWriter, ok bool, msg string) {
	icon := "❌"
	col := "#ec6a72"
	if ok {
		icon, col = "✅", "#3ee08a"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>SocialRelay · Facebook</title>
<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0a0e13;
color:#e6edf3;font-family:'Space Grotesk',system-ui,sans-serif}.c{max-width:440px;text-align:center;padding:32px;
background:#111922;border:1px solid #1e2c38;border-radius:16px}.i{font-size:3rem}h1{font-size:1.2rem;color:` + col + `}
p{color:#7d8b99;line-height:1.6}button{margin-top:14px;background:#28d3f0;color:#04222a;border:0;border-radius:9px;
padding:10px 18px;font-weight:700;cursor:pointer}</style></head><body><div class="c"><div class="i">` + icon + `</div>
<h1>` + map[bool]string{true: "Connecté", false: "Échec"}[ok] + `</h1><p>` + msg + `</p>
<button onclick="window.close()">Fermer</button></div></body></html>`))
}
