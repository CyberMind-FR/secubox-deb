// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
//
// SecuBox-Deb :: sbxwaf — styled 421 "Misdirected Request" page for unrouted hosts.
package main

import (
	"html"
	"io"
	"net/http"
	"strings"
)

// misdirectedPage is a self-contained (no external asset) HTML 421 page on the
// SecuBox charter. Served for a host with no route — so nothing on this host is
// fetchable; everything is inlined, using system fonts. The {{HOST}} token is
// replaced by the HTML-escaped requested host (the Host header is
// attacker-controlled, so it must never be reflected raw).
const misdirectedPage = `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>421 · Requête mal aiguillée · SecuBox</title>
<style>
  :root{
    --void:#0a0a0f; --panel:#111119; --panel2:#0d0d14; --edge:#1e1e2b;
    --gold:#c9a84c; --cyan:#00d4ff; --cinnabar:#e63946;
    --text:#e8e6d9; --muted:#6b6b7a;
    --serif:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,"Times New Roman",serif;
    --mono:"JetBrains Mono",ui-monospace,"SFMono-Regular",Menlo,Consolas,monospace;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  }
  *{box-sizing:border-box;}
  html,body{margin:0;height:100%;}
  body{
    background:
      radial-gradient(1200px 720px at 50% -12%, rgba(201,168,76,.11), transparent 60%),
      radial-gradient(900px 620px at 82% 118%, rgba(0,212,255,.08), transparent 60%),
      var(--void);
    background-attachment:fixed;
    color:var(--text); font-family:var(--sans);
    min-height:100vh; display:grid; place-items:center; padding:6vh 20px;
  }
  body::before{
    content:""; position:fixed; inset:0; pointer-events:none; opacity:.55;
    background-image:
      linear-gradient(rgba(255,255,255,.024) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,255,255,.024) 1px, transparent 1px);
    background-size:44px 44px;
    -webkit-mask-image:radial-gradient(circle at 50% 38%, #000 28%, transparent 78%);
    mask-image:radial-gradient(circle at 50% 38%, #000 28%, transparent 78%);
  }
  .card{
    position:relative; width:min(560px,100%);
    background:linear-gradient(180deg, var(--panel), var(--panel2));
    border:1px solid var(--edge); border-radius:14px; padding:44px 40px 32px;
    box-shadow:0 34px 90px -34px rgba(0,0,0,.85), inset 0 1px 0 rgba(255,255,255,.03);
    overflow:hidden;
  }
  .card::before{
    content:""; position:absolute; inset:0 0 auto 0; height:3px;
    background:linear-gradient(90deg, transparent, var(--cinnabar) 30%, var(--gold) 70%, transparent);
  }
  .scan{
    position:absolute; left:0; right:0; top:-140px; height:140px; pointer-events:none;
    background:linear-gradient(180deg, transparent, rgba(0,212,255,.06), transparent);
    animation:scan 6.5s linear infinite;
  }
  @keyframes scan{ to{ transform:translateY(180%); } }
  .eyebrow{
    font-family:var(--mono); font-size:12px; letter-spacing:.28em; text-transform:uppercase;
    color:var(--muted); margin:0 0 16px;
  }
  .code{
    font-family:var(--serif); font-weight:700; font-size:clamp(76px,17vw,120px); line-height:.86;
    margin:0; color:var(--gold); letter-spacing:.01em;
    text-shadow:0 0 36px rgba(201,168,76,.28);
  }
  .title{
    font-family:var(--serif); font-size:clamp(21px,4.6vw,28px); margin:12px 0 8px;
    color:var(--text); text-wrap:balance;
  }
  .sub{ color:var(--muted); font-size:15px; line-height:1.62; margin:0 0 22px; max-width:47ch; }
  .host{
    display:flex; align-items:center; gap:11px; font-family:var(--mono); font-size:14px;
    background:#0b0b12; border:1px solid var(--edge); border-left:3px solid var(--cyan);
    border-radius:8px; padding:12px 14px; color:var(--cyan); word-break:break-all;
  }
  .host .k{ color:var(--muted); text-transform:uppercase; letter-spacing:.12em; font-size:11px; }
  .foot{
    display:flex; align-items:center; gap:10px; margin-top:26px; padding-top:18px;
    border-top:1px solid var(--edge); color:var(--muted);
    font-family:var(--mono); font-size:11.5px; letter-spacing:.13em; text-transform:uppercase;
  }
  .sigil{
    width:15px; height:15px; border-radius:50%; border:1.5px solid var(--gold); flex:none;
    box-shadow:inset 0 0 9px rgba(201,168,76,.5), 0 0 8px rgba(201,168,76,.35);
  }
  @media (prefers-reduced-motion:reduce){ .scan{ display:none; } }
</style>
</head>
<body>
<main class="card">
  <div class="scan"></div>
  <p class="eyebrow">SecuBox · sbxwaf</p>
  <p class="code">421</p>
  <h1 class="title">Requête mal aiguillée</h1>
  <p class="sub">Aucune route n'est configurée sur cette SecuBox pour l'hôte demandé. Vérifie l'orthographe du domaine — ou cet hôte n'est pas (encore) exposé ici.</p>
  <div class="host"><span class="k">host</span> {{HOST}}</div>
  <div class="foot"><span class="sigil"></span> Misdirected Request · aucun backend</div>
</main>
</body>
</html>
`

// writeMisdirected serves the styled 421 page for an unrouted host. The host is
// HTML-escaped before being reflected into the page.
func writeMisdirected(w http.ResponseWriter, host string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusMisdirectedRequest)
	_, _ = io.WriteString(w, strings.Replace(misdirectedPage, "{{HOST}}", html.EscapeString(host), 1))
}
