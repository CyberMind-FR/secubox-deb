# Metalogue 🕸️

**[EN](Metalogue)** | **🟣 MIND** | 🔎 OSINT

> Maltego-style OSINT — collect passively, correlate, report.

Metalogue is the SecuBox **OSINT investigation suite**: a set of self-hosted,
LXC-sandboxed tools that reproduce the Maltego experience (entity collection →
correlation → dossier) without any cloud transforms. It complements
[[OpenClaw|Anti-Track]]-style *active* recon (openclaw: DNS/ports/IP) with
**passive** collection, automation, and a graph hub.

Each tool runs in its own unprivileged LXC container (`10.100.0.x`), driven by a
least-privilege `<mod>ctl` control plane, aggregator-served API, auth-gated
nginx, and a navbar tile.

---

## 🧩 The stack

| Module | Role | Weight | State |
|--------|------|--------|-------|
| 🔎 **Maigret** | Identity collector — a username → dossier across 3000+ sites | Light | ✅ live |
| 🌀 **SpiderFoot** | Automation engine — 200+ passive modules + correlation graph (interim Maltego-style hub) | Light | ✅ live |
| 🕸️ **OpenCTI** | Graph / link-analysis hub (the true Maltego stand-in) | Heavy (ES+Redis+RabbitMQ+MinIO) | ⬜ deferred (needs a beefier node) |

---

## 🎯 Cas d'usage

### 1️⃣ Empreinte d'identité (Maigret)
Donne un **pseudo** → Maigret cherche des comptes sur 3000+ sites et construit un
dossier (plateforme, catégorie, URL de profil, infos extraites : nom, société…).
Passif, sandboxé LXC, rate-limité (max 3 lookups simultanés), chaque lookup
audité. Panneau `admin.<board>/maigret/` ou `POST /api/v1/maigret/lookup`.

> *« @torvalds → GitHub, Instagram, Telegram, Facebook… avec nom & société. »*

### 2️⃣ Rapport PDF stylisé 📄
Chaque lookup terminé se transforme en **dossier PDF formel SecuBox** (bouton
📄 PDF) : masthead cyber, bloc métadonnées (RÉFÉRENCE · SUJET · CLASSIFICATION
CONFIDENTIAL), §1 Résumé, et §2 Findings en **table cohérente** (# · plateforme ·
catégorie · URL · détails), lignes zébrées, couleurs par catégorie, paginé.

### 3️⃣ Automatisation OSINT (SpiderFoot)
Le « aspirateur de données » : 200+ modules passifs (domaines, IP, emails,
usernames, breach, WHOIS, certificats…) + un moteur de corrélation avec vue
graphe — le **hub Maltego intérimaire** en attendant OpenCTI. UI complète servie
à https://spiderfoot.gk2.secubox.in/ (LAN-gated).

### 4️⃣ Corrélation / graphe (OpenCTI — futur)
Le vrai hub Maltego : entités, relations, timeline, ingestion des findings de
Maigret + SpiderFoot + openclaw. Différé sur un nœud plus costaud (stack
Elasticsearch trop lourde pour le board arm64).

---

## 🟢 Prise en main (ROOT)

```bash
apt install secubox-maigret secubox-spiderfoot   # modules + navbar + nginx
# Provisionner les conteneurs OSINT (debootstrap + piwheels, ~2-3 min chacun) :
sudo maigretctl install       # ou le bouton "Install" du panneau
sudo spiderfootctl install
```

> ⚠️ Les conteneurs ont besoin de la sortie internet du board : `ip_forward=1`
> (`99-secubox-zz-lxc-forward.conf`). Les deps arm64 arrivent via **piwheels**
> (`--extra-index-url https://www.piwheels.org/simple`).

---

## 🔒 Posture sécurité

| Contrôle | Mise en œuvre |
|----------|---------------|
| Sandbox | chaque outil en LXC non privilégié (10.100.0.42 maigret, .43 spiderfoot) |
| Privilège | `<mod>ctl` via sudo (seule surface root) ; username passé **positionnellement** à `lxc_attach` (pas d'interpolation shell), gardes anti-flag-injection |
| Boucle | handlers `def` + workers détachés / threadpool — rien ne bloque la boucle de l'agrégateur |
| Auth | API JWT (`sbx_token`) + audit append-only sur lookup/delete/install ; nginx auth-gated (LAN pass / WAN deny) |
| Exposition | SpiderFoot jamais sur un port hôte ; UI proxifiée à la racine, gated ; pas de WAF bypass |

---

## See also

- [[MODULES-EN]] · [[Architecture]] · [[Billets]]
- Issue [#845](https://github.com/CyberMind-FR/secubox-deb/issues/845) — suivi metalogue
- `.claude/WEBUI-PANEL-GUIDELINES.md` — look & feel des panneaux
