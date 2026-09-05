<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# CLAUDE.md — module `secubox-toolbox`

> Réf. : #475 (Phase 1) sous parent #474 "ToolBoX: Gondwana Captive MITM Pipeline"
> Cible matériel : MochaBin-5G (Armada 7040) avec AR9271 USB (test) ou WLE900VX mPCIe (prod)
> Licence : LicenseRef-CMSD-1.0
> Doctrine : OPAD (CM-WALL-OPAD-2026-05) + R2 consenti (CM-WALL-EGRESS-2026-06)

Ce fichier est le contexte opérationnel de l'agent pour construire le module **ToolBoX** — la
cabine téléphonique numérique. **Lis-le entièrement avant toute action.**

## 0. Concept

ToolBoX = **cabine téléphonique numérique** : borne SecuBox publique avec :
- AP libre (open SSID, p.ex. VILLAGE3B)
- Sandbox réseau isolé (10.99.0.0/24)
- Captive portal avec **consentement R2 explicite**
- MITM transparent (mitmproxy) pour analyse cookies/DPI/avatar/JA4
- SOC relay : feed les modules existants (cookies, dpi, avatar, threat-analyst, soc)
- Rapport éphémère 24h remis à l'utilisateur (lien HMAC anonyme)

## 1. Definition of Done (Phase 1)

1. `.deb` `secubox-toolbox_*.deb` installable
2. `systemctl status secubox-toolbox` actif
3. Endpoints `/`, `/accept`, `/status`, `/ca/mobileconfig`, `/admin/*` répondent
4. CA mobileconfig iOS signé installable sur iPhone (profil "Gondwana ToolBoX CA")
5. nftables TPROXY 80/443 → mitmproxy :8080 (sur les MAC validées et R2-consenties)
6. mitmproxy addons squelettes POST aux sockets existants (cookies/dpi/avatar/ja4/soc)
7. WebUI admin `/toolbox/` accessible avec carte config TOML + liste clients live
8. menu.d entry visible dans navbar (catégorie sécurité/mesh, ordre 26)
9. Pas de régression `/run/secubox` 1777 ni `/etc/secubox` 0755
10. Licence headers `LicenseRef-CMSD-1.0` partout

## 2. Garde-fous (NON négociables)

- **R2 = consent explicite UNIQUEMENT** : le clic "Activer mon accès" est l'opt-in journalisé.
  Sans consentement, **pas** de TLS-break. mitmproxy listen mais relay sans déchiffrer.
- **MAC hashing** : la MAC client est toujours hashée avec un sel rotatif daily avant stockage.
  Aucun mapping session ↔ identité réelle conservé après TTL.
- **Secrets** : CA privé en `/etc/secubox/toolbox/ca/key.pem` chmod 0600 owner `secubox-toolbox`.
  Sel rotatif en `/etc/secubox/secrets/toolbox-mac-salt` chmod 0640 owner `root:secubox-toolbox`.
- **TLS-break uniquement sur la subnet captive** (10.99.0.0/24). Le reste du LAN intact.
- **Perf** : limite mitmproxy à 50 MB/s sustained ; au-delà, backpressure (queue dropped + WARN log)
- **/run/secubox parent reste 1777 root:root** (cf. régression #471). Ne JAMAIS le toucher.
- **/etc/secubox parent reste 0755 secubox:secubox** (cf. #468). Ne JAMAIS le toucher.
- **SQLite** pour storage events / rapports (per feedback_prefer_sqlite). Rétention 24h défaut.

## 3. Arborescence

```
packages/secubox-toolbox/
├── CLAUDE.md                      # ce fichier
├── pyproject.toml
├── secubox_toolbox/
│   ├── __init__.py
│   ├── app.py                     # FastAPI entry uvicorn
│   ├── api.py                     # routes principales + admin
│   ├── models.py                  # pydantic
│   ├── config.py                  # TOML loader
│   ├── mac.py                     # IP→MAC + hash sel rotatif
│   ├── nft.py                     # wrapper nftables
│   ├── ca.py                      # gen mobileconfig + APK cert
│   ├── store.py                   # SQLite events + clients + reports
│   └── reports.py                 # HMAC token + PDF
├── conf/
│   ├── toolbox.toml               # template TOML
│   ├── splash.html.j2             # splash P31 light
│   ├── success.html.j2
│   ├── admin.html.j2              # UI admin config
│   ├── ios.mobileconfig.j2
│   └── nft-toolbox.nft.j2
├── mitmproxy_addons/
│   ├── cookies.py                 # → POST /api/v1/cookies/inject
│   ├── dpi.py                     # → POST /api/v1/dpi/classify
│   ├── avatar.py                  # → POST /api/v1/avatar/fingerprint
│   ├── ja4.py                     # → POST /api/v1/threat-analyst/ja4
│   └── soc_relay.py               # → POST /api/v1/soc/event
├── systemd/
│   ├── secubox-toolbox.service           # FastAPI portal
│   └── secubox-toolbox-mitm.service      # mitmproxy transparent
├── scripts/
│   ├── toolbox-up                 # bring-up bench
│   └── ca-init                    # gen CA premier install
├── www/toolbox/
│   ├── index.html                 # admin UI WebUI
│   └── style.css
├── menu.d/
│   └── 26-toolbox.json
└── debian/
    ├── control
    ├── changelog
    ├── rules
    ├── postinst                   # crée user, dirs, CA, services
    ├── prerm
    ├── postrm
    └── source/format
```

## 4. TOML schema (`/etc/secubox/toolbox.toml`)

Voir bloc spec dans #475 — tout est sous `[ap]`, `[dhcp]`, `[portal]`, `[r2]`, `[addons]`,
`[quarantine]`. Le module est **agnostique du hardware** : `iface` paramétrable.

## 5. Routes API

Voir tableau dans #475. Principes :
- Routes publiques (no auth) : splash, captive probes, /accept, /status, /ca/*, /report/{token}
- Routes admin (JWT) : /admin/* (config, clients, quarantine)

## 6. Storage SQLite

`/var/lib/secubox/toolbox/toolbox.db` chmod 0640 owner `secubox-toolbox`.

Tables :
- `consents(mac_hash, ts, ttl, ip, user_agent)` — preuve R2 opt-in
- `clients(mac_hash, ip, score, state, first_seen, last_seen)` — état session
- `events(id, mac_hash, ts, source, payload_json)` — feed addons (cookies, dpi, ja4...)
- `reports(token, mac_hash, ts, pdf_path, expires_at)`

Purge auto via tâche async toutes les 1h (TTL `report_ttl` configurable).

## 7. mitmproxy addons (skeletons Phase 1)

Chaque addon est un fichier Python chargeable par mitmproxy (`mitmproxy_addons/*.py`).
Pattern uniforme :

```python
# mitmproxy_addons/cookies.py — squelette
from mitmproxy import http
import httpx, asyncio
TARGET = "http+unix:///run/secubox/cookies.sock/inject"

class CookiesRelay:
    def response(self, flow: http.HTTPFlow):
        # Extract Set-Cookie + cookies from flow
        payload = {
            "url": flow.request.pretty_url,
            "method": flow.request.method,
            "set_cookie": flow.response.headers.get_all("set-cookie"),
            "cookie": flow.request.headers.get_all("cookie"),
        }
        # Fire-and-forget POST (no blocking)
        asyncio.create_task(self._post(payload))
    async def _post(self, p): ...

addons = [CookiesRelay()]
```

Phase 1 = juste les skeletons. Phase 2 = scoring/correlation.

## 8. nftables TPROXY (Phase 1)

Remplace les DNAT actuels (PoC `inet ap` table). Pattern :

```
table inet toolbox {
    set validated_macs { type ether_addr; flags timeout; timeout 24h; }
    set consented_r2_macs { type ether_addr; flags timeout; timeout 24h; }
    set quarantine_macs { type ether_addr; flags timeout; timeout 1h; }

    chain mangle {
        type filter hook prerouting priority -150;
        # MITM uniquement pour MAC consented (R2 opt-in)
        iifname IFACE ether saddr @consented_r2_macs tcp dport { 80, 443 } \
            tproxy ip to 10.99.0.1:8080 meta mark set 0x1
        # Captive portal pour MAC non validées
        iifname IFACE ether saddr != @validated_macs tcp dport { 80, 443 } \
            dnat ip to 10.99.0.1:8088
    }

    chain forward {
        type filter hook forward priority 10; policy accept;
        iifname IFACE oifname "lan0" ether saddr @validated_macs accept
        iifname IFACE oifname "lan0" ether saddr @quarantine_macs drop
        iifname IFACE oifname "lan0" drop
        iifname "lan0" oifname IFACE ct state established,related accept
    }
}
```

Le marquage `meta mark 0x1` permet à mitmproxy de différencier le trafic transparent.

## 9. Ordre des tâches Phase 1

1. ✅ Scaffold (`pyproject.toml`, `__init__.py`, `CLAUDE.md`)
2. `models.py` → `config.py` → `mac.py` (loader TOML + sel rotatif)
3. `nft.py` (wrappers add/del éléments aux sets) + `ca.py` (gen mobileconfig)
4. `store.py` (SQLite) + `reports.py` (HMAC token PDF)
5. `api.py` + `app.py` (FastAPI 6+ routes)
6. Templates Jinja2 (splash + admin + iOS profile)
7. mitmproxy addons skeletons (5 fichiers)
8. systemd units (FastAPI + mitmproxy transparent)
9. scripts `toolbox-up` + `ca-init`
10. `debian/` complet
11. WebUI admin + menu.d
12. Build `.deb` + deploy gk2 + E2E iPhone test

## 10. Hors périmètre Phase 1

- SOC corrélation / scoring (Phase 2)
- OPAD decision tree / auto-quarantine (Phase 3)
- Rapport PDF complet + lien éphémère (Phase 4)
- ECH JA4 advanced detection (Phase 4)
- Android APK CA install profile (Phase 4 — pour l'instant les utilisateurs Android suivront un tutoriel manuel via `/ca/install-help`)

---

*CyberMind — Gérald Kerma. Document interne, FR faisant foi. LicenseRef-CMSD-1.0.*
