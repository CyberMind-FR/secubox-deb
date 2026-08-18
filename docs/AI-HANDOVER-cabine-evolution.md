<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Cabine Numérique VILLAGE3B — Brief technique pour LLM externe (GPT-5 / Gemini 2.x / Claude)

> Self-contained prompt destiné à un autre assistant pour comprendre l'état + contribuer à l'évolution de la cabine SecuBox-Deb / Gondwana ToolBoX sans contexte préalable.

---

## 1. Mission produit

**Cabine numérique VILLAGE3B** = AP WiFi captif sur MochaBin (Marvell Armada 7040 ARM64) qui propose à un utilisateur grand public :

- Connexion réseau libre (R0)
- Analyse passive de session (R1) avec rapport PDF + HTML
- Inspection TLS-break opt-in éclairé (R2) avec bandeau injecté sur chaque page Safari
- (Roadmap) Mode WireGuard portable (R3) qui marche hors-WiFi cabine

Cible : CSPN ANSSI, déploiements collectivités, candidature France.gouv (ANCT, Beta.gouv, ANSSI, France2030, CNIL).

**Licence** : LicenseRef-CMSD-1.0 (Source-Disclosed License — code ouvert pour audit citoyen, droits d'usage régis par licence CyberMind). **PAS** AGPL/Apache.

---

## 2. Stack technique

| Couche | Choix | Notes |
|--------|-------|-------|
| OS | Debian 12 bookworm arm64 | MochaBin Armada 7040 |
| Captive AP | hostapd open SSID `VILLAGE3B`, dnsmasq | wlxa854b2428fbb iface |
| Transparent proxy | mitmproxy 8.1.1 transparent (HOST) | sur 10.99.0.1:8080 |
| WAF mitm | mitmproxy 11.0.2 (LXC container `mitmproxy`) | sur 10.100.0.60:8080 — séparé |
| FastAPI portal | uvicorn 10.99.0.1:8088 unix socket | secubox-toolbox.service |
| nftables | table `inet toolbox` | sets validated_macs / consented_r2_macs / r2_banner_macs |
| Storage | SQLite `/var/lib/secubox/toolbox/toolbox.db` | clients + events + reports |
| PDF | fpdf2 + DejaVu + Symbola + NotoColorEmoji | drapeaux + emoji rendering OK |
| Rule engine | `secubox_core.rule_engine` | static YAML + generative predicates + sensitivity profiles low/medium/high/paranoid |

---

## 3. Architecture mitm — 2 instances DISJOINTES

```
HOST gk2 (192.168.1.200)
├─ ToolBox transparent mitm (PHASE 3 actuel)
│   - mitmproxy 8.1.1 natif process
│   - listen 10.99.0.1:8080 captive subnet
│   - addons : dpi, cookies, avatar, soc_relay, ja4, inject_banner, local_store
│   - CA : /etc/secubox/toolbox/ca/
│
├─ HAProxy frontal :443 + :80
│   - termine TLS pour vhosts externes
│   - route vers backend mitmproxy_inspector (LXC)
│
└─ LXC container "mitmproxy" (10.100.0.60)
    - WAF mitm (mitmproxy 11.0.2)
    - listen :8080
    - addons : secubox_waf.py + cookie_audit.py
    - inspecte vhosts externes (chess.maegia.tv, etc.)
```

**Règle d'or** : les 2 mitm ne se touchent PAS, certs séparés, addons séparés, IPs séparées.

---

## 4. Niveaux d'opt-in R0/R1/R2 (Phase 3 #492 — MERGED PR #493)

| Niveau | nft sets | mitm | Banner inject | Cert installé requis |
|--------|----------|------|---------------|----------------------|
| R0 — Bypass complet | validated_macs | NON | NON | NON |
| R1 — Analyse passive (défaut recommandé) | validated_macs + consented_r2_macs | OUI | NON | OUI sinon HTTPS fail |
| R2 — Analyse + bandeau Safari | + r2_banner_macs | OUI | OUI (TCP only) | OUI sinon HTTPS fail |
| R3 — WireGuard (#496 ROADMAP) | TBD | OUI (mode wireguard) | OUI (incl QUIC) | OUI (bundled WG profile) |

**QUIC drop rule retirée** (commit a9db3144) car cassait surf iPhone en R2. Bandeau apparaît seulement sur TCP HTTPS HTML — limitation acceptée.

---

## 5. Phases roadmap

```
PHASE 1 (#475)   PoC captive + splash + accept
PHASE 1.5 (#477) MITM transparency banner + reports + WebUI metrics
PHASE 2 (#485)   SOC scoring multi-signal (threat-intel + DGA + beaconing)
PHASE 2a+ (#486) geo flags + nDPI-style + cookies providers + avatar
PHASE 2b (#488)  wire mitm addons -> 5 receiving modules
PHASE 2c (#490)  receiving modules actual enrichment
PHASE 3 (#492)   Transparency layer : whitelist + analysis-status + quality + R0/R1/R2 opt-in
                 -> PR #493 ready pour merge
PHASE 4 (TBD)    Active blocking via rule_engine.should_block() — mitm addon flow.kill()
                 -> sensitivity profiles low/medium/high/paranoid
PHASE 5 (#495)   ToolBox mitm dans LXC dédié (séparation host-native)
                 -> Foundation pour Phase 6
PHASE 6 (#496)   WireGuard + autocert + mitm R3 mode
                 -> mitmproxy --mode wireguard sur UDP 51820
                 -> Endpoint cabine : kbin.gk2.net:51820
                 -> Profile WG bundled avec CA root, install via QR code
                 -> Marche hors VILLAGE3B WiFi (4G/5G/autre WiFi)
PHASE 7 (TBD)    Admin WebUI per-client level switch + config default_level + auto-mode
PHASE 8 (TBD)    Multi-cabine cluster + WG mesh
```

---

## 6. Endpoints API (Phase 3 actuel)

```
GET  /                                 splash (always rendered, Cache-Control no-store)
POST /accept                            level=r0/r1/r2 → 303 → dashboard
POST /change-level                      level=r0/r1/r2 → 303 → dashboard?switched=1
GET  /status                            JSON ip + mac_hash + validated + r2_consented
GET  /ca/mobileconfig                   iOS profile CA install
GET  /ca/android.crt                    .crt download Android/PC
GET  /ca/install-help                   HTML guide
GET  /ca/fingerprint                    JSON sha1 + sha256 + subject
GET  /ca/webclip-cabine.mobileconfig    iOS WebClip add-to-home-screen
GET  /client-status                     anonymous client status
GET  /report/me/html                    live dashboard (auto-refresh 15s)
GET  /report/me                         PDF download (mac IP→ARP)
GET  /report/{token}                    PDF via HMAC ephemeral token
GET  /admin/config                      admin
GET  /admin/clients                     admin
GET  /admin/metrics                     admin
GET  /admin/clients/{mh}/report         admin per-client report
GET  /admin/clients/{mh}/events         admin per-client events
GET  /health                            liveness probe
```

**Phase 6 (#496) ajoutera** :
```
POST /accept                            level=r3 → returns WG .conf + .mobileconfig + QR data URI
GET  /wg/profile/new                    generates new client WG profile + CA bundle
GET  /wg/profile/{token}                ephemeral profile retrieval
GET  /wg/qr.png                         QR code PNG
GET  /wg/status                         WG peer + handshake state
```

---

## 7. Rule engine — sensitivity profiles (Phase 3 #492)

`/etc/secubox/toolbox/rule-engine.yaml` :

```yaml
sensitivity: low | medium | high | paranoid

# Operator can append static rules :
static_rules:
  - pattern: "*.example.com"
    reason: "whitelisted by operator"
    category: custom
```

| Profile | Threat-intel | DGA score | Beaconing score | Block unknown |
|---------|--------------|-----------|-----------------|---------------|
| 🟢 low | block | ≥90 | never | NO |
| 🟡 medium (défaut) | block | ≥70 | ≥75 | NO |
| 🟠 high | block | ≥50 | ≥50 | NO (+ low-rep ASN block) |
| 🔴 paranoid | block | ≥30 | ≥30 | YES (default-deny) |

Phase 4 wirera `should_block()` dans un mitm addon `block_known_bad.py` qui appelle `flow.kill()`.

---

## 8. Drapeaux + emojis (PDF + HTML)

PDF embeds 5 fonts :
- DejaVuSans Book/Bold/Oblique : texte + Unicode basique
- Symbola : monochrome emoji (📱📡🔍🔒🎯🎵🐙📊🍪)
- NotoColorEmoji : color bitmap, flags 🇫🇷🇺🇸🇩🇪 + recent emoji

HTML utilise NCR entities `&#x1F50D;` etc. dans les banners injectés pour bypass tout charset issue.

---

## 9. Composants à installer côté iPhone (Splash quick-up menu)

```
🔐 Certificat iPhone     → /ca/mobileconfig (.mobileconfig)
🤖 Certificat Android/PC → /ca/android.crt (.crt)
📱 Icône Home iPhone     → /ca/webclip-cabine.mobileconfig (WebClip)
📜 Guide pas-à-pas       → /ca/install-help
🧪 Test certificat       → JS probe https://example.com/favicon.ico
```

**Phase 6 ajoutera** :
```
🌐 Profile WireGuard     → /wg/profile/new (.conf + bundled CA)
📷 QR code WG            → modal scan
```

---

## 10. Dette technique connue (à NE PAS confondre avec features)

| Issue | Description | Plan |
|-------|-------------|------|
| #494 | secubox-core.service ExecStart écrase tmpfiles.d → /run/secubox perms drift | Worktree existant, à finir |
| #494 bis | /var/log/suricata missing → secubox-threats 226/NAMESPACE crash loop | Inclus dans #494 |
| WAF chess.maegia.tv | LXC mitm intermittent, 504 + ACME challenge fail | Hors scope ToolBox |
| acme-monitor.sh | Bashisme [[ ]] mais script sh — FIXED live, source non-tracké | NA |
| 5 certs expirés gk2 | arm/armada/chat/endlesslapse → wildcard fallback FIXED, diyegg.maegia.tv encore expiré (ACME fail) | Need WAF stable d'abord |
| /etc/secubox/secrets perms | Drift bloquait salt access → banner inject KO en R2 — FIXED live via chmod 0750 + chown | Postinst gère déjà |

---

## 11. Comment contribuer (LLM external)

Si tu lis ce brief et veux contribuer, voici les bonnes pratiques :

1. **Worktree obligatoire** pour tout fix > 30min ou > 3 fichiers :
   ```bash
   bash scripts/agent-worktree.sh start --issue <NN>
   cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/<NN>-...
   ```

2. **Pas de master commit direct**. PR → user valide → user merge.

3. **Licence header obligatoire** sur tout nouveau fichier Python/Bash :
   ```python
   # SPDX-License-Identifier: LicenseRef-CMSD-1.0
   # Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
   ```

4. **Pas de référence** "Claude Code", "Anthropic", "OpenAI" dans les commits/PRs (global ref CyberMind suffit).

5. **Tests E2E réels sur board** gk2 (192.168.1.200) via SSH key. Pas de mock-only.

6. **Honesty over magic** — si une analyse est partielle (cert-pinning, QUIC), le rapport DOIT le dire (transparency layer).

7. **Conformité ANSSI CSPN** :
   - JWT auth obligatoire sur tous endpoints (sauf splash/accept/health)
   - Hash anonyme MAC quotidien rotatif (jamais MAC en clair sauf in-memory mitm)
   - Logs audit immuables `/var/log/secubox/audit.log`
   - AppArmor enforce par service
   - HAProxy TLS 1.3 frontal pour exposition externe

---

## 12. Status au 2026-06-05

- **Phase 3 (#492) PR #493 ready pour merge** : R0/R1/R2 + transparency + cert auto-check + filtering visibility + level switcher + hero widgets PDF/HTML + 4 quick install buttons + 108-pattern whitelist + sensitivity profiles + rule engine generative + jinja syntax fixes + R2 QUIC drop removal + 5 commits this week
- **Phase 5 (#495) issue ouverte + worktree créé** : ToolBox mitm en LXC dédié
- **Phase 6 (#496) issue ouverte + worktree créé** : WireGuard + autocert + R3 mode sur kbin.gk2.net:51820

User direction Jun 5 : "go genial" + "prompt technique de rapport pour gpt et gemini" + "belle evolution".

---

## 13. Contact

Gérald Kerma (Gandalf) — CyberMind
devel@cybermind.fr
Notre-Dame-du-Cruet, Savoie, FR
https://cybermind.fr · https://secubox.in
GitHub : https://github.com/CyberMind-FR/secubox-deb

---

**Fin du brief.** Tu peux maintenant lire ce document à vide et contribuer en cohérence avec l'écosystème.
