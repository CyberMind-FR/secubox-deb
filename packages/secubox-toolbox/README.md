# SecuBox ToolBoX — Cabine Numérique Gondwana

> **Borne publique de check compromission cybersécurité** — open SSID + captive
> portal + opt-in MITM analyzer + rapport PDF personnel anonyme.
>
> Hommage à la **cabine téléphonique publique** : un point fixe, libre d'accès,
> gratuit, qui rend un service civique. Ici : un diagnostic gratuit de l'état
> de sécurité de ton smartphone.

| | |
|---|---|
| **Package** | `secubox-toolbox` |
| **Catégorie navbar** | **Wall** 🛡️ |
| **Parent issue** | [#474](https://github.com/CyberMind-FR/secubox-deb/issues/474) Cabine Numérique |
| **Phase 1** | [#475](https://github.com/CyberMind-FR/secubox-deb/issues/475) (captive + MITM + addons) |
| **Phase 1.5** | [#477](https://github.com/CyberMind-FR/secubox-deb/issues/477) (transparency banner + PDF) |
| **Licence** | LicenseRef-CMSD-1.0 |
| **Doctrine** | OPAD (CM-WALL-OPAD-2026-05) + R2 consenti (CM-WALL-EGRESS-2026-06) |

---

## 🧭 Mission

Chaque borne SecuBox équipée de ce module devient une **cabine numérique
publique** :

1. **Accès WiFi gratuit anonyme** (SSID `VILLAGE3B` par défaut, configurable)
2. **Sandbox réseau isolé** (subnet 10.99.0.0/24, NAT vers Internet)
3. **Captive portal avec consentement R2 explicite** (CSPN compliant)
4. **MITM TLS-break opt-in** via mitmproxy transparent + addons (cookies, DPI,
   avatar, JA4, SOC-relay)
5. **Transparency banner** injecté dans chaque page HTML (CA SHA1 visible)
6. **Rapport PDF personnel** anonyme remis à l'utilisateur (hash MAC rotatif)
7. **Détection compromission** : feeds abuse.ch + heuristiques (Phase 2 = SOC
   scoring multi-signal)

## 🏗️ Architecture

```
[Smartphone]                                    [SecuBox-Deb borne]
    │                                                    │
    │  1. Connect "VILLAGE3B" WiFi open                  │
    │ ─────────────────────────────────────────────────→ │ hostapd
    │                                                    │
    │  2. DHCP                                           │
    │ ←─────────────────────────────────────────────────  │ dnsmasq
    │     10.99.0.x/24, GW=10.99.0.1, DNS=10.99.0.1     │
    │                                                    │
    │  3. iOS/Android captive probe                      │
    │ ────────────  http://detect/   ──────────────────→ │
    │ ←─ DNS hijack to 10.99.0.1 ───  splash page  ──────│ secubox-toolbox
    │                                                    │   (FastAPI)
    │  4. User clicks "Activer mon accès"                │
    │ ─────────  POST /accept   ───────────────────────→ │
    │                                          ↳ nft add @validated_macs
    │                                          ↳ nft add @consented_r2_macs
    │                                          ↳ store consent in SQLite
    │                                                    │
    │  5. User installs Gondwana ToolBoX CA              │
    │ ←──── GET /ca/mobileconfig (iOS) ──────────────────│
    │                                                    │
    │  6. Browse HTTPS                                   │
    │ ──── TCP 443 ──→ nft DNAT ──→ 10.99.0.1:8080 ──────│ mitmproxy
    │                                                    │   (transparent)
    │     mitmproxy presents OUR cert (signed by CA)     │
    │     iPhone trusts (CA installed)                   │
    │     mitmproxy decrypts                             │
    │                                                    │
    │     Addons fire fire-and-forget POSTs :            │
    │       cookies.py    → /run/secubox/cookies.sock    │
    │       dpi.py        → /run/secubox/dpi.sock        │
    │       avatar.py     → /run/secubox/avatar.sock     │
    │       ja4.py        → /run/secubox/threat-analyst  │
    │       soc_relay.py  → /run/secubox/soc.sock        │
    │                                                    │
    │     inject_banner.py → injects <script> in HTML    │
    │       showing "📡 R2 active · CA SHA1: XX:YY..."  │
    │                                                    │
    │  7. User downloads PDF report                      │
    │ ──── GET /report/me ──────────────────────────────→ │
    │ ←──── application/pdf (HMAC-signed token) ─────────│
    │                                                    │
```

## 🔑 Routes API

| Method | Path | Auth | Rôle |
|---|---|---|---|
| GET | `/` | none | Splash page (HTML) |
| GET | `/hotspot-detect.html` | none | iOS captive probe |
| GET | `/generate_204` | none | Android captive probe |
| GET | `/connecttest.txt` | none | Windows captive probe |
| POST | `/accept` | none | Consent → MAC à validated + consented_r2 |
| GET | `/status` | none | État client courant (JSON) |
| GET | `/client-status` | none | + CA fingerprint pour banner JS |
| GET | `/ca/mobileconfig` | none | iOS profile signé |
| GET | `/ca/android.crt` | none | Android DER cert |
| GET | `/ca/install-help` | none | Tutoriel install par-OS |
| GET | `/ca/fingerprint` | none | SHA1+SHA256+subject du CA |
| GET | `/report/me` | none | PDF rapport du client courant |
| GET | `/report/{token}` | HMAC | PDF rapport par token éphémère |
| GET | `/admin/config` | JWT | TOML config |
| GET | `/admin/clients` | JWT | Liste clients live |
| GET | `/health` | none | Liveness |

## 📦 Installation

```bash
sudo apt install secubox-toolbox

# Adapter la config au hardware
sudo $EDITOR /etc/secubox/toolbox.toml
# Spécialement [ap].iface = ton iface WiFi (cf. `iw dev`)

# Apporter la table nftables
sudo /usr/sbin/toolbox-up

# Démarrer le portail + mitmproxy
sudo systemctl start secubox-toolbox secubox-toolbox-mitm

# Démarrer hostapd + dnsmasq côté wireless (cf. /etc/secubox/toolbox.toml)
# (la config hostapd/dnsmasq est gérée par secubox-mesh ou bring-up manuel)
```

## 🔧 Configuration TOML

`/etc/secubox/toolbox.toml` :

```toml
[ap]
ssid     = "VILLAGE3B"
iface    = "wlxa854b2428fbb"     # ← adapter au hardware
channel  = 1
band     = "2g"

[dhcp]
range_start = "10.99.0.10"
range_end   = "10.99.0.250"
lease_ttl   = "1h"
gateway     = "10.99.0.1"

[portal]
listen_host  = "10.99.0.1"
listen_port  = 8088
mac_salt_ref = "file:///etc/secubox/secrets/toolbox-mac-salt"
report_ttl   = "24h"

[r2]
enabled     = true                 # Mettre false pour metadata-only (R1)
mitm_listen = "10.99.0.1:8080"
ca_bundle   = "/etc/secubox/toolbox/ca/ca.pem"

[quarantine]
score_throttle   = 30
score_quarantine = 70
ban_on_crowdsec  = true
```

## 🔒 Garde-fous CSPN

- **R2 = consent explicite UNIQUEMENT** (click "Activer mon accès" = opt-in journalisé)
- **MAC hashing avec sel rotatif daily** (HMAC-SHA256) — anonymisation
- **CA self-signed 10y** dans `/etc/secubox/toolbox/ca/` chmod 0750 root:secubox-toolbox
- **Sel rotatif** dans `/etc/secubox/secrets/toolbox-mac-salt` chmod 0640
- **TLS-break SEULEMENT sur 10.99.0.0/24** (la subnet captive, le reste du LAN intact)
- **Rapport éphémère 24h** (HMAC token) — supprimé après TTL
- **Logs bruts purgés** automatiquement (purge_expired toutes les heures)
- **Apps cert-pinned** restent inviolables (Signal, banking, Apple, GitHub…) — c'est un bon signe
- **Garde-fous platform** : `/etc/secubox` 0755 (cf. #468), `/run/secubox` 1777 root:root (cf. #471) — JAMAIS touchés

## 📊 Rapport PDF

Disponible via :
- **Pendant la session** : `http://10.99.0.1:8088/report/me` (lien sur splash success)
- **Via token éphémère** : `http://10.99.0.1:8088/report/{token}` (HMAC scellé 24h)

Le PDF contient :
- **Identifiant anonyme** (hash MAC rotatif daily, **pas** la vraie MAC)
- **Métriques session** : connexions, hosts uniques, succès, cert-pin blocks
- **Apps détectées** (par SNI + IP forensics)
- **Analyse compromission** : score risque + indicateurs
- **Apps protégées par cert-pinning** (Signal, banking, etc.) — preuve de sécurité
- **Traffic inspecté** (URLs déchiffrées, seulement avec R2 consenti)
- **Recommandations** personnalisées
- **Politique de rétention** (24h max)

## 🛠️ Maintenance

```bash
# Vérifier qu'AP est actif
iw dev wlxa854b2428fbb info

# Voir les clients validés
nft list set inet toolbox validated_macs
nft list set inet toolbox consented_r2_macs

# Voir le trafic intercepté en live
journalctl -u secubox-toolbox-mitm -f

# Tester l'API
curl -s http://10.99.0.1:8088/health
curl -s http://10.99.0.1:8088/admin/config | jq

# Forcer la rotation du sel MAC (= rotation immediate des hashes)
sudo head -c 32 /dev/urandom | base64 > /etc/secubox/secrets/toolbox-mac-salt
sudo systemctl restart secubox-toolbox
```

## 🌐 WebUI Admin

Dashboard P31-light dans le SecuBox admin :
**https://admin.gk2.secubox.in/toolbox/**

Carte Config + Clients actifs (MAC hash, IP, score, last seen) + Liveness, auto-refresh 10s.

## 📡 SSID brand "VILLAGE3B"

Référence à la mission communautaire :
- **VILLAGE** : ancré dans le village, hommage cabine téléphonique publique
- **3B** : trois broches (CTL / LXC / BUNDLE) — l'architecture-pattern SecuBox

À adapter selon la commune / le déploiement.

## 🔗 References

- Parent issue [#474](https://github.com/CyberMind-FR/secubox-deb/issues/474) — architecture E2E
- [#475](https://github.com/CyberMind-FR/secubox-deb/issues/475) — Phase 1
- [#477](https://github.com/CyberMind-FR/secubox-deb/issues/477) — Phase 1.5 banner + PDF
- Spec [CM-WALL-EGRESS-2026-06](../../docs/specs/CM-WALL-EGRESS-2026-06.md) §3 (R2 régime)
- Doctrine OPAD CM-WALL-OPAD-2026-05

## 📝 Licence

LicenseRef-CMSD-1.0 — Source-Disclosed License (FR faisant foi). Code source ouvert pour audit et tests, droits d'usage strictement régis par la licence CMSD.

**Auteur** : Gerald Kerma — CyberMind / Gondwana — devel@cybermind.fr
