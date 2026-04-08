# CLAUDE.md — SecuBox-DEB
## Migration OpenWrt → Debian · GlobalScale Marvell Armada
### Instructions pour Claude Code dans VSCode

---

## 🧭 Session Startup — Lire d'abord

**À chaque session, lire dans cet ordre :**

1. `.claude/WIP.md`             → ce qui est en cours, le prochain à faire
2. `.claude/TODO.md`            → backlog priorisé par phase
3. `.claude/MIGRATION-MAP.md`   → état de chaque module (✅ / 🔄 / ⬜)
4. `.claude/PATTERNS.md`        → patterns RPCD→FastAPI avec exemples réels
5. `.claude/MODULE-COMPLIANCE.md` → **règles de conformité obligatoires**

**Quand l'utilisateur dit "continue" / "suivant" / "next" :**
Consulter `WIP.md` → prendre le premier item "⬜ Next Up" → l'implémenter → mettre à jour les fichiers `.claude/`.

---

## 🏗️ Ce qu'est ce projet

**SecuBox-DEB** est le portage Debian bookworm arm64 de SecuBox OpenWrt.

**Source** : `https://github.com/gkerma/secubox-openwrt`
Chaque `package/secubox/luci-app-<module>/` devient un paquet Debian `secubox-<module>`.

**Principe de migration :**
- Frontend `htdocs/` (HTML/JS/CSS) → **conservé à l'identique** dans `www/`
- Backend `root/usr/libexec/rpcd/luci.<module>` (shell) → **porté** en `api/main.py` (FastAPI)
- Config `root/etc/config/` (UCI) → `debian/` + `/etc/secubox/<module>.toml`
- Makefile OpenWrt → `debian/control` + `debian/rules` + `debian/postinst`
- Menu/ACL JSON → conservés, plus middleware JWT FastAPI

**Stack cible :**
- Debian bookworm arm64
- Kernel 6.6 LTS mainline (DTS Marvell upstream)
- FastAPI + Uvicorn sur Unix socket par module
- Nginx reverse proxy : statics htdocs + `/api/v1/<module>/*`
- nftables, netplan, WireGuard kernel natif
- CrowdSec dpkg officiel, HAProxy TLS 1.3
- APT repo signé GPG : `apt.secubox.in`

---

## 📁 Structure du repo

```
secubox-deb/
├── .claude/                    ← Suivi de projet (lire en premier)
│   ├── TODO.md
│   ├── WIP.md
│   ├── MIGRATION-MAP.md
│   └── PATTERNS.md
├── .github/workflows/          ← CI GitHub Actions cross-arm64
│   ├── build-image.yml
│   └── build-packages.yml
├── .vscode/                    ← Tasks VSCode
│   └── tasks.json
├── board/                      ← Config par board GlobalScale
│   ├── mochabin/               ← Armada 7040, cible Pro
│   │   ├── config.mk
│   │   └── netplan/00-secubox.yaml
│   ├── espressobin-v7/         ← Armada 3720, cible Lite
│   └── espressobin-ultra/      ← Armada 3720 Ultra
├── image/                      ← Scripts de construction d'image
│   ├── build-image.sh          ← debootstrap → .img flashable
│   ├── firstboot.sh            ← SSH keys, JWT, hostname
│   └── partition-layout.sh     ← GPT : ESP + rootfs + data
├── common/                     ← Code partagé
│   ├── secubox_core/           ← Lib Python : JWT, config, logging
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   ├── config.py
│   │   └── logger.py
│   ├── nginx/secubox.conf      ← Template nginx reverse proxy
│   └── systemd/                ← Units systemd génériques
├── packages/                   ← 14 paquets Debian
│   ├── secubox-core/           ← Bibliothèque partagée Python
│   ├── secubox-hub/            ← luci-app-secubox → dashboard central
│   ├── secubox-crowdsec/       ← luci-app-crowdsec-dashboard
│   ├── secubox-netdata/        ← luci-app-netdata-dashboard
│   ├── secubox-wireguard/      ← luci-app-wireguard-dashboard
│   ├── secubox-dpi/            ← luci-app-netifyd-dashboard + dpi-dual
│   ├── secubox-netmodes/       ← luci-app-network-modes
│   ├── secubox-nac/            ← luci-app-client-guardian
│   ├── secubox-auth/           ← luci-app-auth-guardian
│   ├── secubox-qos/            ← luci-app-bandwidth-manager
│   ├── secubox-mediaflow/      ← luci-app-media-flow
│   ├── secubox-cdn/            ← luci-app-cdn-cache
│   ├── secubox-vhost/          ← luci-app-vhost-manager
│   └── secubox-system/         ← luci-app-system-hub
├── scripts/                    ← Outils dev/déploiement
│   ├── new-package.sh          ← Scaffold un nouveau paquet
│   ├── deploy.sh               ← Déployer sur board via SSH
│   ├── port-frontend.sh        ← Copier htdocs depuis secubox-openwrt
│   └── rewrite-xhr.py          ← Réécrire /cgi-bin/luci → /api/v1
├── docs/
│   └── PORTING-GUIDE.md        ← Guide complet de portage module par module
├── secubox.conf.example        ← /etc/secubox/secubox.conf (TOML)
├── setup-dev.sh                ← Installation environnement dev
└── README.md
```

---

## 🔑 Règles impératives

### Réseau / Sécurité
- **JAMAIS** de waf_bypass ni de port ouvert inutile
- nftables DEFAULT DROP — ouvrir explicitement seulement ce qui est nécessaire
- HAProxy en frontal TLS 1.3 pour toute exposition externe
- AppArmor profile enforce pour chaque service

### Pattern FastAPI (RPCD → API)
- Chaque méthode RPCD `luci.<module>/<method>` → `GET /api/v1/<module>/<method>`
- Les méthodes d'action (set_*, apply, ban...) → `POST /api/v1/<module>/<method>`
- Authentification JWT **obligatoire** sur tous les endpoints via `Depends(auth.require_jwt)`
- Socket Unix `/run/secubox/<module>.sock` — jamais de port TCP direct

### Packaging Debian
- Versioning : `1.0.0-1~bookworm1`
- `debian/postinst` : `systemctl enable --now secubox-<module>`
- `debian/prerm` : `systemctl stop secubox-<module>`
- Toujours `debian/compat` = 13, `Standards-Version: 4.6.2`

### Frontend (htdocs conservé)
- **Ne pas modifier** le JS/CSS/HTML des vues LuCI
- Le script `scripts/rewrite-xhr.py` remplace les appels ubus par des appels REST
- URL pattern : `rpc.declare({object: 'luci.X', method: 'Y'})` → `fetch('/api/v1/X/Y')`

### Mise à jour des fichiers de suivi
Après chaque module complété :
- Cocher `✅` dans `.claude/MIGRATION-MAP.md`
- Mettre à jour `.claude/WIP.md` (déplacer vers "Fait", pointer le suivant)
- Appender à `.claude/HISTORY.md` avec la date

---

## 🔒 Security Policies — Héritées de secubox-openwrt, adaptées Debian

### WAF Bypass — Interdiction absolue

* **JAMAIS de `waf_bypass` dans une config HAProxy** — tout le trafic DOIT passer
  par mitmproxy pour inspection
* Quand tu ajoutes un nouveau vhost, route systématiquement via le backend
  `mitmproxy_inspector` dans HAProxy
* Si un service nécessite WebSocket ou long-polling, configure mitmproxy
  pour forward correctement — ne pas bypasser le WAF
* Après ajout d'un backend HAProxy, mettre à jour `/srv/mitmproxy/haproxy-routes.json`
  ET `/srv/mitmproxy-in/haproxy-routes.json` :
```json
  "domain.example.com": ["127.0.0.1", PORT]
```
* Redémarrer : `systemctl restart mitmproxy`

---

## ⚡ Performance Patterns — Double Caching (porté depuis OpenWrt)

Le pattern shell → cron + fichier statique se traduit en Debian par
**background task FastAPI + fichier cache JSON** :

### Pattern Debian (FastAPI + asyncio)
```python
# Dans api/main.py de chaque module stats-heavy
import asyncio, json
from pathlib import Path

CACHE_FILE = Path("/var/cache/secubox/<module>/stats.json")
_cache: dict = {}

async def refresh_cache():
    """Tourne en background, met à jour toutes les 60s."""
    while True:
        try:
            data = await _compute_stats()  # logique métier
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(json.dumps(data))
            _cache.update(data)
        except Exception as e:
            logger.error(f"cache refresh failed: {e}")
        await asyncio.sleep(60)

@app.on_event("startup")
async def startup():
    asyncio.create_task(refresh_cache())

@app.get("/stats")
async def get_stats():
    if _cache:
        return _cache
    if CACHE_FILE.exists():
        return json.loads(CACHE_FILE.read_text())
    return {"error": "cache not ready"}
```

### Règle d'application (identique OpenWrt)

* **Toujours** pour les dashboards stats (WAF, CrowdSec, bandwidth, DPI…)
* **Toujours** quand l'endpoint lit des logs ou calcule des agrégats
* **Toujours** quand la donnée peut être périmée de 60s sans impact utilisateur
* **Jamais** pour les actions temps-réel (start/stop/restart/ban)

---

## 🚀 Punk Exposure Engine — Directive Architecturale

Héritée de `secubox-openwrt/package/secubox/PUNK-EXPOSURE.md`.
Le modèle trois-verbes **Peek / Poke / Emancipate** s'applique identiquement
sur base Debian — seuls les transports changent.

### Trois canaux d'exposition

| Canal    | OpenWrt              | Debian                          |
|----------|----------------------|---------------------------------|
| Tor      | secubox-app-tor      | tor.service + secubox-exposure  |
| DNS/SSL  | HAProxy + ACME + UCI | HAProxy TLS1.3 + certbot + TOML |
| Mesh     | secubox-p2p (à porter) | secubox-p2p-deb (à porter)    |

### Règles invariantes (Debian = OpenWrt)

* **Join par port, jamais par nom** — cross-référencer scan ↔ Tor/SSL/Mesh
  via le numéro de port backend uniquement
* **Jamais d'auto-exposition de 127.0.0.1** — seuls les services sur
  `0.0.0.0` ou IP LAN spécifique sont éligibles à l'exposition externe
* **Emancipate est multi-canal** — un service peut activer Tor + DNS + Mesh
  dans un seul workflow ; chaque canal est indépendamment toggleable

### CLI Debian (cible)
```bash
# Port depuis OpenWrt — même interface, backend Debian
secubox-exposure emancipate <service> <port> <domain> --all
secubox-exposure emancipate secret 8888 --tor
secubox-exposure revoke myapp --all
```

---

## 📝 Documentation Update Workflow (identique OpenWrt)

Après chaque modification de code :

1. **`.claude/HISTORY.md`** — ajouter entrée datée
2. **`.claude/WIP.md`** — déplacer "fait", pointer le suivant
3. **`.claude/MIGRATION-MAP.md`** — cocher `✅` si module complété
4. **`packages/<module>/README.md`** — mettre à jour si CLI ou API change

Format de commit :
```
git commit -m "docs: Update tracking files for <feature>"
```

Déclencheurs obligatoires de mise à jour README :
* Nouvel endpoint FastAPI ajouté
* Modèle Pydantic modifié (= contrat API changé)
* Options TOML ajoutées ou renommées
* Dépendance Debian ajoutée dans `debian/control`

---

## 🛡️ Règles CSPN / Sécurité formelle

*(Critiques pour certification ANSSI)*

* **Double-buffer PARAMETERS** : toute modification de config sensible passe
  par un buffer shadow → validation → swap atomique. Rollback 4R obligatoire
  (Read → Write → Validate → Rollback-or-Commit)
* **Journalisation immuable** : chaque décision de sécurité (ban, unban,
  changement de règle WAF) écrite dans `/var/log/secubox/audit.log`
  (append-only, rotation sans truncate)
* **Séparation de privilèges** : chaque daemon tourne sous `secubox-<module>`
  (user/group dédié créé dans `debian/postinst`), jamais root
* **Secrets hors code** : `/etc/secubox/secrets/` chmod 600, owner
  `secubox-<module>`. Aucun secret dans le code ni dans TOML versionné
* **AppArmor enforce** : profil obligatoire pour chaque service, livré dans
  `debian/` et activé dans `postinst`

---

## 🛠️ Commandes usuelles

```bash
# Build un paquet .deb localement (cross arm64)
cd packages/secubox-crowdsec
dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b

# Déployer sur le MOCHAbin
bash scripts/deploy.sh secubox-crowdsec root@192.168.1.1

# Construire l'image complète
bash image/build-image.sh --board mochabin --out /tmp/secubox-deb.img

# Porter le frontend d'un module depuis le repo source
bash scripts/port-frontend.sh crowdsec-dashboard

# Réécrire les appels XHR d'un module
python3 scripts/rewrite-xhr.py packages/secubox-crowdsec/www/

# Lancer l'API d'un module en dev local
cd packages/secubox-crowdsec && uvicorn api.main:app --reload --uds /tmp/crowdsec.sock
```

---

## 🎯 Priorité de migration

| Ordre | Module | Complexité | Raison |
|-------|--------|------------|--------|
| 1 | secubox-core | — | Dépendance de tous |
| 2 | secubox-hub | Facile | Référence de pattern |
| 3 | secubox-crowdsec | Facile | API REST déjà dispo |
| 4 | secubox-netdata | Facile | Proxy simple |
| 5 | secubox-wireguard | Facile | wg CLI natif |
| 6 | secubox-vhost | Facile | Templates nginx |
| 7 | secubox-dpi | Moyen | Socket netifyd |
| 8 | secubox-mediaflow | Facile | Consomme secubox-dpi |
| 9 | secubox-qos | Moyen | pyroute2 tc HTB |
| 10 | secubox-system | Moyen | pystemd DBus |
| 11 | secubox-netmodes | Complexe | netplan + bridge |
| 12 | secubox-nac | Complexe | nft sets + dnsmasq |
| 13 | secubox-auth | Moyen | authlib OAuth2 |
| 14 | secubox-cdn | Moyen | squid/nginx cache |

---

## 📡 Auteur

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr · https://secubox.in
