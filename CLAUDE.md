# CLAUDE.md — SecuBox-DEB
## Migration OpenWrt → Debian · GlobalScale Marvell Armada
### Instructions pour Claude Code dans VSCode

---

## 🧭 Session Startup — Lire d'abord

### Fichiers de référence obligatoires

| Priorité | Fichier | Description | Quand lire |
|----------|---------|-------------|------------|
| 1 | `.claude/WIP.md` | Travail en cours, prochain item | **Toujours en premier** |
| 2 | `.claude/TODO.md` | Backlog priorisé par phase | Pour planifier |
| 3 | `.claude/HISTORY.md` | Historique des changements | Pour contexte |
| 4 | `.claude/MIGRATION-MAP.md` | État modules (✅/🔄/⬜) | Pour status |
| 5 | `.claude/PATTERNS.md` | Patterns RPCD→FastAPI | Pour coder |
| 6 | `.claude/MODULE-COMPLIANCE.md` | Règles conformité | **Obligatoire avant code** |

### Fichiers de référence techniques

| Fichier | Description | Quand lire |
|---------|-------------|------------|
| `docs/TOOLS.md` | Référence outils build/génération | Pour builder |
| `.claude/QUICKSHEET-REFERENCE.md` | Quick ref commandes | Pour commandes |
| `.claude/DESIGN-CHARTER.md` | Charte UI/UX (C3BOX hermétique) | Pour frontend |
| `.claude/WEBUI-PANEL-GUIDELINES.md` | **Look & feel DÉFAUT des webui de gestion des modules** (cyan hybrid-dark, Courier Prime, emoji ; réf. `/certs/`) | Avant tout panel/admin webui |
| `.claude/WIKI-STYLE-GUIDE.md` | Style documentation | Pour docs |
| `.claude/NOTES.md` | Notes de session | Pour contexte additionnel |

### Workflow "continue" / "suivant" / "next"

1. Lire `WIP.md` → identifier le premier item "⬜ Next Up"
2. Implémenter selon `PATTERNS.md` et `MODULE-COMPLIANCE.md`
3. Mettre à jour les fichiers `.claude/` :
   - Cocher ✅ dans `MIGRATION-MAP.md` si module terminé
   - Déplacer dans "✅ Fait" dans `WIP.md`
   - Ajouter entrée datée dans `HISTORY.md`
   - Mettre à jour `TODO.md` si nécessaire

### Liens GitHub Issues

Pour les bugs et features : `https://github.com/CyberMind-FR/secubox-deb/issues`

Quand créer une issue :
- Bug non trivial nécessitant investigation
- Feature request de l'utilisateur
- Tâche à reporter pour plus tard

### Synchronisation GitHub Issues — Workflow Obligatoire

**Principe fondamental** : Transparence maximale. Chaque plan/feature majeure doit être synchronisée avec une GitHub Issue pour traçabilité publique.

#### Workflow complet (Open by Default)

```
┌─────────────────────────────────────────────────────────────────────┐
│  1. CRÉATION DU PLAN                                                │
│     ├─ Identifier la feature/bug dans WIP.md ou TODO.md             │
│     ├─ Créer GitHub Issue avec label approprié                      │
│     │   gh issue create --title "..." --body "..." --label "..."    │
│     └─ Référencer l'issue # dans WIP.md/TODO.md                     │
├─────────────────────────────────────────────────────────────────────┤
│  2. IMPLÉMENTATION                                                  │
│     ├─ Mettre à jour WIP.md avec progression                        │
│     ├─ Commenter l'issue avec avancement significatif               │
│     │   gh issue comment <#> --body "Progress: ..."                 │
│     └─ Cocher les sous-tâches dans l'issue si applicable            │
├─────────────────────────────────────────────────────────────────────┤
│  3. COMPLÉTION (NE PAS FERMER)                                      │
│     ├─ Créer commit avec référence issue : "feat: X (ref #42)"      │
│     ├─ Mettre à jour HISTORY.md avec entrée datée                   │
│     ├─ Déplacer vers "✅ Fait" dans WIP.md                          │
│     ├─ Commenter l'issue : "Implementation complete, pending review"│
│     └─ NE JAMAIS fermer automatiquement                             │
├─────────────────────────────────────────────────────────────────────┤
│  4. VALIDATION MANUELLE (User uniquement)                           │
│     ├─ User teste/valide la feature                                 │
│     ├─ User confirme : "Validated, closing"                         │
│     └─ User ferme l'issue OU demande corrections                    │
└─────────────────────────────────────────────────────────────────────┘
```

#### Labels GitHub recommandés

| Label | Usage |
|-------|-------|
| `migration` | Portage OpenWrt → Debian |
| `hardware` | LED, GPIO, I2C, board-specific |
| `api` | FastAPI endpoints |
| `frontend` | Dashboard, UI, CSS |
| `security` | CSPN, nftables, WAF |
| `infra` | HAProxy, nginx, systemd |
| `documentation` | README, CLAUDE.md |
| `wip` | Travail en cours |
| `blocked` | Bloqué par dépendance |

#### Commandes rapides

```bash
# Créer une issue depuis la ligne de commande
gh issue create --title "Port LED heartbeat from OpenWrt" \
  --body "$(cat <<'EOF'
## Context
Description du problème ou de la feature.

## Tasks
- [ ] Task 1
- [ ] Task 2
- [ ] Task 3

## Files
- `path/to/file.py`

## References
- Related: #XX
EOF
)" --label "migration,hardware"

# Lister les issues ouvertes
gh issue list --state open

# Commenter une issue
gh issue comment 42 --body "Progress: Backend completed, testing frontend"

# Voir une issue
gh issue view 42

# Fermer (USER UNIQUEMENT après validation)
gh issue close 42 --comment "Validated and deployed"
```

#### Règles strictes

1. **Jamais de fermeture automatique** — Seul le user peut valider et fermer
2. **Référencer dans les commits** — `feat: Add X (ref #42)` ou `fix: Y (closes #42)` si user a pré-validé
3. **Synchroniser WIP.md** — Chaque issue ouverte doit apparaître dans WIP.md
4. **Snapshot avant clôture** — Commit + tag si feature majeure
5. **Issues publiques** — Workflow open source, traçabilité maximale

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
│   ├── WIP.md                  ← Travail en cours
│   ├── TODO.md                 ← Backlog priorisé
│   ├── HISTORY.md              ← Historique changements
│   ├── MIGRATION-MAP.md        ← État migration modules
│   ├── PATTERNS.md             ← Patterns code
│   ├── MODULE-COMPLIANCE.md    ← Règles conformité
│   ├── QUICKSHEET-REFERENCE.md ← Quick ref commandes
│   ├── DESIGN-CHARTER.md       ← Charte UI/UX
│   └── NOTES.md                ← Notes session
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
├── scripts/                    ← Outils dev/déploiement (voir scripts/README.md)
│   ├── README.md               ← Documentation scripts
│   ├── build-packages.sh       ← Build tous les .deb
│   ├── deploy.sh               ← Déployer sur board via SSH
│   ├── new-package.sh          ← Scaffold un nouveau paquet
│   └── port-frontend.sh        ← Copier htdocs depuis secubox-openwrt
├── remote-ui/                  ← Interfaces UI déportées (voir remote-ui/README.md)
│   ├── README.md               ← Documentation remote-ui
│   └── round/                  ← Eye Remote Dashboard Pi Zero W
├── docs/
│   ├── TOOLS.md                ← Référence outils build/génération
│   └── PORTING-GUIDE.md        ← Guide portage module par module
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

## 🌿 Multi-Agent Worktree Workflow — Obligatoire

Chaque travail non-trivial doit s'exécuter dans un worktree dédié, créé via
`scripts/agent-worktree.sh start --issue <#>`. Le checkout principal
(`~/CyberMindStudio/secubox-deb/secubox-deb/`) est réservé au `master`
housekeeping et au travail humain — pas aux agents.

### Quand créer un worktree

- Toute issue GitHub avec label `bug`, `enhancement`, `documentation`,
  `eye-remote`, ou tout label métier (migration, hardware, api, frontend,
  security, infra)
- Toute tâche estimée > 30 min ou touchant ≥ 3 fichiers
- Toute feature/fix qui finira en PR

### Quand NE PAS en créer

- Édition triviale d'un seul fichier de suivi (`HISTORY.md`, `WIP.md`,
  `TODO.md`)
- Exploration read-only, réponse à une question
- Commits administratifs sur master (tags, bumps de version)

### Cycle obligatoire

```text
gh issue create
  → scripts/agent-worktree.sh start --issue <#>
  → cd ~/CyberMindStudio/secubox-deb-worktrees/<#>-<slug>
  → code + commits (chaque message: "(ref #<#>)")
  → scripts/agent-worktree.sh finish     # push + PR avec "Closes #<#>"
  → [user valide et merge la PR]
  → scripts/agent-worktree.sh clean <#>  # supprime worktree + branche
```

### Parallélisme

`start` refuse de créer un second worktree pour la même issue. Deux sessions
Claude (deux terminaux) peuvent travailler simultanément sur deux issues
distinctes sans collision.

### Source de vérité opérationnelle

`scripts/agent-worktree.sh --help`

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

### Mitmproxy Route Configuration (complet)

Quand tu ajoutes un nouveau service qui passe par HAProxy → mitmproxy :

1. Ajouter le vhost HAProxy :
   ```bash
   haproxyctl vhost add <domain>
   ```

2. Le backend sera par défaut `mitmproxy_inspector` (correct)

3. Ajouter la route mitmproxy (les DEUX fichiers) :
   ```bash
   # Éditer /srv/mitmproxy/haproxy-routes.json
   # Éditer /srv/mitmproxy-in/haproxy-routes.json
   ```
   ```json
   {
     "domain.example.com": ["127.0.0.1", PORT]
   }
   ```

4. Recharger mitmproxy :
   ```bash
   systemctl restart mitmproxy
   ```

5. Tester :
   ```bash
   curl -k https://domain.example.com/
   journalctl -u mitmproxy -f  # Voir les logs
   ```

---

## 🐧 Debian Shell Scripting Guidelines

### Différences avec OpenWrt

| Commande | OpenWrt | Debian |
|----------|---------|--------|
| JSON parsing | `jsonfilter` | `jq` |
| Timeout | Non disponible | `timeout` |
| Socket check | `netstat -tln` | `ss -tlnp` |
| Service | `/etc/init.d/X restart` | `systemctl restart X` |
| Logs | `logread` | `journalctl` |
| Config | UCI | TOML + netplan |

### Bonnes pratiques Bash sur Debian

```bash
#!/bin/bash
set -euo pipefail  # Strict mode

# Utiliser jq pour JSON (installé sur Debian)
value=$(jq -r '.field' /path/to/file.json)

# Vérifier port ouvert avec ss
ss -tlnp | grep -q ":8080 " && echo "Port 8080 open"

# Logs avec journalctl
journalctl -u secubox-crowdsec --since "1 hour ago" --no-pager

# Timeout disponible
timeout 5 curl -s http://localhost:8080/health || echo "Timeout"

# Netplan au lieu de UCI
netplan generate && netplan apply
```

### Detection de processus

```bash
# Sur Debian, pgrep -x fonctionne
pgrep -x crowdsec >/dev/null && echo "CrowdSec running"

# Ou utiliser systemctl
systemctl is-active --quiet secubox-crowdsec && echo "Active"
```

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

## 📡 API Reference — Eye-Remote Boot Media (v2.1.0+)

### Boot Media API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/eye-remote/boot-media/state` | Boot media state |
| POST | `/api/v1/eye-remote/boot-media/upload` | Upload to shadow |
| POST | `/api/v1/eye-remote/boot-media/swap` | Swap active/shadow |
| POST | `/api/v1/eye-remote/boot-media/rollback` | Rollback swap |
| GET | `/api/v1/eye-remote/boot-media/tftp/status` | TFTP status |

### Systemd Services

| Service | Description |
|---------|-------------|
| `secubox-eye-gadget.service` | USB gadget (ECM+ACM+mass_storage) |
| `secubox-eye-serial.service` | Serial console via xterm.js |
| `secubox-eye-websocket.service` | WebSocket API server |

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
