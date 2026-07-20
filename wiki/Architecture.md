# Architecture

SecuBox-Deb est structuré autour de six modules canoniques organisés en chemin hamiltonien. Chaque module expose une API REST FastAPI, le tout orchestré par un profile-generator hiérarchique YAML.

---

## Six modules — Chemin hamiltonien

```
AUTH → WALL → BOOT → MIND → ROOT → MESH
```

Les modules forment un graphe complet où chaque nœud est connecté à tous les autres, mais le chemin canonique définit l'ordre de priorité et de dépendance.

| Module | Couleur | Hex | Fonction |
|--------|---------|-----|----------|
| **AUTH** | Terracotta | `#C04E24` | Authentification, ZeroTrust, MFA, portail captif |
| **WALL** | Ocre | `#9A6010` | Firewall nftables, CrowdSec, WAF, IDS/IPS |
| **BOOT** | Brique | `#803018` | Déploiement, provisioning, clonage, vault |
| **MIND** | Indigo | `#3D35A0` | IA, analyse comportementale, DPI, SOC |
| **ROOT** | Vert profond | `#0A5840` | Système, CLI, hardening, hub central |
| **MESH** | Bleu nuit | `#104A88` | Réseau, WireGuard, HAProxy, QoS, TURN |

### Paires complémentaires

Les modules s'associent en paires complémentaires pour certaines fonctions :

- `BOOT ↔ ROOT` — Provisioning et système
- `WALL ↔ MIND` — Défense et analyse
- `MESH ↔ AUTH` — Réseau et identité

---

## Stack technique

### Base système

| Composant | Choix | Notes |
|-----------|-------|-------|
| OS | Debian 12 (bookworm) ARM64/AMD64 | Pas d'OpenWrt, pas de LuCI |
| Kernel | 6.6 LTS mainline | Device trees upstream Marvell |
| Init | systemd | Units par module |
| Firewall | nftables | DEFAULT DROP, pas d'iptables |
| Réseau | netplan | Configuration YAML |

### Stack applicative

| Composant | Choix | Notes |
|-----------|-------|-------|
| Backend | FastAPI + Uvicorn | Socket Unix par module |
| Frontend | HTML/CSS/JS vanilla | Palette CyberMind, pas de framework lourd |
| Config | YAML + TOML | Double-buffer, 4R versioning |
| Reverse proxy | Nginx | Statics + proxy API |
| TLS | HAProxy | TLS 1.3 minimum, Let's Encrypt |

### Sécurité active

| Composant | Choix | Notes |
|-----------|-------|-------|
| IDS/IPS | Suricata + CrowdSec | Bouncers intégrés |
| WAF | mitmproxy + ModSecurity rules | Inspection HTTPS |
| DPI | nDPId + netifyd | Dual-stream via tc mirred |
| DNS | Unbound | Vortex DNS + blocklists |

---

## Profile-generator

Le profile-generator est un système hiérarchique YAML qui génère la configuration de chaque carte à partir de profils empilés.

```
defaults/
  └── base.yaml           # Configuration commune
boards/
  ├── mochabin/
  │   └── profile.yaml    # Spécificités MOCHAbin
  ├── espressobin-v7/
  │   └── profile.yaml    # Spécificités ESPRESSObin
  └── x64-vm/
      └── profile.yaml    # Spécificités VM
profiles/
  ├── full.yaml           # Tous les modules
  ├── lite.yaml           # Modules essentiels
  └── minimal.yaml        # Firewall + SSH uniquement
```

L'héritage : `defaults → board → profile → user overrides`

---

## Framework GK·HAM-HASH ZKP

La cryptographie s'appuie sur un framework Zero-Knowledge Proof à trois niveaux.

### L1 — Auth twins (Prover/Verifier)

Authentification NIZKProof hamiltonien. Rotation du graphe G toutes les 24h avec Perfect Forward Secrecy.

### L2 — Routing twins (double-buffer)

Configuration en double-buffer : `active/` (lecture seule) et `shadow/` (édition). Swap atomique conditionné par validation ZKP. Rollback 4R (4 snapshots).

### L3 — Endpoint twins (service/witness)

MirrorNet P2P avec `did:plc`, tunnels WireGuard, et Chain of Hamiltonians pour la preuve de présence réseau.

---

## API REST

Chaque module expose une API FastAPI sur socket Unix :

```
/run/secubox/hub.sock      → /api/v1/hub/*
/run/secubox/crowdsec.sock → /api/v1/crowdsec/*
/run/secubox/wireguard.sock → /api/v1/wireguard/*
...
```

Nginx reverse proxy unifie l'accès :

```text
GET  /api/v1/<module>/<method>   # Lecture
POST /api/v1/<module>/<method>   # Action
```

Authentification JWT obligatoire sur tous les endpoints via `Depends(auth.require_jwt)`.

### Opérations privilégiées — le webui sous-traite au `ctl` confiné et audité (REQUIRED)

L'API/webui tourne **sans privilège** (`User=secubox`, et servie in-process par
l'aggregator elle partage son contexte `secubox`). Elle ne peut donc ni lire/écrire
la config root (ex. `/etc/secubox/waf` est `0750 root:root`), ni piloter
systemd/LXC/une app en direct.

> **Principe.** Toute opération qui touche un fichier root ou qui **cause au
> système / à une app** (start/stop/reload d'une unit, écriture d'une config live,
> exécution d'un binaire privilégié) est **déléguée au helper root
> `secubox-<module>ctl`**. Le webui devient un client JWT léger ; le **`ctl` est la
> surface privilégiée unique** — confinée (sudoers scopé, commande exacte),
> **auditée** (`/var/log/secubox/audit.log`), et c'est elle qui pilote réellement.

Chaîne : `panel (JWT) → route def → sudo -n secubox-<module>ctl <verbe> --json →`
le `ctl` (root) valide, agit, audite, renvoie un payload `--json` que le panel rend.
Le grant sudoers (`/etc/sudoers.d/secubox-<module>`, `0440`, commande exacte, sans
wildcard) est **livré par le paquet** et documenté. Symptôme si absent :
`PermissionError` → 500 (« request error » / panneau vide).

Note aggregator : une route servie in-process par l'aggregator n'apparaît qu'après
`systemctl restart secubox-aggregator` (le code module est importé au démarrage).

Réf. d'implémentation : `secubox-cvectl` (génération de règles WAF),
`secubox-profilectl` (bascule on/off des modules). Contrat complet :
[`.claude/MODULE-COMPLIANCE.md`](../.claude/MODULE-COMPLIANCE.md) → *Privileged Operations*.

### Dual-vhost split — REQUIRED pour les modules avec UI applicative

Un module qui embarque une application avec sa propre interface web
(LMS Material, zigbee2mqtt, Authelia, Nextcloud, Grafana, …) **DOIT**
séparer ses deux surfaces sur des hôtes distincts :

| URL | Rôle |
| --- | --- |
| `https://admin.gk2.secubox.in/<module>/` | Admin SecuBox (statique, appelle `/api/v1/<module>/*`) |
| `https://<module>.gk2.secubox.in/` | App réelle servie à la racine du vhost, Authelia-gated |

Reverse-proxy de l'app sous `/<module>/` casse silencieusement les
URLs d'assets absolues (`/material/`, `/cometd/`, `/apps/`, `/public/`).
Le bouton `Open <module> UI →` de la page admin lit son href depuis
`/api/v1/<module>/access` au runtime — jamais hardcoded.

Détails complets : [`docs/MODULE-GUIDELINES.md`](../docs/MODULE-GUIDELINES.md) §4 (REQUIRED) + §5.

---

## Scale-to-zero — cycle de vie des modules (ref #896)

`secubox-profiles` porte, en plus de l'inventaire/apply déjà décrits, une
politique de cycle de vie par module (`lifecycle` dans son manifeste
`/etc/secubox/modules.d/<id>.toml`) : `always-on` (jamais éteint — un
`protected` l'est toujours, quoi qu'il déclare), `eager` (démarre au boot,
peut se rendormir), `on-demand` (éteint par défaut, réveillé sur accès) et
`manual` (opérateur uniquement).

Deux services dédiés pilotent le sommeil/réveil :

- **`secubox-sleeper.service`** (root, tick 30s) — endort tout module
  `eager`/`on-demand` observé idle (aucune connexion active depuis le seuil
  configuré, aucun réveil en cours) via le même actionneur `apply_plan` que
  `secubox-profilectl apply` (snapshot 4R, audit, rollback si échec). Ne dort
  jamais sur un signal indéterminé.
- **`secubox-waker.service`** (`User=secubox`, non privilégié) — reçoit du
  trafic **sbxwaf** (le WAF Go, `packages/secubox-toolbox-ng`/`secubox-waf-ng`) :
  un vhost on-demand sans route active est proxifié vers `/_wake/<vhost>` au
  lieu d'un 421. Le waker sert un splash 503 (`templates/waking.html`) et
  déclenche le réveil via `sudo→systemd-run→secubox-wakectl` (webui→ctl,
  jamais en direct — même patron que les autres `ctl` confinés).

Ce mécanisme **remplace** le déclencheur nginx `@waker` envisagé initialement
(PIVOT 2026-07-20) : `sbxwaf` est le point d'entrée du trafic public sur ce
dépôt, c'est donc lui qui détecte l'accès à un vhost éteint, pas nginx.

Détails complets (table lifecycle, format manifeste, procédure pilote) :
[`packages/secubox-profiles/README.md`](../packages/secubox-profiles/README.md#scale-to-zero--lifecycle-waker-sleeper-ref-896).

---

## Contraintes ANSSI CSPN

Le projet vise la certification ANSSI CSPN à horizon 2027. Contraintes respectées :

| Exigence | Implémentation |
|----------|----------------|
| Séparation des privilèges | User/group dédié par daemon |
| Chiffrement | TLS 1.3 minimum partout |
| Journalisation | Append-only, horodaté RFC 3339 |
| Rollback | Double-buffer 4R obligatoire |
| Surface d'attaque | Services désactivés par défaut |
| Tests | Couverture ≥ 80%, tests régression |

---

## Liens

- **[[Modules|MODULES-EN]]** — Documentation des 125 paquets
- **[[API-Reference]]** — Référence API (2000+ endpoints)
- **[[Hardware-Matrix]]** — Cibles matérielles supportées
- **[[Roadmap]]** — État du développement
