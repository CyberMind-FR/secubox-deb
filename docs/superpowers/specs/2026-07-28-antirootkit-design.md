<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-antirootkit — Design (host-IDS / anti-rootkit)

*Issue #915. Né de l'incident #914 (backdoor C2 `notwork-monitoring` restée ~7 semaines non détectée).*

## Objectif

Détecter, alerter et **préparer** la neutralisation des persistances non autorisées type C2/trojan sur un hôte SecuBox, en distinguant automatiquement le légitime (paquet dpkg signé) du malveillant (hors-paquet + comportement suspect). Répondre instantanément à « **ce process est-il légitime ?** » — la question que l'incident #914 et la confusion YaCy/threat-analyst ont rendue concrète.

## Décisions validées (brainstorming)

- **Home + base de détection** : nouveau paquet Debian `secubox-antirootkit` qui **orchestre des outils éprouvés** (`debsums`, `aide`, `rkhunter`, `chkrootkit`) + une **couche SecuBox** (heuristiques C2, baseline, alerte mesh, préparation quarantaine).
- **Posture de réponse — deux niveaux distincts :**
  - **Anti-escape (egress) = AUTO-BLOQUE.** Un process **hors-dpkg** qui tente une connexion sortante est **bloqué immédiatement** (le C2/exfil meurt avant son 1er beacon) + alerte. C'est sûr : bloquer l'egress d'un inconnu ne casse quasi jamais du légitime. **C'est la capacité prioritaire (« super anti-escape »).**
  - **Neutralisation du process (kill/quarantaine) = ALERTE SEULE.** Le module *prépare* la séquence de quarantaine ; l'opérateur valide. (Justifié : gk2 a 200+ services ; un faux positif tué casserait du légitime.)
- **Traçage des exec (cœur du process scanner)** : **auditd** (`-S execve`), qui logue chaque exec **tenté ET réussi/échoué** (forensic, standard CSPN).

## Prérequis (bloquant install, dette existante)

Sur gk2, `apt install` échoue (deps cassées : `secubox-ndpid`/`secubox-netifyd`/`secubox-p2p`/`secubox-rtty` → `ndpid`/`netifyd`/`python3-aiohttp`/`rtty` introuvables) **et `/boot` est plein à 100%**. Le module dépend de `auditd`, `debsums`, `aide`, `rkhunter`, `chkrootkit` → **réparer l'état apt + nettoyer `/boot` est un prérequis** avant déploiement. À traiter hors périmètre de ce module (tâche de maintenance).

## Architecture

Paquet `secubox-antirootkit` : daemon Python + API FastAPI sur socket Unix `/run/secubox/antirootkit.sock` (pattern SecuBox aggregator-served). Trois sous-systèmes isolés, chacun avec une responsabilité et une interface claires.

### A. Process Scanner (cœur — priorité v1) — via auditd

**Responsabilité** : ne rien laisser s'exécuter (ni *tenter* de s'exécuter) sans trace, et alerter sur les exec anormaux.

- **Règle auditd** livrée dans `/etc/audit/rules.d/99-sbx-procwatch.rules` :
  ```
  -a exit,always -F arch=b64 -S execve -k sbx_exec
  -a exit,always -F arch=b32 -S execve -k sbx_exec
  ```
  (Alternative bas-volume si nécessaire : watches ciblées `-w /usr/local/bin -p x`, `/tmp`, `/dev/shm`, `/opt`, `/usr/lib/jvm` — voir §Perf.)
- **Daemon `sbx-procwatchd`** lit le flux audit (via `auditd` + `ausearch`/`aureport`, ou socket `audispd`) et enregistre chaque exec dans une base **SQLite append-only** `/var/lib/secubox/antirootkit/execlog.db` : `ts, pid, ppid, uid, exe, argv, cwd, success (yes/no), exit, key, dpkg_pkg (nullable)`.
- **Champ `dpkg_pkg`** résolu par `dpkg -S <exe>` (mis en cache) → **la réponse « légitime ? » = `dpkg_pkg IS NOT NULL`**. (YaCy → `secubox-yacy` ✓ ; threat-analyst → `secubox-threat-analyst` ✓ ; `notwork-monitoring` → NULL ✗.)
- **Heuristiques d'alerte** (score, pas de kill) :
  - exec d'un binaire **hors-dpkg** depuis `/usr/local/bin|sbin`, `/tmp`, `/dev/shm`, `/opt`, `$HOME` ;
  - **exec en échec répété** (`success=no` récurrent pour le même exe) = signature crash-loop (`notwork` tentait toutes les 10s et échouait sur l'arch) ;
  - exe hors-dpkg **+ connexion sortante** (corrélation avec `secubox-netstats`/conntrack) ;
  - exe dont l'unit systemd a `Restart=always` **+** `StandardOutput/Error=null` (logs silencés).

### A2. Process Network Sentinel — anti-escape (cœur v1, capacité PRIORITAIRE)

**Responsabilité** : empêcher tout process **inconnu (hors-dpkg)** de communiquer vers l'extérieur — stopper le C2/exfil avant le 1er paquet.

**Mécanisme (élégant, piloté par A)** : le scanner exec (auditd, §A) détecte l'exec d'un binaire dont `dpkg_pkg IS NULL` (hors-dpkg) → le daemon place immédiatement le PID (et ses enfants) dans un **cgroup v2 `sbx-untrusted.slice`** → une règle **nftables** droppe l'egress de ce cgroup :
```
table inet secubox_antiescape {
  chain output {
    type filter hook output priority filter; policy accept;
    socket cgroupv2 level 2 "sbx-untrusted.slice" ip daddr != @lan_safe drop
  }
}
```
- Un binaire **dpkg-backed** (YaCy, threat-analyst, tous les `secubox-*`) n'est **jamais** mis dans `sbx-untrusted` → egress libre. **Zéro impact sur le légitime.**
- Un binaire **hors-dpkg** (profil `notwork`, un dropper dans `/tmp`…) → egress **bloqué dès le connect** + alerte enrichie (destination, IOC match).
- **Allow-list d'exceptions** (TOML) pour les scripts `/usr/local/bin` légitimes non-dpkg identifiés (ex : `certbot`, `acme-*`, `jws` — déjà audités sur gk2) → sortis de `sbx-untrusted`.
- Corrélation destination : match IOC connus (`cyberfeed`/`threatmesh`), résolution du process propriétaire du socket (via le PID cgroup-jailé), log dans l'execlog.

**Pourquoi ça aurait tué #914** : `notwork-monitoring` (hors-dpkg) aurait été cgroup-jailé dès son 1er exec → son beacon vers `5.182.207.11` droppé avant d'aboutir, + alerte immédiate. (Et sur gk2 il ne s'exécutait même pas — arch ; mais sur l'amd64 il aurait été neutralisé côté réseau instantanément.)

### B. Integrity Scanner (wrap outils — v1 léger)

**Responsabilité** : intégrité des fichiers et points de persistance.

- Orchestre en tâche planifiée (timer) : `debsums -c` (fichiers dpkg altérés), `aide --check` (baseline signée `/var/lib/secubox/antirootkit/aide.db`), `rkhunter --check --sk` + `chkrootkit` (signatures connues).
- Surveille les **points de persistance** : `/usr/local/{bin,sbin}` (fichiers hors-dpkg), units systemd (`Restart=always` + logs null + `ExecStart` hors-dpkg), `~/.ssh/authorized_keys` (clés inconnues vs baseline), crontabs, `/etc/ld.so.preload`, `/etc/systemd/system/*.timer`.
- Baseline signée (clé nœud, comme les autres modules SecuBox) → dérive = alerte.

### C. Alerte + Préparation-quarantaine (alerte SEULE)

**Responsabilité** : notifier et outiller l'opérateur, sans jamais agir seul.

- **Alerte** : émet vers `secubox-soc` (agrégateur), mail, et `threatmesh` (mesh). Enrichit avec match **IOC connus** (feed `secubox-cyberfeed`/`secubox-threatmesh` : hash/IP/domaine/ASN — incluant les IOC #914 : `notwork-monitoring`, `5.182.207.11`, AS213250).
- **Préparation quarantaine** (jamais exécutée automatiquement) : pour une menace confirmée, prépare et présente dans le SOC la séquence — `chmod 000` + copie horodatée + `sha256` + bundle de preuves + `nft output ip daddr <C2> drop` + `systemctl disable` de l'unit — **derrière un bouton de validation opérateur**.
- **Panneau webui** `/antirootkit` (pattern WEBUI-PANEL-GUIDELINES) : timeline des exec (qui/quoi/quand/où/parent), verdict légitime/suspect par ligne, état des scans intégrité, file d'alertes avec bouton « quarantiner » (validation manuelle).

## Flux de données

```
auditd (execve) ──→ sbx daemon ──┬─ dpkg-backed ? ─── oui ─→ egress libre
                                 │                    non ─→ cgroup sbx-untrusted.slice
                                 │                            └─→ nft DROP egress (anti-escape) + alerte
                                 ├─→ SQLite append-only (execlog: qui/quoi/quand/où/parent/dpkg)
                                 └─→ moteur de règles ─┬─→ alerte SOC/mail/mesh (+ IOC match)
aide/debsums/rkhunter/keys ──────┘                     └─→ bouton quarantaine process (MANUEL)
                                                       └─→ API/panneau /antirootkit
```

## Gestion d'erreurs

- auditd absent/cassé → le module démarre en **mode dégradé** (scan intégrité seul) + alerte « process-scan indisponible » (ne bloque pas le boot).
- `dpkg -S` lent → cache mémoire + persistant.
- Base SQLite corrompue → recrée + alerte, ne perd pas le daemon.
- Volume audit élevé → bascule automatique sur watches ciblées (§Perf) + rotation.

## Performance

- La règle `-S execve` globale est **volumineuse** sur une box à 200+ services (health-checkers spawnent en continu). v1 : **watches ciblées** sur les chemins à risque (`/usr/local/{bin,sbin}`, `/tmp`, `/dev/shm`, `/opt`, `/usr/lib/jvm`) + rotation `audit.log`. La règle globale reste une **option** (config TOML `procwatch.mode = targeted|full`).
- Double-cache (pattern SecuBox) pour l'API stats du panneau.

## Tests

- **⭐ Anti-escape (priorité)** : un binaire hors-dpkg qui tente une connexion sortante → **egress DROPPÉ dès le connect** (cgroup `sbx-untrusted` + nft), le beacon n'aboutit jamais, alerte émise. Un binaire dpkg-backed (YaCy/`secubox-*`) qui sort → **jamais bloqué**.
- **Rejeu du profil #914** : binaire hors-dpkg dans `/usr/local/bin` + unit `Restart=always` + `Standard*=null` + (simulateur de) beacon → **doit lever une alerte FORTE**, apparaître non-dpkg dans l'execlog, ET son egress être bloqué.
- **Non-régression légitime (0 faux positif)** : YaCy (`secubox-yacy`, java) + `secubox-threat-analyst` (Python) → **verdict légitime** (dpkg-backed), aucune alerte, jamais quarantinés.
- **Crash-loop** : unit qui échoue à l'exec en boucle → détecté via `success=no` récurrent.
- **Intégrité** : altérer un fichier dpkg → `debsums` le détecte ; ajouter une clé à `authorized_keys` → dérive baseline détectée.
- **Alerte-seule** : vérifier qu'aucune neutralisation n'est jamais exécutée sans validation.
- Tests repo `.venv`, per-directory (pytest.ini).

## Hors périmètre (v1)

- Auto-**kill/quarantaine** du process (posture = alerte seule). ⚠️ NB : l'auto-**blocage egress** (anti-escape §A2), lui, EST dans le périmètre v1 — c'est une action sûre et prioritaire, à ne pas confondre avec la neutralisation du process.
- eBPF (auditd retenu pour l'exec ; l'anti-escape v1 = cgroup+nft. eBPF `cgroup/connect` = évolution v2 pour bloquer au connect() avec plus de finesse).
- Sweep fleet inter-nœuds (le module est host-local ; la fédération passe par `threatmesh`/SOC existants).
- Réparation de l'état apt / `/boot` (prérequis de maintenance, hors module).

## Invariants SecuBox

- **Jamais root in-process** pour les actions : le daemon tourne sous `secubox-antirootkit` ; les actions root (quarantaine) passent par un `ctl` scoped-sudo validé opérateur (pattern `feedback_webui_delegates_to_confined_ctl`).
- Journal execlog **append-only** (posture CSPN).
- Jamais de chown des parents partagés (`/run/secubox`, `/var/lib/secubox`).
- Alerte-seule = aucune action destructive automatique.
