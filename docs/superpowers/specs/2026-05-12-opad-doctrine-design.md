<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# OPAD Doctrine Documents — Design Specification

**Date** : 2026-05-12
**Référence** : CM-WALL-OPAD-2026-05
**Version** : 2.4.0
**Auteur** : CyberMind / Claude Code
**Statut** : Approuvé pour implémentation

---

## 1. Résumé exécutif

Ce document spécifie la création des documents doctrinaux OPAD (Off-Path Active Defense) pour SecuBox-Deb v2.4.0. OPAD devient la doctrine canonique de sécurité, remplaçant l'approche IDGP in-path.

### Doctrine en une ligne

> La SecuBox n'est pas dans le chemin. Elle est à côté du chemin, et elle gagne des courses. Quand elle est là, elle protège par disruption ciblée. Quand elle n'est pas là, le réseau ne le remarque pas.

### Livrables

| # | Document | Chemin | Audience |
|---|----------|--------|----------|
| 1 | OPAD.md | `doctrine/opad/OPAD.md` | CSPN + équipe |
| 2 | CSPN.matrix.md | `doctrine/opad/CSPN.matrix.md` | ANSSI |
| 3 | opad-profile.schema.json | `schemas/opad-profile.schema.json` | Développeurs |
| 4 | models.py | `common/secubox_core/opad/models.py` | Développeurs |
| 5 | OPAD-OPERATIONS.md | `doctrine/opad/OPAD-OPERATIONS.md` | Exploitants |

---

## 2. Contexte et motivation

### 2.1 Problème avec l'approche antérieure

La doctrine IDGP (In-line Deep Guard Protection) place SecuBox dans le chemin de données :

```
[LAN] ←→ [SecuBox Bridge] ←→ [WAN]
```

**Violations identifiées** :
- Crash SecuBox = rupture réseau totale
- Latence ajoutée sur chaque paquet
- Surface d'attaque étendue (SecuBox joignable)
- Mode de défaillance non-silencieux

### 2.2 Solution OPAD

OPAD place SecuBox hors du chemin, en observation passive avec injection active :

```
[LAN] ←→ [Switch] ←→ [WAN]
              ↑
        [SecuBox] (observe + injecte)
```

**Garanties** :
- Retrait physique = aucun impact
- Latence zéro sur trafic normal
- Surface d'attaque minimale
- Fail-silent par design

---

## 3. Invariants OPAD

Ces 8 invariants sont non-négociables et doivent être testés :

| ID | Invariant | Test de vérification |
|----|-----------|---------------------|
| INV-01 | Retrait physique sans impact LAN↔WAN | Kill SecuBox, ping continue |
| INV-02 | Aucun forwarding utilisateur via SecuBox | Inspection topologique |
| INV-03 | Journalisation ALERTE·DÉPÔT systématique | Chaque injection = log signé |
| INV-04 | Marquage OPAD_INJECT_LOST sur courses perdues | Simulation + vérification log |
| INV-05 | Aucune réponse IP-active côté LAN en nominal | nmap depuis LAN = 0 réponse |
| INV-06 | Surface d'attaque WAN nulle | Scan externe = 0 port ouvert |
| INV-07 | Fail-silent par défaut | kill -9 = 0 impact trafic |
| INV-08 | Escalade in-path révocable et explicite | Test escalade + révocation |

---

## 4. Architecture des primitifs d'injection

### 4.1 Vue d'ensemble

```
┌─────────────────────────────────────────────────────────────┐
│                     MODULE WALL (OPAD)                       │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  OBSERVER   │  │  INJECTOR   │  │      POLICY         │  │
│  │  (BPF/pcap) │  │  (scapy)    │  │  (règles/scoring)   │  │
│  │             │  │             │  │                     │  │
│  │ - DNS parse │  │ - DNS-R     │  │ - Match rules       │  │
│  │ - DHCP parse│  │ - DHCP-R    │  │ - MIND score        │  │
│  │ - TCP parse │  │ - RST-I     │  │ - AUTH device       │  │
│  │ - ARP parse │  │ - ARP-R     │  │ - Action décision   │  │
│  └──────┬──────┘  └──────▲──────┘  └──────────▲──────────┘  │
│         │                │                     │             │
│         └────────────────┴─────────────────────┘             │
│                    Événements internes                       │
├─────────────────────────────────────────────────────────────┤
│                     JOURNALISATION ROOT                      │
│              (audit.log, signée, append-only)                │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Primitif DNS-R (DNS Race)

**Objectif** : Répondre au client DNS avant le serveur légitime.

**Mécanisme** :
1. Observer DNS Query (UDP/53) en promiscuous
2. Évaluer contre politique (domaine interdit ? device suspect ?)
3. Si action requise : forger réponse DNS
4. Injecter réponse avec TTL court
5. Client accepte première réponse reçue

**Paramètres** :
```json
{
  "enabled": true,
  "target_success_rate": 0.99,
  "modes": ["nxdomain", "sinkhole", "redirect_captive"],
  "sinkhole_ip": "127.0.0.1",
  "ttl": 300
}
```

**Taux de succès** : ≥ 99% (SecuBox plus proche du client que le serveur DNS)

### 4.3 Primitif DHCP-R (DHCP Race)

**Objectif** : Attribuer une IP de quarantaine avant le serveur DHCP légitime.

**Mécanisme** :
1. Observer DHCP DISCOVER (UDP/67-68)
2. Si device non autorisé ou suspect
3. Forger DHCP OFFER avec IP quarantaine
4. Gateway pointe vers captive portal SecuBox
5. Lease court (300s) pour réévaluation rapide

**Paramètres** :
```json
{
  "enabled": true,
  "target_success_rate": 0.95,
  "quarantine_pool": {
    "start": "10.99.0.10",
    "end": "10.99.0.250",
    "lease_time": 300,
    "gateway": "10.99.0.1"
  }
}
```

**Taux de succès** : ≥ 95%

### 4.4 Primitif RST-I (TCP RST Injection)

**Objectif** : Couper une connexion TCP établie par injection de RST.

**Mécanisme** :
1. Observer connexion TCP (SYN/ACK ou données)
2. Si connexion vers C2 ou destination interdite
3. Calculer sequence numbers valides
4. Injecter RST vers les deux endpoints (double-ended)
5. Connexion coupée des deux côtés

**Paramètres** :
```json
{
  "enabled": true,
  "target_success_rate": 0.90,
  "double_ended": true,
  "timing_window_ms": 10
}
```

**Taux de succès** : ≥ 90% (limité par fenêtre TCP et timing)

### 4.5 Primitif ARP-R (ARP Redirect)

**Objectif** : Rediriger le trafic d'un device vers captive portal.

**Mécanisme** :
1. Identifier device à rediriger (MAC)
2. Envoyer Gratuitous ARP : "IP gateway = MAC SecuBox"
3. Device envoie son trafic vers SecuBox captive
4. Refresh périodique pour maintenir redirection
5. Arrêt du refresh = retour à la normale automatique

**Paramètres** :
```json
{
  "enabled": true,
  "target_success_rate": 0.98,
  "refresh_interval_s": 30,
  "captive_mac": "aa:bb:cc:dd:ee:ff"
}
```

**Taux de succès** : ≥ 98% (sauf ARP statique côté client)

---

## 5. Profil de configuration 3-broche

### 5.1 Structure conceptuelle

```
┌─────────────────────────────────────────┐
│            PROFIL OPAD 3-BROCHE          │
├─────────────┬─────────────┬─────────────┤
│  BROCHE 1   │  BROCHE 2   │  BROCHE 3   │
│ OBSERVATION │  INJECTION  │  POLITIQUE  │
├─────────────┼─────────────┼─────────────┤
│ interfaces  │ dns_race    │ rules[]     │
│ bpf_filter  │ dhcp_race   │ default_act │
│ protocols   │ rst_inject  │ escalation  │
│ fingerprint │ arp_redirect│ scoring     │
└─────────────┴─────────────┴─────────────┘
```

### 5.2 Validation

- JSON Schema draft-07 : `schemas/opad-profile.schema.json`
- Modèles Pydantic : `common/secubox_core/opad/models.py`
- Commande CLI : `secubox-validate /etc/secubox/opad/profile.json`

### 5.3 Stockage (double-buffer 4R)

```
/etc/secubox/opad/
├── active/
│   └── profile.json    ← Config live (lecture seule)
├── shadow/
│   └── profile.json    ← Édition en cours
├── rollback/
│   ├── R1/             ← Snapshot le plus récent
│   ├── R2/
│   ├── R3/
│   └── R4/             ← Snapshot J-7
└── pending/
    └── profile.json    ← En attente validation
```

---

## 6. Intégration avec les modules existants

### 6.1 Mapping modules → OPAD

| Module | Rôle OPAD | Interactions |
|--------|-----------|--------------|
| **AUTH** | Registre devices autorisés | WALL consulte pour policy match |
| **WALL** | Moteur OPAD (observer + inject) | Cœur de l'implémentation |
| **BOOT** | Sélection mode au démarrage | Valide profil, refuse si incohérent |
| **MIND** | Scoring comportemental | WALL consulte pour seuils |
| **ROOT** | Journalisation signée | Reçoit tous les événements OPAD |
| **MESH** | Synchronisation hors-bande | Ne participe JAMAIS au chemin LAN |

### 6.2 Flux d'événements

```
[Paquet observé]
      │
      ▼
[WALL/Observer] ──parse──▶ [Événement interne]
      │                            │
      │                            ▼
      │                    [WALL/Policy]
      │                            │
      │         ┌─────────────────┴─────────────────┐
      │         ▼                                   ▼
      │   [AUTH: device?]                    [MIND: score?]
      │         │                                   │
      │         └─────────────────┬─────────────────┘
      │                           ▼
      │                    [Décision action]
      │                           │
      ├───────────────────────────┤
      ▼                           ▼
[allow/observe]            [WALL/Injector]
      │                           │
      │                           ▼
      │                    [Injection paquet]
      │                           │
      └───────────┬───────────────┘
                  ▼
           [ROOT/Logger]
           (événement signé)
```

---

## 7. Matrice CSPN menace × capacité

### 7.1 Résumé de couverture

| Catégorie | Total | Couvert (◉) | Partiel (◐) | Hors portée (✕) |
|-----------|-------|-------------|-------------|-----------------|
| DNS | 5 | 5 | 0 | 0 |
| Réseau | 7 | 5 | 2 | 0 |
| Malware | 8 | 4 | 3 | 1 |
| Accès | 6 | 2 | 3 | 1 |
| Données | 5 | 1 | 1 | 3 |
| Crypto | 5 | 0 | 0 | 0 |
| **Total** | **36** | **17** | **9** | **5** |

**Couverture active** : 72% (26/36 menaces)

### 7.2 Périmètre explicitement exclu

| ID | Capacité | Raison d'exclusion |
|----|----------|-------------------|
| X01 | Interception TLS | Nécessite in-path (MitM), viole INV-02 |
| X02 | Drop hard de paquet | Nécessite forwarding, viole INV-02 |
| X03 | Segmentation VLAN stricte | Hors périmètre fonctionnel WALL |
| X04 | Bandwidth shaping | Nécessite tc inline, viole INV-02 |
| X05 | Protection WAN entrante | Surface WAN = 0, rien à protéger |

---

## 8. Modes opératoires

### 8.1 `opad-only` (défaut canonique)

- Observation passive uniquement
- Injection active selon politique
- Aucun forwarding, jamais
- Fail-silent garanti

### 8.2 `opad-with-escalation`

- Mode OPAD par défaut
- Escalade vers in-path possible
- Requiert consentement explicite (INV-08)
- Auto-revert après timeout (défaut: 3600s)
- Journalisation complète de l'escalade

### 8.3 `legacy-in-path` (déprécié)

- Mode bridge transparent hérité
- **WARNING** affiché au boot
- Conservé pour migration uniquement
- Sera supprimé en v3.0

---

## 9. API REST OPAD

### 9.1 Endpoints principaux

| Méthode | Path | Description |
|---------|------|-------------|
| GET | `/api/v1/wall/status` | État OPAD (mode, stats) |
| GET | `/api/v1/wall/metrics` | Métriques injection |
| GET | `/api/v1/wall/policy/rules` | Liste règles actives |
| POST | `/api/v1/wall/policy/rules` | Ajouter règle |
| DELETE | `/api/v1/wall/policy/rules/{id}` | Supprimer règle |
| POST | `/api/v1/wall/inject/dns` | Injection DNS manuelle |
| POST | `/api/v1/wall/inject/rst` | Injection RST manuelle |
| POST | `/api/v1/wall/escalate` | Demande d'escalade |
| DELETE | `/api/v1/wall/escalate` | Révocation escalade |
| GET | `/api/v1/wall/profile` | Profil 3-broche actif |
| PUT | `/api/v1/wall/profile` | Mise à jour profil (shadow) |
| POST | `/api/v1/wall/profile/swap` | Swap shadow → active |
| POST | `/api/v1/wall/profile/rollback` | Rollback |

### 9.2 Authentification

Tous les endpoints (sauf `/health`) requièrent JWT via `Depends(require_jwt)`.

---

## 10. Tests d'invariants

### 10.1 Fichier de tests

`tests/test_opad_invariants.py`

### 10.2 Tests requis

```python
def test_inv_01_retrait_sans_rupture():
    """Kill SecuBox, vérifier que ping LAN↔WAN continue."""

def test_inv_02_no_forwarding():
    """Vérifier qu'aucune route ne passe par SecuBox."""

def test_inv_03_logging_systematique():
    """Chaque injection produit un log signé ROOT."""

def test_inv_04_marquage_course_perdue():
    """Simulation course perdue → marquage OPAD_INJECT_LOST."""

def test_inv_05_silence_lan_ip_active():
    """nmap depuis LAN vers SecuBox = 0 réponse."""

def test_inv_06_surface_wan_nulle():
    """Scan externe WAN = 0 port ouvert."""

def test_inv_07_fail_silent():
    """kill -9 des démons OPAD = 0 impact trafic."""

def test_inv_08_escalade_revocable():
    """Escalade puis révocation atomique."""
```

---

## 11. Structure des fichiers à créer

```
secubox-deb/
├── doctrine/
│   └── opad/
│       ├── OPAD.md                 # Document 1 (~1500 lignes)
│       ├── CSPN.matrix.md          # Document 2 (~800 lignes)
│       └── OPAD-OPERATIONS.md      # Document 5 (~600 lignes)
├── schemas/
│   └── opad-profile.schema.json    # Document 3 (~300 lignes)
├── common/
│   └── secubox_core/
│       └── opad/
│           ├── __init__.py
│           └── models.py           # Document 4 (~250 lignes)
└── tests/
    └── test_opad_invariants.py     # Tests (~200 lignes)
```

---

## 12. Dépendances

### 12.1 Python

```
pydantic>=2.0
scapy>=2.5.0
jsonschema>=4.0
```

### 12.2 Système

```
libpcap-dev
python3-dev
```

---

## 13. Critères d'acceptation

- [ ] 5 documents créés aux chemins spécifiés
- [ ] JSON Schema valide (jsonschema draft-07)
- [ ] Modèles Pydantic exportent le même schema
- [ ] Tests d'invariants passent
- [ ] Documentation intégrée dans le projet
- [ ] Commits signés avec référence CM-WALL-OPAD-2026-05

---

## 14. Hors portée de cette spécification

- Implémentation du code des moteurs d'injection (phase ultérieure)
- Migration du module WALL existant (phase ultérieure)
- Tests d'intégration complets (phase ultérieure)
- Documentation wiki publique (phase ultérieure)

---

## 15. Références

- CLAUDE.md : Instructions projet SecuBox-Deb
- .claude/DESIGN-CHARTER.md : Système 6 modules (AUTH/WALL/BOOT/MIND/ROOT/MESH)
- .claude/PATTERNS.md : Patterns FastAPI
- ANSSI CSPN : https://www.ssi.gouv.fr/entreprise/certification_cspn/
