<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox P2P — Poster GPT & Roadmap (Gondwana Mesh)

> Livrable de synthèse pour les évolutions **secubox-p2p DHT / Federation / Master-link**
> (#774 · PR #775 · branche `feature/p2p-dht-federation`).
> Deux parties : **(1)** un prompt prêt-à-coller pour un générateur d'image GPT (poster),
> **(2)** une **vue roadmap** textuelle des phases livrées et à venir.

---

## 1 · Prompt poster — à coller dans GPT (image)

> Copier le bloc ci-dessous tel quel. Format cible : affiche verticale A2 (portrait),
> haute densité, lisible imprimée.

```
Create a high-detail vertical A2 technical poster, cyberpunk-hermetic aesthetic,
titled "SECUBOX · GONDWANA MESH" in an engraved Cinzel serif at the top, subtitle
"Peer-to-Peer Trust Substrate — DHT · Federation · Master-Link" in JetBrains Mono.

PALETTE (strict): background cosmos-black #0a0a0f with subtle carbon texture; primary
accent hermetic-gold #c9a84c; secondary cyber-cyan #00d4ff; signal matrix-green #00ff41;
depth void-purple #6e40c9; alert cinnabar #e63946; body text warm off-white #e8e6d9,
muted labels #6b6b7a. Everything glows softly against the dark, like an alchemical
circuit board crossed with a star chart.

CENTRAL MOTIF — a triangular 3-node WireGuard mesh forming a Hamiltonian cycle (sacred
geometry nod to GK-HAM). Three glowing nodes joined by luminous encrypted tunnels:
  • TOP node "gk2 · 10.10.0.1" wears a small hermetic-GOLD crown labelled "MASTER —
    term 1 · prio 10". Brightest, gold halo.
  • BOTTOM-LEFT node "c3box · 10.10.0.2" and BOTTOM-RIGHT node "amd64 · 10.10.0.3",
    both cyber-cyan, labelled "SATELLITE — following master". Thin heartbeat lines
    (matrix-green pulses) travel from satellites up to the crown.
  • The three tunnels are labelled "wg-mesh · 51822 · WireGuard".

AROUND THE MESH, three annotated technical rings (like an astrolabe), each a subsystem:
  1. DHT ring — a Kademlia constellation: small orbiting record cards reading
     "reachability record {did, id_pubkey, wg_pubkey, endpoint, ts, sig}", a wax-seal
     icon marked "Ed25519 signed", a bucket ladder, and the label "UDP :51823 ·
     iterative α-parallel lookup · peers discovered = 2 per node".
  2. FEDERATION ring — a health pulse/EKG line with green "UP" and cinnabar "DOWN"
     beacons, a debounce spring icon, label "health-checks · aiohttp+TCP probe ·
     published via DHT".
  3. MASTER-LINK ring — a crown-and-scepter election glyph over a term counter dial,
     label "UDP :51824 · deterministic election · term-based failover · signed
     heartbeats · no split-brain".

BOTTOM THIRD — a horizontal ROADMAP TIMELINE band on a faint void-purple rail, left to
right, four milestones as illuminated waypoints:
  ● "SHIPPED — DHT + Federation + Master-Link · LIVE on 3-node mesh" (gold, checkmark)
  ● "NEXT — Mesh bans → sbxwaf engine bridge" (cyan)
  ● "NEXT — macroctl on satellites (privilege path)" (cyan)
  ● "HORIZON — Mesh phases 2–4 · NIZK GK-HAM binding · new macro kinds" (void-purple, dashed)

FOOTER strip in JetBrains Mono: "17 tasks · 132 tests · subagent-driven TDD · #774 /
PR #775   —   CyberMind · secubox.in". A small "OPAD — off by default, opt-in" seal in a
corner.

STYLE: crisp vector-meets-engraving, thin glowing lines, alchemical marginalia and
circuit traces, faint constellation grid in the background, no photographic elements,
no people. Balanced, symmetrical, poster-grade typography. Ultra sharp, print-ready.
```

**Variante courte** (si le générateur tronque) : garder le titre, la palette, le motif
central 3-nœuds avec la couronne sur gk2, et la bande roadmap 4 jalons ; retirer le détail
des trois anneaux.

---

## 2 · Vue Roadmap — P2P Gondwana

Légende : ✅ livré & live · 🔜 prochain · 🌀 horizon (conçu, non construit)

### ✅ SHIPPED — Substrat DHT / Federation / Master-Link (#774 · PR #775)

| Sous-système | Transport | État live |
|---|---|---|
| **Kademlia DHT** | UDP `:51823`, JSON, records `{did,id_pubkey,wg_pubkey,endpoint,ts,sig}` Ed25519 | ✅ 3 nœuds, chacun découvre les 2 autres (peers=2) |
| **Federation health-checks** | aiohttp GET `/health` + fallback TCP, debounce up/down, publié via DHT | ✅ sweep actif sur les 3 nœuds |
| **Master-link hiérarchique** | UDP `:51824`, élection déterministe + failover par *term* + heartbeats signés | ✅ gk2 master (term 1, prio 10), pas de split-brain |
| **Activation** | `/etc/secubox/p2p.toml` `[dht]/[federation]/[masterlink]`, OPAD off-by-default | ✅ enabled=true sur gk2/c3box/amd64 |
| **nginx endpoint gk2** | route `/api/v1/p2p/` → `p2p.sock` (standalone qui porte les daemons) | ✅ `/dht/peers` reflète le vrai état |
| **nft reboot-persist** | allow `wg-mesh` udp `{51823,51824}` dans `/etc/nftables.conf` | ✅ c3box + amd64 (gk2 = 10/8 large) |
| **Mesh viz UI** | onglet Mesh du dashboard p2p (canvas, rôle/term/DHT peers) | ✅ déployé 3 box |
| **Auth login-bounce fix** | correctif du rebond de login | ✅ déployé 3 box |
| **Qualité** | 17 tâches, 132 tests, SDD subagent-driven + revue adversariale | ✅ |

### 🔜 NEXT — court terme

- **🔜 Pont bans mesh → moteur sbxwaf** — aujourd'hui les bans fédérés (threatmesh #768)
  s'appliquent **au niveau nft** (`inet secubox_meshban`) uniquement. Les faire alimenter
  le moteur **sbxwaf** (bouncer CrowdSec) : `cscli decisions add --ip X -R "secubox-mesh"
  -d 4h` → LAPI → événement WAF. Anti-boucle : filtre par *reason* (`secubox-mesh`) dans
  `secubox-threatmesh-bridge` pour ne pas re-fédérer une décision déjà reçue.
- **🔜 macroctl sur satellites** — l'unité `secubox-p2p` standalone tourne avec
  `NoNewPrivileges=yes` ⇒ `sudo macroctl activate` refusé (« NNP flag is set »). Sur gk2 ça
  marche car p2p tourne dans l'aggregator (NNP=no). Fixer proprement le chemin privilégié
  côté satellites sans affaiblir le durcissement (drop-in ciblé / helper setuid vetté).
- **🔜 Fenêtre transitoire du socket p2p** — pendant un restart de `secubox-p2p`, le webui
  satellite renvoie 502/504 le temps que `p2p.sock` soit recréé. Lisser (socket-wait /
  `RuntimeDirectoryPreserve`) pour éviter les erreurs `apiGet` visibles à l'écran.

### 🌀 HORIZON — conçu, non construit

- **🌀 Mesh phases 2–4** (voir `project_mesh_gk2_c3box`) — au-delà du full-mesh WireGuard
  Phase 1 : orchestration, résilience multi-master régionale, exposition contrôlée.
- **🌀 Liaison NIZK / PSI GK·HAM** — remplacer les stubs `ZKP-HAM-v1` par le vrai
  `zkp-hamiltonian` (cffi) dans les verbes annuaire/p2p.
- **🌀 Nouveaux kinds macro** — `wg-relay`, `dns-resolver`, `http-mirror` (chaque kind =
  plugin `macros.d/<kind>` vetté + profil AppArmor, même framework que `tor-exit`).
- **🌀 Macros en mode `pending`** — fédération cross-nœud des Subscription/APPROVE.
- **🌀 Mesh sens master→satellite** — pull satellite→master OK ; master→satellite bloqué
  (nft c3box) ; + Freebox forward UDP 51822 pour le remote.

---

*CyberMind · Gérald Kerma · https://secubox.in — #774 / PR #775*
