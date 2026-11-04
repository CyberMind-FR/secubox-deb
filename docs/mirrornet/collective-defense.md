<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Collective Defense (MCD) — ActorD, SBX WAF, nftables, bans fédérés (#3429, #3417, phase B)

CONCEPTION, non implémentée. Composant N9. L'état existant fait foi dans `docs/audit/ddos-defense-audit.md` (cité
« audit DDoS ») ; chemins `sbxwaf` réels : `secubox-toolbox-ng/cmd/sbxwaf/`. Marquage : EXISTANT / À ÉTENDRE / NOUVEAU.

## 1. Répartition des rôles (arbitrage)

```
 ActorD  ── détecte, corrèle (multi-IP, campagnes, par site), PROPOSE ─┐   EXISTANT : ne bloque jamais (main.go:60-66)
                                                                      ▼
 SBX WAF ── DÉCIDE avec ses garde-fous (preuve locale, plafonds, exclusions)   EXISTANT actorban.go:5-17
                                                                      ▼
 nftables ─ NEUTRALISE (sets à timeout v4/v6, priorité -100)                   EXISTANT nftban.go:20-40,126-141
                                                                      ▼
 MirrorNet ─ PARTAGE des bans signés, datés, révocables (annuaire)             À ÉTENDRE (A22)
```

La décision reste **locale à la box cible** : un ban reçu du maillage est une **entrée** des garde-fous du WAF, jamais
un ordre. Décision 5 inchangée par la vision du 2026-11-03 ; seule incidence : les sites étant répartis
automatiquement entre nœuds, le `site_id` (porté par la route du nom court comme du nom de nœud) est la clé de
corrélation d'une campagne visant un même site sur plusieurs copies.

## 2. Modes OBSERVE / ASSISTED / AUTONOMOUS (À ÉTENDRE)

Un réglage unique par box, `/etc/secubox/defense.toml` `mode = "observe" | "assisted" | "autonomous"` (NOUVEAU), traduit
vers les modes EXISTANTS `off|propose|auto` de sbxwaf (`main.go:1336-1345`) :

| Mode | `--actor-ban`, `--campagne-ban`, `--mesures` | Bans fédérés reçus |
|---|---|---|
| OBSERVE | `propose` (rien n'est appliqué, tout est journalisé) | affichés seulement |
| ASSISTED | `propose`, validation par l'administrateur dans la webui | proposés à l'administrateur |
| AUTONOMOUS | `auto` (état livré aujourd'hui, `secubox-waf-ng.service:143-146`) | appliqués s'ils passent § 4 |

Défaut d'une **nouvelle** installation : ASSISTED. Box existantes : AUTONOMOUS conservé (pas de régression de
protection) — **validé 2026-11-03** (décision 5, `architecture.md` § 0), avec le seuil de consensus du § 4
(k = 2 éditeurs PARTNER ou 1 TRUSTED).

## 3. Alpha 21 : correctifs immédiats et étape A (locale)

| Lot | Contenu | Référence de l'écart |
|---|---|---|
| retrait threatmesh | arrêt de `POST /mesh/ingest` non signé et du port `0.0.0.0:8780` ; paquet `secubox-threatmesh` réduit aux flux publics (`sbin/secubox-threatfeed`) ou retiré ; `secubox-blacklist-sync` ne lit plus les IoC du maillage | audit DDoS § 1.4 B (`secubox-threatmesh/api/main.py:236-251`, `systemd/secubox-threatmesh.service:13`) |
| IP de gk2 figée | retirer la plage propre à gk2 de l'unité générique ; source unique `allow_admin` dans `ddos.toml` | `secubox-waf-ng.service:147` |
| A1 liste blanche admin unique | `/etc/secubox/ddos.toml` `[admin] v4 = […] v6 = […]` ; lue par sbxwaf, rate-limit, meshban | audit DDoS écart 6 |
| A2 table `inet secubox_ddos` | drop-in `/etc/nftables.d/` (survit au `flush ruleset`), priorité -150 ; meters SYN/UDP/ICMP par source (v4 /32, v6 /64), `size` borné ; **compteurs seuls** d'abord (shadow), drop après mesure au banc | audit DDoS § 1.3, écarts 2-3 |
| A3 sysctl | `nf_conntrack_max` dimensionné par mémoire, `icmp_ratelimit` | audit DDoS § 1.3 |
| A4 HAProxy | `timeout http-request`, stick-table par source (compteur d'abord) | `haproxyctl:1060-1068` |
| `site_id` | identifiant de site dans les événements ActorD (corrélation par site, arbitrage #3420) | `envelope.go:100-108` |

Contrainte d'exploitation : aucune action d'interface WAN (MTU, down/up) ; purement nft et sysctl ; jamais d'abord
sur gk2 (banc gk4/gk6).

## 4. Alpha 22 : étapes B et C

**B — volumétrie dans ActorD** (NOUVEAU) : capteur nft → ActorD sur le modèle du capteur de balayage
(`secubox-hub/nftables.d/zz-secubox-scan-tap.nft:10-15`, `sbxwaf/scansensor.go`) ; famille d'événements
« volumétrique » ; campagne DDoS = nombreuses sources, même cible (vhost/`site_id`), même fenêtre ; **corrélation par
site** entre nœuds : chaque nœud publie un résumé signé `{site_id, fenetre, signature_campagne, nb_sources}` (pas les
IP) dans l'annuaire ; ActorD local fusionne.

**C — bans fédérés signés** (À ÉTENDRE `BanRecord`, `secubox-annuaire/annuaire/model.py:723-744`) :

| Exigence | Conception |
|---|---|
| durée obligatoire | `expires_at` requis, ≤ 7 j ; `annuairectl --ttl` sans défaut permanent (`annuairectl:471`) |
| IPv6 | v4 /32 et v6 /64 au plus large ; meshban v4+v6 (`annuaire/threatmesh.py:20-29` IPv4 seul aujourd'hui) |
| exclusions | `allow_admin` de `ddos.toml`, IP du maître et de tous les nœuds (`NodeRecord.endpoint`), plages privées, boucle, lien-local, multicast ; vérifiées **à la réception**, chez chaque box |
| consensus | appliqué si ≥ k éditeurs distincts de niveau ≥ PARTNER (k = 2 proposé) **ou** 1 éditeur TRUSTED ; un éditeur < PARTNER est ignoré |
| plafond | ≤ 200 bans actifs par éditeur ; au-delà, ignorés et fait de réputation |
| révocation | par l'éditeur (`verbs.py:1966`, EXISTANT) ; par un administrateur local (levée locale, auditée) |
| alimentation | sbxwaf publie ses bans **appliqués avec preuve locale** (pas les propositions) via l'API annuaire ; ActorD ne publie jamais directement |
| application | set nft dédié `meshban{4,6}` à timeout, priorité après `allow_admin` |

## 5. Tableaux de bord

A21 : rien de nouveau hors compteurs shadow de l'étape A (lecture `require_lecture` dans la console ActorD existante,
`secubox-waf-ng/www/actor/index.html`). A22 : vue SOC « défense collective » (bans reçus/appliqués/ignorés et motif).

## 6. Risques

Coupure de l'administrateur (4G, hôtel) : `allow_admin` consultée avant toute règle, TTL courts. CGNAT/IPv6 : seuils
par préfixe prudents, jamais de ban par pays. Mémoire 1 Go : `size` sur chaque set, flood absorbé par le noyau.
`flush ruleset` : toute table dans `/etc/nftables.d`. Retrait threatmesh : perte du partage non signé **avant** que la
MCD signée existe (A22) — accepté par l'arbitrage, à annoncer.
