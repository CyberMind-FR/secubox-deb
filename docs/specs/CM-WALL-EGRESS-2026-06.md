<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Détection egress & corrélation menaces — SecuBox-Deb (module WALL)

| | |
|---|---|
| **Réf.** | CM-WALL-EGRESS-2026-06 |
| **Module** | WALL (paire complémentaire **WALL↔MIND**) |
| **Compagnon de** | CM-MESH-MPCIE-2026-06 (plan RF / radios) |
| **Doctrine** | CM-WALL-OPAD-2026-05 (Off-Path Active Defense) |
| **Statut** | DRAFT |
| **Version** | v0.1.0-draft |
| **Date** | 2026-06-02 |
| **Programme** | Gondwana-Air — pilote Maurienne |
| **Licence** | LicenseRef-CMSD-1.0 (FR faisant foi) |

---

## 1. SITUATION

La passerelle SecuBox-Deb est le **point de vue privilégié** pour détecter, depuis les clients du mesh : intrusions, exfiltration (« évasions »), et trafic de commande-et-contrôle (C2) — y compris lorsqu'il se cache derrière des **providers cloud légitimes**.

Mais le réseau d'accès Gondwana-Air est **ouvert** (BYOH, public). Contrainte juridique structurante (LCEN, secret des correspondances) : **casser le TLS d'un usager anonyme = interception illicite.** Toute l'architecture se conçoit donc en **deux régimes séparés**.

---

## 2. MISSION

Détecter intrusion / exfil / C2 depuis les clients, **sans déchiffrer le contenu** sur l'accès ouvert ; réserver l'inspection de contenu aux segments consentis/gérés ; alimenter le **RDS** (rogue) et le **dashboard MIND** ; rester conforme **OPAD** (détection passive par défaut, réaction off-path opt-in, journalisée).

---

## 3. LES DEUX RÉGIMES (frontière non négociable)

| Régime | Périmètre | Licite sur accès ouvert | Posture |
|---|---|---|---|
| **R1 — Métadonnées** | flux, DNS, TLS-méta, IP-intel, signatures NIDS | **Oui** | détection passive par défaut |
| **R2 — Contenu (TLS-break / DPI profonde)** | déchiffrement, extraction fichiers | **Non** — segments **consentis/gérés** uniquement (quarantaine, honeypot, endpoints managés, infra de test) | régime restreint, opt-in explicite + traçabilité |

> **Invariant.** Le guardian/miroir sert à *voir* le MITM et l'exfil, et à *bloquer off-path* le rogue — **jamais à intercepter le contenu des usagers**. Sur l'ouvert : R1. Sur le consenti : R2.

---

## 4. COUCHES DE DÉTECTION (R1)

| # | Couche | Quoi détecter | Outil Debian ARM64 | OPAD |
|---|---|---|---|---|
| L0 | **Flux** | beaconing (périodicité), exfil volumique, destinations anormales | `conntrack`, NetFlow/IPFIX (`goflow2`/`nfdump`) | passif |
| L1 | **DNS** | DGA, DNS-tunneling, détection **DoH**, domaines malveillants | résolveur souverain (`unbound`/`knot`) + **RPZ** | passif (blocage RPZ = réaction off-path) |
| L2 | **TLS métadonnées** | empreinte **JA3/JA4** (stack cliente malware), issuer cert, SNI *(cf. ECH §6)* | **Suricata 7.x**, **Zeek** | passif |
| L3 | **IP / ASN / cloud-intel** | C2 hébergé sur clouds légitimes, fast-flux, infra connue | feeds **abuse.ch** (Feodo/SSLBL/ThreatFox), **ET Open**, Spamhaus DROP/EDROP, **MISP** | passif |
| L4 | **NIDS / NSM** | intrusion, latéralité, exfil, signatures | **Suricata** (IDS) / **Zeek** (logs conn/dns/ssl + intel framework + notice) | IDS passif ; **IPS inline = opt-in** |
| L5 | **Contenu** | payload malware, fichiers | Suricata file-extract, proxy **explicite** | **R2 — consenti only** |

---

## 5. CAS D'USAGE CIBLÉS

### 5.1 Évasions depuis les clients

Un client compromis menace les *autres* usagers et l'infra ; le détecter les protège.

- **Domain fronting / cloud-C2** — C2 logé sur AWS/Azure/GCP/Cloudflare/Fastly pour se fondre. → matching IP/ASN vs ThreatFox/Feodo + anomalie d'usage CDN. *(« providers cloud utilisés dans les attaques ».)*
- **DoH-C2 / DoT** — C2 dans du DNS chiffré. → détecter connexions vers résolveurs DoH connus + **forcer le DNS souverain** (RPZ).
- **DNS-tunneling** — entropie/longueur de sous-domaines, volume de requêtes.
- **Beaconing** — périodicité de flux (approche type RITA) ; **la cadence trahit le C2 même sur trafic chiffré**, sans lire le contenu.

### 5.2 Corrélation RDS (radio ↔ flux)

Signal composite : un **evil-twin détecté par le guardian-radio** (CM-MESH §4bis) **+** un client qui **beacon** vers une infra C2 = corrélation forte → escalade RDS, quarantaine off-path.

---

## 6. CONTRAINTE 2026 — ECH (Encrypted ClientHello) ⚠

ECH **chiffre le SNI** → la détection par nom d'hôte (L2 SNI) **s'effondre**.

**Conséquence de conception (à acter) :** déporter le poids de la détection sur **L0 flux + JA4 + L3 IP-intel + cadence (beaconing)**, indépendants du nom en clair. Ne pas bâtir la détection sur le SNI.

---

## 7. ARCHITECTURE SecuBox-Deb (module WALL)

### Pattern 3-broches

| Broche | Rôle |
|---|---|
| **CTL** | orchestration Suricata/Zeek/résolveur, gestion intel, décisions de réaction |
| **LXC** | isolation du plan d'inspection (capture en `netns` dédié, droits minimaux) |
| **BUNDLE** | `.deb` : moteurs NIDS + jeux de règles + feeds intel + RPZ + templates TOML |

### Consommateurs

- **RDS** — corrélation rogue-radio ↔ flux suspect.
- **MIND** (paire WALL↔MIND) — télémétrie flux/alertes vers le dashboard génératif (pipeline existant).

### Configuration TOML (extrait)

```toml
[wall.regime]
content_inspection = false      # R2 désactivé par défaut (accès ouvert)
ips_inline         = false      # IDS passif par défaut ; inline = opt-in

[wall.flow]
ipfix      = true
beaconing  = true               # détection de périodicité

[wall.dns]
resolver   = "unbound"
rpz        = true
doh_detect = true

[wall.tls]
ja4        = true
sni        = "best_effort"      # dégradé sous ECH (cf. §6)

[wall.intel]
feeds = ["abuse.ch/feodo", "abuse.ch/threatfox", "et-open", "spamhaus-drop"]
misp_url_ref = "file:///etc/secubox/secrets/misp"

[wall.nids]
engine = "suricata"             # suricata | zeek | both
```

### API FastAPI / Uvicorn

```
GET  /wall/flows           # flux actifs + scores anomalie/beaconing
GET  /wall/dns             # requêtes, hits RPZ, suspicions tunneling/DoH
GET  /wall/alerts          # alertes NIDS
GET  /wall/intel           # état des feeds, derniers matchs cloud-C2
POST /wall/quarantine      # quarantaine client (réaction off-path, journalisée)
```

### OPAD

Détection **passive par défaut** (IDS sur span/tap). Réaction **off-path, opt-in, journalisée** : RPZ block, drop nftables, **quarantaine VLAN**, steering. **IPS inline** et **R2** = opt-in explicite, tracés.

---

## 8. FRONTIÈRE LÉGALE (rappel opérationnel)

- **Accès ouvert** → **R1 (métadonnées) uniquement**. Conservation de logs conforme LCEN.
- **Contenu / TLS-break** → **R2** : seulement sur segment **consenti/géré/quarantaine** ou infra de test. Jamais en silence sur un usager.
- Le dispositif est **défensif** : détection + confinement d'un attaquant, pas interception de tiers.

---

## 9. POINTS OUVERTS

1. **ECH** — calibrer la bascule SNI→JA4/IP/cadence ; mesurer le taux de couverture résiduel.
2. **Charge sur Armada 7040** — Suricata/Zeek en ARM64 quad-A72 : dimensionner le débit inspectable (offload packet-processor 7040 ?).
3. **Fraîcheur intel** — cadence de mise à jour des feeds vs partitions mesh (nœuds isolés).
4. **Faux positifs cloud-intel** — un cloud légitime héberge bon et mauvais ; exiger corrélation multi-signaux avant quarantaine.
5. **Périmètre R2** — définir précisément les segments consentis (CGU portail, quarantaine) avant toute inspection de contenu.

---

*CyberMind — Gérald Kerma — Notre-Dame-du-Cruet (73130). Document interne, version FR faisant foi. LicenseRef-CMSD-1.0.*
