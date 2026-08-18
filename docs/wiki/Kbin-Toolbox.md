<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# kbin — ToolBoX, le premier outil du couteau suisse cyber

**CyberMind · Gondwana · Notre-Dame-du-Cruet · Savoie** | [Home](Home) | [Anti-Track](Anti-Track) | [Modules](Modules)

> **kbin** (`kbin.gk2.secubox.in`) est le portail public de la **ToolBoX** SecuBox —
> la *cabine téléphonique numérique*. C'est le **premier outil du couteau suisse cyber
> modulaire** de [cybermind.fr](https://cybermind.fr) : on s'y connecte, on surfe, et la
> lame inspecte, nettoie et protège le trafic de façon transparente.

---

## Le concept en une phrase

> **Branche-toi, navigue normalement — kbin rend ta session rapide, chiffrée, sans pub
> et bientôt anonyme.**

kbin est la face publique du module [`secubox-toolbox`](../../packages/secubox-toolbox/).
Le client rejoint l'AP libre, consent (R1 passif / R2 TLS-break), et tout son trafic
traverse le pipeline de forge MITM SecuBox — sans configuration, sans app obligatoire.

---

## Les 5 lames déjà affûtées

| 🗡️ Lame | Ce qu'elle fait | Implémentation |
|---------|-----------------|----------------|
| **⚡ Performance transparente** | Débit ligne, latence quasi nulle ; on ne déchiffre que ce qu'on modifie (SNI-splice sélectif des flux pur-asset). | `tls_splice` addon (#649), workers R3 |
| **🔒 Full encrypted** | Inspection MITM complète sur HTTPS sortant : forge de cert par hôte, chaîne de certs vérifiée, fingerprint Chrome (uTLS) côté upstream. | Go forging core (#662), uTLS HelloChrome |
| **☠️ Injection de poison & smog** | Le trafic ad-tech / tracker entre dans la chambre d'inspection et ressort empoisonné/embrumé : pseudo-réponses, scripts neutralisés, IP-drop + DNS-refuse. | Anti-Track v2 (#633), `privacy_guard`, ad-ghoster |
| **🚫 Bandeau anti-adware** | Bannière de transparence injectée dans la page : « tu as été pisté / X trackers bloqués », immune au CSP, SPA-aware. | banner saga (#636/#639), webext (#655) |
| **🛡️ Safe browsing** | Blocklists Vortex DNS, blacklist nft (CrowdSec + threat-intel), détection anti-bot/challenge passive. | Phase 13 enforcement plane, Vortex Unbound |

---

## La lame suivante : 🧅 Tor quick-switch (#683 — implémenté DARK en 2.7.1)

> **Statut** : switch + tunnel livrés dans `secubox-toolbox` 2.7.1, **défaut OFF /
> fail-closed**. Onglet 🧅 Tor dans la WebUI opérateur (badge bootstrap/circuits/IP
> de sortie, toggle arm/désarm, nouvelle identité NEWNYM, sonde de fuite SOCKS).
> Granularité = mode Tor **global** (l'owner-match nft ne peut pas être par-client ;
> le per-client viendra avec le dialer SOCKS5 du cœur Go #662). Avant de basculer
> ON : soak + test de fuite hors-board (l'IP réelle ne doit jamais apparaître).

C'est la **pointe manquante** : l'anonymat de la sortie.

Aujourd'hui kbin voit, nettoie et protège — mais le trafic ressort par le WAN de la box,
avec l'IP réelle. Le **endpoint Tor** ajoute un interrupteur :

> **Un tap sur kbin → 🧅 « Mode Tor »** → le surf du client ressort **par le réseau Tor**
> au lieu du WAN. Pseudo-réseau, IP de sortie anonyme, identité réseau masquée.

Invariants de conception (voir
[spec](../superpowers/specs/2026-06-19-kbin-tor-anonymized-surfing-design.md)) :

- **L'inspection reste intacte** — Tor se place *après* le cœur de forge MITM, sur le
  transport upstream (dialer SOCKS5). On garde poison/smog + bandeau + safe browsing ;
  seules **l'IP de sortie et l'identité réseau** changent.
- **Opt-in par client** (scopé WG-hash), **défaut OFF**, respecte le niveau de consentement R.
- **Fail-closed** — si Tor tombe, **pas** de repli clearnet (l'anonymat est un invariant,
  pas un best-effort).
- **Pas de fuite DNS** — résolution via Tor quand le mode est actif, pas via l'Unbound local.
- **CSPN** — chaque bascule Tor on/off est journalisée (audit-log immuable) ; aucune sortie
  en clair.

### Cas d'usage

1. **Cabine VILLAGE3B** — un visiteur veut consulter un site sensible (santé, juridique,
   presse) depuis la borne publique sans laisser l'IP de la box. Tap 🧅 → surf anonyme.
2. **Pseudo-network surfing** — naviguer comme depuis un autre pays / une autre identité
   réseau, le temps d'une session éphémère 24h.
3. **Renouvellement de circuit** — bouton « nouvelle identité » (NEWNYM) pour changer
   d'IP de sortie à la volée.

> Direction **opposée** à `secubox-exposure` : celui-ci publie des *services cachés* Tor
> (entrant) ; kbin Tor endpoint fait sortir le surf client *par* Tor (sortant).

---

## Où ça vit

| Élément | Emplacement |
|---------|-------------|
| Portail public | `kbin.gk2.secubox.in` → HAProxy → `toolbox_landing` → `10.99.0.1:8088` |
| Tableau opérateur | `admin.gk2.secubox.in/toolbox/` |
| Vue carto perso | `kbin.gk2.secubox.in/social/me` |
| Module | [`packages/secubox-toolbox/`](../../packages/secubox-toolbox/) |
| Canal Tor (réutilisé) | [`packages/secubox-exposure/`](../../packages/secubox-exposure/) |

---

## Voir aussi

- [Anti-Track](Anti-Track) — moteur bloque/empoisonne/anonymise (couche DNS/IP)
- [FAQ kbin & Tor](../FAQ-KBIN-TOR.md)
- Punk Exposure Engine — canal Tor, doctrine dans `CLAUDE.md`
- Epic [#662](https://github.com/CyberMind-FR/secubox-deb/issues/662) — migration cœur MITM (Go)
- Plan [#683](https://github.com/CyberMind-FR/secubox-deb/issues/683) — kbin Tor endpoint

---

*CyberMind — Gérald Kerma · LicenseRef-CMSD-1.0*
