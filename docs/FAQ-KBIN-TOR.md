<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# FAQ — kbin & le mode Tor anonymisé

> kbin (`kbin.gk2.secubox.in`) = le portail public de la **ToolBoX** SecuBox, premier
> outil du couteau suisse cyber CyberMind. Cette FAQ couvre le surf protégé et le futur
> **mode Tor quick-switch** ([#683](https://github.com/CyberMind-FR/secubox-deb/issues/683)).

---

### Qu'est-ce que kbin exactement ?

Le portail public de `secubox-toolbox`. On rejoint l'AP libre de la cabine, on consent,
et tout le trafic traverse le pipeline de forge MITM SecuBox : inspection chiffrée,
nettoyage pub/tracker, bandeau de transparence, safe browsing. Voir
[Kbin-Toolbox](wiki/Kbin-Toolbox.md).

### kbin voit-il tout mon trafic ? C'est pas dangereux ?

C'est **consenti et éphémère**. La MAC est hashée avec un sel rotatif 24 h, aucune valeur
de cookie brute n'est persistée, aucun mapping session ↔ identité réelle ne survit au TTL.
Trois niveaux d'opt-in : R0 (bypass complet), R1 (analyse passive, recommandé), R2/R3
(TLS-break + bandeau). Sans consentement, **pas** de déchiffrement.

### « Performance transparente », ça veut dire quoi ?

On ne déchiffre que ce qu'on modifie. Les flux pur-asset (vidéo, images CDN) sont
*splicés* dès le ClientHello TLS (`tls_splice`, #649) — les workers ne forgent/déchiffrent
pas ce qui n'a aucune valeur L7. Débit ligne, latence quasi nulle.

### C'est quoi « l'injection de poison et de smog » ?

Le trafic ad-tech et tracker n'est pas seulement bloqué : il est **empoisonné**. Anti-Track
v2 (#633) renvoie des pseudo-réponses, neutralise les scripts CDN préchargés, et au niveau
réseau fait de l'IP-drop + DNS-refuse. Le profil publicitaire ressort pollué, pas vide —
indistinguable d'un vrai blocage côté tracker.

### Le bandeau anti-adware, il bloque quoi ?

Une bannière de transparence injectée dans la page : nombre de trackers vus/bloqués,
acteurs reconnus cross-site. Elle est immune au CSP et SPA-aware (#636/#639, webext #655).
C'est l'affichage ; le blocage réel vient des blocklists Vortex DNS + blacklist nft.

---

## Mode Tor (plan #683)

### Le mode Tor, ça fait quoi ?

Un interrupteur 🧅 sur kbin : un tap → ton surf ressort **par le réseau Tor** au lieu du
WAN de la box. IP de sortie anonyme, identité réseau masquée — du « pseudo-network
surfing ».

### Est-ce que kbin arrête de m'inspecter/protéger en mode Tor ?

Non. Tor se place **après** le cœur de forge MITM, sur le transport upstream (dialer
SOCKS5). Tu gardes le poison/smog, le bandeau et le safe browsing ; **seules l'IP de sortie
et l'identité réseau changent**.

### Et si Tor tombe, ça repasse en clair ?

**Jamais.** Le design est **fail-closed** : si Tor n'est pas disponible, le trafic est
coupé, pas renvoyé en clearnet. L'anonymat est un invariant, pas un best-effort.

### Y a-t-il des fuites DNS ?

Non. Quand le mode Tor est actif, la résolution passe **par Tor**, pas par l'Unbound local.

### C'est la même chose que `secubox-exposure` ?

Non, direction opposée. `secubox-exposure` publie des **services cachés** Tor (entrant —
exposer un service interne). kbin Tor endpoint fait sortir ton **surf** par Tor (sortant).
Le contrôle Tor (bootstrap, NEWNYM/nouvelle identité) est réutilisé entre les deux.

### Comment je change d'IP de sortie ?

Bouton « nouvelle identité » (NEWNYM) → nouveau circuit Tor → nouvelle IP de sortie, à la
volée, sans reconnecter.

### C'est activé par défaut ?

Non. **Opt-in par client** (scopé WG-hash), **défaut OFF**, respecte ton niveau de
consentement R. Chaque bascule on/off est journalisée (audit-log CSPN immuable).

---

## Voir aussi

- [Kbin-Toolbox](wiki/Kbin-Toolbox.md) — la page use-case complète
- [Spec mode Tor](superpowers/specs/2026-06-19-kbin-tor-anonymized-surfing-design.md)
- [Anti-Track](wiki/Anti-Track.md) — bloque/empoisonne/anonymise (couche DNS/IP)

---

*CyberMind — Gérald Kerma · LicenseRef-CMSD-1.0*
