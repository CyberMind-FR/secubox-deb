<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Acknowledgments

Cette page crédite les contributeurs au projet SecuBox-Deb : donateurs, sponsors de portage, et contributeurs techniques.

Le format s'inspire de la section 8.0 du readme MBROLA v3.01h (TCTS Lab Mons, 8 juin 1999) — qui créditait déjà GK² comme premier porteur Mac il y a un quart de siècle.

---

## Postcards & Donations

Contributeurs financiers et postcard-ware. Par défaut anonyme ; nom/pseudo sur opt-in, par ordre chronologique.

```
---------------------------------------------------------------------
                         DONATIONS WALL
---------------------------------------------------------------------

[Cette section sera alimentée au fil des contributions]

Placeholder — En attente de premiers donateurs

Pour apparaître ici :
- Faites un don via les canaux listés sur [[Support]]
- Indiquez votre préférence (anonyme, pseudo, nom complet)
- Les cartes postales sont photographiées avec consentement

---------------------------------------------------------------------
```

---

## Sponsors / Mécènes

Organisations et individus ayant sponsorisé du développement ou des portages matériels.

```
---------------------------------------------------------------------
                         SPONSORS WALL
---------------------------------------------------------------------

[Cette section sera alimentée au fil des sponsorisations]

Placeholder — En attente de premiers sponsors

Format d'entrée :
  [Nom ou Organisation]
  Période : YYYY-MM à YYYY-MM (ou "ongoing")
  Périmètre : [description du soutien]
  [Logo opt-in si fourni]

Pour devenir sponsor, voir [[Sponsor-a-Port]] ou contactez devel@cybermind.fr

---------------------------------------------------------------------
```

---

## Ports sponsorisés

Portages matériels financés par des sponsors, avec crédit technique.

```
---------------------------------------------------------------------
                      SPONSORED PORTS
---------------------------------------------------------------------

[Cette section sera alimentée au fil des portages]

Format d'entrée :

  HARDWARE PORT — [Nom de la carte]
  ─────────────────────────────────
  Sponsored by    : [Nom | Anonymous]
  Delivered       : YYYY-MM-DD
  Commits         : <first>..<last>
  Release         : vX.Y.Z
  Profile         : board/<name>/config.mk
  Status          : Tested & Supported

---------------------------------------------------------------------
```

---

## Contributeurs techniques

Contributions de code, documentation, traductions, tests.

```
---------------------------------------------------------------------
                    TECHNICAL CONTRIBUTORS
---------------------------------------------------------------------

Mainteneur principal :
  Gérald Kerma (GK²) <devel@cybermind.fr>
  Notre-Dame-du-Cruet, Savoie
  https://cybermind.fr
```

### Premier partenaire et client de la SecuBox

<a href="https://reepoststudio.fr"><img src="https://reepoststudio.fr/logo.png" alt="reepoststudio.fr" height="60" align="right"></a>

**[reepoststudio.fr](https://reepoststudio.fr)** est le **premier partenaire et client** de
la SecuBox.

* **Pré-2025** — Évaluations terrain, sponsoring matériel et financement de
  l'infrastructure de POC qui a permis la maturation de SecuBox-OpenWrt puis
  la migration SecuBox-Deb.
* **2026-05** — Contributions techniques : validation hardware Pi 4B + DSI,
  Pi Zero W + HyperPixel ; co-design des dashboards remote-ui converged
  (round/square) sur la base `secubox_common` ; radar concentric painter
  avec animation phase ; cleanup d'image round (ifupdown, sudo secubox,
  commentaire OTG).
* **PRs techniques** : [#140](https://github.com/CyberMind-FR/secubox-deb/pull/140),
  [#142](https://github.com/CyberMind-FR/secubox-deb/pull/142),
  [#143](https://github.com/CyberMind-FR/secubox-deb/pull/143)

```
Format d'entrée :
  [Nom/Pseudo]
  Contribution : [description]
  Commits      : <range> ou PR#
  Période      : YYYY-MM

Pour contribuer, voir https://github.com/CyberMind-FR/secubox-deb

---------------------------------------------------------------------
```

---

## Remerciements projets

Projets libres sur lesquels SecuBox-Deb s'appuie.

```
---------------------------------------------------------------------
                    PROJECT ACKNOWLEDGMENTS
---------------------------------------------------------------------

Debian Project          — Base OS, packaging system
Marvell / GlobalScale   — Armada SoCs, device trees mainline
CrowdSec                — Community-driven security engine
Suricata                — IDS/IPS engine
nftables                — Modern Linux firewall
FastAPI                 — Python web framework
U-Boot / Tow-Boot       — ARM bootloaders

Et tous les mainteneurs des paquets Debian utilisés.

---------------------------------------------------------------------
```

---

## Comment apparaître ici

| Type | Action |
|------|--------|
| **Donateur** | Don via [[Support]], indiquez votre préférence de crédit |
| **Sponsor** | Sponsorisation via [[Sponsor-a-Port]] |
| **Contributeur** | PR acceptée sur GitHub, crédit automatique |
| **Postcard** | Envoi carte postale à Notre-Dame-du-Cruet |

Les crédits sont opt-in. Par défaut, les contributions sont anonymes.

---

*Dernière mise à jour : 2026-05-17*
