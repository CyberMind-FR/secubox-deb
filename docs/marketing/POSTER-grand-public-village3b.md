<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Poster grand public — Cabine Numérique VILLAGE3B 📡

> Format : A2 portrait, lisible à 1m de distance. Police monospace style P31 phosphor green (#00ff55) sur fond noir cosmos (#0a0a0f). Accents Gold Hermétique (#c9a84c) pour éléments clés.

---

## 🎯 ZONE 1 — Titre principal (1/4 supérieur)

```
        📡 VILLAGE3B
   CABINE NUMÉRIQUE GONDWANA

   Diagnostic compromission iPhone
   Anonyme · Gratuit · Open Source
   ✓ Pas de pub · ✓ Pas de revente
```

---

## 🎯 ZONE 2 — 3 niveaux d'opt-in (1/4 milieu-haut)

```
   👇 CHOISIS TON NIVEAU D'ANALYSE

   ╔════════════════════════════════╗
   ║  🌐 R0 — Bypass complet         ║
   ║    Réseau seul, ZÉRO analyse    ║
   ║    (comme un AP WiFi normal)    ║
   ╚════════════════════════════════╝

   ╔════════════════════════════════╗
   ║  🛡 R1 — Analyse passive        ║
   ║    ✓ DÉFAUT RECOMMANDÉ          ║
   ║    Rapport sur ta session,      ║
   ║    aucun impact sur le surf     ║
   ╚════════════════════════════════╝

   ╔════════════════════════════════╗
   ║  🔍 R2 — Analyse + bandeau      ║
   ║    Déchiffrement TLS opt-in     ║
   ║    (installer notre CA d'abord) ║
   ╚════════════════════════════════╝
```

---

## 🎯 ZONE 3 — Ce que tu vas voir dans ton rapport (1/4 milieu-bas)

```
   📊 TON RAPPORT INCLURA :

   🌐 N connexions HTTPS observées
   📡 N hôtes uniques contactés
   ✅ N requêtes 2xx réussies
   🔒 N cert-pinning détectés (= bon signe)

   📺 Apps détectées (YouTube, Signal, GitHub, iCloud...)
   🍪 Trackers identifiés (Google Analytics, Facebook Pixel...)
   🌍 Pays contactés (drapeaux + ASN)
   🎯 Score de risque (🟢/🟡/🔴 0-100)
   📱 Empreinte device (iPhone iOS X.X + Safari version)

   🔎 INSPECTION TRANSPARENTE :
   🔍 X% Inspecté (HTTPS via notre CA)
   🛡 X% Bypassé whitelist (Apple/banque/Signal)
   🔒 X% Cert-pinning (app refuse notre CA = normal)
   🔐 X% E2E messaging (Signal/iMessage opaques)

   📜 108 patterns whitelist actifs (Apple, banques FR,
   gov.fr, santé, streaming, gaming, workplace...)
```

---

## 🎯 ZONE 4 — Confidentialité / Conformité (1/8)

```
   🛡 CONFORMITÉ CSPN ANSSI + LCEN

   ✓ Consentement explicite par appareil (R0/R1/R2)
   ✓ Hash anonyme MAC quotidien rotatif
   ✓ Données effacées après 24h
   ✓ Rapport téléchargeable PDF
   ✓ Aucun envoi externe (analyse 100% locale)
   ✓ Open Source CMSD-1.0 (audit citoyen)

   ⚠ La cabine N'INTERCEPTE PAS les tiers :
       analyse uniquement ton trafic, avec ton accord.
```

---

## 🎯 ZONE 5 — Bottom : QR codes (1/8)

```
   📥 INSTALLATION RAPIDE iPhone :

   ┌──────────┐  ┌──────────┐  ┌──────────┐
   │ QR code  │  │ QR code  │  │ QR code  │
   │          │  │          │  │          │
   │  Splash  │  │  Cert    │  │  Webclip │
   │  village3b│  │  iPhone  │  │  Home    │
   └──────────┘  └──────────┘  └──────────┘

   Empreinte CA SHA-1 :
   62:A1:E5:3B:1F:C2:B2:97:77:AE:BB:58:61:B2:39:5A:6E:82:71:FF
```

---

## 🎯 ZONE 6 — Footer

```
   📡 Gondwana ToolBoX · CyberMind / Gérald Kerma
   Notre-Dame-du-Cruet (73130) · Savoie · France
   Source : github.com/CyberMind-FR/secubox-deb
   Contact : devel@cybermind.fr · https://cybermind.fr

   //  DIY · Open Source · Open Audit
   //  Soutiens : liberapay.com/cybermind
```

---

## Variantes A4 / A5 / dépliant 3-volets

Le poster A2 ci-dessus peut être adapté :
- **A4** : retirer Zone 3 détaillée, garder titre + 3 niveaux + QR codes + footer
- **A5** : titre + invitation à scanner + 1 QR code
- **Dépliant 3 volets** : volet 1 = titre + 3 niveaux ; volet 2 = exemple rapport ; volet 3 = conformité + QR + contact

---

## Choix typographiques + couleurs (charte DESIGN-CHARTER.md)

```css
--cosmos-black: #0a0a0f;        /* fond */
--gold-hermetic: #c9a84c;       /* accents titre */
--matrix-green: #00ff41;        /* texte principal */
--phos: #00dd44;                /* bordures, P31 lab */
--phos-hot: #00ff55;            /* highlights */
--amber: #ffb347;               /* warning R2 */
--cinnabar: #e63946;            /* alertes risque HIGH */

font-family-titles: 'Cinzel', serif;
font-family-body: 'IM Fell English', serif;
font-family-mono: 'JetBrains Mono', monospace;
```

---

## Print specs

- **Format A2** : 420×594 mm, marges 15 mm
- **Résolution** : 300 dpi minimum
- **Bleed** : 3 mm
- **Couleur** : CMYK (RGB pour digital)
- **Papier** : mat 200 g/m² (pour outdoor : laminé)

---

## Output formats à générer

- [ ] PDF print-ready A2 + A4 + A5
- [ ] SVG éditable (Inkscape source)
- [ ] PNG digital 1920×1080 (réseaux sociaux)
- [ ] Story Instagram 1080×1920
- [ ] LinkedIn banner 1584×396

---

**Status** : Draft v1 — 2026-06-05 — synchronisé avec Phase 3 (#492) actuelle.
Update prévue après Phase 6 (#496 WireGuard R3 mode) pour inclure le 4ème niveau + bénéfice mobile-first.
