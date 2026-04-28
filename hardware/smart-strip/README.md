# Fritzing — SecuBox Smart-Strip v1.1

> Livrables Fritzing pour la documentation, l'enseignement et la communauté open hardware.
> **Important** Fritzing n'est PAS l'outil de conception du PCB Smart-Strip
> (cf. KiCad pour le PCB 4 couches USB HS controlled-impedance). Ces fichiers servent
> à représenter le module dans des sketches Fritzing communautaires.

---

## Contenu

| Fichier | Usage |
|---|---|
| `secubox-smart-strip.fzpz` | **Fritzing part** importable (drag-and-drop dans Fritzing) |
| `fritzing-breadboard-mockup.html` | **Mockup HTML/SVG** style Fritzing pour Ulule/blog/doc |
| `svg/` | Sources SVG individuelles (icon, breadboard, schematic, pcb) + .fzp XML |
| `README.md` | ce fichier |

---

## 1. Installation du part Fritzing

Méthode 1 — Drag-and-drop (recommandée) :

1. Lancer Fritzing 0.9.10+ (<https://fritzing.org/download/>)
2. Glisser `secubox-smart-strip.fzpz` dans la fenêtre Fritzing
3. Le part apparaît dans **Mine** dans le bin (panneau Parts)
4. Drag dans le sketch breadboard, schematic ou PCB

Méthode 2 — Import via menu :

1. Fritzing → File → Open
2. Sélectionner `secubox-smart-strip.fzpz`
3. Le part s'installe dans la bibliothèque utilisateur

Désinstallation :

- Right-click sur le part dans le bin **Mine** → Remove

---

## 2. Connecteurs exposés

Le part expose les **4 broches du connecteur JST-SH** (interface I²C secondary).
Le port USB-C n'est pas modélisé comme connecteur Fritzing (il sort vers un câble
USB hors-breadboard, peu utile dans un sketch Fritzing).

| Connector ID | Nom | Rôle | Fil Qwiic standard |
|---|---|---|---|
| `connector0` | GND | Masse | Noir |
| `connector1` | 3V3 | Alimentation 3.3V (entrée depuis hôte) | Rouge |
| `connector2` | SDA | I²C data line (open-drain, pull-up 4.7kΩ onboard) | Bleu |
| `connector3` | SCL | I²C clock line (open-drain, pull-up 4.7kΩ onboard) | Jaune |

**Adresse I²C par défaut** : `0x42` (configurable via straps R17/R18 ou flash secure storage)

---

## 3. Sketches d'exemple

### 3.1 Smart-Strip + Raspberry Pi 4 via Qwiic

Le mockup HTML `fritzing-breadboard-mockup.html` montre cette configuration :

```
Pi 4 GPIO header :
  Pin 1  (3V3)    →  JST pin 2  (3V3)   [fil rouge]
  Pin 3  (SDA1)   →  JST pin 3  (SDA)   [fil bleu]
  Pin 5  (SCL1)   →  JST pin 4  (SCL)   [fil jaune]
  Pin 6  (GND)    →  JST pin 1  (GND)   [fil noir]
```

Pour reproduire dans Fritzing :

1. Drag le part **Raspberry Pi 4** depuis le bin Core Parts
2. Drag le part **SecuBox Smart-Strip** depuis le bin Mine
3. Connecter les 4 fils selon le tableau ci-dessus
4. Vue Schematic → vérifier le routage logique

### 3.2 Smart-Strip + Arduino via I²C (3.3V level)

```
Arduino Pro Mini 3.3V :
  VCC          →  JST pin 2  (3V3)
  GND          →  JST pin 1  (GND)
  A4 (SDA)     →  JST pin 3  (SDA)
  A5 (SCL)     →  JST pin 4  (SCL)
```

⚠️ **NE PAS connecter à un Arduino UNO 5V** sans level-shifter. Le Smart-Strip
est 3.3V uniquement (les broches I²C ne sont pas tolérantes au 5V malgré les TVS).

### 3.3 Smart-Strip + ESP32

```
ESP32 dev board :
  3V3          →  JST pin 2  (3V3)
  GND          →  JST pin 1  (GND)
  GPIO 21 (SDA) →  JST pin 3  (SDA)
  GPIO 22 (SCL) →  JST pin 4  (SCL)
```

---

## 4. Limites de Fritzing pour ce projet

Le PCB final du Smart-Strip est **conçu en KiCad**, pas en Fritzing. Raisons :

| Contrainte | Fritzing | KiCad |
|---|---|---|
| Couches PCB | 2 layers max | 4+ layers (notre cas : JLC04161H-7628) |
| Contrôle d'impédance USB diff 90Ω | non | oui (calculator + DRC) |
| DRC complet | basique | avancé (length matching, courtyard, etc.) |
| Net classes | non | oui (8 classes définies pour le Smart-Strip) |
| Differential pair routing | non | oui |
| Plan GND continu sous USB diff | manuel et fragile | géré par zones avec rules |
| Empreintes professionnelles | limitées | bibliothèque KiCad complète + custom |
| Export Gerber pro | OK pour 2 couches | OK pour N couches via kicad-cli |

→ Fritzing **convient pour** : représentation pédagogique, sketches communautaires,
documentation Ulule, schémas de mise en service.

→ Fritzing **ne convient pas pour** : fabrication d'un PCB 4 couches USB HS comme
le Smart-Strip v1.1.

C'est pourquoi le part Fritzing fourni ici est un **bloc abstrait** (the Smart-Strip
"as a black box with 4 I²C pins"), pas le détail du PCB. Pour le PCB réel, voir le
livrable `smart-strip-kicad/` séparé (netlist + design rules + DXF + scripts fab).

---

## 5. Mockup HTML breadboard

Le fichier `fritzing-breadboard-mockup.html` est un visuel **standalone** (aucune
dépendance externe) montrant le Smart-Strip connecté à un Raspberry Pi 4 via
câble Qwiic JST-SH 4 fils, dans l'esthétique caractéristique de Fritzing :

- Fond crème breadboard
- Composants illustrés top-down (Pi avec USB ports, HDMI, GPIO header gold)
- Câbles colorés courbes avec ombres portées
- Labels manuscrits (police hand-drawn)
- Annotations bus I²C

Usages :
- Page de campagne Ulule (embed iframe ou screenshot)
- Article de blog technique CyberMind
- Documentation utilisateur SecuBox (intégration via JST-SH)
- Capture vidéo pour réseaux sociaux

Capture statique : ouvrir dans Chrome, devtools → Capture full-page screenshot.

---

## 6. Customiser le part

Pour modifier le part Fritzing (par exemple ajouter le connecteur USB-C en
breadboard view, ou changer les couleurs charte) :

```bash
# Décompresser le .fzpz
mkdir custom && cd custom
unzip ../secubox-smart-strip.fzpz

# Éditer les SVG dans Inkscape ou éditeur texte
inkscape svg.breadboard.SecuBoxSmartStrip_breadboard.svg

# Éditer le metadata
nano part.SecuBoxSmartStrip_v1_1.fzp

# Repackager
zip -j ../secubox-smart-strip-custom.fzpz part.*.fzp svg.*.svg
```

**Règles à respecter pour ne pas casser le part** :

- IDs des connecteurs dans le SVG **doivent** être : `connector0pin`, `connector0terminal`, ..., `connector3pin`, `connector3terminal` (breadboard et schematic)
- IDs des pads PCB **doivent** être : `connector0pad`, ..., `connector3pad` (PCB view sur layer copper0/copper1)
- Le `.fzp` référence ces IDs via `svgId="..."` — toute modification doit être cohérente
- Garder la version Fritzing à 0.9.10 ou supérieure dans `<module fritzingVersion="...">`

---

## 7. Soumission au Fritzing Parts repo (optionnel)

Pour partager le part avec la communauté Fritzing :

1. Fork <https://github.com/fritzing/fritzing-parts>
2. Ajouter `secubox-smart-strip.fzpz` (renommé selon convention)
3. Tester install/uninstall dans Fritzing 0.9.10
4. Ouvrir une PR avec description (cf. `parts/contrib/CONTRIBUTING.md` du repo)

Avantage : le part devient découvrable directement dans Fritzing pour tous les
utilisateurs, sans installation manuelle.

---

## 8. Licence

- **Part Fritzing (`.fzpz`)** : CC-BY-SA 4.0 (compatible Fritzing Parts repo)
- **SVGs sources** : CC-BY-SA 4.0
- **Mockup HTML** : MIT (libre intégration sur n'importe quel site, y compris commercial Ulule)
- **Brand assets** : "SecuBox", "CyberMind", monogramme — réservé CyberMind / Gandalf

---

*CyberMind / SecuBox · SBX-STR-01 v1.1 · 2026-04-27*
