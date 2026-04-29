# Charte Graphique SecuBox-Deb

> **Version** : 2.0.0
> **Auteur** : CyberMind — Gérald Kerma (GK²)
> **Dernière mise à jour** : Avril 2026

---

## Palette de couleurs — Les 6 Modules

Le système SecuBox utilise une palette de 6 couleurs représentant les modules fonctionnels et les couches de sécurité. Ces couleurs sont utilisées de manière cohérente sur tous les composants :
- Dashboard Eye Remote (HyperPixel 2.1 Round)
- Smart-Strip HMI (6 LEDs + tactile)
- Plymouth boot screen
- Web UI SecuBox Hub

### Codes couleurs officiels

| Module | Hex | RGB | HSL | Rôle |
|--------|-----|-----|-----|------|
| **AUTH** | `#C04E24` | rgb(192, 78, 36) | hsl(16, 68%, 45%) | Authentification / ZKP / CPU |
| **WALL** | `#9A6010` | rgb(154, 96, 16) | hsl(35, 81%, 33%) | WAF / Firewall / Mémoire |
| **BOOT** | `#803018` | rgb(128, 48, 24) | hsl(14, 68%, 30%) | Hardware / BootLoader / Disque |
| **MIND** | `#3D35A0` | rgb(61, 53, 160) | hsl(244, 50%, 42%) | Intelligence / DPI / Charge |
| **ROOT** | `#0A5840` | rgb(10, 88, 64) | hsl(162, 80%, 19%) | Système / API Runtime / Température |
| **MESH** | `#104A88` | rgb(16, 74, 136) | hsl(211, 79%, 30%) | Réseau / WireGuard / WiFi |

### Paires complémentaires (Jumelage Twin)

Les modules fonctionnent en paires asymétriques :

| Paire | Fonction | Relation |
|-------|----------|----------|
| **AUTH ↔ ROOT** | Identité ↔ Runtime | Authentification → Système |
| **WALL ↔ MIND** | Défense ↔ Intelligence | Protection → Analyse |
| **BOOT ↔ MESH** | Démarrage ↔ Réseau | Initialisation → Connexion |

### Ordre Hamiltonien

L'ordre de traversée des modules suit le **chemin Hamiltonien** SecuBox :
```
AUTH → WALL → BOOT → MIND → ROOT → MESH → AUTH...
```

Cet ordre est utilisé pour :
- Animation sweep sur Smart-Strip
- Anneaux concentriques Eye Remote
- Séquence boot Plymouth

---

## Eye Remote Dashboard — Module → Métrique

Le dashboard Eye Remote (HyperPixel 2.1 Round 480×480) associe chaque module à une métrique système :

```
┌────────┬──────────┬─────────────┬──────────┬─────────────────────────────────┐
│ Module │ Couleur  │ Métrique    │ Anneau r │ Sémantique                      │
├────────┼──────────┼─────────────┼──────────┼─────────────────────────────────┤
│ AUTH   │ #C04E24  │ CPU %       │ r = 214  │ Charge auth = CPU-intensif      │
│ WALL   │ #9A6010  │ MEM %       │ r = 201  │ Filtrage réseau = RAM-intensif  │
│ BOOT   │ #803018  │ DISK %      │ r = 188  │ Intégrité boot = état stockage  │
│ MIND   │ #3D35A0  │ LOAD avg    │ r = 175  │ Supervision = charge générale   │
│ ROOT   │ #0A5840  │ TEMP °C     │ r = 162  │ Accès root = chauffe système    │
│ MESH   │ #104A88  │ WiFi dBm    │ r = 149  │ Réseau maillé = qualité lien    │
└────────┴──────────┴─────────────┴──────────┴─────────────────────────────────┘
```

### Seuils d'alerte (couleur dynamique)

| Métrique | Nominal | Warning | Critical |
|----------|---------|---------|----------|
| CPU %    | < 70%   | 70-85%  | > 85%    |
| MEM %    | < 75%   | 75-90%  | > 90%    |
| DISK %   | < 80%   | 80-95%  | > 95%    |
| LOAD     | < 2.0   | 2.0-4.0 | > 4.0    |
| TEMP °C  | < 65°C  | 65-75°C | > 75°C   |
| WiFi dBm | > -60   | -60/-70 | < -70    |

---

## CSS Variables (Design Tokens)

```css
:root {
  /* Couleurs primaires des modules */
  --color-auth: #C04E24;
  --color-wall: #9A6010;
  --color-boot: #803018;
  --color-mind: #3D35A0;
  --color-root: #0A5840;
  --color-mesh: #104A88;

  /* Variantes claires (hover/accent) */
  --color-auth-light: #e06030;
  --color-wall-light: #c08018;
  --color-boot-light: #a04020;
  --color-mind-light: #5045c0;
  --color-root-light: #108060;
  --color-mesh-light: #1860b0;

  /* Variantes sombres (pressed/shadow) */
  --color-auth-dark: #903818;
  --color-wall-dark: #704808;
  --color-boot-dark: #602010;
  --color-mind-dark: #2d2580;
  --color-root-dark: #084030;
  --color-mesh-dark: #083868;

  /* Couleurs d'interface */
  --color-bg-primary: #080808;    /* Fond Eye Remote */
  --color-bg-secondary: #0a0a0f;  /* Fond SecuBox Hub */
  --color-bg-tertiary: #12121a;
  --color-bg-card: #1a1a24;

  --color-text-primary: #e8e6d9;
  --color-text-secondary: #a8a69a;
  --color-text-muted: #6b6b7a;

  /* Transport badges */
  --color-transport-otg: var(--color-root);   /* OTG = vert ROOT */
  --color-transport-wifi: var(--color-mesh);  /* WiFi = bleu MESH */
  --color-transport-sim: #3a3a3a;             /* SIM = gris */

  /* Effets CRT */
  --color-glow-cyan: #00d4ff;
  --color-glow-green: #00ff41;
  --color-scanline: rgba(0, 0, 0, 0.15);

  /* Status indicators */
  --color-nominal: var(--color-root);
  --color-warning: var(--color-wall);
  --color-critical: var(--color-auth);
  --color-info: var(--color-mesh);
}
```

---

## Typographie

| Usage | Police | Fallback |
|-------|--------|----------|
| **Titres hermétiques** | Cinzel | Georgia, serif |
| **Corps texte** | IM Fell English | Georgia, serif |
| **Code / Terminal** | JetBrains Mono | Consolas, monospace |
| **UI / Interface** | Space Grotesk | system-ui, sans-serif |
| **Eye Remote (monospace)** | system-ui monospace | sans-serif |

### Hiérarchie

```css
h1 { font-family: 'Cinzel', serif; font-size: 2.5rem; }
h2 { font-family: 'Cinzel', serif; font-size: 1.8rem; }
h3 { font-family: 'Space Grotesk', sans-serif; font-size: 1.4rem; }
p  { font-family: 'IM Fell English', serif; font-size: 1rem; }
code { font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; }

/* Eye Remote specific - pas de web fonts */
.eye-remote { font-family: system-ui, sans-serif; }
```

---

## Icônes des modules

Chaque module possède une icône symbolique :

| Module | Icône | Fichier PNG | Signification |
|--------|-------|-------------|---------------|
| AUTH | Cible hexagonale | `auth-{22,48,96}.png` | Authentification, identité |
| WALL | Mur de briques | `wall-{22,48,96}.png` | Protection, défense |
| BOOT | Fusée | `boot-{22,48,96}.png` | Démarrage, énergie |
| MIND | Robot IA | `mind-{22,48,96}.png` | Intelligence, analyse |
| ROOT | Terminal $>_ | `root-{22,48,96}.png` | Système, fondation |
| MESH | Engrenage réseau | `mesh-{22,48,96}.png` | Réseau, interconnexion |

### Fichiers PNG (Plymouth/UI/Eye Remote)

```
remote-ui/round/assets/icons/
├── auth-22.png    [~1.2 KB]
├── auth-48.png    [~3.6 KB]
├── auth-96.png    [~9.3 KB]
├── wall-22.png
├── wall-48.png
├── wall-96.png
├── boot-22.png
├── boot-48.png
├── boot-96.png
├── mind-22.png
├── mind-48.png
├── mind-96.png
├── root-22.png
├── root-48.png
├── root-96.png
├── mesh-22.png
├── mesh-48.png
└── mesh-96.png

image/plymouth/secubox-cube/
├── icon-auth.png  [64x64]
├── icon-wall.png
├── icon-boot.png
├── icon-mind.png
├── icon-root.png
└── icon-mesh.png
```

---

## Smart-Strip LED Mapping

Le Smart-Strip utilise 6 LEDs SK6812-MINI-E correspondant aux modules :

| Index | Module | Couleur RGB | Comportement standard |
|-------|--------|-------------|----------------------|
| 0 | AUTH | (192, 78, 36) | Fixe = VPN OK · Flash = erreur · Pulse = handshake |
| 1 | WALL | (154, 96, 16) | Flash rouge = rejet · Vert pâle = autorisé |
| 2 | BOOT | (128, 48, 24) | Battement de cœur 1 Hz |
| 3 | MIND | (61, 53, 160) | Intensité ∝ charge CPU |
| 4 | ROOT | (10, 88, 64) | Blanc = secure · Orange = debug |
| 5 | MESH | (16, 74, 136) | Bleu = connecté · Éteint = isolé |

### Animations Smart-Strip

| ID | Nom | Description |
|----|-----|-------------|
| 0 | Manuel | Contrôle direct par commande |
| 1 | Hamiltonien | Sweep AUTH → MESH en boucle |
| 2 | Panic | Flash rouge ROOT + sweep inverse |
| 3 | Breathing | Pulsation lente sur toutes LEDs |
| 4+ | Custom | Réservé pour extensions |

---

## Eye Remote Dashboard Layout

### Mockup ASCII — Dashboard 480×480

```
╔════════════════════════════════════════╗
║          ● SECUBOX ROUND              ║  ← badge transport (OTG/WiFi/SIM)
║                                        ║
║          ┌────────────────┐            ║
║     [ROOT]               [WALL]        ║  ← pods gauche/droite haut
║    TEMP°C   ●━━━━━━━━━━●  MEM%        ║
║            ┌──────────┐                ║
║            │ 14:32:07 │                ║  ← horloge centrale
║            │mer 15 avr│                ║
║   [MIND]   │secubox-zr│   [BOOT]       ║
║   LOAD×    │ up 24h00 │   DISK%       ║
║            └──────────┘                ║
║      [AUTH]            [MESH]          ║  ← pods bas
║      CPU%              WiFidBm        ║
║                                        ║
║       ═══════════════════════          ║  ← 6 anneaux concentriques
║     AUTH WALL BOOT MIND ROOT MESH      ║    (Canvas, dessinés derrière)
║                                        ║
║          ● NOMINAL                    ║  ← barre statut
║     TEMP [████░░░░░░░░] 44°C          ║  ← barre température
╚════════════════════════════════════════╝
```

### Pod Layout (position des 6 modules)

```
         ROOT (haut gauche)    WALL (haut droite)
              ↖                   ↗
                 ╲             ╱
                   ╲         ╱
      MIND (milieu)  ● centre ●  BOOT (milieu)
      gauche           ╲   ╱      droite
                        ╲ ╱
               AUTH (bas gauche)   MESH (bas droite)
```

---

## Effets visuels

### Effet CRT (Cathode Ray Tube)

L'interface SecuBox utilise un effet rétro-futuriste CRT :

```css
/* Scanlines */
.crt-overlay::before {
  content: '';
  position: absolute;
  inset: 0;
  background: repeating-linear-gradient(
    transparent 0px,
    transparent 2px,
    var(--color-scanline) 2px,
    var(--color-scanline) 4px
  );
  pointer-events: none;
}

/* Glow effect */
.crt-glow {
  text-shadow:
    0 0 5px currentColor,
    0 0 10px currentColor,
    0 0 20px currentColor;
}

/* Vignette */
.crt-vignette {
  box-shadow: inset 0 0 100px rgba(0, 0, 0, 0.5);
}
```

### Animation de pulsation (modules)

```css
@keyframes pulse-glow {
  0%, 100% { opacity: 1; filter: brightness(1); }
  50% { opacity: 0.8; filter: brightness(1.2); }
}

.module-indicator {
  animation: pulse-glow 2s ease-in-out infinite;
}
```

### Animation Eye Remote (arcs progressifs)

```javascript
// 6 anneaux concentriques
const RINGS = [
  { module: 'AUTH', color: '#C04E24', r: 214, width: 8 },
  { module: 'WALL', color: '#9A6010', r: 201, width: 8 },
  { module: 'BOOT', color: '#803018', r: 188, width: 8 },
  { module: 'MIND', color: '#3D35A0', r: 175, width: 8 },
  { module: 'ROOT', color: '#0A5840', r: 162, width: 8 },
  { module: 'MESH', color: '#104A88', r: 149, width: 8 },
];

// Arc progressif : angle = 2π × (valeur / max)
// Dot lumineux en tête d'arc pour repère
```

---

## Composants UI

### Boutons

```css
.btn-module {
  padding: 0.75rem 1.5rem;
  border: 2px solid var(--module-color);
  background: transparent;
  color: var(--module-color);
  transition: all 0.3s ease;
}

.btn-module:hover {
  background: var(--module-color);
  color: var(--color-bg-primary);
  box-shadow: 0 0 20px var(--module-color);
}
```

### Cartes

```css
.card-module {
  background: var(--color-bg-tertiary);
  border-left: 4px solid var(--module-color);
  padding: 1.5rem;
  border-radius: 4px;
}
```

### Status indicators

```css
.status-nominal { color: var(--color-root); }
.status-warning { color: var(--color-wall); }
.status-critical { color: var(--color-auth); }
.status-info { color: var(--color-mesh); }
```

---

## Thème sombre / clair

### Mode sombre (défaut)

```css
[data-theme="dark"] {
  --bg-primary: #080808;
  --bg-secondary: #0a0a0f;
  --text-primary: #e8e6d9;
}
```

### Mode clair (optionnel)

```css
[data-theme="light"] {
  --bg-primary: #f5f5f0;
  --bg-secondary: #ffffff;
  --text-primary: #1a1a24;
}
```

---

## Cohérence inter-composants

| Composant | Fond | Modules | Interaction |
|-----------|------|---------|-------------|
| Eye Remote | #080808 | 6 anneaux + pods | Touch/tap sur pods |
| Smart-Strip | N/A (physique) | 6 LEDs + pads | Capacitif 6 zones |
| SecuBox Hub Web | #0a0a0f | Cards + navigation | Click/touch |
| Plymouth Boot | Noir | 6 icônes sequence | N/A (boot) |

---

## Références

- **Design Tokens** : `packages/secubox-hub/www/css/design-tokens.css`
- **CRT Effects** : `packages/secubox-hub/www/css/crt-system.css`
- **Plymouth Theme** : `image/plymouth/secubox-cube/`
- **Eye Remote** : `remote-ui/round/` (CLAUDE.md complet)
- **Smart-Strip** : `docs/hardware/smart-strip-v1.1.md`
- **Boot Architecture** : `docs/architecture/boot-architecture.md`

---

*CyberMind © 2026 — Charte graphique SecuBox-Deb v2.0*
