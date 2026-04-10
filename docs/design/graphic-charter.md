# Charte Graphique SecuBox-Deb

> **Version** : 1.5.0
> **Auteur** : CyberMind — Gérald Kerma (GK²)
> **Dernière mise à jour** : Avril 2026

---

## Palette de couleurs — Les 6 Modules

Le système SecuBox utilise une palette de 6 couleurs représentant les modules fonctionnels et les couches de sécurité.

### Codes couleurs

| Module | Hex | RGB | HSL | Rôle |
|--------|-----|-----|-----|------|
| **BOOT** | `#803018` | rgb(128, 48, 24) | hsl(14, 68%, 30%) | Hardware / BootLoader |
| **WALL** | `#9A6010` | rgb(154, 96, 16) | hsl(35, 81%, 33%) | WAF / Firewall périmétrique |
| **MIND** | `#3D35A0` | rgb(61, 53, 160) | hsl(244, 50%, 42%) | Intelligence / DPI / Analyse |
| **ROOT** | `#0A5840` | rgb(10, 88, 64) | hsl(162, 80%, 19%) | Système / API Runtime |
| **MESH** | `#104A88` | rgb(16, 74, 136) | hsl(211, 79%, 30%) | Réseau / WireGuard / P2P |
| **AUTH** | `#C04E24` | rgb(192, 78, 36) | hsl(16, 68%, 45%) | Authentification / ZKP |

### Paires complémentaires

Les modules fonctionnent en paires asymétriques :

| Paire | Fonction | Relation |
|-------|----------|----------|
| **BOOT ↔ ROOT** | Démarrage ↔ Runtime | Initialisation → Production |
| **WALL ↔ MIND** | Défense ↔ Intelligence | Protection → Analyse |
| **MESH ↔ AUTH** | Réseau ↔ Identité | Transport → Authentification |

---

## CSS Variables (Design Tokens)

```css
:root {
  /* Couleurs primaires des modules */
  --color-boot: #803018;
  --color-wall: #9A6010;
  --color-mind: #3D35A0;
  --color-root: #0A5840;
  --color-mesh: #104A88;
  --color-auth: #C04E24;

  /* Variantes claires (hover/accent) */
  --color-boot-light: #a04020;
  --color-wall-light: #c08018;
  --color-mind-light: #5045c0;
  --color-root-light: #108060;
  --color-mesh-light: #1860b0;
  --color-auth-light: #e06030;

  /* Variantes sombres (pressed/shadow) */
  --color-boot-dark: #602010;
  --color-wall-dark: #704808;
  --color-mind-dark: #2d2580;
  --color-root-dark: #084030;
  --color-mesh-dark: #083868;
  --color-auth-dark: #903818;

  /* Couleurs d'interface */
  --color-bg-primary: #0a0a0f;
  --color-bg-secondary: #12121a;
  --color-bg-tertiary: #1a1a24;

  --color-text-primary: #e8e6d9;
  --color-text-secondary: #a8a69a;
  --color-text-muted: #6b6b7a;

  /* Effets CRT */
  --color-glow-cyan: #00d4ff;
  --color-glow-green: #00ff41;
  --color-scanline: rgba(0, 0, 0, 0.15);
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

### Hiérarchie

```css
h1 { font-family: 'Cinzel', serif; font-size: 2.5rem; }
h2 { font-family: 'Cinzel', serif; font-size: 1.8rem; }
h3 { font-family: 'Space Grotesk', sans-serif; font-size: 1.4rem; }
p  { font-family: 'IM Fell English', serif; font-size: 1rem; }
code { font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; }
```

---

## Icônes des modules

Chaque module possède une icône symbolique :

| Module | Icône | Signification |
|--------|-------|---------------|
| BOOT | ⚡ / Éclair | Démarrage, énergie initiale |
| WALL | 🛡️ / Bouclier | Protection, défense |
| MIND | 🧠 / Cerveau | Intelligence, analyse |
| ROOT | 🌳 / Racine | Fondation, système |
| MESH | 🕸️ / Toile | Réseau, interconnexion |
| AUTH | 🔐 / Cadenas | Sécurité, identité |

### Fichiers PNG (Plymouth/UI)

Les icônes sont disponibles en PNG 64x64 dans :
```
image/plymouth/secubox-cube/
├── icon-boot.png
├── icon-wall.png
├── icon-mind.png
├── icon-root.png
├── icon-mesh.png
└── icon-auth.png
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

### Animation de pulsation

```css
@keyframes pulse-glow {
  0%, 100% { opacity: 1; filter: brightness(1); }
  50% { opacity: 0.8; filter: brightness(1.2); }
}

.module-indicator {
  animation: pulse-glow 2s ease-in-out infinite;
}
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
  background: var(--color-bg-secondary);
  border-left: 4px solid var(--module-color);
  padding: 1.5rem;
  border-radius: 4px;
}
```

### Status indicators

```css
.status-ok { color: var(--color-root); }
.status-warning { color: var(--color-wall); }
.status-error { color: var(--color-auth); }
.status-info { color: var(--color-mesh); }
```

---

## Thème sombre / clair

### Mode sombre (défaut)

```css
[data-theme="dark"] {
  --bg-primary: #0a0a0f;
  --bg-secondary: #12121a;
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

## Références

- **Design Tokens** : `packages/secubox-hub/www/css/design-tokens.css`
- **CRT Effects** : `packages/secubox-hub/www/css/crt-system.css`
- **Plymouth Theme** : `image/plymouth/secubox-cube/`
- **Boot Architecture** : `docs/architecture/boot-architecture.md`

---

*CyberMind © 2026 — Charte graphique SecuBox-Deb*
