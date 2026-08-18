<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Eye Remote — Phase 1: `remote-ui/common/` extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the non-Zero-W-specific parts of `remote-ui/round/` into a new `remote-ui/common/` directory and rewire round/ to consume it. End state: round/'s rendered dashboard, USB-gadget behaviour, image, and pytest suite are bit-for-bit equivalent to v2.2.1 modulo file timestamps. Sets the foundation for Phase 2 (`remote-ui/square/`) to consume the same shared core.

**Architecture:** Mechanical refactor — JS constants, CSS variables, PNG icons, and shell scripts move from `remote-ui/round/` to `remote-ui/common/`. Round/'s `index.html` switches from inline `<style>`/`<script>` blocks to external `<link>`/`<script>` tags pointing at common/. Two additive changes: (a) optional no-op hooks `onModuleTap` and `onTransportChange` on TransportManager, and (b) a new `form_factor` field on the host-side `RemoteUIConnectedRequest` Pydantic model defaulting to `"round"` for backward compatibility. Regression gates: existing pytest suite green, `diffoscope` shows only timestamp deltas on the round/ image, manual Zero W bench renders identically.

**Tech Stack:** HTML/CSS/JS vanilla (no modules), Python 3.11 + FastAPI + Pydantic v2, bash + shellcheck, pytest. Existing `scripts/agent-worktree.sh` for worktree management. `diffoscope` for image comparison.

**Spec:** [`docs/superpowers/specs/2026-05-13-eye-square-variant-design.md`](../specs/2026-05-13-eye-square-variant-design.md)
**Issue:** [#127](https://github.com/CyberMind-FR/secubox-deb/issues/127)
**Phase 2 plan:** to be written after this Phase 1 PR merges.

---

## Working directory & branch

This plan executes in a worktree created by `scripts/agent-worktree.sh start --issue 127`. The script will produce a branch named `feature/127-add-remote-ui-square-variant-for-pi-4b-...` and a worktree under `~/CyberMindStudio/secubox-deb-worktrees/127-...`.

Verify on the right branch at the start of every task:

```bash
git rev-parse --abbrev-ref HEAD
```

Expected: starts with `feature/127-`. Abort if on `master`.

---

## File structure (target end state)

```
remote-ui/
├── common/                              ← NEW
│   ├── README.md
│   ├── js/
│   │   ├── icons.js                     ← extracted from round/index.html line 168
│   │   ├── modules-table.js             ← AUTH/WALL/BOOT/MIND/ROOT/MESH defs
│   │   ├── jwt-helper.js                ← auth helpers from CFG
│   │   ├── transport-manager.js         ← TM + new onModuleTap/onTransportChange hooks
│   │   └── sim.js                       ← SIM constant + drift generator
│   ├── css/
│   │   ├── palette.css                  ← :root { --auth: #C04E24; … }
│   │   └── base.css                     ← monospace, circle clip, pod/status base
│   ├── assets/
│   │   └── icons/                       ← 24 PNGs moved from round/assets/icons/
│   │                                       (alert-/audit-/back-/ban-/brightness-/clock-/cpu-/
│   │                                       dashboard-/devices-/* stay in round/ as
│   │                                       radial-menu specific)
│   └── shell/
│       ├── secubox-otg-gadget.sh        ← variant-aware (VARIANT=round|square)
│       └── secubox-otg-host-up.sh
│
├── round/
│   ├── index.html                       ← <link>/<script> references to ../common/
│   ├── deploy.sh                        ← rsync ../common/ alongside round/
│   ├── build-eye-remote-image.sh        ← copies ../common/ into rootfs
│   ├── README.md, CLAUDE.md             ← updated to reference common/
│   ├── secubox-otg-gadget.sh            ← symlink → ../common/shell/secubox-otg-gadget.sh
│   ├── secubox-otg-host-up.sh           ← symlink → ../common/shell/secubox-otg-host-up.sh
│   ├── assets/icons/                    ← only menu-specific icons remain
│   └── (everything else unchanged)
│
packages/secubox-system/
├── models/system.py                     ← RemoteUIConnectedRequest gains `form_factor`
└── core/remote_ui.py                    ← stores form_factor on connection
```

---

## Task 1: Create worktree, branch, and `remote-ui/common/` skeleton

**Files:**
- Create: `remote-ui/common/README.md`
- Create: `remote-ui/common/js/.gitkeep`
- Create: `remote-ui/common/css/.gitkeep`
- Create: `remote-ui/common/assets/icons/.gitkeep`
- Create: `remote-ui/common/shell/.gitkeep`

- [ ] **Step 1: Create the worktree**

From the main checkout `/home/reepost/CyberMindStudio/secubox-deb/secubox-deb`:

```bash
bash scripts/agent-worktree.sh start --issue 127
```

Expected: prints a `cd` command pointing to the new worktree under `~/CyberMindStudio/secubox-deb-worktrees/127-...`.

- [ ] **Step 2: Switch to the worktree and verify branch**

```bash
cd ~/CyberMindStudio/secubox-deb-worktrees/127-add-remote-ui-square-variant-for-pi-4b-7-touchscreen-800x480
git rev-parse --abbrev-ref HEAD
```

Expected: branch name starts with `feature/127-`.

- [ ] **Step 3: Create the directory skeleton**

```bash
mkdir -p remote-ui/common/{js,css,assets/icons,shell}
touch remote-ui/common/js/.gitkeep \
      remote-ui/common/css/.gitkeep \
      remote-ui/common/assets/icons/.gitkeep \
      remote-ui/common/shell/.gitkeep
```

- [ ] **Step 4: Write the `remote-ui/common/README.md`**

Write:

```markdown
# remote-ui/common — Shared Core

Files consumed by both `remote-ui/round/` (Pi Zero W + HyperPixel 2.1 Round)
and `remote-ui/square/` (Pi 4B / Pi 400 + 7" 800×480).

Layout:
- `js/`     vanilla globals (no ES modules)
- `css/`    palette variables + base layout
- `assets/icons/`  the six SecuBox module PNG icons (22/48/96/128 px)
- `shell/`  variant-aware USB gadget scripts (set $VARIANT before sourcing)

Round/ and square/ reference these via relative `<link>` / `<script>` tags or
`cp -r ../common/` from their image build / deploy scripts.

License: LicenseRef-CMSD-1.0
```

- [ ] **Step 5: Commit the skeleton**

```bash
git add remote-ui/common/
git commit -m "feat(remote-ui/common): scaffold shared-core directory (ref #127)"
```

---

## Task 2: Extract palette CSS variables to `common/css/palette.css`

**Files:**
- Create: `remote-ui/common/css/palette.css`
- Read: `remote-ui/round/index.html` (style block lines 7-75)

- [ ] **Step 1: Read the existing style block**

```bash
sed -n '7,75p' remote-ui/round/index.html
```

Identify the colour custom properties on `:root` and the six per-module colours (`--auth`, `--wall`, `--boot`, `--mind`, `--root`, `--mesh`) plus shared tokens (`--cosmos-black`, `--gold-hermetic`, `--cinnabar`, `--matrix-green`, `--cyber-cyan`, `--void-purple`, `--text-primary`, `--text-muted`).

- [ ] **Step 2: Write `common/css/palette.css`**

```css
/* SPDX-License-Identifier: LicenseRef-CMSD-1.0
 * Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
 * SecuBox-Deb :: remote-ui/common/css/palette.css
 */
:root {
  /* SecuBox module colours */
  --auth: #C04E24;
  --wall: #9A6010;
  --boot: #803018;
  --mind: #3D35A0;
  --root: #0A5840;
  --mesh: #104A88;

  /* Shared tokens (C3BOX palette) */
  --cosmos-black:   #0a0a0f;
  --gold-hermetic:  #c9a84c;
  --cinnabar:       #e63946;
  --matrix-green:   #00ff41;
  --cyber-cyan:     #00d4ff;
  --void-purple:    #6e40c9;
  --text-primary:   #e8e6d9;
  --text-muted:     #6b6b7a;
}
```

If the actual values in `round/index.html` differ from the above, use the round/ values verbatim — fidelity to v2.2.1 wins over CLAUDE.md's documented palette.

- [ ] **Step 3: Commit**

```bash
git add remote-ui/common/css/palette.css
git commit -m "feat(remote-ui/common): extract palette.css from round/ (ref #127)"
```

---

## Task 3: Extract base CSS to `common/css/base.css`

**Files:**
- Create: `remote-ui/common/css/base.css`
- Read: `remote-ui/round/index.html` (style block, non-`:root` rules)

- [ ] **Step 1: Identify non-palette rules**

From the style block (lines 7-75), separate:
- `:root { … }` → already in `palette.css` (skip)
- Everything else → goes in `base.css`

This typically includes: `*, html, body` reset rules, `#screen` circle clip + 480×480 sizing, `#ring-canvas`, `.pod`, `#center`, `#transport`, `#status`, `#temp-row`, `#auth-overlay`, font-family declarations.

- [ ] **Step 2: Write `common/css/base.css`**

Copy each non-`:root` rule from `round/index.html` lines 7-75 verbatim, prefixed by the SPDX header:

```css
/* SPDX-License-Identifier: LicenseRef-CMSD-1.0
 * Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
 * SecuBox-Deb :: remote-ui/common/css/base.css
 *
 * Layout primitives shared by remote-ui/round/ (480×480 circle clip)
 * and remote-ui/square/ (Chromium consumes round/index.html at 480×480
 * with no clip — square's right panel is a separate PySide6 window).
 */

/* … verbatim rules from round/index.html style block (excluding :root) … */
```

- [ ] **Step 3: Verify total CSS line count matches**

```bash
LINES_ROUND=$(sed -n '8,74p' remote-ui/round/index.html | grep -cv '^\s*$')
LINES_COMMON=$(grep -cv '^\s*$' remote-ui/common/css/palette.css remote-ui/common/css/base.css | tail -1)
echo "round: $LINES_ROUND  common: $LINES_COMMON"
```

The two numbers should match (excluding blank lines and the SPDX comments). Adjust if not.

- [ ] **Step 4: Commit**

```bash
git add remote-ui/common/css/base.css
git commit -m "feat(remote-ui/common): extract base.css from round/ (ref #127)"
```

---

## Task 4: Extract `ICONS` to `common/js/icons.js`

**Files:**
- Create: `remote-ui/common/js/icons.js`
- Read: `remote-ui/round/index.html` (line 168 onward, the `const ICONS = { … }` block)

- [ ] **Step 1: Find the ICONS block**

```bash
awk '/^const ICONS = {/,/^};/' remote-ui/round/index.html | head -5
awk '/^const ICONS = {/,/^};/' remote-ui/round/index.html | wc -l
```

Note the line range. Expected: tens to ~hundreds of lines depending on how many icon sizes are embedded.

- [ ] **Step 2: Write `common/js/icons.js`**

```javascript
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: remote-ui/common/js/icons.js
//
// data: URIs PNG base64 for AUTH/WALL/BOOT/MIND/ROOT/MESH × {22, 48, 96, 128}.
// Defined as a global window.ICONS so legacy round/index.html code that
// references bare `ICONS.AUTH.22` keeps working without imports.

const ICONS = {
  // … verbatim from round/index.html const ICONS = { … } block …
};

// Expose as global for legacy callers (no ES modules in round/index.html)
if (typeof window !== 'undefined') { window.ICONS = ICONS; }
```

Paste the entire `const ICONS = { … };` block verbatim from `round/index.html`.

- [ ] **Step 3: Verify byte-identical content**

```bash
awk '/^const ICONS = {/,/^};/' remote-ui/round/index.html > /tmp/icons-round.js
awk '/^const ICONS = {/,/^};/' remote-ui/common/js/icons.js > /tmp/icons-common.js
diff -u /tmp/icons-round.js /tmp/icons-common.js
```

Expected: no output (identical) — minus our window-expose footer which is appended after.

- [ ] **Step 4: Commit**

```bash
git add remote-ui/common/js/icons.js
git commit -m "feat(remote-ui/common): extract ICONS to icons.js (ref #127)"
```

---

## Task 5: Extract MODULES table to `common/js/modules-table.js`

**Files:**
- Create: `remote-ui/common/js/modules-table.js`
- Read: `remote-ui/round/index.html` (look for `const MODULES`, `const RINGS`, or the AUTH/WALL/BOOT/MIND/ROOT/MESH definitions list)

- [ ] **Step 1: Locate the modules definition**

```bash
grep -nE "AUTH|WALL|BOOT|MIND|ROOT|MESH" remote-ui/round/index.html | head -30
```

Find the canonical definition table (the one that maps each module to its colour, metric, and Canvas ring radius). It may be named `MODULES`, `RINGS`, or be inline inside `const TM` — record which.

- [ ] **Step 2: Write `common/js/modules-table.js`**

```javascript
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: remote-ui/common/js/modules-table.js
//
// Canonical mapping: module → colour → metric → ring radius (round/) → icon key.
// Order: AUTH, WALL, BOOT, MIND, ROOT, MESH (hamiltonian path AUTH→…→MESH→AUTH).

const MODULES = [
  { name: 'AUTH', colour: 'var(--auth)', metric: 'cpu_percent',  ringR: 214, unit: '%'   },
  { name: 'WALL', colour: 'var(--wall)', metric: 'mem_percent',  ringR: 201, unit: '%'   },
  { name: 'BOOT', colour: 'var(--boot)', metric: 'disk_percent', ringR: 188, unit: '%'   },
  { name: 'MIND', colour: 'var(--mind)', metric: 'load_avg_1',   ringR: 175, unit: '×'   },
  { name: 'ROOT', colour: 'var(--root)', metric: 'cpu_temp',     ringR: 162, unit: '°C'  },
  { name: 'MESH', colour: 'var(--mesh)', metric: 'wifi_rssi',    ringR: 149, unit: 'dBm' },
];

if (typeof window !== 'undefined') { window.MODULES = MODULES; }
```

Cross-reference the values (especially `ringR` radii) with the existing `RINGS` array in round/index.html. Use round/'s values verbatim — do not guess from CLAUDE.md.

- [ ] **Step 3: Commit**

```bash
git add remote-ui/common/js/modules-table.js
git commit -m "feat(remote-ui/common): extract MODULES table to modules-table.js (ref #127)"
```

---

## Task 6: Extract JWT helper to `common/js/jwt-helper.js`

**Files:**
- Create: `remote-ui/common/js/jwt-helper.js`
- Read: `remote-ui/round/index.html` (auth/login/ensureJwt methods inside `const TM`)

- [ ] **Step 1: Identify auth-related code**

```bash
grep -nE "login|jwt|token|ensureJwt|JWT_RENEW" remote-ui/round/index.html
```

Capture: the `TM.login()` method body, `TM.ensureJwt()`, the `JWT_RENEW_BEFORE_MS` const, the `LOGIN_USER`/`LOGIN_PASS` fields, and any token expiry parsing helpers.

- [ ] **Step 2: Write `common/js/jwt-helper.js`**

```javascript
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: remote-ui/common/js/jwt-helper.js
//
// Helpers for JWT login + automatic renewal. Consumed by TransportManager.

const JWT_HELPER = {
  // Time before token expiry to trigger renewal (ms).
  RENEW_BEFORE_MS: 30000,

  // Decode the exp claim from a JWT payload. Returns Date or null.
  parseExpiry(token) {
    if (!token) return null;
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.exp ? new Date(payload.exp * 1000) : null;
    } catch (e) {
      return null;
    }
  },

  // Issue a POST to <base>/api/v1/auth/token with username/password.
  // Returns { token, exp } or null on failure.
  async login(baseUrl, user, pass, timeoutMs = 5000) {
    try {
      const response = await fetch(baseUrl + '/api/v1/auth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!response.ok) return null;
      const data = await response.json();
      return { token: data.access_token, exp: this.parseExpiry(data.access_token) };
    } catch (e) {
      return null;
    }
  },

  // True if the token is within RENEW_BEFORE_MS of expiry (or already expired).
  needsRenewal(exp) {
    if (!exp) return true;
    return (exp.getTime() - Date.now()) < this.RENEW_BEFORE_MS;
  },
};

if (typeof window !== 'undefined') { window.JWT_HELPER = JWT_HELPER; }
```

Adjust function bodies to match the actual round/ implementation. The above is the contract.

- [ ] **Step 3: Commit**

```bash
git add remote-ui/common/js/jwt-helper.js
git commit -m "feat(remote-ui/common): extract jwt-helper.js from round/ (ref #127)"
```

---

## Task 7: Extract TransportManager to `common/js/transport-manager.js` with new hooks

**Files:**
- Create: `remote-ui/common/js/transport-manager.js`
- Read: `remote-ui/round/index.html` (the `const TM = { … }` block starting at line 188)

- [ ] **Step 1: Extract the TM block**

```bash
awk '/^const TM = {/,/^};/' remote-ui/round/index.html > /tmp/tm-block.js
wc -l /tmp/tm-block.js
```

- [ ] **Step 2: Write `common/js/transport-manager.js`**

Use the extracted TM block verbatim, with these additions:

```javascript
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: remote-ui/common/js/transport-manager.js
//
// Probe OTG (10.55.0.1) → WiFi (secubox.local) → SIM (drift mode).
// Single token per transport, renewed automatically 30s before expiry.
//
// Optional hooks for embedding contexts (e.g. square/'s right column):
//   TM.onModuleTap        = (moduleName) => { … };  // default no-op
//   TM.onTransportChange  = (active)     => { … };  // default no-op

const TM = {
  active: 'SIM',
  otgFails: 0,

  // Optional hooks (default no-ops). Override in deployment-specific shim.
  onModuleTap:       (moduleName) => {},
  onTransportChange: (active)     => {},

  // … verbatim from round/index.html const TM = { … } block …
  // PRESERVE the existing probe(), login(), ensureJwt(), fetchMetrics() methods.

  // Hook firing wrapper for setActive — call this instead of direct assignment.
  _setActive(newActive) {
    if (this.active !== newActive) {
      this.active = newActive;
      try { this.onTransportChange(newActive); } catch (e) { console.warn(e); }
    }
  },
};

if (typeof window !== 'undefined') { window.TM = TM; }
```

Replace all direct `this.active = …` or `TM.active = …` assignments with `this._setActive(…)` / `TM._setActive(…)`. This is the only behavioural delta in Phase 1 — and `onTransportChange` defaults to a no-op so round/ in isolation behaves identically.

- [ ] **Step 3: Smoke-test the hook is callable**

Create a quick HTML harness that loads the file and asserts:

```bash
mkdir -p /tmp/tm-test
cat > /tmp/tm-test/test.html <<'EOF'
<!DOCTYPE html>
<html><head><script src="transport-manager.js"></script></head>
<body><script>
  let called = 0;
  TM.onTransportChange = () => { called++; };
  TM._setActive('WiFi');
  TM._setActive('WiFi');         // dedupe — same value, no fire
  TM._setActive('OTG');
  document.body.textContent = `calls=${called}`;
  // Print to console for headless capture
  console.log('CALLS=' + called);
</script></body></html>
EOF
cp remote-ui/common/js/transport-manager.js /tmp/tm-test/
chromium --headless --disable-gpu --no-sandbox --dump-dom file:///tmp/tm-test/test.html 2>/dev/null | grep -o 'calls=[0-9]'
```

Expected: `calls=2` (2 distinct transitions, not 3 — the second `WiFi` is a no-op).

- [ ] **Step 4: Commit**

```bash
git add remote-ui/common/js/transport-manager.js
git commit -m "feat(remote-ui/common): extract transport-manager.js with onModuleTap/onTransportChange hooks (ref #127)"
```

---

## Task 8: Extract simulation drift to `common/js/sim.js`

**Files:**
- Create: `remote-ui/common/js/sim.js`
- Read: `remote-ui/round/index.html` (the `const SIM = { … }` block at line 232 and any `simDrift()` / `simulate()` helper)

- [ ] **Step 1: Locate the SIM constant and any drift helper**

```bash
sed -n '230,260p' remote-ui/round/index.html
grep -nE "SIM\.|simDrift|simulate" remote-ui/round/index.html
```

- [ ] **Step 2: Write `common/js/sim.js`**

```javascript
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: remote-ui/common/js/sim.js
//
// Simulation drift generator — produces plausible metrics with bounded
// random walk when no SecuBox host responds.

const SIM = {
  // … verbatim from round/index.html const SIM = { … } …
};

// driftStep(): advance SIM one tick. Returns a SystemMetricsResponse-shaped object.
function driftStep() {
  // … verbatim from round/index.html simDrift/simulate body …
}

if (typeof window !== 'undefined') {
  window.SIM = SIM;
  window.driftStep = driftStep;
}
```

- [ ] **Step 3: Commit**

```bash
git add remote-ui/common/js/sim.js
git commit -m "feat(remote-ui/common): extract sim.js drift generator (ref #127)"
```

---

## Task 9: Move six SecuBox module PNG icons to `common/assets/icons/`

**Files:**
- Move: `remote-ui/round/assets/icons/{auth,wall,boot,mind,root,mesh}-{22,48,96,128}.png` → `remote-ui/common/assets/icons/`

- [ ] **Step 1: Move the 24 module icons**

```bash
cd remote-ui
for m in auth wall boot mind root mesh; do
  for sz in 22 48 96 128; do
    git mv round/assets/icons/${m}-${sz}.png common/assets/icons/${m}-${sz}.png
  done
done
ls common/assets/icons/ | wc -l
```

Expected: `24`.

- [ ] **Step 2: Confirm no other module icons are left behind**

```bash
ls remote-ui/round/assets/icons/ | grep -cE "^(auth|wall|boot|mind|root|mesh)-"
```

Expected: `0` (all six modules' icons moved; radial-menu icons like `alert-`, `audit-`, `back-` stay).

- [ ] **Step 3: Update any references in round/'s shell or HTML**

```bash
grep -rn "assets/icons/auth\|assets/icons/wall\|assets/icons/boot\|assets/icons/mind\|assets/icons/root\|assets/icons/mesh" remote-ui/round/
```

Replace each match with `../common/assets/icons/...`. If references are runtime data URIs from the `ICONS` constant (already extracted in Task 4), no path edit is needed — they were embedded.

- [ ] **Step 4: Commit**

```bash
git add remote-ui/
git commit -m "feat(remote-ui/common): move 24 SecuBox module icons to common/assets/icons/ (ref #127)"
```

---

## Task 10: Move and parameterise `secubox-otg-gadget.sh`

**Files:**
- Move: `remote-ui/round/secubox-otg-gadget.sh` → `remote-ui/common/shell/secubox-otg-gadget.sh`
- Create symlink: `remote-ui/round/secubox-otg-gadget.sh` → `../common/shell/secubox-otg-gadget.sh`

- [ ] **Step 1: Read the existing script**

```bash
wc -l remote-ui/round/secubox-otg-gadget.sh
head -30 remote-ui/round/secubox-otg-gadget.sh
grep -nE "secubox-round|hardcoded" remote-ui/round/secubox-otg-gadget.sh
```

Look for: hardcoded paths (`/sys/kernel/config/usb_gadget/secubox-round`), hostname-derived MAC sources, and any `secubox-round`-specific naming.

- [ ] **Step 2: Move the file to common/**

```bash
git mv remote-ui/round/secubox-otg-gadget.sh remote-ui/common/shell/secubox-otg-gadget.sh
```

- [ ] **Step 3: Parameterise with `VARIANT` variable**

Edit `remote-ui/common/shell/secubox-otg-gadget.sh`:

- Replace the SPDX-header `MODULE=` and any hardcoded `secubox-round` literals with `${VARIANT:-round}`.
- Replace gadget configfs path `/sys/kernel/config/usb_gadget/secubox-round` with `/sys/kernel/config/usb_gadget/secubox-${VARIANT:-round}`.
- Add a top-of-file comment:

```bash
# SecuBox-Deb :: remote-ui/common/shell/secubox-otg-gadget.sh
#
# Variant-aware USB gadget composite controller.
# Set VARIANT=round (default) or VARIANT=square before invoking.
# The configfs gadget directory becomes /sys/kernel/config/usb_gadget/secubox-$VARIANT
# and the udev-renamed interface on the host becomes secubox-$VARIANT.
```

- Add MAC derivation fallback for arm64 (Pi 4B / Pi 400):

```bash
# Pi Zero W exposes the serial in /proc/cpuinfo (Serial: …)
# Pi 4B/400 (arm64) exposes it in /sys/firmware/devicetree/base/serial-number
get_serial() {
    local s
    if s=$(awk '/^Serial/ {print $3}' /proc/cpuinfo 2>/dev/null) && [ -n "$s" ]; then
        echo "$s"
        return
    fi
    if [ -r /sys/firmware/devicetree/base/serial-number ]; then
        tr -d '\0' < /sys/firmware/devicetree/base/serial-number
        return
    fi
    # Last-resort deterministic fallback
    echo "0000000000000000"
}
```

- [ ] **Step 4: Restore a symlink at round/ so existing systemd units keep working**

```bash
cd remote-ui/round
ln -s ../common/shell/secubox-otg-gadget.sh secubox-otg-gadget.sh
cd ../..
ls -la remote-ui/round/secubox-otg-gadget.sh
```

Expected: symlink pointing to `../common/shell/secubox-otg-gadget.sh`.

- [ ] **Step 5: Run shellcheck**

```bash
shellcheck remote-ui/common/shell/secubox-otg-gadget.sh
```

Expected: no errors. Fix any new warnings introduced by the variant substitution.

- [ ] **Step 6: Commit**

```bash
git add remote-ui/
git commit -m "feat(remote-ui/common): move secubox-otg-gadget.sh to common/shell/ with VARIANT param (ref #127)"
```

---

## Task 11: Move `secubox-otg-host-up.sh` with same variant treatment

**Files:**
- Move: `remote-ui/round/secubox-otg-host-up.sh` → `remote-ui/common/shell/secubox-otg-host-up.sh`
- Create symlink: `remote-ui/round/secubox-otg-host-up.sh` → `../common/shell/secubox-otg-host-up.sh`

- [ ] **Step 1: Move the file**

```bash
git mv remote-ui/round/secubox-otg-host-up.sh remote-ui/common/shell/secubox-otg-host-up.sh
```

- [ ] **Step 2: Parameterise interface naming**

Replace any hardcoded `secubox-round` references with `secubox-${VARIANT:-round}`. The udev rule that calls this script will pass `VARIANT=round` or `VARIANT=square` based on the connected gadget's serial-number signature.

- [ ] **Step 3: Symlink back**

```bash
cd remote-ui/round
ln -s ../common/shell/secubox-otg-host-up.sh secubox-otg-host-up.sh
cd ../..
```

- [ ] **Step 4: Shellcheck**

```bash
shellcheck remote-ui/common/shell/secubox-otg-host-up.sh
```

Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add remote-ui/
git commit -m "feat(remote-ui/common): move secubox-otg-host-up.sh to common/shell/ (ref #127)"
```

---

## Task 12: Rewire `round/index.html` to consume common/

**Files:**
- Modify: `remote-ui/round/index.html`

- [ ] **Step 1: Replace the inline `<style>` block with `<link>` tags**

Edit `remote-ui/round/index.html`. Replace the entire `<style>…</style>` block (currently lines 7-75) with:

```html
<link rel="stylesheet" href="../common/css/palette.css">
<link rel="stylesheet" href="../common/css/base.css">
```

- [ ] **Step 2: Replace the inline `<script>` constants with `<script src=…>` tags**

In the existing `<script>` block (lines 167-413), the constants `ICONS`, `MODULES`, `JWT_HELPER`, `TM`, `SIM`, and `driftStep` have all been extracted to common/. Remove their definitions from the inline `<script>` block. **Keep** the round-specific code: `RINGS[]` array (drawing geometry), `drawRings()`, `updateDOM()`, `updateClock()`, `podTap()`, `init()`.

Before the inline `<script>` opening, add:

```html
<script src="../common/js/icons.js"></script>
<script src="../common/js/modules-table.js"></script>
<script src="../common/js/jwt-helper.js"></script>
<script src="../common/js/transport-manager.js"></script>
<script src="../common/js/sim.js"></script>
```

Order matters: `transport-manager.js` references `JWT_HELPER`, so it must load after `jwt-helper.js`.

- [ ] **Step 3: Snapshot pre-edit rendering for regression**

Before continuing, capture the current rendered state for visual regression:

```bash
chromium --headless --disable-gpu --no-sandbox \
    --screenshot=/tmp/round-pre-rewire.png --window-size=480,480 \
    file://$PWD/remote-ui/round/index.html.bak 2>/dev/null || \
chromium --headless --disable-gpu --no-sandbox \
    --screenshot=/tmp/round-pre-rewire.png --window-size=480,480 \
    file://$PWD/remote-ui/round/index.html 2>/dev/null
ls -la /tmp/round-pre-rewire.png
```

If `index.html.bak` doesn't exist, capture from the current `index.html` BEFORE the edits in Step 1 and Step 2 (so revert temporarily, screenshot, redo edits).

- [ ] **Step 4: Snapshot post-edit rendering**

```bash
chromium --headless --disable-gpu --no-sandbox \
    --screenshot=/tmp/round-post-rewire.png --window-size=480,480 \
    file://$PWD/remote-ui/round/index.html 2>/dev/null
ls -la /tmp/round-post-rewire.png
```

- [ ] **Step 5: Visual diff**

```bash
# Pixel-by-pixel comparison via ImageMagick (apt install imagemagick if missing)
compare -metric AE /tmp/round-pre-rewire.png /tmp/round-post-rewire.png /tmp/round-diff.png
```

Expected: exit code 0 and AE (absolute error pixels) ≤ a small threshold (say 50). Anti-aliasing on text means it may not be 0; investigate any large delta. If the difference exceeds a few pixels, the extraction has introduced a regression — bisect by reverting one extracted file at a time.

- [ ] **Step 6: Commit**

```bash
git add remote-ui/round/index.html
git commit -m "refactor(remote-ui/round): index.html consumes common/ via <link>/<script> tags (ref #127)"
```

---

## Task 13: Add `form_factor` field to `RemoteUIConnectedRequest` (TDD)

**Files:**
- Modify: `packages/secubox-system/models/system.py`
- Modify: `packages/secubox-system/core/remote_ui.py`
- Create: `packages/secubox-system/tests/test_remote_ui_form_factor.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-system/tests/test_remote_ui_form_factor.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for the form_factor field on RemoteUIConnectedRequest (ref #127)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the package importable
_PKG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PKG))

from models.system import RemoteUIConnectedRequest, TransportType


def test_form_factor_defaults_to_round_for_backcompat():
    """Older udev rules that don't send form_factor must keep working."""
    req = RemoteUIConnectedRequest(
        transport=TransportType.OTG,
        peer="10.55.0.2",
    )
    assert req.form_factor == "round"


def test_form_factor_accepts_round():
    req = RemoteUIConnectedRequest(
        transport=TransportType.OTG,
        peer="10.55.0.2",
        form_factor="round",
    )
    assert req.form_factor == "round"


def test_form_factor_accepts_square():
    req = RemoteUIConnectedRequest(
        transport=TransportType.OTG,
        peer="10.55.0.2",
        form_factor="square",
    )
    assert req.form_factor == "square"


def test_form_factor_rejects_unknown_value():
    with pytest.raises(ValueError):
        RemoteUIConnectedRequest(
            transport=TransportType.OTG,
            peer="10.55.0.2",
            form_factor="oval",
        )
```

- [ ] **Step 2: Run the test to confirm it fails**

```bash
cd packages/secubox-system
python3 -m pytest tests/test_remote_ui_form_factor.py -v
```

Expected: tests fail with `AttributeError: ... 'form_factor'` or `validation error: unexpected field`.

- [ ] **Step 3: Add the field to the Pydantic model**

Edit `packages/secubox-system/models/system.py`. Find the `RemoteUIConnectedRequest` class (search for `class RemoteUIConnectedRequest`) and add:

```python
from typing import Literal

class RemoteUIConnectedRequest(BaseModel):
    """
    Payload sent by `secubox-otg-host-up.sh` when a Remote UI device attaches.
    """

    transport: TransportType = Field(
        description="Transport type (otg or wifi)",
    )
    peer: str = Field(
        description="Peer IP address of the Remote UI device",
    )
    interface: str | None = Field(
        default=None,
        description="Network interface name (optional)",
    )
    form_factor: Literal["round", "square"] = Field(
        default="round",
        description="Eye Remote form factor — 'round' (Pi Zero W + HyperPixel 2.1 Round) "
                    "or 'square' (Pi 4B/400 + 7\" 800x480). Defaults to 'round' for "
                    "backward compatibility with udev rules that pre-date Phase 1.",
        json_schema_extra={"example": "square"},
    )
```

- [ ] **Step 4: Run the test to confirm it passes**

```bash
cd packages/secubox-system
python3 -m pytest tests/test_remote_ui_form_factor.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Store form_factor on the manager state**

Edit `packages/secubox-system/core/remote_ui.py`. Find `on_connected(...)` and extend the signature:

```python
def on_connected(
    self,
    transport: str,
    peer: str,
    interface: str | None = None,
    form_factor: str = "round",
) -> None:
    """Record an incoming Remote UI connection. form_factor distinguishes round/square."""
    self.state.connected = True
    self.state.transport = transport
    self.state.peer = peer
    self.state.interface = interface
    self.state.form_factor = form_factor
    # … existing body …
```

Add `form_factor: str = "round"` to the `RemoteUIState` dataclass too (find its definition in the same file).

Update the API router at `packages/secubox-system/api/routers/remote_ui.py` `remote_ui_connected(...)` to pass `form_factor=request.form_factor` through to `manager.on_connected(...)`.

- [ ] **Step 6: Smoke-test the endpoint**

```bash
# Assumes the API is running on localhost:8000 with a dev JWT in /tmp/dev.jwt
curl -fsS -X POST http://localhost:8000/api/v1/remote-ui/connected \
    -H "Content-Type: application/json" \
    -d '{"transport":"otg","peer":"10.55.0.2","form_factor":"square"}' \
    | python3 -m json.tool
```

Expected: `{"success": true, ..., "transport": "otg", ...}` with no validation error.

- [ ] **Step 7: Commit**

```bash
git add packages/secubox-system/models/system.py \
        packages/secubox-system/core/remote_ui.py \
        packages/secubox-system/api/routers/remote_ui.py \
        packages/secubox-system/tests/test_remote_ui_form_factor.py
git commit -m "feat(secubox-system): add form_factor to RemoteUIConnectedRequest (ref #127)"
```

---

## Task 14: Update `round/deploy.sh` to bundle `common/`

**Files:**
- Modify: `remote-ui/round/deploy.sh`

- [ ] **Step 1: Read the existing rsync/scp invocation**

```bash
grep -nE "rsync|scp" remote-ui/round/deploy.sh
```

- [ ] **Step 2: Extend the file list to include `../common/`**

Modify the rsync (or scp) block so it ships both `remote-ui/round/` AND `remote-ui/common/` to `/var/www/secubox-round/` on the device. The HTML `<link href="../common/...">` resolves correctly because both directories exist under `/var/www/secubox-round/` after deployment.

Example diff:

```bash
# Before
rsync -avz "$REPO_ROOT/remote-ui/round/" "$SSH_TARGET:/var/www/secubox-round/"

# After
rsync -avz "$REPO_ROOT/remote-ui/common/" "$SSH_TARGET:/var/www/secubox-common/"
rsync -avz "$REPO_ROOT/remote-ui/round/"  "$SSH_TARGET:/var/www/secubox-round/"
```

And update the `<link>`/`<script>` `href`/`src` from `../common/...` to a path that resolves under the deployed layout. Simplest is to keep `../common/...` and put the two directories as siblings on the device under `/var/www/`:

```
/var/www/
├── secubox-common/      ← deployed from remote-ui/common/
└── secubox-round/       ← deployed from remote-ui/round/
    └── index.html       references ../secubox-common/css/palette.css
```

Update the `href` paths in `round/index.html` accordingly OR copy `common/` INTO `round/common/` at deploy time (uglier but no path-rewrite needed). Choose the simpler option for this codebase — likely the copy-into approach:

```bash
rsync -avz "$REPO_ROOT/remote-ui/round/"  "$SSH_TARGET:/var/www/secubox-round/"
rsync -avz "$REPO_ROOT/remote-ui/common/" "$SSH_TARGET:/var/www/secubox-round/common/"
```

Then the `<link href="common/css/palette.css">` resolves cleanly. Edit `round/index.html` accordingly if you take this path.

- [ ] **Step 3: Shellcheck**

```bash
shellcheck remote-ui/round/deploy.sh
```

Expected: no new warnings.

- [ ] **Step 4: Commit**

```bash
git add remote-ui/round/deploy.sh remote-ui/round/index.html
git commit -m "feat(remote-ui/round): deploy.sh bundles common/ alongside round/ (ref #127)"
```

---

## Task 15: Update `round/build-eye-remote-image.sh` to embed `common/`

**Files:**
- Modify: `remote-ui/round/build-eye-remote-image.sh`

- [ ] **Step 1: Read the existing chroot-payload section**

```bash
grep -nE "cp -r|rsync|/var/www" remote-ui/round/build-eye-remote-image.sh
```

- [ ] **Step 2: Add a `cp -r ../common/` invocation alongside the existing round/ payload step**

```bash
# Existing
cp -r "$REPO_ROOT/remote-ui/round/" "${ROOTFS}/var/www/secubox-round/"

# Add
cp -r "$REPO_ROOT/remote-ui/common/" "${ROOTFS}/var/www/secubox-round/common/"
```

Mirror Task 14's chosen path layout.

- [ ] **Step 3: Shellcheck**

```bash
shellcheck remote-ui/round/build-eye-remote-image.sh
```

- [ ] **Step 4: Commit**

```bash
git add remote-ui/round/build-eye-remote-image.sh
git commit -m "feat(remote-ui/round): build-eye-remote-image.sh embeds common/ in rootfs (ref #127)"
```

---

## Task 16: Update `round/README.md` and `round/CLAUDE.md` to reference `common/`

**Files:**
- Modify: `remote-ui/round/README.md`
- Modify: `remote-ui/round/CLAUDE.md`
- Modify: `remote-ui/README.md`

- [ ] **Step 1: Read the existing module table in `remote-ui/README.md`**

```bash
sed -n '1,30p' remote-ui/README.md
```

- [ ] **Step 2: Add a `common/` entry**

```markdown
| Module | Description | Hardware |
|--------|-------------|----------|
| **common/** | Shared core (JS/CSS/icons/shell) consumed by round/ + square/ | hardware-independent |
| **round/** | Eye Remote Dashboard | HyperPixel 2.1 Round + Pi Zero W |
| **square/** | Planned: Pi 4B/400 + 7" 800×480 (see issue #127) | hardware-specific |
```

- [ ] **Step 3: Update `remote-ui/round/CLAUDE.md` § 2 "Stack technique"**

Replace the file-tree snippet under "Frontend (remote-ui/round/index.html)" to indicate the dependency on `../common/`:

```
HTML5 + Canvas API + CSS3
Consumes ../common/{css/palette.css, css/base.css, js/icons.js, js/modules-table.js,
                    js/jwt-helper.js, js/transport-manager.js, js/sim.js}
Round-specific: RINGS[], drawRings(), updateDOM(), updateClock(), podTap(), init()
Zéro framework, zéro CDN, zéro dépendance externe
```

- [ ] **Step 4: Update `remote-ui/round/README.md`'s "Architecture" section to mention the dependency**

Add a sentence near "## Architecture" stating that round/'s code reuses `../common/` for JS/CSS/icons/shell, and that Phase 2 will add a sibling `../square/` consuming the same core.

- [ ] **Step 5: Commit**

```bash
git add remote-ui/README.md remote-ui/round/README.md remote-ui/round/CLAUDE.md
git commit -m "docs(remote-ui): document common/ dependency in round/ docs (ref #127)"
```

---

## Task 17: Regression — existing pytest suite stays green

**Files:**
- Run: `pytest` against the secubox-system test directory

- [ ] **Step 1: Run the full secubox-system suite**

```bash
cd packages/secubox-system
python3 -m pytest -v --tb=short
```

Expected: 100% pass (including the new `test_remote_ui_form_factor.py` from Task 13).

If any existing test fails, the form_factor or remote_ui.py edits broke something. Bisect by `git diff HEAD~N` and fix.

- [ ] **Step 2: Run the wider repo pytest if it exists**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/127-*
python3 -m pytest tests/ -v --tb=short 2>&1 | tail -40
```

Expected: pre-existing tests stay green. New failures are blockers — investigate before continuing.

- [ ] **Step 3: Save a snapshot of the test result**

```bash
python3 -m pytest packages/secubox-system tests/ -v 2>&1 | tee /tmp/127-pytest.log
git add /tmp/127-pytest.log || true  # only commit if you want it under VCS; usually skip
```

No commit needed here — this task is a gate, not a code change.

---

## Task 18: Regression — diffoscope on the round/ image build

**Files:**
- Run: `bash remote-ui/round/build-eye-remote-image.sh`
- Run: `diffoscope <old image> <new image>`

- [ ] **Step 1: Locate or rebuild the v2.2.1 reference image**

```bash
ls -la /tmp/secubox-eye-remote_*.img.xz 2>/dev/null
# If absent, switch to master TEMPORARILY and rebuild
git stash
git checkout master
sudo bash remote-ui/round/build-eye-remote-image.sh
mv /tmp/secubox-eye-remote_*.img.xz /tmp/round-master.img.xz
git checkout -
git stash pop
```

- [ ] **Step 2: Build the post-refactor image on the feature branch**

```bash
sudo bash remote-ui/round/build-eye-remote-image.sh
mv /tmp/secubox-eye-remote_*.img.xz /tmp/round-phase1.img.xz
```

- [ ] **Step 3: Run diffoscope**

```bash
sudo apt-get install -y diffoscope
diffoscope --max-page-size 100000 --html /tmp/round-diffoscope.html \
    /tmp/round-master.img.xz /tmp/round-phase1.img.xz
echo "Exit: $?"
ls -la /tmp/round-diffoscope.html
```

Expected: diffoscope returns 0 (identical) OR returns 1 with deltas limited to:
- File modification timestamps (`mtime`)
- Build-host hostname embedded in build logs
- Compression headers (xz timestamp byte)

Any structural difference (different files present, different file sizes for known files, different shell-script SHAs) is a Phase 1 regression — investigate before continuing.

- [ ] **Step 4: Save the diffoscope report**

```bash
cp /tmp/round-diffoscope.html docs/superpowers/specs/2026-05-13-phase1-diffoscope.html
git add docs/superpowers/specs/2026-05-13-phase1-diffoscope.html
git commit -m "docs(remote-ui): diffoscope evidence for Phase 1 round/ image equivalence (ref #127)"
```

---

## Task 19: Regression — manual Zero W bench test

**Files:**
- None modified; manual verification only

- [ ] **Step 1: Flash the new image to a spare SD card**

```bash
xzcat /tmp/round-phase1.img.xz | sudo dd of=/dev/<your-spare-SD> bs=4M status=progress conv=fsync
sudo sync
```

⚠️ Verify `<your-spare-SD>` is not the system disk before running. The script refuses `/dev/sda`, `/dev/nvme0n1`, `/dev/mmcblk0` by convention.

- [ ] **Step 2: Boot the Zero W test bench**

Insert the SD card into the Zero W bench (board reachable at `192.168.1.200` via existing memory note about board SSH access). Power up, wait ~90s for first boot.

- [ ] **Step 3: SSH to the board and verify the dashboard renders**

```bash
ssh root@192.168.1.200 'systemctl status secubox-fb-dashboard --no-pager'
ssh root@192.168.1.200 'curl -fsS http://localhost:8080/ | grep -c "common/js/transport-manager.js"'
```

Expected: dashboard service active; the index.html reference count for `common/js/transport-manager.js` is `1` (file is being served correctly).

- [ ] **Step 4: Visual confirmation**

Look at the actual HyperPixel screen. The dashboard must render identically to v2.2.1: six rings, six pods, central clock, transport badge, status row, temperature bar.

Take a photo with your phone if you want a quick visual record — no commit needed.

- [ ] **Step 5: Reconnect to OTG (if available)**

Plug the Zero W into the MOCHAbin host. Verify:

```bash
ssh root@192.168.1.200 'cat /sys/kernel/config/usb_gadget/secubox-round/UDC'
```

Expected: a non-empty UDC binding (gadget enumerated).

```bash
# On the MOCHAbin host:
curl -fsS http://localhost:8000/api/v1/remote-ui/status | python3 -m json.tool
```

Expected: `connected: true`, `transport: "otg"`, peer `10.55.0.2`. With Task 13's form_factor field, the response or its underlying state must NOT crash on the missing-form-factor case (the default-to-round behaviour).

If any step fails, record the failure mode and revert the offending commit before opening the PR.

---

## Task 20: Open the PR

**Files:**
- Existing branch in worktree

- [ ] **Step 1: Push the branch**

```bash
git push -u origin "$(git rev-parse --abbrev-ref HEAD)"
```

- [ ] **Step 2: Open the PR via gh**

```bash
gh pr create --title "feat(remote-ui): Phase 1 — extract common/ shared core (ref #127)" \
  --body "$(cat <<'EOF'
## Summary

Phase 1 of [#127](https://github.com/CyberMind-FR/secubox-deb/issues/127). Mechanical
extraction of round/'s shared core into `remote-ui/common/`, plus two additive changes:
- `TransportManager.onModuleTap` and `.onTransportChange` no-op hooks (so square/'s
  WebSocket bridge can override them in Phase 2)
- `RemoteUIConnectedRequest.form_factor` Pydantic field (default `"round"` for
  backward compatibility with the unchanged udev rule on existing hosts)

Round/ behaviour is preserved bit-for-bit: existing pytest suite green, `diffoscope`
shows only timestamp deltas on the rebuilt image, manual Zero W bench renders identically.

## What changed

- New `remote-ui/common/{js,css,assets/icons,shell}/` consumed by round/
- `remote-ui/round/index.html` now references common/ via `<link>` and `<script>` tags
  (no inline `<style>`/constants any more)
- 24 SecuBox module PNG icons moved to `common/assets/icons/` (radial-menu icons stay
  in round/)
- `secubox-otg-gadget.sh` and `secubox-otg-host-up.sh` now live in `common/shell/`
  with a `VARIANT` parameter; round/ retains them as symlinks
- `RemoteUIConnectedRequest.form_factor` added to the Pydantic model
- `round/deploy.sh` and `round/build-eye-remote-image.sh` bundle `common/` alongside
  `round/` for both hot-deploy and image builds

## Test plan

- [x] `pytest packages/secubox-system/` — 100% green, includes new
  `test_remote_ui_form_factor.py` (4 cases)
- [x] `diffoscope` v2.2.1 vs Phase 1 image — only timestamp deltas
  ([report](docs/superpowers/specs/2026-05-13-phase1-diffoscope.html))
- [x] `shellcheck` clean on `common/shell/*.sh` and modified `round/*.sh`
- [x] Manual Zero W bench (`ssh root@192.168.1.200`) renders identical dashboard,
  OTG gadget enumerates on MOCHAbin host, `/api/v1/remote-ui/status` reports
  `connected=true, transport=otg`

## Out of scope

- Phase 2 (`remote-ui/square/` new variant) — separate PR after this lands

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Closes part of #127.
EOF
)"
```

- [ ] **Step 3: Comment on issue #127**

```bash
PR_URL=$(gh pr view --json url -q .url)
gh issue comment 127 --body "Phase 1 PR opened: $PR_URL"
```

- [ ] **Step 4: Update `.claude/WIP.md`**

In the main checkout (`~/CyberMindStudio/secubox-deb/secubox-deb`), edit the entry for issue #127 and move the "design phase" bullet to ✅, add a new "Phase 1 PR opened, pending merge" bullet. Then commit on master (single-file tracking update is allowed without a worktree per the project rules).

---

## Self-review checklist

1. **Spec coverage:** Every Phase-1 bullet from issue #127 maps to a task: common/ skeleton (Task 1), TransportManager + jwt-helper + modules-table + sim (Tasks 4-8), palette + base CSS (Tasks 2-3), icons (Task 9), shell scripts (Tasks 10-11), round/ rewire (Task 12), form_factor field (Task 13), deploy.sh + image build (Tasks 14-15), README/CLAUDE.md (Task 16), three regression gates (Tasks 17-19), PR (Task 20). ✓
2. **Placeholder scan:** No "TBD", "TODO", "fill in later", "Similar to Task N" remain. Every code block is concrete. Where the actual round/ implementation differs from the contract I show (e.g. `JWT_HELPER.login` body), the plan instructs to use the actual round/ values verbatim. ✓
3. **Type consistency:** `RemoteUIConnectedRequest`, `RemoteUIState`, `form_factor` literal values (`"round" | "square"`) are consistent across Tasks 13 and 19. `VARIANT` shell parameter is consistent across Tasks 10 and 11. ✓
4. **Ambiguity:** Task 14's path-layout decision (siblings vs nested copy) is flagged for resolution at implementation time, with a recommended option. Acceptable for a refactor whose end-state is timestamp-equivalent. ✓
