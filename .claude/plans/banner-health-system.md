<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Plan: Banner Injector + Health Status System

## Overview
Global health monitoring banner system with smart doctor diagnostics,
touchscreen-optimized borders, and double-buffered caching.

## Components

### 1. Health Banner (sidebar-injected)
```
┌─────────────────────────────────────────────────────┐
│ 🩺 SYSTEM HEALTH ████████░░ 82%  │ 🔴 WAF │ 🟢 CS │
└─────────────────────────────────────────────────────┘
```

**Location:** Top/bottom of every page via sidebar.js injection
**Data:** Aggregated from all module `/health` endpoints

### 2. Smart Doctor Advisor
- Analyzes health metrics across modules
- Generates contextual advice: "WAF blocking 23% traffic - review rules"
- Priority levels: critical, warning, info
- Auto-dismissing notifications with delayed animations

### 3. Touch Screen Borders
- Edge-triggered panels (swipe from left/right/top/bottom)
- Delayed reveal animations (200ms hover before show)
- One-screen piping (content flows between edge panels)

### 4. Double-Buffer Cache Architecture
```
┌──────────────────┐      ┌──────────────────┐
│   ACTIVE CACHE   │◄────►│   SHADOW CACHE   │
│  (read-only)     │      │  (write buffer)  │
└──────────────────┘      └──────────────────┘
         │                         │
         ▼                         ▼
    Sync readers              Async writers
    (UI render)               (API fetchers)
```

**Lock mechanism:** Prevents overloop escapes during swap

### 5. Metrics Collector
- Background fetch from all module APIs
- Aggregation by category (security, network, system)
- Trend analysis (last 5min, 1h, 24h)

## Implementation Files

| File | Purpose |
|------|---------|
| `www/shared/health-banner.js` | Banner component + injection |
| `www/shared/doctor-advisor.js` | Smart diagnostics engine |
| `www/shared/touch-borders.js` | Edge panel system |
| `www/shared/cache-buffer.js` | Double-buffer with locks |
| `packages/secubox-metrics/api/main.py` | Aggregation API |

## API Endpoints

```
GET /api/v1/metrics/health/all     → All modules health
GET /api/v1/metrics/health/summary → Aggregated score
GET /api/v1/metrics/advisor        → Doctor recommendations
GET /api/v1/metrics/trends         → Historical data
```

## Banner Injection (sidebar.js)

```javascript
// Inject health banner at page load
function injectHealthBanner() {
    const banner = document.createElement('div');
    banner.id = 'health-banner';
    banner.className = 'health-banner collapsed';
    document.body.insertBefore(banner, document.body.firstChild);

    // Double-buffer: read from active cache
    const health = window._healthCache?.active || {};
    renderBanner(banner, health);

    // Async: update shadow cache
    fetchHealthData().then(data => {
        window._healthCache.shadow = data;
        if (!window._healthCache.locked) {
            swapCacheBuffers();
        }
    });
}
```

## Touch Border Panels

```css
.touch-border-left {
    position: fixed;
    left: -280px;
    width: 300px;
    height: 100vh;
    transition: left 0.3s ease;
}
.touch-border-left.reveal {
    left: 0;
}
```

## Doctor Advisor Rules

```javascript
const DOCTOR_RULES = [
    {
        condition: (h) => h.waf?.blocked_pct > 20,
        severity: 'warning',
        message: 'WAF blocking {pct}% of traffic - review rules',
        action: '/waf/#rules'
    },
    {
        condition: (h) => h.crowdsec?.decisions > 100,
        severity: 'info',
        message: '{count} active bans - check CrowdSec dashboard',
        action: '/crowdsec/'
    },
    {
        condition: (h) => h.system?.cpu > 80,
        severity: 'critical',
        message: 'CPU at {cpu}% - check processes',
        action: '/system/#processes'
    }
];
```

## Synchronous Master Pattern

```javascript
// Master coordinator for async callers
class HealthMaster {
    constructor() {
        this.activeBuffer = {};
        this.shadowBuffer = {};
        this.locked = false;
        this.subscribers = [];
    }

    // Sync read (immediate, from active)
    read() {
        return this.activeBuffer;
    }

    // Async write (to shadow, non-blocking)
    async write(module, data) {
        this.shadowBuffer[module] = data;
        this.notifySubscribers();
    }

    // Atomic swap with lock
    swap() {
        if (this.locked) return false;
        this.locked = true;
        [this.activeBuffer, this.shadowBuffer] =
            [this.shadowBuffer, this.activeBuffer];
        this.locked = false;
        return true;
    }
}
```

## Phase 1: Core Banner
- [ ] Create health-banner.js
- [ ] Add banner CSS to sidebar.css
- [ ] Inject via sidebar.js
- [ ] Fetch /health from all modules

## Phase 2: Doctor Advisor
- [ ] Create doctor-advisor.js
- [ ] Define rule engine
- [ ] Add notification UI
- [ ] Contextual action links

## Phase 3: Touch Borders
- [ ] Create touch-borders.js
- [ ] Edge detection handlers
- [ ] Delayed reveal animations
- [ ] Panel content routing

## Phase 4: Double-Buffer Cache
- [ ] Create cache-buffer.js
- [ ] Lock mechanism
- [ ] Swap coordination
- [ ] Overloop escape protection
