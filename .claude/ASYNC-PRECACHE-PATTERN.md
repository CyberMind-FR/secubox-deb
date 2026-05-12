<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Async Pre-Cache Pattern — Development Design

## SecuBox Health-Aware Navigation Architecture

**Version**: 1.0.0
**Author**: CyberMind / Gérald Kerma
**Pattern Name**: Asynchronous Over-Chronous Pre-Cache (AOPC)

---

## Philosophy

> "Pre-cache for speed, refresh for truth."

Two complementary layers working asynchronously over time:

| Layer | Purpose | Speed | Accuracy | Blocking |
|-------|---------|-------|----------|----------|
| **Pre-cache** | Instant UX | Fast (0ms) | Stale (≤TTL) | Never |
| **Refresh** | Ground truth | Slow (100-4000ms) | Real-time | Never |

---

## Core Principles

### 1. Optimistic Display
```
User experience > Perfect accuracy
Show something immediately, correct it later
```

### 2. Non-Blocking Everything
```
No await on critical path
Background tasks update UI progressively
```

### 3. Graceful Degradation
```
Missing endpoint → Fallback check
Timeout → Use cached value
Error → Show last known state
```

### 4. Per-Item Timestamps
```
Each module has its own staleness clock
Refresh only what's stale, not everything
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        PAGE LOAD                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 1: PRE-CACHE (Synchronous Read)                          │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  localStorage.getItem('health_cache')                    │    │
│  │  ├─ Parse JSON                                           │    │
│  │  ├─ Filter by TTL (discard expired modules)              │    │
│  │  └─ Return valid cached health states                    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  INSTANT RENDER                                          │    │
│  │  └─ Display LEDs from pre-cache (T=0ms)                  │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ (non-blocking)
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 2: REFRESH (Asynchronous Background)                     │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Promise.allSettled(modules.map(checkHealth))            │    │
│  │  ├─ Each module checks independently                     │    │
│  │  ├─ Timeout: 4s per module                               │    │
│  │  ├─ Fallback: HEAD request to module page                │    │
│  │  └─ Update LED as each result arrives                    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  PROGRESSIVE UPDATE                                      │    │
│  │  ├─ LED updates individually (T=100-4000ms)              │    │
│  │  ├─ Sort order updates after batch complete              │    │
│  │  └─ Save new timestamps to pre-cache                     │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ (interval: 30s)
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 3: STALE REFRESH (Periodic Background)                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  For each module:                                        │    │
│  │  ├─ Check timestamp age                                  │    │
│  │  ├─ If age > REFRESH_INTERVAL → Re-check                 │    │
│  │  └─ Skip fresh modules (bandwidth efficient)             │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Data Structures

### Pre-Cache Schema (localStorage)

```javascript
{
  "module_name": {
    "status": "ok" | "warn" | "error" | "unknown",
    "msg": "Human readable message",
    "data": { /* optional extra data */ },
    "timestamp": 1778237632000,  // Per-module timestamp
    "fallback": true | false     // Was this from page check?
  },
  ...
}
```

### Constants

```javascript
const HEALTH_CACHE_KEY = 'sbx_health_cache';
const HEALTH_CACHE_TTL = 120000;        // 2 minutes max staleness
const HEALTH_REFRESH_INTERVAL = 30000;  // 30s between refreshes
const HEALTH_REQUEST_TIMEOUT = 4000;    // 4s per module timeout
```

---

## Implementation Patterns

### Pattern 1: Instant Pre-Cache Load

```javascript
function loadPreCache() {
    try {
        const cached = localStorage.getItem(HEALTH_CACHE_KEY);
        if (!cached) return null;

        const data = JSON.parse(cached);
        const now = Date.now();
        const valid = {};

        for (const mod in data) {
            const age = now - (data[mod].timestamp || 0);
            if (age < HEALTH_CACHE_TTL) {
                valid[mod] = data[mod];
            }
        }

        return Object.keys(valid).length > 0 ? valid : null;
    } catch (e) {
        return null;
    }
}
```

### Pattern 2: Non-Blocking Health Check

```javascript
async function checkModuleHealth(mod) {
    const endpoint = MODULE_HEALTH[mod];

    // Prevent duplicate concurrent checks
    if (inProgress[mod]) {
        return cache[mod] || { status: 'checking' };
    }
    inProgress[mod] = true;

    try {
        const ctrl = new AbortController();
        const timeout = setTimeout(() => ctrl.abort(), TIMEOUT);

        const res = await fetch(endpoint, { signal: ctrl.signal });
        clearTimeout(timeout);

        if (res.ok) {
            const data = await res.json();
            return { status: data.status, timestamp: Date.now() };
        }

        // 404 = No health endpoint, try fallback
        if (res.status === 404) {
            return await checkPageFallback(mod);
        }

        return { status: 'error', msg: 'HTTP ' + res.status };
    } catch (e) {
        if (e.name === 'AbortError') {
            return await checkPageFallback(mod);
        }
        return { status: 'error', msg: 'Failed' };
    } finally {
        inProgress[mod] = false;
    }
}
```

### Pattern 3: Fallback Page Check

```javascript
async function checkPageFallback(mod) {
    const page = '/' + mod + '/';

    try {
        const res = await fetch(page, {
            method: 'HEAD',
            timeout: 2000
        });

        if (res.ok || res.status === 401) {
            // Page exists (401 = needs auth but exists)
            return {
                status: 'ok',
                msg: 'Page accessible',
                fallback: true
            };
        }
        return { status: 'unknown', msg: 'No health API' };
    } catch (e) {
        return { status: 'unknown', msg: 'Unreachable' };
    }
}
```

### Pattern 4: Stale-Only Refresh

```javascript
async function refreshStaleHealth() {
    const now = Date.now();
    const stale = [];

    // Identify stale modules only
    for (const mod in MODULE_HEALTH) {
        const cached = healthCache[mod];
        const age = now - (cached?.timestamp || 0);
        if (age > REFRESH_INTERVAL) {
            stale.push(mod);
        }
    }

    if (stale.length === 0) return;

    // Refresh stale modules in parallel
    await Promise.allSettled(stale.map(async (mod) => {
        const result = await checkModuleHealth(mod);
        healthCache[mod] = result;

        // Update UI immediately as each result arrives
        updateSingleLED(mod, result);
    }));

    // Persist to pre-cache
    savePreCache(healthCache);
}
```

### Pattern 5: Progressive LED Update

```javascript
function updateSingleLED(mod, health) {
    const item = document.querySelector(`[data-module="${mod}"]`);
    const led = item?.querySelector('.status-led');
    if (!led) return;

    // Update LED emoji
    led.textContent = LED_EMOJI[health.status] || '⚫';
    led.title = health.msg;

    // Animate if status changed significantly
    if (health.status === 'ok' && item.classList.contains('offline')) {
        item.classList.add('reappear');
        setTimeout(() => item.classList.remove('reappear'), 600);
    }
}
```

---

## Timeline Example

```
T=0ms      Page loads
           └─ Pre-cache read: {hub: ok, waf: ok, system: warn} (30s old)
           └─ LEDs display: 🟢 🟢 🟡

T=10ms     Background refresh starts (non-blocking)
           └─ fetch('/api/v1/hub/health')
           └─ fetch('/api/v1/waf/health')
           └─ fetch('/api/v1/system/health')

T=150ms    Hub responds first
           └─ LED updates: 🟢 (confirmed)

T=800ms    WAF responds
           └─ LED updates: 🟢 (confirmed)

T=2500ms   System responds (slow)
           └─ LED updates: 🟢 (was warn, now ok!)

T=30000ms  Stale refresh cycle
           └─ Check: hub (age: 30s) → refresh
           └─ Skip: waf (age: 29s) → still fresh
           └─ Skip: system (age: 27s) → still fresh
```

---

## Error Handling Matrix

| Scenario | Pre-Cache | Refresh | Result |
|----------|-----------|---------|--------|
| Fresh cache, API ok | ✅ Show cached | ✅ Confirm | 🟢 Instant + verified |
| Fresh cache, API timeout | ✅ Show cached | ⚠️ Fallback | 🟢 Cached (may be stale) |
| Fresh cache, API 404 | ✅ Show cached | ⚠️ Page check | 🟢 or ⚫ depends on page |
| Stale cache, API ok | ⚠️ Show stale | ✅ Update | 🟢 Corrected |
| No cache, API ok | ⚫ Show unknown | ✅ Update | 🟢 Discovered |
| No cache, API fail | ⚫ Show unknown | ❌ Fallback | ⚫ or 🔴 |

---

## Benefits

1. **Zero perceived latency** — User sees status instantly
2. **Eventually consistent** — Truth arrives within seconds
3. **Bandwidth efficient** — Only refresh stale items
4. **Fault tolerant** — Graceful fallbacks at every layer
5. **Progressive enhancement** — Works even with missing APIs

---

## Anti-Patterns to Avoid

```javascript
// ❌ BAD: Blocking wait for all health checks
const health = await Promise.all(modules.map(check));
renderSidebar(health);  // User waits 4+ seconds

// ✅ GOOD: Pre-cache first, refresh in background
const cached = loadPreCache();
renderSidebar(cached);  // Instant
checkAllHealth().then(updateLEDs);  // Background
```

```javascript
// ❌ BAD: Single timestamp for entire cache
cache = { data: {...}, timestamp: Date.now() }

// ✅ GOOD: Per-module timestamps
cache = {
  hub: { status: 'ok', timestamp: T1 },
  waf: { status: 'ok', timestamp: T2 }  // Different freshness
}
```

```javascript
// ❌ BAD: Refresh everything every cycle
setInterval(() => checkAllModules(), 30000);

// ✅ GOOD: Refresh only stale modules
setInterval(() => refreshStaleOnly(), 30000);
```

---

## Integration Points

### Sidebar Navigation
- Pre-cache on page load
- Background refresh on mount
- Interval refresh every 30s
- LED updates as results arrive

### Module Dashboards
- Can contribute to shared pre-cache
- Read pre-cache for cross-module status
- Push updates to cache on local health changes

### Error Pages
- Read pre-cache to show system status
- Trigger refresh to verify current state

---

## Future Extensions

1. **WebSocket layer** — Real-time push updates
2. **Service Worker** — Offline-first caching
3. **Shared Worker** — Cross-tab cache synchronization
4. **IndexedDB** — Larger cache with history

---

*This pattern enables instant UI responsiveness while maintaining factual accuracy through asynchronous background verification.*
