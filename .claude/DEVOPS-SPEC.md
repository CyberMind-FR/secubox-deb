# SecuBox DevOps Dashboard Specification
*Created: 2026-03-21*

---

## Design Principles

**LIGHTWEIGHT & EFFICIENT:**
- Vanilla JavaScript only (no heavy frameworks)
- Static HTML with minimal API calls
- Server-side caching (JSON files, not real-time DB)
- Lazy loading, no unnecessary computations
- Single-file dashboards when possible
- < 100KB total page weight
- Works offline after first load

---

## Overview

A comprehensive development dashboard for tracking SecuBox migration progress between:
- **Source**: `secubox-openwrt` (OpenWrt LuCI packages)
- **Target**: `secubox-deb` (Debian bookworm FastAPI packages)

---

## Features Required

### 1. Repository Comparison Widget
- Side-by-side view of modules in both repos
- Migration status: ⬜ Pending, 🔄 In Progress, ✅ Complete
- Code line counts (RPCD shell → FastAPI Python)
- API endpoint counts per module

### 2. Historical Progress Graphs
- Migration timeline chart (modules completed over time)
- Lines of code migrated per week
- Commit activity comparison between repos
- Burndown chart for remaining modules

### 3. Commit Synchronization
- Track commits in secubox-openwrt that need porting
- Link related commits across repos
- Show delta: changes in source not yet in target
- Auto-detect new features/fixes to port

### 4. Voting & Priority System
- Vote on module migration priority
- Adaptive ranking based on:
  - Dependencies (required by other modules)
  - Complexity score
  - User demand
  - Security impact
- Cumulative priority score per module

### 5. Responsive WebUI Design Principles
```css
/* Mobile-first responsive design */
:root {
  --breakpoint-sm: 576px;
  --breakpoint-md: 768px;
  --breakpoint-lg: 992px;
  --breakpoint-xl: 1200px;
}

/* Grid system */
.container { max-width: 100%; padding: 0 1rem; }
@media (min-width: 768px) { .container { max-width: 720px; } }
@media (min-width: 992px) { .container { max-width: 960px; } }
@media (min-width: 1200px) { .container { max-width: 1140px; } }

/* Flex layouts for adaptive content */
.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1rem;
}

/* Touch-friendly targets */
.btn, .form-input { min-height: 44px; }

/* Collapsible sidebar for mobile */
@media (max-width: 768px) {
  .sidebar { position: fixed; transform: translateX(-100%); }
  .sidebar.open { transform: translateX(0); }
}
```

---

## Implementation Plan

### Phase 1: Data Collection Module
```python
# secubox-devops/api/main.py

@router.get("/modules/comparison")
async def compare_modules():
    """Compare modules between secubox-openwrt and secubox-deb."""
    openwrt_modules = scan_openwrt_packages()
    deb_modules = scan_deb_packages()
    return {
        "source_count": len(openwrt_modules),
        "target_count": len(deb_modules),
        "migrated": len(set(openwrt_modules) & set(deb_modules)),
        "pending": list(set(openwrt_modules) - set(deb_modules)),
        "modules": merge_comparison(openwrt_modules, deb_modules)
    }

@router.get("/commits/delta")
async def commit_delta():
    """Show commits in source not yet reflected in target."""
    # Parse git logs from both repos
    # Match related commits
    # Return delta
    pass

@router.get("/stats/history")
async def migration_history():
    """Historical migration progress data."""
    # Read from .claude/MIGRATION-MAP.md history
    # Parse git commit dates for module completions
    # Return time-series data
    pass
```

### Phase 2: Voting System
```python
class VoteRequest(BaseModel):
    module: str
    priority: int  # 1-5
    reason: Optional[str] = None

@router.post("/modules/{module}/vote")
async def vote_module(module: str, req: VoteRequest, user=Depends(require_jwt)):
    """Vote on module migration priority."""
    votes = load_votes()
    votes[module] = votes.get(module, [])
    votes[module].append({
        "user": user["sub"],
        "priority": req.priority,
        "reason": req.reason,
        "timestamp": datetime.now().isoformat()
    })
    save_votes(votes)
    return calculate_priority_score(module, votes)
```

### Phase 3: Dashboard UI
- Responsive sidebar with hamburger menu on mobile
- Card-based module display
- Chart.js for historical graphs
- Real-time updates via WebSocket or polling

---

## Module List for Comparison

### From secubox-openwrt (not yet in secubox-deb):
| Module | RPCD Lines | Complexity | Priority |
|--------|------------|------------|----------|
| luci-app-secubox-portal | 450 | Medium | ✅ Done |
| luci-app-device-intel | 800 | High | ⬜ |
| luci-app-vortex-dns | 600 | High | ⬜ |
| luci-app-vortex-firewall | 500 | Medium | ⬜ |
| luci-app-meshname-dns | 400 | Medium | ⬜ |
| luci-app-secubox-p2p | 550 | High | ⬜ |
| luci-app-threat-intel | 700 | High | ⬜ |
| luci-app-dns-provider | 350 | Easy | ⬜ |
| luci-app-exposure-check | 300 | Easy | ⬜ |

---

## Responsive Design Checklist

For all SecuBox WebUI modules:

- [ ] Mobile viewport meta tag
- [ ] Fluid grid layouts (no fixed widths)
- [ ] Touch-friendly buttons (min 44px)
- [ ] Collapsible sidebar on mobile
- [ ] Readable text without zooming (16px base)
- [ ] No horizontal scroll on any viewport
- [ ] Fast load time (< 3s on 3G)
- [ ] Progressive enhancement
- [ ] Dark theme by default
- [ ] Accessible contrast ratios

---

## Next Steps

1. Create `secubox-devops` module with comparison API
2. Add historical data collection from git logs
3. Implement voting system with persistent storage
4. Build responsive dashboard UI
5. Integrate with CI/CD for auto-updates
