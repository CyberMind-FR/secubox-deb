<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox-Dev Methodology
*A reusable development methodology for AI-assisted embedded system projects*

**Version:** 1.0.0
**Extracted from:** SecuBox-DEB Project (Session 88)
**Author:** CyberMind / Gérald Kerma
**License:** MIT (methodology only)

---

## Overview

SecuBox-Dev is a structured methodology for developing embedded system software with AI coding assistants. It provides:

1. **Tracking Files** — Structured project state management
2. **Session-Based Development** — Isolated work units with clear documentation
3. **Migration Patterns** — Systematic code porting with traceability
4. **Compliance Framework** — Quality gates and verification
5. **Performance Patterns** — Embedded-optimized code patterns

This methodology emerged from 88+ sessions of AI-assisted development migrating a complex embedded security platform from OpenWrt to Debian.

---

## Part 1: Project Tracking Structure

### Directory: `.claude/`

Central project state directory. Read on session start.

```
.claude/
├── WIP.md              ← Current work in progress (READ FIRST)
├── TODO.md             ← Backlog organized by phases
├── HISTORY.md          ← Change log with root cause analysis
├── PATTERNS.md         ← Code patterns with before/after examples
├── MODULE-COMPLIANCE.md ← Quality requirements checklist
├── NOTES.md            ← Temporary observations, investigation notes
└── skills/             ← Domain-specific coding guides
```

### File: `WIP.md` (Work In Progress)

**Purpose:** What's being worked on RIGHT NOW. First file to read.

**Format:**
```markdown
# WIP — Work In Progress
*Mis à jour : YYYY-MM-DD (Session XX)*

---

## ⬜ Next Up — [Feature Name]

**Goal:** One-sentence description

**Approach:**
1. Step one
2. Step two
3. Step three

---

## ✅ Complété (Session XX) — [Feature Name]

**Problem:** What was broken

**Root Cause:**
- Technical reason 1
- Technical reason 2

**Fix:**
- What was changed

**Files Modified:**
- `path/to/file.py` — Description of change

**Result:**
- Observable outcome
```

**Key Rules:**
- Only ONE item in "Next Up" at a time
- Completed items move to "Complété" with session number
- Include root cause analysis for every fix
- List all modified files

### File: `TODO.md` (Backlog)

**Purpose:** Prioritized work organized by phases.

**Format:**
```markdown
# TODO — Backlog

---

## ✅ Phase 1 — [Phase Name] (TERMINÉ)

- [x] Task completed
- [x] Another completed task

## 🔄 Phase 2 — [Phase Name] (EN COURS)

- [x] Completed task
- [ ] Pending task
- [ ] Another pending task

## ⬜ Phase 3 — [Phase Name] (À VENIR)

- [ ] Future task
```

**Status Symbols:**
| Symbol | Meaning |
|--------|---------|
| ✅ | Phase complete |
| 🔄 | Phase in progress |
| ⬜ | Phase not started |
| ⏸ | Phase blocked |

### File: `HISTORY.md` (Change Log)

**Purpose:** Detailed change history with root cause analysis.

**Format:**
```markdown
# HISTORY — Change Log

---

## Session XX — [Feature/Fix Name]
*YYYY-MM-DD*

### Goal
What we set out to accomplish.

### Problem
Symptom observed by user.

### Investigation
1. First thing checked
2. Second thing checked
3. Discovery made

### Root Cause
Technical explanation of why the problem occurred.

### Fix
What was changed to resolve it.

### Files Changed
- `path/file.py` — What changed and why
- `path/other.py` — What changed and why

### Commits
- `abc1234` feat(module): Description

### Result
Observable outcome confirming fix worked.
```

**Key Rules:**
- Every entry has a Session number
- Root cause is REQUIRED (not just "fixed it")
- List exact files changed
- Include verification result

### File: `PATTERNS.md` (Code Patterns)

**Purpose:** Reusable code patterns with source → target examples.

**Format:**
```markdown
# PATTERNS — Code Reference

---

## Pattern N — [Pattern Name]

### When to Use
Describe the situation where this pattern applies.

### Source (Before)
```language
// Original code or legacy format
```

### Target (After)
```language
// Migrated/improved code
```

### Key Transformations
- Transformation 1
- Transformation 2

### Common Mistakes
- Don't do X because Y
```

### File: `MODULE-COMPLIANCE.md` (Quality Gates)

**Purpose:** Checklist that MUST pass before marking work complete.

**Format:**
```markdown
# MODULE-COMPLIANCE — Quality Requirements

---

## Checklist

### 1. Documentation
- [ ] README.md exists with all sections
- [ ] API endpoints documented
- [ ] Configuration documented

### 2. Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual verification complete

### 3. Structure
- [ ] Directory structure matches template
- [ ] Required files present
- [ ] Naming conventions followed

### 4. Performance
- [ ] Response time < threshold
- [ ] Memory usage < limit
- [ ] No blocking operations in hot paths
```

---

## Part 2: Session-Based Development

### What is a Session?

A **session** is a bounded unit of work with:
- Single goal or closely related goals
- Clear start and end
- Documented changes
- Traceable commits

### Session Workflow

```
1. READ WIP.md → Identify current task
2. READ relevant files → Understand context
3. IMPLEMENT → Make changes
4. TEST → Verify changes work
5. UPDATE tracking files:
   - Move task to "Complété" in WIP.md
   - Add entry to HISTORY.md
   - Update TODO.md phase status
6. COMMIT → With session reference
```

### Session Numbering

Sessions are numbered sequentially (S01, S02, ..., S88, etc.)

**In commit messages:**
```
feat(module): Add feature X (Session 42)
fix(api): Resolve 500 error on /status (Session 43)
```

**In HISTORY.md:**
```markdown
## Session 43 — API 500 Error Fix
```

### Session Documentation Template

```markdown
## Session XX — [Title]
*YYYY-MM-DD*

### Goal
[One sentence]

### Changes
1. [Change 1]
2. [Change 2]

### Files
- `path/file.py` — [What changed]

### Testing
- [How verified]

### Result
- [Observable outcome]
```

---

## Part 3: Migration Patterns (Legacy → Modern)

### Pattern 1: Shell Script → Python API

**Source (Shell/UCI):**
```sh
#!/bin/sh
status() {
    json_init
    local running=0
    pgrep service >/dev/null && running=1
    json_add_boolean "running" "$running"
    json_print
}
```

**Target (FastAPI):**
```python
from fastapi import APIRouter, Depends
import subprocess

router = APIRouter()

@router.get("/status")
async def status(user=Depends(require_auth)):
    running = subprocess.run(
        ["pgrep", "service"], capture_output=True
    ).returncode == 0
    return {"running": running}
```

### Pattern 2: Config File → Structured API

**Source (UCI config):**
```
config service 'main'
    option enabled '1'
    option port '8080'
```

**Target (TOML + Pydantic):**
```python
# config.toml
[service]
enabled = true
port = 8080

# Python
from pydantic import BaseModel
import toml

class ServiceConfig(BaseModel):
    enabled: bool = True
    port: int = 8080

def get_config() -> ServiceConfig:
    data = toml.load("/etc/app/config.toml")
    return ServiceConfig(**data.get("service", {}))
```

### Pattern 3: Action Endpoint (POST)

**Source (Shell):**
```sh
restart() {
    /etc/init.d/service restart
    json_init
    json_add_boolean "success" "1"
    json_print
}
```

**Target (FastAPI):**
```python
@router.post("/restart")
async def restart(user=Depends(require_auth)):
    result = subprocess.run(
        ["systemctl", "restart", "service"],
        capture_output=True, text=True
    )
    return {
        "success": result.returncode == 0,
        "message": result.stderr if result.returncode != 0 else "OK"
    }
```

---

## Part 4: Performance Patterns (Embedded)

### Pattern: Background Cache Refresh

**Problem:** Stats endpoints block on expensive operations.

**Solution:**
```python
import asyncio
import json
from pathlib import Path

CACHE_FILE = Path("/var/cache/app/stats.json")
_cache: dict = {}

async def _refresh_cache():
    """Background task: refresh every 60s."""
    while True:
        try:
            data = await _compute_expensive_stats()
            CACHE_FILE.write_text(json.dumps(data))
            _cache.update(data)
        except Exception as e:
            log.error(f"cache refresh: {e}")
        await asyncio.sleep(60)

@app.on_event("startup")
async def startup():
    asyncio.create_task(_refresh_cache())

@router.get("/stats")
async def stats():
    return _cache or {"error": "not ready"}
```

**When to Use:**
- Dashboard statistics
- Log aggregation
- Metrics collection
- Anything reading files/subprocesses

**When NOT to Use:**
- Real-time actions (restart, ban, apply)
- User-initiated operations

### Pattern: Parallel Subprocess Execution

**Problem:** Sequential CLI calls are slow.

**Solution:**
```python
async def run_cmd(cmd: str) -> str:
    proc = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE
    )
    stdout, _ = await proc.communicate()
    return stdout.decode()

async def get_all_status():
    # Parallel execution
    results = await asyncio.gather(
        run_cmd("cmd1"),
        run_cmd("cmd2"),
        run_cmd("cmd3"),
    )
    return {"r1": results[0], "r2": results[1], "r3": results[2]}
```

### Pattern: Device-Specific Limits

```python
DEVICE_PROFILES = {
    "low-memory": {     # 1GB RAM
        "max_entries": 1000,
        "cache_ttl": 120,
    },
    "standard": {       # 4-8GB RAM
        "max_entries": 10000,
        "cache_ttl": 60,
    },
}

def get_profile() -> dict:
    board = os.environ.get("DEVICE_PROFILE", "standard")
    return DEVICE_PROFILES.get(board, DEVICE_PROFILES["standard"])
```

---

## Part 5: Compliance Verification

### Pre-Completion Checklist

Before marking ANY task complete:

```
□ Code compiles/runs without errors
□ Tests pass (unit + integration)
□ Manual verification performed
□ README updated (if API/config changed)
□ WIP.md updated (moved to Complété)
□ HISTORY.md entry added with root cause
□ Commit made with session reference
```

### Module Completion Checklist

```
□ Directory structure matches template
□ Required endpoints implemented
□ Authentication enforced
□ Health endpoint responds
□ Configuration documented
□ README complete with examples
□ No blocking operations in GET endpoints
□ Memory usage verified
```

### Debugging Template

When investigating issues:

```markdown
## Investigation: [Issue Title]

### Symptom
What the user observed.

### Hypothesis 1
What I think might be wrong.

### Test 1
How I tested it.

### Result 1
What I found.

### Hypothesis 2
...

### Root Cause
The actual reason.

### Fix
What I changed.

### Verification
How I confirmed it worked.
```

---

## Part 6: Quick Reference

### Status Symbols

| Symbol | Meaning |
|--------|---------|
| ✅ | Complete |
| 🔄 | In progress |
| ⬜ | Not started |
| ⏸ | Blocked |
| ❌ | Failed/Rejected |

### File Naming

- `WIP.md` — Work in Progress
- `TODO.md` — Backlog/Roadmap
- `HISTORY.md` — Change log
- `PATTERNS.md` — Code patterns
- `NOTES.md` — Investigation notes
- `MODULE-COMPLIANCE.md` — Quality checklist

### Session Commands (Git)

```bash
# View recent sessions
git log --oneline -20 | grep Session

# Find session commits
git log --grep="Session 42"

# Session summary
git log --since="2024-01-01" --pretty=format:"%s" | grep -E "^(feat|fix)" | head -20
```

### Tracking File Update Order

1. Make code changes
2. Test changes
3. Update `WIP.md` (move to Complété)
4. Add entry to `HISTORY.md`
5. Update `TODO.md` phase status
6. Commit all together

---

## Part 7: Applying to New Projects

### Step 1: Create `.claude/` Directory

```bash
mkdir -p .claude
touch .claude/{WIP,TODO,HISTORY,PATTERNS,NOTES}.md
```

### Step 2: Initialize Tracking Files

**WIP.md:**
```markdown
# WIP — Work In Progress
*Updated: YYYY-MM-DD (Session 1)*

---

## ⬜ Next Up — Initial Setup

**Goal:** Set up project structure

**Approach:**
1. Create directories
2. Add base files
3. Verify builds
```

**TODO.md:**
```markdown
# TODO — Backlog

## 🔄 Phase 1 — Setup (IN PROGRESS)

- [ ] Project structure
- [ ] Build system
- [ ] CI/CD
```

**HISTORY.md:**
```markdown
# HISTORY — Change Log

## Session 1 — Project Initialization
*YYYY-MM-DD*

### Goal
Initialize project with SecuBox-Dev methodology.

### Changes
- Created .claude/ tracking directory
- Added initial tracking files

### Result
Ready for development.
```

### Step 3: Add to .gitignore (Optional)

If you want tracking files to be local only:
```
# .gitignore
.claude/NOTES.md  # Investigation notes
```

### Step 4: First Session

1. Define Phase 1 tasks in TODO.md
2. Add first task to WIP.md "Next Up"
3. Implement
4. Update tracking files
5. Commit with "Session 1" reference

---

## Appendix: Template Files

### Template: Session Entry

```markdown
## Session XX — [Title]
*YYYY-MM-DD*

### Goal
[One sentence goal]

### Problem
[What was broken, if applicable]

### Root Cause
[Technical reason, if applicable]

### Changes
1. [Change 1]
2. [Change 2]

### Files Modified
- `path/file.ext` — [What changed]

### Testing
- [How verified]

### Commits
- `hash` message

### Result
[Observable outcome]
```

### Template: Pattern Entry

```markdown
## Pattern N — [Name]

### When to Use
[Situation description]

### Source
```language
[Before code]
```

### Target
```language
[After code]
```

### Notes
- [Important consideration 1]
- [Important consideration 2]
```

### Template: README Module

```markdown
# [Module Name]

## Description
[What this module does]

## Features
- Feature 1
- Feature 2

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /status | Get status |
| POST | /action | Perform action |

## Configuration

File: `/etc/app/module.toml`

```toml
[module]
enabled = true
```

## Installation

```bash
apt install module-name
```

## Usage

```bash
# Example command
curl http://localhost/api/module/status
```
```

---

*End of SecuBox-Dev Methodology*
