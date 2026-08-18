<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Gemini Prompt: Busybox Emergency Recovery Tech Tip

## Prompt for Quick Visual Sketch

```
Create a quick tech tip visual sketch/infographic about "Busybox Emergency Recovery" for Linux sysadmins.

SCENARIO:
- All commands fail: "cannot execute: required file not found"
- Cause: /lib symlink to /usr/lib was accidentally replaced by a directory
- libc.so exists but is inaccessible
- System appears completely broken

THE HERO: BUSYBOX
- Busybox is STATICALLY LINKED - doesn't need libc!
- Contains 300+ commands in one binary
- Your lifeline when dynamic linking breaks

RECOVERY STEPS (3 commands):
1. /bin/busybox rm -rf /lib
2. /bin/busybox ln -s usr/lib /lib
3. /bin/busybox ls -la /lib  (verify)

VISUAL ELEMENTS:
- Show broken chain (dynamic linking) vs solid block (static busybox)
- Traffic light: RED (broken) → GREEN (fixed)
- Terminal screenshots of the error and fix
- Busybox Swiss Army knife icon

PREVENTION TIP:
"Never extract tarballs blindly at root!"
tar tzf file.tar.gz | head  # ALWAYS check first!

STYLE:
- Dark terminal aesthetic (green on black)
- Minimalist, quick-reference format
- One page maximum
- Logo: CyberMind SecuBox

TAGLINE:
"When libc fails, busybox prevails"
```

---

## Alternative: ASCII Art Version

```
┌─────────────────────────────────────────────────────────────┐
│  🚨 BUSYBOX EMERGENCY RECOVERY                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  SYMPTOM:                                                   │
│  $ ls                                                       │
│  -bash: /usr/bin/ls: cannot execute: required file not found│
│                                                             │
│  CAUSE: /lib symlink broken → libc inaccessible             │
│                                                             │
│  ┌─────────┐     ┌─────────┐                                │
│  │ /lib    │ ──X─│ libc.so │  Dynamic linking BROKEN        │
│  │ (dir)   │     │         │                                │
│  └─────────┘     └─────────┘                                │
│                                                             │
│  ┌─────────────────────────┐                                │
│  │      BUSYBOX            │  Static binary = WORKS!        │
│  │  [===============]      │                                │
│  └─────────────────────────┘                                │
│                                                             │
│  FIX (3 commands):                                          │
│  ┌─────────────────────────────────────────────────┐        │
│  │ /bin/busybox rm -rf /lib                        │        │
│  │ /bin/busybox ln -s usr/lib /lib                 │        │
│  │ /bin/busybox ls -la /lib  # verify              │        │
│  └─────────────────────────────────────────────────┘        │
│                                                             │
│  ✓ System restored!                                         │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  💡 PREVENTION: tar tzf file.tar.gz | head  # check first!  │
├─────────────────────────────────────────────────────────────┤
│  "When libc fails, busybox prevails"                        │
│                          — CyberMind SecuBox Tech Tips      │
└─────────────────────────────────────────────────────────────┘
```

---

## Short Version (Tweet/Toot)

```
🚨 Linux Emergency: All commands fail with "cannot execute"?

Your /lib symlink is broken! Fix with static busybox:

/bin/busybox rm -rf /lib
/bin/busybox ln -s usr/lib /lib

"When libc fails, busybox prevails" 🔧

#Linux #SysAdmin #TechTip
```

---

*CyberMind SecuBox — 2026-05-08*
