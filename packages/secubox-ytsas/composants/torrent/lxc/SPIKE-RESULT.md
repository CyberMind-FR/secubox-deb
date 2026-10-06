<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-torrent v2.0 — wrtc-arm64 spike result

**Date:** 2026-07-28
**Ref:** #917

## Result

```
WEBRTC_AVAILABLE=true
```

`@roamhq/wrtc` loads a working `RTCPeerConnection` on arm64. The pinned
dependency set in `app/package.json` (including `@roamhq/wrtc`) is kept
as-is — no fallback removal needed.

## How it was validated

The dev workstation is x86-64 and cannot answer the arm64 question. Per
the task-1 resolution, an EXISTING arm64 Node environment on gk2 was used
instead of provisioning the `torrent` LXC on prod (that provisioning is
Task 7's job):

- Host: gk2 (`ssh root@192.168.1.200`), Debian 12.14 aarch64.
- Container: the `peertube` LXC (`lxc-attach -n peertube -P /data/lxc`),
  which already has Node installed.
- Node version tested: **v22.22.2** (npm 10.9.7).
- Scratch dir: `/tmp/wrtc-spike` inside the `peertube` LXC — `npm init -y`
  then `npm install @roamhq/wrtc`.
- **npm install outcome:** clean, no errors. Resolved `@roamhq/wrtc@0.10.0`
  (brief pins `^0.8.0`; the installed prebuild satisfies the same major
  API and pulled in the `@roamhq/wrtc-linux-arm64` optional prebuild
  package — confirms a linux-arm64 native binding exists and installs
  without a source build). `npm warn deprecated domexception@4.0.0` only
  (transitive, non-blocking).
- Ran the exact shipped `app/wrtc-probe.js` (ESM, matching this package's
  `"type": "module"`) against the scratch install: printed
  `WEBRTC_AVAILABLE=true`, exit 0, no crash.
- Also ran an equivalent CommonJS one-liner
  (`require('@roamhq/wrtc'); new RTCPeerConnection(); pc.close()`)
  directly — same result, confirming the binding itself (not just the
  ESM interop wrapper) works.
- Scratch dirs (`/tmp/wrtc-spike`, `/tmp/wrtc-spike2`) removed after the
  test; nothing persisted in the `peertube` LXC or on gk2.

## Consequence for later tasks

- `WEBRTC_AVAILABLE=true` is the default for `engine.js`'s `webrtc` mode
  in later tasks (webtorrent + WebRTC hybrid streaming, as designed).
- `@roamhq/wrtc` stays in `app/package.json` — no removal required.
- Final confirmation still happens when the dedicated `torrent` LXC is
  provisioned in Task 7 (this spike used a neighboring LXC's Node/OS
  environment as a stand-in, same host arch/Debian release/kernel).
