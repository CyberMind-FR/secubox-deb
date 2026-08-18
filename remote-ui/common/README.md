<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

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
