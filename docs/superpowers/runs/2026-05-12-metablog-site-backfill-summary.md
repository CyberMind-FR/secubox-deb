<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# MetaBlogizer site.json Backfill — 2026-05-12

Live run of `scripts/metablog-site-backfill.sh` on the MOCHAbin.

```json
{
  "created": 104,
  "merged": 0,
  "skip": 61,
  "fail": 0
}
```

Two pre-existing site.json files (`money`, `evolution`) were missing the required `published` field and were fixed via `--force --site <name>` before the final run, so the smoke test's schema gate passes for all 61 originals.

## Sample created files

### xtest
```json
{
  "name": "xtest",
  "domain": "xtest.gk2.secubox.in",
  "published": true,
  "version": "v1.0.0",
  "streamlit_app": null
}
```

### wechat
```json
{
  "name": "wechat",
  "domain": "wechat.gk2.secubox.in",
  "published": true,
  "version": "v1.0.0",
  "streamlit_app": null
}
```

### presse
```json
{
  "name": "presse",
  "domain": "presse.gk2.secubox.in",
  "published": true,
  "version": "v1.0.0",
  "streamlit_app": null
}
```

