<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# MetaBlogizer Ingest Run — 2026-05-12

Live run of `scripts/metablog-ingest.sh` on the MOCHAbin, two passes:

1. First pass: 90 ingested, 4 skipped, 72 failed — root cause: pre-existing broken Gitea repo stubs (DB entry without git objects on disk) from earlier experiments. Failures all printed `fatal: ... does not appear to be a git repository`.

2. Cleanup pass: bulk-deleted the 72 broken stubs via Gitea API (one-shot token, write:repository scope).

3. Second pass results:

```json
{
  "ok": 72,
  "skip": 94,
  "fail": 0
}
```

Sample verification (5 random sites, `git ls-remote`):

```
gandalf: c234c6ff2a0f24fe3a271f54ee607d2297cd11a5
dgse: 2e75a084a65414a9f0d6abaa846778d5bc6444ed
ganimed: b37b971b50c420e316d1dea0cb0f6149487ab8e0
magic: 4749ca74b9fa9eb29bbb4f96d4e6937ed3531c1a
sweedtest: db740d2516a4954b5b091c6f9603d18423e58d7a
```

166 repos total now exist at `https://gitea.gk2.secubox.in/gandalf/?tab=repositories&q=metablog`.
