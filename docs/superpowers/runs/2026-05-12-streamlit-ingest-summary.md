<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Streamlit Gitea Ingest Run — 2026-05-12

Live run of `scripts/streamlit-ingest.sh` on the MOCHAbin, two passes:

1. First pass: 4 ingested, 4 skipped, 20 failed — same broken-stub root cause as sub-project B (#97 Task 6).

2. Cleanup pass: bulk-deleted the 20 broken stubs via Gitea API (one-shot token, write:repository scope).
   Deleted: 20, Failed: 0.

3. Second pass results:

```json
{
  "ok": 20,
  "skip": 8,
  "fail": 0
}
```

Sample verification (5 random apps, `git ls-remote`):

```
generix: cd7fc5e424b4b5db672bb066706d22d9a8d9e91b
yijing_oracle: 4af293c537b82ffb49b5aba4aefca88e21164474
wuyun_liuqi: 577ebb37c03e6d6453741b2f9b7e0a4ab12ce36c
alerte_depot: e5a25a35d28ffc60694c47a8a1839b41c0272c2d
secubox_evolution: 8a0611834787a8fa3779681e087c04485d364bc7
```

28 repos total now exist at `https://gitea.gk2.secubox.in/gandalf/?tab=repositories&q=streamlit`.
