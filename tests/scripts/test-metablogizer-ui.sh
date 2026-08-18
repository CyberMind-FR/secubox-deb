#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# tests/scripts/test-metablogizer-ui.sh
# Smoke test for the MetaBlogizer version dashboard (sub-D of #49).

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO/scripts/lib/test-helpers.sh"

INDEX="$REPO/packages/secubox-metablogizer/www/metablogizer/index.html"
SITE="$REPO/packages/secubox-metablogizer/www/metablogizer/site.html"

log_step() { echo "[smoke step $1] $2"; }

# Gate 1: index.html contains the new column anchors and filter input.
log_step 1 "index.html has the new columns + filter"
assert_file "$INDEX" "index.html present"
grep -q 'data-sort="version"' "$INDEX"     || { echo "FAIL: data-sort=version missing"; exit 1; }
grep -q 'data-sort="last_updated"' "$INDEX" || { echo "FAIL: data-sort=last_updated missing"; exit 1; }
grep -q 'id="filter"' "$INDEX"             || { echo "FAIL: filter input missing"; exit 1; }
grep -q 'installPolling()' "$INDEX"        || { echo "FAIL: polling install missing"; exit 1; }
pass "index.html: version + last_updated + filter + polling all wired"

# Gate 2: site.html exists with the expected anchors.
log_step 2 "site.html drill-in present"
assert_file "$SITE" "site.html present"
grep -q 'URLSearchParams' "$SITE"  || { echo "FAIL: site.html missing URL param parsing"; exit 1; }
grep -q 'link-gitea' "$SITE"       || { echo "FAIL: site.html missing Gitea link"; exit 1; }
grep -q 'link-streamlit' "$SITE"   || { echo "FAIL: site.html missing Streamlit link"; exit 1; }
grep -q 'link-live' "$SITE"        || { echo "FAIL: site.html missing live-site link"; exit 1; }
pass "site.html: URL parsing + 3 external links wired"

# Gate 3: HTML sanity (well-formed, no mismatched tags) for both files.
log_step 3 "HTML well-formedness"
for f in "$INDEX" "$SITE"; do
  python3 -c "
import html.parser, sys
class S(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.errors = []
        self.stack = []
    def handle_starttag(self, tag, attrs):
        if tag not in ('br','hr','img','input','link','meta'):
            self.stack.append(tag)
    def handle_endtag(self, tag):
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()
        else:
            self.errors.append(f'closing {tag} without matching open')
p = S()
p.feed(open('$f').read())
if p.errors:
    print('FAIL', '$f', p.errors[:3])
    sys.exit(1)
" || { echo "FAIL: HTML mismatch in $f"; exit 1; }
done
pass "both HTML files are well-formed"

# Gate 4 (best-effort): live page reachable. SKIP on failure (auth, network).
log_step 4 "live HTTP reachability (best-effort)"
code=$(curl -s -o /dev/null -w "%{http_code}" "https://admin.gk2.secubox.in/metablogizer/" 2>/dev/null || echo "000")
if [[ "$code" == "200" ]]; then
  pass "live /metablogizer/ returns $code"
else
  echo "WARN: live page returned $code (network/auth/cache) — not blocking"
fi

pass "all smoke gates green"
