#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# tests/scripts/test-metablog-site-schema.sh
# 3-gate smoke test for sub-project C (#101).
#
# Gate 1 — Backfill dry-run produces a coherent report
#           (created + merged + skip == total, fail == 0)
# Gate 2 — Every live site.json validates against the JSON Schema (Draft 7)
# Gate 3 — (Best-effort) API returns sites with version populated
#           SKIP if METABLOG_JWT env not set

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO/scripts/lib/test-helpers.sh"

LXC_HOST="${LXC_HOST:-192.168.1.200}"
SITES_DIR="${SITES_DIR:-/srv/metablogizer/sites}"
SCHEMA="$REPO/packages/secubox-metablogizer/schema/site.json.schema.json"
REPORT="$REPO/output/metablog-backfill-report.json"

log_step() { echo "[smoke step $1] $2"; }

# ──────────────────────────────────────────────────────────────────────────────
# Gate 1: Backfill dry-run produces a coherent report
# ──────────────────────────────────────────────────────────────────────────────
log_step 1 "backfill --dry-run"

bash "$REPO/scripts/metablog-site-backfill.sh" --dry-run >/dev/null 2>&1

assert_file "$REPORT" "backfill report should exist"

total=$(jq '.total' "$REPORT")
created=$(jq '.by_status.created' "$REPORT")
merged=$(jq '.by_status.merged' "$REPORT")
skip=$(jq '.by_status.skip' "$REPORT")
fail_count=$(jq '.by_status.fail' "$REPORT")

accounted=$(( created + merged + skip ))
assert_eq "$total" "$accounted" "created($created) + merged($merged) + skip($skip) should equal total($total)"
assert_eq "0" "$fail_count" "no fails in dry-run"

pass "Gate 1: dry-run report consistent — total=$total (created=$created, merged=$merged, skip=$skip), fail=0"

# ──────────────────────────────────────────────────────────────────────────────
# Gate 2: Every existing site.json validates against the schema
#
# Strategy: gather all site.json paths in one SSH round-trip, then copy the
# schema to the host and run a single Python batch-validation pass. This avoids
# one SSH connection per file and the subshell-variable-loss bug that would
# occur with a "while read | ssh" loop.
# ──────────────────────────────────────────────────────────────────────────────
log_step 2 "schema validation of all live site.json files"

# Upload the schema to a temp location on the host so Python can read it
REMOTE_SCHEMA="/tmp/metablog-site-schema-$$.json"
scp -q "$SCHEMA" "root@$LXC_HOST:$REMOTE_SCHEMA" 2>/dev/null

validation_result=$(ssh "root@$LXC_HOST" "SITES_DIR='$SITES_DIR' SCHEMA='$REMOTE_SCHEMA' python3 -c '
import json, sys, os
try:
    import jsonschema
except ImportError:
    print(\"SKIP:jsonschema_not_installed\")
    sys.exit(0)

sites_dir = os.environ[\"SITES_DIR\"]
schema_path = os.environ[\"SCHEMA\"]
schema = json.load(open(schema_path))
v = jsonschema.Draft7Validator(schema)

failures = []
checked = 0
for root, dirs, files in os.walk(sites_dir):
    depth = root[len(sites_dir):].count(os.sep)
    if depth >= 2:
        dirs[:] = []
        continue
    if \"site.json\" in files:
        path = os.path.join(root, \"site.json\")
        try:
            doc = json.loads(open(path).read())
            errs = list(v.iter_errors(doc))
            if errs:
                failures.append((path, [e.message for e in errs]))
            else:
                checked += 1
        except Exception as e:
            failures.append((path, [str(e)]))

if failures:
    for path, msgs in failures:
        print(f\"FAIL: {path}: {msgs[0]}\")
    print(f\"RESULT:fail checked={checked} failures={len(failures)}\")
else:
    print(f\"RESULT:ok checked={checked} failures=0\")
'" 2>/dev/null)

# Clean up temp schema
ssh "root@$LXC_HOST" "rm -f '$REMOTE_SCHEMA'" 2>/dev/null || true

if echo "$validation_result" | grep -q "^SKIP:jsonschema_not_installed"; then
    echo "WARN: Gate 2 SKIP — jsonschema Python package not installed on $LXC_HOST"
    echo "      Install with: pip3 install jsonschema"
else
    # Print any FAIL lines for diagnostics
    echo "$validation_result" | grep "^FAIL:" || true

    result_line=$(echo "$validation_result" | grep "^RESULT:" | tail -1)
    if [[ -z "$result_line" ]]; then
        echo "FAIL: Gate 2 — could not determine validation result (SSH/Python error?)"
        echo "      Raw output: $validation_result"
        exit 1
    fi

    result_status="${result_line#RESULT:}"
    status_code="${result_status%%\ *}"
    checked=$(echo "$result_status" | grep -o 'checked=[0-9]*' | cut -d= -f2)
    failures=$(echo "$result_status" | grep -o 'failures=[0-9]*' | cut -d= -f2)

    if [[ "$status_code" != "ok" ]]; then
        echo "FAIL: Gate 2 — $failures site.json file(s) failed schema validation (checked $checked files)"
        exit 1
    fi
    pass "Gate 2: $checked site.json files validated against schema, 0 failures"
fi

# ──────────────────────────────────────────────────────────────────────────────
# Gate 3: API surface enrichment (best-effort — needs FastAPI up + JWT)
# ──────────────────────────────────────────────────────────────────────────────
log_step 3 "API enrichment (best-effort)"

if [[ -z "${METABLOG_JWT:-}" ]]; then
    echo "SKIP: Gate 3 — METABLOG_JWT not set; API surface check requires a JWT bearer token"
else
    out=$(ssh "root@$LXC_HOST" "curl -sS --unix-socket /run/secubox/metablogizer.sock \
          -H 'Authorization: Bearer $METABLOG_JWT' \
          http://x/sites 2>/dev/null" || true)

    if [[ -z "$out" ]]; then
        echo "WARN: Gate 3 — API returned empty response (socket may be down). Skipping."
    else
        count=$(echo "$out" | jq '.count // (.sites | length) // 0' 2>/dev/null || echo 0)
        if [[ "$count" -lt 100 ]]; then
            echo "WARN: Gate 3 — API returned $count sites (expected ~165). Endpoint may be unavailable."
        else
            versioned=$(echo "$out" | jq '[.sites[] | select(.version != null)] | length' 2>/dev/null || echo 0)
            if [[ "$versioned" -lt 100 ]]; then
                echo "WARN: Gate 3 — only $versioned of $count sites have version populated"
            else
                pass "Gate 3: API — $versioned of $count sites have non-null version"
            fi
        fi
    fi
fi

pass "all smoke gates passed (or skipped with warnings)"
