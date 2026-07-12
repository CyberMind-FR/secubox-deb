#!/bin/bash
# Exercises spiderfootctl's dispatch + status JSON contract. SpiderFoot takes no
# target via ctl (scans run in its own UI), so there is no user-input guard to
# fuzz — instead we assert the dispatch rejects unknown/empty verbs and that
# `status` emits valid JSON with the documented keys. lxc-info + curl are
# stubbed via PATH so no real container is needed.
set -u
CTL="$(cd "$(dirname "$0")/.." && pwd)/sbin/spiderfootctl"
fail=0
pass() { echo "PASS $*"; }
bad()  { echo "FAIL $*"; fail=1; }

# --- 1. unknown subcommand → usage, exit 2 ---
"$CTL" bogus >/dev/null 2>&1; [ $? -eq 2 ] && pass "reject unknown subcommand (exit 2)" || bad "unknown subcommand should exit 2"

# --- 2. no subcommand → usage, exit 2 ---
"$CTL" >/dev/null 2>&1; [ $? -eq 2 ] && pass "reject empty subcommand (exit 2)" || bad "empty subcommand should exit 2"

# --- 3. status emits valid JSON with the expected keys ---
# Stub lxc-info (report RUNNING) and curl (UI answers) via PATH; fake the
# container tree under a temp LXC_PATH so installed=true.
STUB="$(mktemp -d)"
cat > "$STUB/lxc-info" <<'EOF'
#!/bin/sh
echo "State:   RUNNING"
EOF
cat > "$STUB/curl" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$STUB/lxc-info" "$STUB/curl"

LXROOT="$(mktemp -d)"
mkdir -p "$LXROOT/spiderfoot/rootfs/opt/spiderfoot"   # rootfs + checkout → installed=true

out="$(PATH="$STUB:$PATH" SECUBOX_LXC_PATH="$LXROOT" "$CTL" status 2>/dev/null)"
if echo "$out" | python3 -c '
import sys, json
d = json.load(sys.stdin)
expected = {"running", "installed", "ip", "port", "ui_up"}
assert expected <= set(d), "missing keys: %r" % (expected - set(d))
assert d["installed"] is True, d
assert d["running"] is True, d
assert d["ui_up"] is True, d
assert d["port"] == 5001, d
assert d["ip"] == "10.100.0.43", d
' 2>/dev/null; then
    pass "status emits valid JSON with expected keys (running/installed/ip/port/ui_up)"
else
    bad "status JSON invalid or missing keys: $out"
fi

# --- 4. status when NOT installed (empty tree, UI down) ---
LXEMPTY="$(mktemp -d)"
cat > "$STUB/lxc-info" <<'EOF'
#!/bin/sh
echo "State:   STOPPED"
EOF
cat > "$STUB/curl" <<'EOF'
#!/bin/sh
exit 7
EOF
chmod +x "$STUB/lxc-info" "$STUB/curl"
out2="$(PATH="$STUB:$PATH" SECUBOX_LXC_PATH="$LXEMPTY" "$CTL" status 2>/dev/null)"
if echo "$out2" | python3 -c '
import sys, json
d = json.load(sys.stdin)
assert d["installed"] is False, d
assert d["running"] is False, d
assert d["ui_up"] is False, d
' 2>/dev/null; then
    pass "status reports down/uninstalled correctly"
else
    bad "status(down) JSON wrong: $out2"
fi

rm -rf "$STUB" "$LXROOT" "$LXEMPTY"
exit $fail
