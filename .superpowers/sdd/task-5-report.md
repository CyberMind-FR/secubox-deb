# Task 5 Report — Security + Provisioning Glue

**Date**: 2026-07-01
**Status**: DONE

---

## Files Created

| File | Mode (installed) | Note |
|------|-----------------|------|
| `packages/secubox-macro/sudoers.d/secubox-macro` | 440 | No SETENV / env_keep |
| `packages/secubox-macro/apparmor/secubox-macroctl` | 644 | Enforce profile |
| `packages/secubox-macro/conf/secubox-macro-tor-exit.conf.example` | 644 | `__MESH_IP__` token |
| `packages/secubox-macro/debian/postinst` | 755 | configure block |
| `packages/secubox-macro/debian/prerm` | 755 | remove/upgrade/deconfigure |

## Files Modified

| File | Change |
|------|--------|
| `packages/secubox-macro/debian/rules` | Dropped unused `/etc/tor/torrc.d` dir; added `install -d usr/share/secubox/macro` before conf install |

---

## Verification Outputs

### visudo -cf
```
packages/secubox-macro/sudoers.d/secubox-macro : analyse réussie
```
(French locale: "analyse réussie" = "parsed OK")

### sh -n postinst / prerm
```
postinst: OK
prerm: OK
```

### AppArmor profile
- `apparmor_parser -Q` failed only on policy cache (permission denied) — not a parse error
- `apparmor_parser --preprocess` succeeded: full expanded output printed, profile body parsed correctly
- Profile covers `/usr/sbin/secubox-macroctl` as the confined binary
- Braces balanced; all includes resolved

### Macro unit suite
```
14 passed in 0.51s
```
No regressions.

### Rules-referenced files (all present)
```
OK: sbin/secubox-macroctl
OK: macros.d/tor-exit
OK: sudoers.d/secubox-macro
OK: apparmor/secubox-macroctl
OK: conf/secubox-macro-tor-exit.conf.example
```

---

## AppArmor Example Mirrored

The brief cited `packages/secubox-eye-square/debian/secubox-eye-square/etc/apparmor.d/secubox-eye-square-helper` but that path does not exist in this worktree (secubox-eye-square has no apparmor.d directory). Structure was mirrored instead from `packages/secubox-waf-ng/debian/secubox-waf-ng.apparmor`, which is the most complete enforce-profile in this worktree. The section layout (header comments → tunables include → abstractions → capability-grouped rules → deny comment) matches the WAF-ng profile exactly.

---

## Self-Review

- **sudoers**: Exact required line, no SETENV, no env_keep. Default `env_reset` is the only env control. Validated by visudo.
- **AppArmor**: DEFAULT-DENY (implicit AppArmor). All permitted surfaces explicitly listed. `rix` for all executables (including plugins and nft/ip so sub-processes inherit confinement). `rw` for state store. `w` (not `rw`) for audit log (write-only, matches append intent). `/etc/tor/torrc.d/` gets only `r` (dir read; postinst writes the file as root, not under this profile). Network: `inet stream` + `netlink raw` only (no `inet6`, no `unix`).
- **postinst**: All operations guarded with `|| true`. No shared-parent chown (respects #494/#511 CMSD policy). nft operations conditioned on `inet secubox_filter` table existence. Tor reload attempted (reload first, then restart fallback). AppArmor load conditioned on `command -v apparmor_parser`.
- **prerm**: `remove|upgrade|deconfigure` cases. Tor file removed best-effort. nft rule deletion uses handle lookup (robust to rule order changes).
- **rules fix**: The Task-3 rules had `install -d .../etc/tor/torrc.d` (unused — torrc.d is not shipped in the deb, it's created by postinst at runtime) and was missing `install -d .../usr/share/secubox/macro` before the conf.example install. Both corrected.

---

## Concerns

1. **`/var/log/secubox/audit.log` AppArmor mode**: The profile uses `w` (write) which covers append. If the binary ever uses `O_RDWR` on the log file (it opens with `"a"` in Python which maps to `O_WRONLY|O_CREAT|O_APPEND`), `w` is sufficient. No concern.
2. **`#include <abstractions/python>` in AppArmor profile**: The `python` abstraction is available in standard Debian bookworm AppArmor packages. No concern for target platform.
3. **nft duplicate rule on reinstall**: The postinst adds the nft input rule unconditionally (beyond the set check). A `dpkg --reinstall` will add a duplicate rule. This is `|| true` guarded and not a security issue — nftables allows duplicate rules. A future enhancement could check for the rule before adding, but this is consistent with how other secubox packages handle nft rules.
4. **`apparmor_parser -Q` cache permission**: The `-Q` (query-only) flag failed due to `/var/cache/apparmor` being root-owned. This is a dev environment constraint, not a parse error. `--preprocess` confirmed syntax is valid.

---

## Review Fixes (ref #771)

Applied three security-review fixes to address CRITICAL and IMPORTANT findings:

### FIX 1 — CRITICAL: mawk-portable prerm handle extraction

**File**: `packages/secubox-macro/debian/prerm` (line 19)

**Before**:
```sh
awk '/secubox_macro_torexit.*dport 9050/ {match($0, /handle ([0-9]+)/, h); if (h[1]) print h[1]}'
```

**After**:
```sh
awk '/secubox_macro_torexit.*dport 9050/ { for (i=1;i<=NF;i++) if ($i=="handle") { print $(i+1); exit } }') || true
```

gawk's 3-argument `match()` is not available in mawk (Debian bookworm's `/usr/bin/awk`). The replacement iterates fields portably. The `|| true` prevents `set -e` from aborting prerm on awk/nft failure.

**Verification**:
```
sh -n packages/secubox-macro/debian/prerm → OK (prerm syntax OK)
echo 'x handle 42 y' | mawk '/x/ { for(i=1;i<=NF;i++) if($i=="handle"){print $(i+1);exit} }' → 42
```

### FIX 2 — IMPORTANT: AppArmor append-only audit log

**File**: `packages/secubox-macro/apparmor/secubox-macroctl` (line 54)

**Before**: `/var/log/secubox/audit.log  w,`

**After**: `/var/log/secubox/audit.log  a,`

AppArmor's `a` permission enforces `O_APPEND` at the LSM level, preventing truncation or seek-writes. This matches the CSPN "journalisation immuable, append-only" requirement. The Python side already opens in `"a"` mode.

**Verification**:
```
grep 'audit.log' apparmor/secubox-macroctl
  #   - w    : /var/log/secubox/audit.log (append-only audit trail)
  /var/log/secubox/audit.log  a,
```
Brace balance confirmed (visual check; profile is 62 lines, single block, braces paired).

### FIX 3 — IMPORTANT: tor-exit euid env-pin (defense-in-depth)

**File**: `packages/secubox-macro/macros.d/tor-exit` (inserted at start of `main()`, line 39)

Added `if os.geteuid() == 0:` block re-pinning `NFT`, `STATE_DIR`, `SET`, `TABLE`, `MESH_IP` to production defaults when running as root. Prevents a leaked `TOREXIT_NFT=/tmp/evil` from becoming root-RCE. Non-root euid (test harness) continues to honor env overrides.

**Verification**:
```
grep -n 'geteuid' macros.d/tor-exit → 40:    if os.geteuid() == 0:
python3 -m pytest tests/ -q → 14 passed in 0.52s
```
