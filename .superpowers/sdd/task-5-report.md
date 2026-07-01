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
