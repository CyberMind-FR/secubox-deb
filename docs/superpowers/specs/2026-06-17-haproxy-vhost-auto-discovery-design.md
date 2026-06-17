<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# Spec — HAProxy complete dynamic vhost auto-discovery

*2026-06-17 · landed for later (per user) · found while fixing #626/#627*

## Problem
`haproxyctl generate` must produce a COMPLETE config so regen never drops
hand-maintained vhosts. Today ~10 vhosts live only in the hand-edited
`/etc/haproxy/haproxy.cfg` — not in `haproxy.toml` or `cfg.d/`:

- `kbin.gk2.secubox.in` → `toolbox_landing` (backend also live-only)
- `matrix`, `gitea`, `peertube`, `photoprism` (.gk2.secubox.in) → `nginx_vhosts`

These bypass the WAF today (route direct, not through `mitmproxy_inspector`).
A clean regen omits them. PR #627 added a **drift guard** so regen refuses to
clobber when its output has fewer vhosts/backends than live — safe, but not
complete.

## Design (approved direction: auto-discover from modules/LXC)
1. **Drop-in registry.** Generator aggregates `haproxy.toml [vhosts.*]` **plus**
   `/etc/secubox/vhosts.d/*.toml` — one file per module/LXC, dropped by that
   module's postinst (self-registration). New modules appear automatically.
2. **Per-vhost routing intent** replaces the blanket `waf_enabled` override
   (which currently forces *every* vhost through the WAF):
   ```toml
   [vhost]
   domain  = "peertube.gk2.secubox.in"
   backend = "nginx_vhosts"     # or a module/LXC backend
   ssl     = true
   inspect = false              # true → mitmproxy_inspector (WAF); false → direct
   ```
3. **One-time migration.** Seed `vhosts.d/` from the ~10 drifted live entries
   with their real backends + `inspect=false`; register `toolbox_landing` as a
   known backend. After this, regen output == live → drift guard passes.
4. **Module-registration helper** for postinsts (e.g. `haproxyctl vhost register
   --from-file` or a tiny library) so each LXC/module declares its vhost.
5. **Keep the drift guard** as the transition safety net.

## Validation gate (non-negotiable)
Never apply a regenerated cfg to production until a diff proves it reproduces all
~100 live vhosts/backends 1:1 (drift-guard counts match).

## Related: finish the traversal-footgun sweep (#623)
The systemic `install -d -m 0750 .../secubox` footgun is broader than first
swept: **multi-arg** forms like `install -d -m 0750 /run/secubox /var/lib/secubox
…` (e.g. secubox-haproxy, fixed in #627) were missed by the earlier grep
(`…/secubox/[a-z]` required a leaf). Re-sweep with a pattern that catches bare
`/var/{lib,log,cache}/secubox` arguments, and add a **tmpfiles.d + periodic
guard** so the shared parents self-heal to `0755` regardless of which package
clobbers them (this is the root of the recurring kbin/toolbox 500s).

## Status
- Generator no longer crashes (set -e + dup-backend fixed, #627).
- Drift guard prevents clobbering (#627).
- Error pages live + served from `/etc/haproxy/secubox-errors/` (#627).
- This auto-discovery rework + the #623 re-sweep are the remaining work.
