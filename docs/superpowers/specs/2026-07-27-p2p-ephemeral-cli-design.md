<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-p2p Ephemeral-Peer CLI + Escalation Foundation — Design

**Date:** 2026-07-27
**Module:** `secubox-p2p` (new CLI + iface) — consumed by `secubox-assist` (escalate.py)
**Follow-up of:** assist-dual marketplace (escalate.py builders-only; `/usr/sbin/secubox-p2pctl` was a documented dangling dependency)

## Goal

Give `secubox-assist`'s `escalate.py` a real `secubox-p2pctl` so a matched center can be attached as a **session-scoped WireGuard peer** on a dedicated `wg-ephemeral` interface — established when an assistance session opens, auto-revoked when it ends. This iteration builds the **manually-driven mechanism** (WG params supplied via the `join` CLI args); the automatic HTTPS rendezvous is Phase 2 (documented, not built).

## Scope

**In scope (foundation):** `secubox-p2pctl` (`peer-add`/`peer-del`/`ephemeral-revoke`/`iface-up`/`sweep`); the persistent-silent `wg-ephemeral` interface; the ephemeral peer registry; the TTL backstop timer; wiring escalate.py's builders to a real `sudo -n` exec via the assist ctl `join`.

**Out of scope (Phase 2, documented below):** the automatic HTTPS rendezvous where the center POSTs its WG params to `/assist/join/<token>`.

## Inherited invariants (from assist-dual)

- Data-plane is WireGuard-only.
- All actuation via argv lists with `shell=False` — never a shell string.
- No privileged action in-process: `secubox-p2pctl` is the single root surface; the assist daemon/API never touch WireGuard directly.
- An ephemeral identity is NEVER written to the gondwana mesh state and NEVER promoted to a persistent member.
- Fail-closed: a crashed/killed assist must never leave a dangling peer.
- Consent unchanged: an upstream `ASSIST_SESSION_OPEN` (existing double-consent model) is still required; escalation does not add a new consent bypass.
- Never chown the shared parents (`/run/secubox`, `/etc/secubox`, `/var/log/secubox`, `/var/lib/secubox`); chmod-only traversal loosening if needed.

## Architecture

```
matched center (beyond wg-mesh)                     box (gk2)
  ephemeral Ed25519 identity  ── join args ──▶  secubox-assistctl join
  (mint_ephemeral_identity)                       │ validate token (expiry+hash)
                                                   │ sudo -n secubox-p2pctl peer-add …
                                                   ▼
                                          secubox-p2pctl (root)
                                            • iface-up wg-ephemeral (idempotent)
                                            • wg set … peer  (10.11.0.x/32)
                                            • record → /var/lib/secubox/p2p/ephemeral.json
                                                   │
   wg-ephemeral (10.11.0.0/24, udp/51825) ◀───────┘   silent at rest (no peers)
        │ center dials box:51825, reaches assist WS on 10.11.0.1
        ▼
  session close / expiry ─▶ assistctl ─▶ sudo -n secubox-p2pctl peer-del + ephemeral-revoke
  (backstop) secubox-p2p-ephemeral-sweep.timer ─▶ p2pctl sweep (removes expired registry peers)
```

### Component units

| Unit | Responsibility |
|------|----------------|
| `p2p/ephemeral.py` (new, pure) | argv builders + registry read/write/expiry logic; no side-effects beyond the registry file; unit-testable |
| `sbin/secubox-p2pctl` (new, root) | thin CLI over `p2p/ephemeral.py` + the actual `wg`/`ip` calls; `peer-add`/`peer-del`/`ephemeral-revoke`/`iface-up`/`sweep` |
| `systemd/secubox-p2p-ephemeral-sweep.{service,timer}` | ~60s backstop invoking `secubox-p2pctl sweep` |
| `sudoers/secubox-p2p-ephemeral` | `secubox ALL=(root) NOPASSWD: /usr/sbin/secubox-p2pctl` (exact path only) |
| `nft/…-ephemeral.nft` drop-in | INPUT allow udp/51825; ships in `/etc/nftables.d/` (reboot-persistent) |
| `secubox-assist` `sbin/secubox-assistctl` `join` (modify) | validate token → `sudo -n secubox-p2pctl …` the escalate.py argv (was builders-only) |

## `wg-ephemeral` interface

- **Persistent, silent.** Brought up idempotently by `secubox-p2pctl iface-up` (invoked from postinst and defensively before the first `peer-add`). With zero configured peers, WireGuard answers no one → near-zero attack surface at rest.
- **Key:** generated once at install into `/etc/secubox/secrets/p2p/wg-ephemeral.key` (0600, `secubox`-readable per the box's key conventions); the public key is derivable for the center to configure its side.
- **Addressing:** box is `10.11.0.1/24`; peers get `10.11.0.2 … 10.11.0.254`.
- **Listen port:** UDP **51825** (wg-mesh=51822, p2p dht=51823/51824). Requires an nft INPUT allow (drop-in in `/etc/nftables.d/`, reboot-persistent) and a Freebox UDP forward → gk2 (documented deploy step, mirrors wg-mesh 51822).
- Managed by `secubox-p2pctl` directly (`ip link`/`wg set`), NOT folded into the mesh `wg-quick` conf — keeps ephemeral strictly separate from persistent gondwana membership.

## `secubox-p2pctl` CLI

All subcommands run as root (invoked via `sudo -n` from the assist ctl, or directly by an operator). argv only; no shell.

- `iface-up` — idempotent: create `wg-ephemeral` if absent, load the key, set listen-port 51825, address `10.11.0.1/24`, bring up. No-op if already up. Also flushes the registry on a fresh boot (see Registry).
- `peer-add --iface wg-ephemeral --ephemeral --pubkey <pk> --endpoint <ep> --ip <ip> --allowed-ip <ip>/32 [--ttl <s>]` — validates `<ip>` ∈ 10.11.0.0/24 (defense-in-depth; escalate.py also guards), calls `iface-up` first, `wg set wg-ephemeral peer <pk> endpoint <ep> allowed-ips <ip>/32`, records `{pubkey, ip, did?, endpoint, expires_ts}` in the registry. `--ttl` (default hard-cap, e.g. 4h) sets `expires_ts`.
- `peer-del --iface wg-ephemeral --allowed-ip <ip>/32` — `wg set wg-ephemeral peer <pk-from-registry-for-ip> remove`; drop the registry entry. Idempotent (absent → no-op, rc 0).
- `ephemeral-revoke --did <did>` — remove every registry peer with that `did` (both from `wg` and the file). Idempotent.
- `sweep` — remove every registry peer whose `expires_ts` is in the past (from `wg` and the file). The backstop. Idempotent, safe to run when the iface is down.

**`--ephemeral` flag** on `peer-add` is a required guard: the CLI refuses to add a peer to `wg-ephemeral` without it (prevents accidental persistent-peer semantics on this iface) and refuses `--ephemeral` on any iface other than `wg-ephemeral`.

## Ephemeral registry

`/var/lib/secubox/p2p/ephemeral.json` — a list of `{pubkey, ip, did, endpoint, expires_ts}`. Owned appropriately so `secubox-p2pctl` (root) writes it; the sweep reads it.

- `expires_ts` = the session's `expires_ts` passed at `peer-add` (via `--ttl`), hard-capped to a few hours so a long or misconfigured session can't hold a peer indefinitely.
- **Boot flush:** on the first `iface-up` after boot, the registry is cleared and `wg-ephemeral` is (re)created with no peers — a reboot ends every assistance session, so any surviving ephemeral peer is stale. Fail-closed. (Boot detection: compare a stored boot-id against `/proc/sys/kernel/random/boot_id`.)

## Auto-revoke (two layers)

1. **Normal path** — the assist ctl runs escalate.py `teardown(ip, did)` (`peer-del` + `ephemeral-revoke`) on `ASSIST_SESSION_CLOSE` and on session expiry.
2. **Backstop** — `secubox-p2p-ephemeral-sweep.timer` (~60s) → `secubox-p2pctl sweep`. Removes any registry peer past `expires_ts`, independent of assist. A crashed/killed assist never leaves a dangling peer.

secubox-p2p stays ignorant of the assist session model — it only knows a per-peer `expires_ts`. No p2p→assist layering break.

## Live wiring (escalate.py exec)

Today the assist ctl `join` builds escalate.py's argv but does not exec (documented deferral). This iteration:

- `secubox-assistctl join <token> --hash <h> --expires-at <ts> --pubkey <pk> --endpoint <ep> --ip <ip>` — validates the join-token (`joinlink.verify_join` hash + `is_expired`), then **executes** the escalate.py argv via `subprocess.run(["sudo", "-n", *escalate_argv], shell=False)`.
- The invoking unit is the assist WS daemon path that already runs `NoNewPrivileges=false` for the scoped-catalog sudo (the API unit stays NNP=true and never sudoes).
- Reconcile the known redundancy: `escalate.add_ephemeral_peer` currently emits both `--ip` and `--allowed-ip`; keep `--allowed-ip <ip>/32` as the wg-facing value and pass `--ip` only where the registry needs the bare host — or drop the redundant token. Decide in the plan; the CLI accepts both but treats `--allowed-ip` as authoritative for the `wg` call.

## Security model

- **Single privileged surface:** only `secubox-p2pctl` touches WireGuard/`ip`; the assist daemon/API delegate via `sudo -n` under a sudoers entry scoped to the exact ctl path (no wildcard, no `NOPASSWD: ALL`).
- **Ephemeral isolation:** `wg-ephemeral` is a distinct iface with its own key/port/range; ephemeral identities never enter the gondwana mesh state and are never promoted to members.
- **Fail-closed:** boot flush + TTL backstop guarantee no orphan peers; `peer-add` refuses out-of-range IPs and non-`wg-ephemeral` `--ephemeral` use.
- **Consent unchanged:** the upstream `ASSIST_SESSION_OPEN` double-consent still gates a session; a valid single-use join-token is required to redeem; escalation adds transport, not a consent bypass.
- **No secret leakage:** the ephemeral private key (center side) never crosses the box; the box only receives the center's public key. `secubox-p2pctl` never logs private material.

## Testing

- `p2p/ephemeral.py` pure: argv builders (list, no shell, IP-range guard), registry add/remove/`ephemeral-revoke`-by-did, `sweep` expiry (fail-closed on malformed `expires_ts`), boot-flush logic. Unit-tested with a temp registry and injected `wg` runner (no real WireGuard in tests).
- `secubox-p2pctl` subprocess tests with a fake `wg`/`ip` (env-injected) + DRYRUN: subcommands emit the right argv, refuse bad input with a JSON error (not a traceback), `--ephemeral` guard.
- `secubox-assist` `join` test: token-invalid → refused; token-valid → the expected `sudo -n secubox-p2pctl …` argv (fake sudo/p2pctl), no exec on DRYRUN.
- Packaging: sudoers scoped to `/usr/sbin/secubox-p2pctl` only; sweep unit present; nft drop-in in `/etc/nftables.d/`; no shared-parent chown in postinst; iface-up idempotent.

## Deploy prerequisites (out-of-package)

- nft INPUT allow for udp/51825 (ships as a `/etc/nftables.d/` drop-in — reboot-persistent).
- Freebox UDP/51825 forward → gk2 (manual, mirrors wg-mesh 51822 — documented, like the release-rings reprepro-distributions prerequisite).

## Phase 2 (deferred, documented — NOT built here)

Automatic HTTPS rendezvous: the center redeems the join-link at `https://admin.<hub>/assist/join/<token>` (the public join URL fixed in assist 0.2.1), POSTing its ephemeral WG pubkey + endpoint. The box validates the single-use token, allocates the next free `10.11.0.x`, calls `peer-add`, and returns its own `wg-ephemeral` pubkey + endpoint + the assigned IP. The center brings up its half and connects — fully automatic, no manual `join` args. Requires a new token-gated HTTPS endpoint that triggers a privileged `peer-add`; designed once the foundation mechanism is proven live.
