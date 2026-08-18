<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Eye Remote — Multi-Gadget L3 Limitation (and Resolution)

> **Resolved by #158 (Phase 1).** Multiple Pi RNDIS gadgets now coexist
> at L3 as well: the host runs `dnsmasq` scoped to `eye-br0` and hands
> out a stable, per-MAC lease in `10.55.0.10–.250`. Round images
> built from `feature/158-…` onward use DHCP; older images with the
> static `10.55.0.2/30` peer still suffer the limitation documented
> below until they're reflashed. Phase 2 (explicit pairing approval)
> remains a separate follow-up.

**Status: known limitation as of issue #155 fix.**

---

## Problem

The host-side `eye-br0` bridge carries L2 traffic from every plugged-in Pi RNDIS
gadget without IP collisions at L2. However, every Round image flashes the same
static peer configuration: `10.55.0.2/30` with host gateway `10.55.0.1`.

With two or more gadgets attached simultaneously, **all of them ARP-claim the
same address**. The host's bridge ARP cache flaps between them, and exactly one
Pi is reachable at a time — which one depends on which last sent an ARP reply.

## Root Cause

The static address `10.55.0.2` is baked into each Pi image at build time via
`secubox-otg-gadget.sh`. The `eye-br0` bridge (landed in #155 / PR #157) solved
the L2 collision problem but did not assign distinct L3 addresses.

## Symptoms

- `ping 10.55.0.2` succeeds but the responding Pi is non-deterministic when
  two gadgets are plugged in.
- `GET /api/v1/eye-remote/leases` returns at most one reachable peer even when
  two Pis are physically attached.
- `arp -n` on the host shows a single entry for `10.55.0.2` whose MAC flaps
  between the two gadgets every few seconds.

## Workaround (pre-#158)

Attach only one Pi gadget at a time. The first-plugged Pi wins the ARP race;
the second never becomes reachable until the first is unplugged and the ARP
cache entry expires (default 60 s).

## Resolution — Issue #158 Phase 1

Implemented in `feature/158-eye-remote-multi-gadget-l3-dhcp-server-o`:

- **Host:** `dnsmasq` instance bound exclusively to `eye-br0`, leasing
  `10.55.0.10`–`10.55.0.250` from a 24 h pool; per-MAC reservations in
  `/etc/secubox/eye-remote/reservations.conf`.
- **Host:** `leasewatch.sh` dhcp-script hook auto-appends new MACs to the
  reservation file on first attach.
- **Host:** FastAPI router `GET /api/v1/eye-remote/leases` — active leases
  joined with the reservation table.
- **Round image:** `eye0` (formerly `usb0`) switched from static `10.55.0.2/30`
  to DHCP client via `systemd-networkd`. Firstboot derives a unique hostname
  from the Pi's CPU serial number.
- **nftables:** narrow DHCP allow on `eye-br0` only (`udp dport 67`).

Round images built from `feature/158-…` onward get a unique `10.55.0.x` address
automatically. Older images must be reflashed to benefit.

## Phase 2 (Pending — separate issue)

Explicit pairing approval before a lease is granted:

- `dnsmasq` `dhcp-script` hook calls `POST /api/v1/eye-remote/pair/check`.
- Unknown MACs enter a `pending_pairing` queue surfaced in the SecuBox UI.
- UI affordance: "Pi Zero W serial `1000…f3b403` requests to join — Approve / Reject"
  with an audit log entry per decision.
- Optional Phase 2.5: NIZK proof requirement during the pair handshake.

## References

- Issue [#155](https://github.com/CyberMind-FR/secubox-deb/issues/155) — L2 bridge (eye-br0) that set the foundation
- PR [#157](https://github.com/CyberMind-FR/secubox-deb/pull/157) — L2 bridge merged
- Issue [#158](https://github.com/CyberMind-FR/secubox-deb/issues/158) — this resolution (Phase 1 DHCP)
- Spec: [`docs/superpowers/specs/2026-05-16-eye-remote-multi-gadget-dhcp-pairing-design.md`](../../docs/superpowers/specs/2026-05-16-eye-remote-multi-gadget-dhcp-pairing-design.md)
