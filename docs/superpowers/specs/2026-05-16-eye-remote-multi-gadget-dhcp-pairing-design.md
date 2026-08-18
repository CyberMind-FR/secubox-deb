<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Eye Remote — Multi-Gadget L3 via DHCP on `eye-br0` (+ Phase 2 Pairing Stub)

*Spec for issue [#158](https://github.com/CyberMind-FR/secubox-deb/issues/158).
Follows the host-side L2 bridge work landed via [#155](https://github.com/CyberMind-FR/secubox-deb/issues/155) / [PR #157](https://github.com/CyberMind-FR/secubox-deb/pull/157).*

## 1 — Context & Problem

The host-side `eye-br0` bridge (`10.55.0.1/24`) carries L2 traffic from every
plugged-in Pi RNDIS gadget without IP collisions on the SecuBox box, but every
Round image flashes the same static peer configuration: `10.55.0.2/30` with
host gateway `10.55.0.1`. With two or more gadgets attached, all of them
ARP-claim the same address; the host's bridge ARP cache flaps between them and
exactly one Pi is reachable at a time.

Goal: allow N Pi gadgets to coexist at L3 with deterministic per-Pi
addressing, a host-visible registry of every gadget that has ever attached,
and a clean integration point for explicit pairing approval (Phase 2) without
having to re-do the L3 layer.

## 2 — Scope

**In scope (Phase 1, this issue):**

- Host: `dnsmasq` instance bound exclusively to `eye-br0`, leasing
  `10.55.0.10`–`10.55.0.250` from a 24h pool.
- Host: per-MAC reservations in
  `/etc/secubox/eye-remote/reservations.conf`, auto-appended on first
  attach of an unknown MAC.
- Round image: switch `eye0` from static peer config to DHCP client.
- API: read-only `/api/v1/eye-remote/leases` endpoint (active leases joined
  with the reservation table).
- Integration with existing `eye-br0` bridge — no L2 changes.

**Stubbed for Phase 2 (separate issue when Phase 1 has shipped):**

- Pair-before-lease: `dnsmasq` `dhcp-script` hook calls
  `POST /api/v1/eye-remote/pair/check` on the host. Endpoint returns `200`
  only if the MAC is `approved = true` in the reservation TOML; otherwise
  the MAC enters a `pending_pairing` queue surfaced in the SecuBox UI and
  `dhcp-script` rejects the offer.
- UI affordance: "Pi Zero W serial `1000…f3b403` requests to join — Approve
  / Reject" with audit log entry per decision.
- Optional Phase 2.5: NIZK proof requirement during the pair handshake,
  hooked into the existing PARAMETERS / ZKP modules — covered separately.

**Explicitly out of scope:**

- IPv6 — `eye-br0` stays v4-only until a real use case appears.
- DNS service — the existing Vortex DNS resolver continues to serve `lan0`
  clients; `eye-br0` does not need name resolution for the Pi peers.
- mDNS / Avahi — Pis address each other and the host by IP, not name.

## 3 — Architecture

### 3.1 Components

```
┌────────────────────────────────────────────────────────────────────┐
│ SecuBox host (MOCHAbin / ESPRESSObin)                              │
│                                                                    │
│  systemd-networkd ── eye-br0 (10.55.0.1/24, packaged .netdev)      │
│        ▲                                                           │
│        │ (slave enslavement via existing udev rule, unchanged)     │
│        │                                                           │
│  dnsmasq@eye-remote.service                                        │
│    ├── listen-address=10.55.0.1                                    │
│    ├── interface=eye-br0   (and ONLY eye-br0)                      │
│    ├── dhcp-range=10.55.0.10,10.55.0.250,255.255.255.0,24h         │
│    ├── dhcp-leasefile=/var/lib/misc/dnsmasq-eye-remote.leases      │
│    └── conf-file=/etc/dnsmasq.d/eye-remote.conf                    │
│             │                                                      │
│             └─ includes reservation snippets:                      │
│                /etc/secubox/eye-remote/reservations.conf           │
│                                                                    │
│  secubox-eye-remote.service (FastAPI / uvicorn on 10.55.0.1:8000)  │
│    └── GET /api/v1/eye-remote/leases                               │
│         reads dnsmasq-eye-remote.leases + reservations.conf        │
│         returns [{mac, ip, hostname, serial, last_seen, approved}] │
│                                                                    │
│  /usr/lib/secubox/eye-remote-leasewatch.sh                         │
│    ├── invoked via dnsmasq dhcp-script hook (add/old/del)          │
│    ├── on `add` for unseen MAC: append a reservation stub to       │
│    │  reservations.conf (approved=true in Phase 1, false in P2)    │
│    └── always: notify FastAPI on POST /eye-remote/lease-events     │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
        ▲                              ▲
        │   eye-br0 carries DHCP        │
        │                              │
   ┌────┴─────┐                  ┌─────┴─────┐
   │ Pi Zero W│                  │  Pi 4B    │
   │ eye0     │  ← DHCP client    │  eye0     │
   │ DHCP=yes │                  │  DHCP=yes │
   └──────────┘                  └───────────┘
```

### 3.2 Files & ownership

| Path | Package | Role |
|---|---|---|
| `/etc/systemd/network/05-eye-br0.netdev` | `secubox-eye-remote` (shipped by #155) | bridge def |
| `/etc/systemd/network/10-eye-br0.network` | `secubox-eye-remote` (shipped by #155) | bridge IP |
| `/etc/dnsmasq.d/eye-remote.conf` | `secubox-eye-remote` (new) | dnsmasq snippet |
| `/etc/secubox/eye-remote/reservations.conf` | runtime-managed (`dpkg-divert` from package, conffile-noreplace) | per-MAC stable IPs |
| `/var/lib/misc/dnsmasq-eye-remote.leases` | dnsmasq runtime | active leases |
| `/etc/systemd/system/dnsmasq@.service.d/eye-remote.conf` | `secubox-eye-remote` (new) | systemd template drop-in scoping a `dnsmasq@eye-remote` instance |
| `/usr/lib/secubox/eye-remote-leasewatch.sh` | `secubox-system` (new) | `dhcp-script` hook |
| `packages/secubox-eye-remote/api/routers/leases.py` | `secubox-eye-remote` (new) | FastAPI router |

### 3.3 Data flow — DHCP attach (Phase 1)

```
Pi gadget attached on USB
  │
  └─ udev rule (shipped by #155) calls eye-remote-connected.sh
       │
       └─ ip link set <iface> master eye-br0     (existing)
             │
             ├─ kernel/networkd brings the L2 port forwarding state up
             │
             └─ Pi-side networkd boots eye0 with DHCP=yes
                   │
                   ├─ DHCPDISCOVER (broadcast on eye-br0)
                   ├─ dnsmasq@eye-remote receives it
                   │     │
                   │     ├─ matches MAC against reservations.conf
                   │     │   ├─ hit  → DHCPOFFER with reserved IP
                   │     │   └─ miss → DHCPOFFER with pool IP
                   │     │            + dhcp-script add → leasewatch.sh
                   │     │                                    │
                   │     │                                    ├─ append
                   │     │                                    │  reservation
                   │     │                                    │  stub
                   │     │                                    └─ POST API
                   │     │                                       /lease-events
                   │     │
                   │     └─ DHCPACK
                   │
                   └─ Pi-side eye0 configured with the offered IP
```

### 3.4 Data flow — Phase 2 pair gate (sketched)

```
DHCPDISCOVER
  │
  └─ dnsmasq@eye-remote → dhcp-script hook
        │
        └─ leasewatch.sh "discover" subcommand →
             POST http://127.0.0.1:8000/api/v1/eye-remote/pair/check
              { mac, vendor_class_id, hostname }
                │
                ├─ approved=true in reservations.toml → 200 OK → DHCPOFFER
                ├─ approved=false                     → 403   → DHCPNAK
                │                                              UI shows
                │                                              "pending"
                └─ unknown MAC, autoapprove=true (Phase 1) →
                   register approved=true, 200 OK
                   (Phase 2 default flips this to autoapprove=false)
```

The Phase 2 gate is a thin wrapper on top of Phase 1 — same dnsmasq, same
reservation file, just a different default for the `approved` flag and a
synchronous decision endpoint instead of an async lease-event notifier.

## 4 — Component design (Phase 1)

### 4.1 dnsmasq instance

A dedicated dnsmasq instance scoped to `eye-br0`. The Debian
`dnsmasq.service` unit is left at its default (disabled — the existing
SecuBox stack does not use a system-wide dnsmasq). Instead we ship a
template-unit drop-in so `systemctl enable --now dnsmasq@eye-remote.service`
starts only this scoped instance.

**`/etc/dnsmasq.d/eye-remote.conf`:**

```conf
# SecuBox Eye Remote — DHCP server for OTG gadgets on eye-br0
# Owned by package secubox-eye-remote; do not hand-edit.

interface=eye-br0
bind-interfaces
listen-address=10.55.0.1
no-resolv
no-hosts
domain-needed
bogus-priv

dhcp-range=10.55.0.10,10.55.0.250,255.255.255.0,24h
dhcp-authoritative
dhcp-leasefile=/var/lib/misc/dnsmasq-eye-remote.leases

dhcp-script=/usr/lib/secubox/eye-remote-leasewatch.sh

# Reservations (auto-managed by leasewatch.sh on first attach)
conf-file=/etc/secubox/eye-remote/reservations.conf

# Tight log scope
log-dhcp
log-facility=/var/log/secubox/eye-remote-dhcp.log
```

The `bind-interfaces` + `interface=eye-br0` pair ensures dnsmasq cannot
accidentally answer DHCP requests on `lan0` or any LXC veth.

### 4.2 Reservations file

`/etc/secubox/eye-remote/reservations.conf` — dnsmasq-format `dhcp-host`
lines, one per known MAC:

```conf
# auto-managed by /usr/lib/secubox/eye-remote-leasewatch.sh
# format: dhcp-host=<MAC>,<IP>,<hostname>,<lease-time>
# (the [tag:approved] field is Phase 2 — present but ignored in Phase 1)
dhcp-host=02:fb:00:00:11:03,10.55.0.11,rpiz-1000000011f3b403,24h
dhcp-host=02:fb:00:00:d2:7f,10.55.0.12,pi4b-00000000d253b17f,24h
```

The hostname encodes the gadget's USB serial (recovered by leasewatch.sh
from `/sys/class/net/<iface>/device/../serial`) so the host can correlate a
DHCP MAC to the USB device that produced it.

Auto-assignment policy: leasewatch.sh starts at `10.55.0.11` and increments
the last octet until it finds an unused slot (skipping `.1` host gateway).
A reservation is only ever appended; never rewritten. Deletion is a manual
operation (admin edits the file + `systemctl reload dnsmasq@eye-remote`).

### 4.3 Lease-watch hook

`/usr/lib/secubox/eye-remote-leasewatch.sh` is the dnsmasq `dhcp-script`
hook. dnsmasq invokes it with `add | old | del` followed by `MAC`, `IP`,
optional `hostname`:

```bash
#!/usr/bin/env bash
set -euo pipefail
action="${1:-}"; mac="${2:-}"; ip="${3:-}"; hostname="${4:-}"

case "$action" in
    add)
        # First-seen MAC?
        if ! grep -qE "^dhcp-host=${mac}," /etc/secubox/eye-remote/reservations.conf 2>/dev/null; then
            serial=$(eye-remote-find-usb-serial "$mac" || echo unknown)
            host="${hostname:-eye-${serial}}"
            echo "dhcp-host=${mac},${ip},${host},24h" \
                >> /etc/secubox/eye-remote/reservations.conf
            systemctl reload dnsmasq@eye-remote.service
        fi
        ;;
    old|del)
        : # currently no-op; Phase 2 may use these for audit
        ;;
esac

# Notify the API (best-effort, no fail on miss)
curl --max-time 2 -s -X POST \
    "http://127.0.0.1:8000/api/v1/eye-remote/lease-events" \
    -H "Content-Type: application/json" \
    -d "{\"action\":\"$action\",\"mac\":\"$mac\",\"ip\":\"$ip\",\"hostname\":\"$hostname\"}" \
    >/dev/null 2>&1 || true
```

The helper `eye-remote-find-usb-serial` resolves a MAC back to the
underlying USB device's serial by walking `/sys/class/net/<iface>/device/`
links. It is a small shell helper shipped under
`/usr/lib/secubox/eye-remote-find-usb-serial`.

### 4.4 FastAPI router

`packages/secubox-eye-remote/api/routers/leases.py`:

```python
from fastapi import APIRouter, Depends
from secubox_core.auth import require_jwt

router = APIRouter(prefix="/eye-remote", tags=["eye-remote"])

@router.get("/leases", dependencies=[Depends(require_jwt)])
def list_leases():
    """Active DHCP leases joined with the reservation registry."""
    return _read_active_leases()

@router.post("/lease-events", dependencies=[Depends(require_jwt)])
def lease_event(body: LeaseEvent):
    """Receives lease-state notifications from the dnsmasq dhcp-script hook
    (loopback only — listener nftables-restricted to 127.0.0.0/8)."""
    _record_event(body)
    return {"status": "recorded"}
```

`_read_active_leases()` parses `/var/lib/misc/dnsmasq-eye-remote.leases`
(one line per active lease: `<expiry-epoch> <mac> <ip> <hostname>
<client-id>`) and cross-references `/etc/secubox/eye-remote/reservations.conf`
for stable hostnames and any Phase 2 `approved` flags. Both files are
read-only from the API's perspective.

### 4.5 Round image change

Round image `eye0` config switches from static peer to DHCP client. Drop-in
file at `/etc/systemd/network/10-eye0.network` on the Pi:

```ini
[Match]
Name=eye0

[Network]
DHCP=yes
LinkLocalAddressing=no
IPv6AcceptRA=no

[DHCPv4]
UseRoutes=true
UseDNS=false
UseNTP=false
RouteMetric=2048
```

A small Round-side `firstboot` snippet sets the Pi's hostname from its USB
serial: `hostnamectl set-hostname eye-${serial}` so DHCP DISCOVER carries a
useful hostname for the registry.

### 4.6 nftables

`eye-br0` is currently outside the SecuBox nftables rules (it inherits the
DEFAULT DROP policy). Add a narrow allow:

```nft
table inet filter {
    chain input {
        # Existing rules …
        iif "eye-br0" udp dport 67 accept comment "eye-remote DHCP server"
        iif "eye-br0" tcp dport 8000 accept comment "eye-remote API"
    }
}
```

No FORWARD rules — Pis cannot reach `lan0` or any LXC subnet.

## 5 — Failure modes & recovery

| Failure | Detection | Recovery |
|---|---|---|
| dnsmasq@eye-remote down | systemd `Active=failed` ; API returns 503 from `/leases` ; new gadgets get no IP | `Restart=on-failure` (5s); admin via `journalctl -u dnsmasq@eye-remote` |
| reservations.conf corrupt | dnsmasq fails to start on reload; preserves previous in-memory state until restart | `dpkg-reconfigure secubox-eye-remote` regenerates from `/var/lib/secubox/eye-remote/reservations.conf.bak` (rotated by leasewatch.sh on each successful append) |
| leasewatch.sh fails | dnsmasq still hands out lease (script errors are logged, not fatal) ; API lease-event missed | Periodic API task (60s) reconciles `dnsmasq-eye-remote.leases` against its in-memory registry |
| Pi-side DHCP times out | Pi falls back to `eye0` link-local; not pingable from host | Pi-side `Restart=always` on `systemd-networkd-wait-online@eye0.service`; user redeploys image |
| Two Pis briefly request same hostname | dnsmasq logs warn; lease still issued by MAC | leasewatch.sh appends `-${serial-suffix}` to disambiguate before writing reservation |
| Bridge `eye-br0` missing at boot | dnsmasq fails to bind (interface not present) | `dnsmasq@eye-remote.service` declares `After=sys-subsystem-net-devices-eye_br0.device` + `Requires=` so it waits for the bridge |

## 6 — Test plan

### 6.1 Unit (no hardware)

- `tests/unit/eye_remote/test_reservations.py` — round-trip parse / serialize of the reservations.conf format, including the Phase 2 `approved` tag.
- `tests/unit/eye_remote/test_lease_parser.py` — parse `dnsmasq-eye-remote.leases` lines including expired entries.
- `tests/unit/eye_remote/test_leasewatch_assign.py` — given a starting set of reservations + an incoming MAC, asserts leasewatch picks the lowest free octet ≥ `.11`.

### 6.2 Integration (network-namespaced)

- `tests/integration/eye-remote/test_multi_gadget_dhcp.py` — spin up a Linux net-namespace pair with a veth bridge, run dnsmasq inside, simulate two `dhclient` instances with distinct MACs, assert each gets a unique reserved IP across restarts.

### 6.3 Acceptance (live board)

Manual gate, executed on `192.168.1.200` after Phase 1 ships:

1. Power-cycle the rpiz; observe DHCPDISCOVER → DHCPACK in
   `journalctl -u dnsmasq@eye-remote`.
2. Power-cycle the Pi 4B; observe a second distinct lease.
3. From the host, `ping 10.55.0.11` and `ping 10.55.0.12` — both respond.
4. `curl http://10.55.0.1:8000/api/v1/eye-remote/leases` lists both gadgets
   with stable hostnames and matching USB serials.
5. Unplug + replug each Pi; lease and reservation persist across both
   events (no new IP issued).
6. Reboot the host; both gadgets reattach with the same IPs after boot.

## 7 — Migration & compatibility

- The current Round image keeps its `eye0` static-IP firmware until the
  Phase 1 image rebuild lands; mixed-fleet behaviour during the transition
  is the same as today — only one statically-addressed Pi works at a time.
- Existing in-field Pis must be reflashed via the standard eye-remote image
  build (`remote-ui/round/build-eye-remote-image.sh`) once the DHCP-client
  change is in. The image will not auto-upgrade.
- `MULTI-GADGET.md` stays in tree as historical context; a "Resolved by
  #158" banner is added at the top once Phase 1 lands.

## 8 — Open questions (recorded; pinned during plan-writing)

- **Q1**: Should the DHCP lease lifetime be 24h or shorter (1h)? 24h aligns
  with the systemd-networkd default and minimises log spam; 1h gives faster
  reservation reuse if Pis are routinely rotated. **Recommendation: 24h
  for Phase 1, parameterise for Phase 2.**
- **Q2**: Pi-side hostname — `eye-${serial}` (verbose, traceable) vs
  `eye-${last4-of-mac}` (short, may collide). **Recommendation: full
  serial.**
- **Q3**: Where does the lease-events POST go through? Loopback over TCP
  (current API listens on `127.0.0.1:8000` via nginx) keeps the auth path
  identical to other internal callers; a Unix socket on
  `/run/secubox/eye-remote-events.sock` would tighten the surface further.
  **Recommendation: loopback for Phase 1, switch to Unix socket if Phase 2
  pairing approval adds CSPN-relevant audit requirements.**

## 9 — Phase 2 stub (recorded, not implemented here)

When Phase 2 starts:

1. Flip `autoapprove` from `true` → `false` in the Phase 1 leasewatch hook's
   default config; new MACs get `approved=false`.
2. Add `POST /api/v1/eye-remote/pair/check` synchronous endpoint (replaces
   the `lease-events` async notifier for the discover path; the event
   notifier survives for `add/old/del` lifecycle reporting).
3. Wire `dhcp-script` to call `pair/check` synchronously before answering
   DHCPDISCOVER; on non-200 return, dnsmasq is invoked with the
   `--dhcp-ignore` flag dynamically via signal-driven config reload.
4. UI: new SecuBox dashboard tile listing `pending_pairing` MACs with
   Approve / Reject buttons; decisions write back to reservations.conf with
   `approved=true|false`.
5. Optional Phase 2.5: require a NIZK pair proof — `pair/check` verifies a
   ZKP submitted by the Pi via a tiny pre-DHCP HTTP exchange on
   `10.55.0.1:8001` (separate port to avoid coupling to the main API).

The Phase 1 deliverables intentionally do not block on any Phase 2 design
decision: every Phase 2 change extends a Phase 1 file rather than
replacing it.
