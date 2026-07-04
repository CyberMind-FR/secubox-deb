# Per-vhost exposure switch (localhost/LAN/WAN + mesh/Tor) — design

**Issue:** #793 · **Date:** 2026-07-04 · **Status:** design

## Goal

Give operators a per-vhost **exposure switch** that decides how far each service
reaches, from one control surface:

- a **nested network-reach** setting — `localhost ⊂ LAN ⊂ WAN` (pick one level; each
  includes the narrower ones),
- plus two independent **channel toggles** — `mesh` (wg-mesh peers) and `Tor` (onion).

**Secure-by-default:** a vhost's default exposure is **LAN-only, mesh off, Tor off**
(PUNK-EXPOSURE / CSPN — nothing is auto-exposed to the WAN).

**Control** lives in the **secubox-exposure** webui (configure + apply); **display** of
the current per-vhost state lives in the **secubox-vhost** webui (read-only).

## Model

A per-vhost exposure record, owned by secubox-exposure's state:

```json
{ "vhost": "zigbee.gk2.secubox.in",
  "reach": "lan",          // "localhost" | "lan" | "wan"
  "mesh": false,
  "tor": false }
```

`reach` is the exclusive network scope; `mesh`/`tor` are additive channels. Default for a
newly-recorded vhost: `reach=lan, mesh=false, tor=false`.

## Application (per channel)

### reach → nginx include snippet
secubox-exposure writes `/etc/nginx/snippets/exposure/<vhost>.conf`; each vhost includes
it **once** inside its gated `location` block(s):

- `localhost`:
  ```nginx
  allow 127.0.0.1;
  deny all;
  ```
- `lan`:
  ```nginx
  allow 127.0.0.1;
  allow 10.0.0.0/8;
  allow 172.16.0.0/12;
  allow 192.168.0.0/16;
  deny all;
  ```
- `wan`: an **empty** snippet (no restriction — public).
- when `mesh=true`, `allow 10.10.0.0/24;` (the wg-mesh CIDR) is added to the snippet
  regardless of reach, so mesh peers reach the vhost even at `localhost`/`lan`.

**real_ip is load-bearing.** These `allow`/`deny` match `$remote_addr`. Behind
HAProxy→sbxwaf→nginx that is `127.0.0.1` unless the global `set_real_ip_from` /
`real_ip_header X-Forwarded-For` (shipped by secubox-hub `nginx/secubox-lan-geo.conf`,
http context) rewrites it to the real client IP. The design REQUIRES that rewrite to be
in effect for the gated server; the acceptance test proves a real external IP is denied at
`lan`/`localhost` (a hand-patched vhost earlier failed exactly here).

### mesh toggle
Reuses the existing exposure **emancipate mesh** channel (nft allow of the mesh CIDR to
the backend port + annuaire advertise) for true direct mesh-IP access, AND adds the
`allow 10.10.0.0/24;` line to the reach snippet (so the HTTP vhost also accepts mesh
peers). Toggling off revokes both.

### Tor toggle
Reuses the existing `/tor/add` and `/tor/remove` endpoints (onion hidden service).
No new mechanism.

## Components

1. **Exposure model + state** (secubox-exposure): the per-vhost record above, persisted in
   the module's state file; add `reach` to the channel model (Tor/mesh already exist).
2. **Snippet generator** (secubox-exposure): `reach + mesh → allow/deny block`; atomic
   write to `/etc/nginx/snippets/exposure/<vhost>.conf`, `nginx -t` before reload,
   fail-safe (keep last-good snippet on error). Pure, unit-testable.
3. **Exposure API** (secubox-exposure): `GET /exposure/{vhost}` (current record),
   `POST /exposure/{vhost}` `{reach, mesh, tor}` (set + apply: regenerate snippet, toggle
   tor/mesh, reload nginx), guarded by `require_jwt`; append to audit log.
4. **Exposure webui panel** (secubox-exposure): reach slider (localhost/LAN/WAN) + mesh &
   Tor toggles per vhost, with immediate apply + a health/reachability readout.
5. **Vhost exposure display** (secubox-vhost): `GET /vhosts` gains an `exposure` field
   (read the active snippet + tor/mesh state → derive `{reach, mesh, tor}`); the webui
   shows a per-vhost exposure badge (localhost/LAN/WAN + 🕸️ mesh + 🧅 Tor). Read-only;
   editing links to the exposure module.
6. **Vhost include wiring**: secubox-vhost's generated-vhost template emits the one-line
   `include /etc/nginx/snippets/exposure/<vhost>.conf;` in its gated location; the two
   hand-authored vhosts touched during discovery (zigbee, lyrion) get the same line.
   A vhost with no snippet file present → the include is `include ... ;` guarded so a
   missing snippet doesn't 500 (ship a default LAN snippet on first record, and use
   nginx's tolerant include only if the file exists — see Safety).

## Data flow

```
operator sets reach/mesh/tor in exposure webui
  → POST /exposure/{vhost}
  → write state record
  → regenerate /etc/nginx/snippets/exposure/<vhost>.conf   (reach + mesh CIDR)
  → toggle tor (/tor/add|remove) + mesh (emancipate) as needed
  → nginx -t && reload
  → secubox-vhost /vhosts reflects the new exposure (reads the snippet)
```

## Safety, security, CSPN

- **Never edit vhost files** — only the per-vhost snippet. (Regex edits on vhosts is what
  broke zigbee during discovery.)
- **Atomic + validated**: write snippet to a temp file, `nginx -t`, then swap + reload;
  on any failure keep the last-good snippet and report.
- **Missing-snippet safety**: a vhost's `include` must not 500 if the snippet is absent.
  Ship the snippet on first record; where a vhost may be included before a record exists,
  the packaging creates a default `lan` snippet so the file always exists. (nginx `include`
  of a missing file is a hard error, so the file must exist — the generator/packaging
  guarantees it.)
- **Default LAN-only**, but **no silent re-confinement**: applying the default must not
  flip an already-public vhost to LAN and break remote access. On first adoption a vhost's
  record is created from its CURRENT effective reach (public vhost → `wan`), not blindly
  `lan`; `lan` is the default only for vhosts with no current public route.
- **real_ip verified**: acceptance test asserts a simulated external client is denied at
  `lan`/`localhost` and allowed at `wan`, proving the gate is effective (not a no-op).
- **Audit**: every exposure change appended to `/var/log/secubox/audit.log`.

## Testing

- **Snippet generator (golden)**: each `reach` (+ mesh on/off) → exact allow/deny block;
  `wan` → empty; `localhost` → deny-all-but-127; mesh adds the mesh CIDR.
- **real_ip effectiveness (live/acceptance)**: with the snippet at `lan`, a request whose
  real client IP is external is denied (403); LAN/mesh allowed; at `wan` all allowed.
- **API**: set/get round-trips the record; apply regenerates the snippet + reloads;
  auth-guarded; audit written.
- **Vhost display**: `/vhosts` derives the correct `{reach, mesh, tor}` from the snippet +
  tor/mesh state.
- **Fail-safe**: a generator error keeps the previous snippet; nginx-t failure aborts the
  swap.

## Scope / decomposition

Single spec. The **new** work is: the `reach` model + the nginx snippet generator + the
exposure API/webui reach control + the vhost exposure display + the include wiring. The
**mesh** and **Tor** channels reuse the existing exposure mechanisms (emancipate mesh / nft
+ annuaire; `/tor/add`) plus the mesh-CIDR allow line. Deep "mesh-direct service" (nft port
+ annuaire advertise) stays on the existing emancipate channel — not re-implemented here.

## Out of scope / follow-ons

- The sbxwaf WebSocket-forwarding gap (zigbee z2m `wss://…/api` 404 through the WAF) —
  separate live/ops issue.
- The pretty error pages (#789) — separate.
- A fleet-wide "expose this on all nodes" mesh-federated exposure — later.
