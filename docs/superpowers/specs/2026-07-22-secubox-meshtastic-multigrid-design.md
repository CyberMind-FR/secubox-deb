# secubox-meshtastic — Multi-Grid LoRa Mesh Node + Passive Listener — Design

**Goal:** A SecuBox module that turns the box into a Meshtastic node driving a USB-attached LoRa device, operating across three composable "grids" (off-grid RF, private shared-grid over MirrorNet, opt-in public on-grid MQTT), and optionally as a passive RF listener that feeds the SOC.

**Architecture:** A native-host daemon (`secubox-meshtasticd`) owns the serial device via the `meshtastic` Python API, maintains live mesh state behind the double-cache pattern, and performs **host-side** serial↔MQTT bridging so SecuBox — not the device firmware — enforces egress, WAF routing, and per-channel grid policy. A FastAPI webui + hub panel present it; a confined `ctl` handles privileged config (PSKs, region, grid/egress toggles). Private shared-grid federation rides a self-hosted mosquitto bound to the existing WireGuard MirrorNet.

**Tech stack:** Python 3.11 + `meshtastic` (SerialInterface, pubsub) + FastAPI/uvicorn; mosquitto (private broker); nftables egress control; WAF/mitmproxy for public egress; vanilla-JS webui (cyan hybrid-dark skin). Native host module (systemd), not LXC.

## Global constraints

- **Band EU868** (863–870 MHz). Device region set to `EU_868`.
- **Host-side MQTT bridging only** — never device-firmware MQTT (the device has no independent uplink and firmware bridging would be an uncontrolled exfil path).
- **No `waf_bypass`**; public egress is `nft` DEFAULT DROP + explicit broker allow + WAF/mitmproxy; **off by default, opt-in per channel**.
- **Privilege separation**: dedicated `secubox-meshtastic` user (in `dialout`); privileged config only through the audited `secubox-meshtasticctl` (webui→ctl); secrets `0600` under `/etc/secubox/secrets/meshtastic/`.
- **Graceful no-device state**: with no radio attached (the current reality — see #897), the daemon runs, serves the webui, and persists all config; it reports `radio: absent` rather than failing.
- **Offline-clean webui**: no external tile CDN or font/CDN dependency (CSP + off-grid ethos).

---

## 1. Purpose & scope

SecuBox becomes a first-class Meshtastic participant. One module, two capabilities, selectable by mode:

- **Active node** — send/receive text, positions, telemetry across the grids.
- **Passive listener** — observe-only capture of everything heard on the configured RF preset, feeding the SOC (RF-layer analogue of DPI).

Mode selector: `active-node` | `passive-listener` | `both`.

All three grids are specified and built in v1 (implementation MAY still land in layers, but the grid abstraction is designed up front). Hardware procurement is tracked in **#897**; board validation is deferred until a device is purchased.

## 2. Hardware

Recommended: **RAK WisBlock Meshtastic Starter Kit EU868 (RAK19007 + RAK4631, SX1262 / nRF52840)** + an external 868 MHz SMA antenna (dominant factor given gk2's valley siting). Alternative with GPS+battery: **LILYGO T-Beam Supreme EU868**. Full shortlist, prices, and EU/FR merchant links in **#897**. The device choice is grid-agnostic — a "dumb radio" the host drives over USB serial (`/dev/ttyUSB*` or `/dev/ttyACM*`).

## 3. Grid model

Meshtastic natively supports peer-to-peer + multi-hop relay (off-grid) and MQTT bridging (on-grid). SecuBox maps these to three grids, and — like the Punk Exposure engine's Tor/DNS/Mesh channels — **each Meshtastic channel independently selects its grid(s)** (per-channel grid policy).

| Grid | Mechanism | Transport | Default | Notes |
|---|---|---|---|---|
| **off-grid** | LoRa RF managed-flood mesh | radio | on (when a device is present) | P2P direct hops **and** automatic multi-hop relay; AES per-channel PSK |
| **shared-grid** (private) | serial↔MQTT bridge to a private broker | **WireGuard MirrorNet (10.10.0.0/24)** | opt-in per channel | SecuBox↔SecuBox federation of local LoRa meshes over the already-encrypted mesh; broker binds to the mesh IP only, never `0.0.0.0` |
| **on-grid** (public) | serial↔MQTT bridge to a public broker | Internet (WAF/mitmproxy, `nft` egress-locked) | **off** (opt-in per channel) | connects to the global community mesh; TLS to broker; the only exfil surface, tightly contained |

**Linchpin — host-side bridging.** The daemon (not the device) republishes MeshPackets between the serial mesh and MQTT brokers, applying per-channel grid policy. This is what makes "all three grids, safely" possible: only the host can egress-lock, WAF-route, and gate per channel. MQTT topic mapping follows Meshtastic's `msh/<region>/2/e/<channel>/<gatewayId>` convention for encrypted republish.

## 4. Components

Each component has one responsibility and a defined interface:

1. **`secubox-meshtasticd`** (host daemon; systemd; `User=secubox-meshtastic` ∈ `dialout`).
   - Owns the serial device via `meshtastic.SerialInterface`; subscribes to `meshtastic.receive`, `meshtastic.node.updated`, `meshtastic.connection.{established,lost}`.
   - Maintains live state (nodes, messages per channel, telemetry, channels) behind the **double-cache pattern** (in-memory + `/var/cache/secubox/meshtastic/state.json`, background refresh thread — the pattern the cache-lint recognizes).
   - Presents a local control API (Unix socket `/run/secubox/meshtastic.sock`) for the webui: read state, send message, set desired config (validated), report status.
   - Implements the **grid bridge** (§3) and the **passive capture pipeline** (§5).
   - Handles the `radio: absent` state (poll for device presence; never crash on no device).

2. **Private MQTT broker** (mosquitto): self-hosted, bound to the MirrorNet WG IP, for shared-grid federation. Hardened systemd unit; ACL restricting topics; no anonymous access. Only present when shared-grid is enabled.

3. **`secubox-meshtasticctl`** (root `ctl`, webui→ctl): privileged config — set channel PSK, set region/modem preset, set node role (incl. `CLIENT_MUTE`), toggle a channel's grid policy, (re)generate the `nft` egress allow-list for on-grid brokers, provision the private broker. Scoped, audited to `/var/log/secubox/audit.log`. The panel `sudo`s to it (systemd-run to escape `ProtectSystem=strict`, as with profiles).

4. **FastAPI webui** (reads the cache; sends via the daemon socket) + **hub panel** (cyan hybrid-dark skin, Courier Prime — WEBUI-PANEL-GUIDELINES).

5. **Secrets**: `/etc/secubox/secrets/meshtastic/` (channel PSKs, MQTT credentials/TLS), `0600`, owner `secubox-meshtastic`.

## 5. Passive listener mode

- **Observe-only posture** = Meshtastic **`CLIENT_MUTE`** role (receives + displays, does **not** rebroadcast/relay, minimal TX — does not announce into the mesh). Set via `ctl`.
- **Capture pipeline**: every received packet → normalize → **append-only packet log** `/var/log/secubox/meshtastic/packets.jsonl` (CSPN audit style, RFC-3339 timestamps, rotation without truncate) + **passive node census** (every node *heard*, including non-members: node ID, shortname/longname, position, hardware, role, first/last-heard, RSSI/SNR) + **per-channel activity stats**.
- **Decryption scope**: channels whose PSK we hold (including the public `LongFast` default) are decoded to payloads; all others are logged **metadata-only** from the cleartext LoRa header (from/to node IDs, channel hash, portnum, hop limit, RSSI/SNR).
- **SOC integration**: the census + packet feed drive dashboard widgets and alerting hooks (new node appeared, position jump, traffic spike).
- **Honest RF limitation** (documented, not hidden): one radio hears **one modem preset (frequency slot + spreading factor) at a time**; simultaneous full-spectrum capture needs multiple radios or an SDR (a future SDR-backed variant is a separate study). Undecryptable channels remain metadata-only.

## 6. Security / CSPN posture

- **off-grid**: Meshtastic AES per-channel PSK (native).
- **shared-grid**: MQTT rides the existing WireGuard MirrorNet (already-encrypted transport); broker binds to the mesh IP only; topic ACLs; contained.
- **on-grid (public)**: `nft` egress DEFAULT DROP → allow only the configured broker host:port; TLS to the broker; routed via WAF/mitmproxy (no bypass); **opt-in per channel**, off by default. The `nft` allow-list is generated by `ctl` from the enabled on-grid brokers.
- **Privilege separation**: `secubox-meshtastic` user; privileged ops only via the audited `ctl`; secrets `0600`.
- **Immutable audit**: grid toggles, PSK changes, egress changes, and role changes written to `/var/log/secubox/audit.log` (append-only).

## 7. Data model & interfaces

- **State (cache)** `/var/cache/secubox/meshtastic/state.json`: `{ radio: present|absent, mode, nodes[], channels[], messages_by_channel, telemetry, grids: {off,shared,on per channel}, bridges: {shared,on: up|down, peers} }`.
- **Packet log** `/var/log/secubox/meshtastic/packets.jsonl`: one JSON object per heard packet (ts, from, to, channel_hash, portnum, decoded?|metadata-only, rssi, snr, hop).
- **Desired config** (TOML) `/etc/secubox/meshtastic.toml`: mode, region, channels (name, grid policy), brokers (private/public, endpoints), passive settings. Secrets referenced by name, not inlined.
- **HTTP API** (`/api/v1/meshtastic/…`, JWT-guarded): `GET status`, `GET nodes`, `GET messages`, `GET telemetry`, `GET packets` (passive feed), `POST send`, `POST channel` (→ ctl), `POST grid` (→ ctl), `POST mode` (→ ctl). Read endpoints serve the cache; action endpoints delegate to the daemon/ctl.

## 8. Webui scope (v1)

Nodes list + **offline node map** (canvas plot of GPS positions with SNR/distance rings — no external tiles) · messages send/receive per channel · **channels with per-channel grid policy toggle** (off / shared / on) · telemetry (battery/env) · **grid dashboard** (radio present?, grids up, bridge/peer status) · **Sniffer view** (live packet feed, full heard-node census, channel activity, SNR heatmap) · device admin (region EU868, role, PSK) via ctl.

## 9. Testing

- Mock `meshtastic.SerialInterface` (CI has no device): packet→state parsing, the `radio: absent` path, cache correctness.
- **Grid-policy routing**: given a channel policy set, assert which packets bridge to which broker (and that off/off-by-default holds).
- **Egress allow-list generation**: `ctl` produces the expected `nft` rules for enabled on-grid brokers (and nothing when none enabled).
- **Passive pipeline**: a fake packet stream produces the expected packet-log lines + census + metadata-only handling for unknown channels.
- MQTT bridge tested against a local mosquitto.
- Board validation (real RF, real device, EU868 range from the valley) **deferred to hardware arrival (#897)**.

## 10. Modes & config summary

```toml
# /etc/secubox/meshtastic.toml (desired state; secrets referenced by name)
mode = "both"            # active-node | passive-listener | both
region = "EU_868"
serial = "auto"          # or /dev/ttyACM0

[[channel]]
name = "family"
grid = ["off", "shared"]        # off-grid + private federation, no internet
psk_secret = "family-psk"

[[channel]]
name = "community"
grid = ["off", "on"]            # off-grid + public MQTT (opt-in, WAF-routed)
psk_secret = "community-psk"

[shared_grid]
broker = "10.10.0.1:1883"       # private mosquitto on MirrorNet WG

[on_grid]
broker = "mqtt.example.org:8883"  # public, TLS, nft-egress-locked, WAF-routed
enabled = false

[passive]
role = "CLIENT_MUTE"
packet_log = "/var/log/secubox/meshtastic/packets.jsonl"
```

## 11. Open questions / future

- **SDR-backed wide capture** (hear multiple presets at once) — separate study; out of scope for v1.
- **Bridge to MirrorNet application layer** (relay Meshtastic messages as SecuBox mesh events / alerts) — candidate follow-up once shared-grid is live.
- **Multi-device** (one radio per preset) — future, if passive coverage needs to widen.
