# Tor Enhancement — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the box's Tor stack into an egress-VPN + hidden-service exposure control surface: global exit-country, per-LAN-client Tor-VPN, emancipate the webui as a `.onion` (auto-detected, standalone), persist `.onion`s across restarts, and auto `.onion` DNS.

**Architecture:** Extend the existing on-demand Tor egress (`secubox-toolbox-tor-reconcile` drop-in mechanism + `nft-toolbox-tor.nft` + `torrc-toolbox-egress.conf`) with an exit-country drop-in and a NEW prerouting nft chain for per-client routing; extend `secubox-exposure`'s `_tor_add_sync` HS machinery with a standalone `federate` flag + a persist-on-boot reconcile; make `secubox-tor`'s webui the presentation layer (country picker, VPN-client table, emancipate button, auto-detected `.onion` list, `.onion`-DNS status). State lives in flat files under `/etc/secubox/toolbox/`.

**Tech Stack:** bash (reconcile), nftables, tor (torrc.d drop-ins, control port), Unbound (forward-zone drop-in), Python/FastAPI (`secubox-tor`, `secubox-exposure` APIs), pytest, vanilla JS dashboard, Debian packaging.

## Global Constraints

- **Tor egress is on-demand** (`#793` switch: `filters.json` `tor_mode` → `secubox-toolbox-tor.path` → `secubox-toolbox-tor-reconcile arm|disarm`). All Phase-1 features are **gated on egress being armed** — a disarmed box has no torrc/nft drop-ins and Tor stopped.
- **Existing egress is skuid-based** (`meta skuid "secubox-toolbox"` in `nft-toolbox-tor.nft` output hooks) — it torifies the mitm/"kbin" egress *user*, NOT LAN clients. Per-client Tor-VPN (feature ⑤) is a SEPARATE new `prerouting` chain matching client source IPs; do not repurpose the skuid output chain.
- **DNSPort is referenced in TWO places** — `torrc-toolbox-egress.conf` (`DNSPort 127.0.0.1:5353`) and `nft-toolbox-tor.nft` (`redirect to :5353`). Moving it to `9053` (feature ④, to clear the avahi-daemon conflict on 5353) MUST update both, in lockstep.
- **Fail-closed** is sacred: nft (incl. kill-switch) loads BEFORE tor starts; a country with no exit (`StrictNodes 1`) must be surfaced, never silently leaked direct.
- **Drop-in survival:** nft drop-ins go to `/etc/nftables.d/zz-*.nft` (load after wg tables); torrc drop-ins to `/etc/tor/torrc.d/*.conf` (with the idempotent `%include`). Reconcile re-applies them; never rely on runtime-only state.
- **Validation before write:** ISO-3166 alpha-2 country codes (`^[A-Za-z]{2}$`), client selectors (`ip`/`cidr` via `ipaddress`, `mac` via `^[0-9a-fA-F:]{17}$`) — reject invalid with 400, no state change.
- **State store:** flat files under `/etc/secubox/toolbox/`, owned `secubox-toolbox:secubox-toolbox` — `tor-exit-country.txt` (one CC per line) and `tor-vpn-clients.txt` (one `kind:selector` per line). Mirrors the existing `tor-exempt-hosts` / exclusion file pattern.
- **No `waf_bypass`**; emancipated webui `.onion` routes the normal nginx hub (`HiddenServicePort 80 → 127.0.0.1:9080`). Never re-chown/loosen `/run/secubox` (1777), `/etc/secubox` (0755), `/var/log/secubox` (0755) parents.
- **Aggregator safety:** any handler in an aggregator-mounted module that shells out is plain `def` (never `async def` on a subprocess) — verify per module before adding handlers.
- **Board:** `ssh root@192.168.1.200`. Tor egress currently OFF; live tasks must `arm` first, verify, then restore prior state.
- **Reference files (read before mirroring):** `packages/secubox-toolbox/sbin/secubox-toolbox-tor-reconcile`, `packages/secubox-toolbox/conf/{nft-toolbox-tor.nft,torrc-toolbox-egress.conf}`, `packages/secubox-exposure/api/main.py` (`_tor_add_sync` @658, discovery @533, `/emancipate` @812), `packages/secubox-tor/api/main.py` (`/hidden_services` @433).

---

## File Structure

- `packages/secubox-toolbox/conf/torrc-toolbox-egress.conf` — `DNSPort` → 9053.
- `packages/secubox-toolbox/conf/nft-toolbox-tor.nft` — `redirect to :9053`; NEW `prerouting` client-VPN chain.
- `packages/secubox-toolbox/conf/48-secubox-onion.conf` — NEW Unbound forward-zone (installed to `/etc/unbound/unbound.conf.d/`).
- `packages/secubox-toolbox/sbin/secubox-toolbox-tor-reconcile` — emit exit-country drop-in, per-client nft set, install/neutralize Unbound `.onion` forward-zone on arm/disarm.
- `packages/secubox-toolbox/api/…` (the toolbox portal API) — exit-country + VPN-client CRUD writing the state files + audit.
- `packages/secubox-exposure/api/main.py` — `federate` flag on the emancipate path; `secubox-exposure-tor-reconcile` persist-on-boot + unit; webui-emancipate endpoint.
- `packages/secubox-tor/api/main.py` — filesystem-discovering `/hidden_services`; `.onion`-DNS status; proxy/read of toolbox exit-country + VPN state for the UI.
- `packages/secubox-toolbox/www/toolbox/index.html` (the existing `#tor` tab, `data-tab="tor"`) — add country picker, VPN-client table, emancipate button, `.onion` list, DNS status ALONGSIDE the existing Tor-egress switch. (The Tor UI lives in `/toolbox/#tor`, not a separate `/tor/` page.)

---

### Task 1: ④ Move DNSPort 5353→9053 + Unbound `.onion` forward-zone

**Files:**
- Modify: `packages/secubox-toolbox/conf/torrc-toolbox-egress.conf`
- Modify: `packages/secubox-toolbox/conf/nft-toolbox-tor.nft`
- Create: `packages/secubox-toolbox/conf/48-secubox-onion.conf`
- Modify: `packages/secubox-toolbox/sbin/secubox-toolbox-tor-reconcile`

**Interfaces:**
- Produces: egress DNSPort on `127.0.0.1:9053`; `arm` installs `/etc/unbound/unbound.conf.d/48-secubox-onion.conf` + reloads unbound; `disarm` removes it + reloads. Consumed by all later tasks (the automap DNS backend).

- [ ] **Step 1: Write the failing test** — `packages/secubox-toolbox/tests/test_onion_dns.py`:
```python
from pathlib import Path
CONF = Path(__file__).resolve().parents[1] / "conf"
def test_dnsport_moved_off_avahi_5353():
    torrc = (CONF / "torrc-toolbox-egress.conf").read_text()
    assert "DNSPort 127.0.0.1:9053" in torrc
    assert "5353" not in torrc          # avahi owns 5353
def test_nft_redirect_targets_9053():
    nft = (CONF / "nft-toolbox-tor.nft").read_text()
    assert "redirect to :9053" in nft
    assert ":5353" not in nft
def test_unbound_onion_forward_zone_valid():
    conf = (CONF / "48-secubox-onion.conf").read_text()
    assert 'name: "onion."' in conf
    assert "forward-addr: 127.0.0.1@9053" in conf
```

- [ ] **Step 2: Run — expect FAIL** (`cd packages/secubox-toolbox && python3 -m pytest tests/test_onion_dns.py -q`) → fails (5353 still present, file missing).

- [ ] **Step 3: Edit the two configs + create the Unbound drop-in**
  - In `conf/torrc-toolbox-egress.conf`: change `DNSPort 127.0.0.1:5353` → `DNSPort 127.0.0.1:9053`.
  - In `conf/nft-toolbox-tor.nft`: change `redirect to :5353` → `redirect to :9053`.
  - Create `conf/48-secubox-onion.conf`:
```
# SecuBox: resolve .onion via the toolbox Tor egress DNSPort (automap).
# Installed by secubox-toolbox-tor-reconcile only while egress is armed.
server:
    do-not-query-localhost: no
forward-zone:
    name: "onion."
    forward-addr: 127.0.0.1@9053
```

- [ ] **Step 4: Wire the reconcile** — in `sbin/secubox-toolbox-tor-reconcile`, add near the other path constants:
```bash
UNBOUND_ONION_SRC=/usr/lib/secubox/toolbox/conf/48-secubox-onion.conf
UNBOUND_ONION_DST=/etc/unbound/unbound.conf.d/48-secubox-onion.conf
```
In `arm()` (after tor start), install + reload unbound:
```bash
  if [ -f "$UNBOUND_ONION_SRC" ] && [ -d /etc/unbound/unbound.conf.d ]; then
    install -m 0644 "$UNBOUND_ONION_SRC" "$UNBOUND_ONION_DST"
    unbound-checkconf >/dev/null 2>&1 && systemctl reload unbound 2>/dev/null || \
      { rm -f "$UNBOUND_ONION_DST"; log "WARN unbound .onion forward-zone rejected — removed"; }
  fi
```
In `disarm()`:
```bash
  if [ -f "$UNBOUND_ONION_DST" ]; then rm -f "$UNBOUND_ONION_DST"; systemctl reload unbound 2>/dev/null || true; fi
```

- [ ] **Step 5: Run test → PASS** and `bash -n sbin/secubox-toolbox-tor-reconcile`.

- [ ] **Step 6: Commit**
```bash
git add packages/secubox-toolbox/conf/{torrc-toolbox-egress.conf,nft-toolbox-tor.nft,48-secubox-onion.conf} packages/secubox-toolbox/sbin/secubox-toolbox-tor-reconcile packages/secubox-toolbox/tests/test_onion_dns.py
git commit -m "feat(toolbox): move Tor egress DNSPort 5353→9053 (avahi conflict) + Unbound .onion forward-zone"
```

---

### Task 2: ① Global exit-country — torrc drop-in + reconcile + state file

**Files:**
- Modify: `packages/secubox-toolbox/sbin/secubox-toolbox-tor-reconcile`
- Test: `packages/secubox-toolbox/tests/test_exit_country.py`

**Interfaces:**
- Consumes: reconcile arm/disarm. Produces: `arm` reads `/etc/secubox/toolbox/tor-exit-country.txt` (one ISO CC per line), and if non-empty writes `/etc/tor/torrc.d/11-secubox-exit-country.conf` with `ExitNodes {cc},… ` + `StrictNodes 1`; empty/absent → no such drop-in (default routing). A bash helper `_exit_country_dropin` emits the config.

- [ ] **Step 1: Write the failing test** (drives a testable bash helper via a hidden subcommand) — `tests/test_exit_country.py`:
```python
import subprocess, os
from pathlib import Path
CTL = Path(__file__).resolve().parents[1] / "sbin" / "secubox-toolbox-tor-reconcile"
def _emit(codes, tmp_path):
    f = tmp_path / "cc.txt"; f.write_text(codes)
    return subprocess.run(["bash", str(CTL), "__emit_exit_country", str(f)],
                          capture_output=True, text=True)
def test_valid_codes_emit_exitnodes(tmp_path):
    r = _emit("DE\nFR\n", tmp_path)
    assert "ExitNodes {de},{fr}" in r.stdout.lower()
    assert "StrictNodes 1" in r.stdout
def test_empty_emits_nothing(tmp_path):
    assert _emit("\n", tmp_path).stdout.strip() == ""
def test_bad_code_skipped(tmp_path):
    r = _emit("DE\nXXX\n12\n", tmp_path)
    assert "{de}" in r.stdout.lower()
    assert "xxx" not in r.stdout.lower() and "{12}" not in r.stdout.lower()
```

- [ ] **Step 2: Run — expect FAIL** (subcommand unknown).

- [ ] **Step 3: Implement the helper + wire arm** — in the reconcile, add:
```bash
EXIT_CC_STATE=/etc/secubox/toolbox/tor-exit-country.txt
EXIT_CC_DROPIN=/etc/tor/torrc.d/11-secubox-exit-country.conf
# Emit an ExitNodes/StrictNodes stanza from a CC-per-line file. Invalid codes
# (not exactly 2 ASCII letters) are dropped. Empty result → emit nothing.
_emit_exit_country() {
  local f="$1" cc list=""
  [ -f "$f" ] || return 0
  while IFS= read -r cc; do
    cc="$(echo "$cc" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
    [[ "$cc" =~ ^[a-z]{2}$ ]] || continue
    list="${list:+$list,}{$cc}"
  done < "$f"
  [ -n "$list" ] || return 0
  printf 'ExitNodes %s\nStrictNodes 1\n' "$list"
}
```
Add the dispatch arm to `main()`'s `case`: `__emit_exit_country) _emit_exit_country "${2:-}"; exit 0 ;;` (place BEFORE the `*)` catch-all). In `arm()`, after the egress torrc install:
```bash
  local cc_stanza; cc_stanza="$(_emit_exit_country "$EXIT_CC_STATE")"
  if [ -n "$cc_stanza" ]; then printf '# SecuBox exit-country\n%s\n' "$cc_stanza" > "$EXIT_CC_DROPIN"
  else rm -f "$EXIT_CC_DROPIN"; fi
```
In `disarm()`: `rm -f "$EXIT_CC_DROPIN"`.

- [ ] **Step 4: Run test → PASS**; `bash -n` clean.

- [ ] **Step 5: Commit** — `feat(toolbox): global Tor exit-country drop-in (ExitNodes/StrictNodes from state file)`.

---

### Task 3: ⑤ Per-client Tor-VPN — prerouting nft chain + reconcile set population

**Files:**
- Modify: `packages/secubox-toolbox/conf/nft-toolbox-tor.nft`
- Modify: `packages/secubox-toolbox/sbin/secubox-toolbox-tor-reconcile`
- Test: `packages/secubox-toolbox/tests/test_vpn_clients.py`

**Interfaces:**
- Consumes: the armed egress (TransPort 9040, DNSPort 9053). Produces: a `tor_vpn_src` set + a `prerouting` chain that redirects **only** listed client source IPs' 80/443 → TransPort and their DNS → 9053; reconcile populates `tor_vpn_src` from `/etc/secubox/toolbox/tor-vpn-clients.txt`. Empty file → set empty → no client routed.

- [ ] **Step 1: Write failing test** — `tests/test_vpn_clients.py`:
```python
from pathlib import Path
CONF = Path(__file__).resolve().parents[1] / "conf"
def test_prerouting_chain_and_set_present():
    nft = (CONF / "nft-toolbox-tor.nft").read_text()
    assert "set tor_vpn_src" in nft
    # a prerouting nat chain that redirects listed sources to TransPort/DNSPort
    assert "prerouting" in nft and "9040" in nft and "9053" in nft
    assert "ip saddr @tor_vpn_src" in nft
```
(Selector-parsing validation is unit-tested in the API task; here we assert the nft topology.)

- [ ] **Step 2: Run — FAIL** (no `tor_vpn_src`).

- [ ] **Step 3: Add the prerouting client-VPN chain** to `conf/nft-toolbox-tor.nft`, INSIDE `table inet toolbox_tor`, after the existing chains:
```
    set tor_vpn_src {
        type ipv4_addr
        flags interval
    }

    chain prerouting_vpn {
        type nat hook prerouting priority -100; policy accept;
        iifname "lo" return
        ip daddr @tor_exempt return
        ip saddr @tor_vpn_src meta l4proto { tcp, udp } th dport 53 redirect to :9053
        ip saddr @tor_vpn_src tcp dport { 80, 443 } redirect to :9040
    }
```
(Client-source-matched — distinct from the skuid `output_nat`. `tor_exempt` still shields box-local/self targets.)

- [ ] **Step 4: Populate the set in reconcile** — add:
```bash
VPN_CLIENTS_STATE=/etc/secubox/toolbox/tor-vpn-clients.txt
# Fill tor_vpn_src from `kind:selector` lines (ip:/cidr:). MAC selectors are
# resolved to current IPs via the neigh table (best-effort). Invalid → skipped.
populate_vpn_clients() {
  [ -f "$VPN_CLIENTS_STATE" ] || return 0
  local line kind sel ip
  while IFS= read -r line; do
    kind="${line%%:*}"; sel="${line#*:}"
    case "$kind" in
      ip|cidr) [[ "$sel" =~ ^[0-9./]+$ ]] && nft add element inet toolbox_tor tor_vpn_src "{ $sel }" 2>/dev/null || true ;;
      mac) ip="$(ip neigh 2>/dev/null | awk -v m="${sel,,}" 'tolower($5)==m{print $1; exit}')"
           [ -n "$ip" ] && nft add element inet toolbox_tor tor_vpn_src "{ $ip }" 2>/dev/null || true ;;
    esac
  done < "$VPN_CLIENTS_STATE"
}
```
Call `populate_vpn_clients` in `arm()` right after `populate_exempt`.

- [ ] **Step 5: Run test → PASS**; `bash -n` clean; `nft -c -f conf/nft-toolbox-tor.nft` if nft available locally (else defer to Task 8 live).

- [ ] **Step 6: Commit** — `feat(toolbox): per-client Tor-VPN prerouting chain + tor_vpn_src set population`.

---

### Task 4: ①⑤ Toolbox API — exit-country + VPN-client CRUD (validated, audited)

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/api.py` — the toolbox FastAPI app (serves `/api/v1/toolbox/…`, writes `filters.json`). Add the exit-country + VPN-client endpoints here; mirror its existing style, `def` if aggregator-mounted.
- Test: `packages/secubox-toolbox/tests/test_tor_vpn_api.py`

**Interfaces:**
- Produces: `GET/POST /exit_country {countries:[...]}`, `GET /vpn/clients`, `POST /vpn/client {kind, selector}`, `DELETE /vpn/client {kind, selector}`. Each writes the corresponding `/etc/secubox/toolbox/tor-*.txt`, appends to `/var/log/secubox/audit.log`, and triggers the reconcile (write a `filters.json`-adjacent trigger the existing `.path` watches, OR `subprocess` the reconcile if the API already runs privileged — match how the egress arm/disarm is currently triggered).

- [ ] **Step 1: Failing tests** — validators are the security core:
```python
import importlib
def _load(monkeypatch, tmp_path):
    import secubox_toolbox.api as m; importlib.reload(m)
    monkeypatch.setattr(m, "TOR_EXIT_CC", tmp_path/"cc.txt")
    monkeypatch.setattr(m, "TOR_VPN_CLIENTS", tmp_path/"vpn.txt")
    monkeypatch.setattr(m, "_trigger_reconcile", lambda: None)
    return m
def test_country_codes_validated(monkeypatch, tmp_path):
    m = _load(monkeypatch, tmp_path)
    assert m._valid_cc("DE") and m._valid_cc("fr")
    assert not m._valid_cc("XXX") and not m._valid_cc("1")
def test_vpn_selector_validated(monkeypatch, tmp_path):
    m = _load(monkeypatch, tmp_path)
    assert m._valid_selector("ip","192.168.1.5") and m._valid_selector("cidr","10.0.0.0/24")
    assert m._valid_selector("mac","aa:bb:cc:dd:ee:ff")
    assert not m._valid_selector("ip","1.2.3.999") and not m._valid_selector("mac","zz")
    assert not m._valid_selector("bad","x")
```
(Module is `secubox_toolbox.api`; run tests from `packages/secubox-toolbox/` with its conftest.)

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement** — add validators + endpoints. Validators (complete):
```python
import re, ipaddress
_CC_RE = re.compile(r"^[A-Za-z]{2}$")
_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")
def _valid_cc(c): return bool(_CC_RE.fullmatch(c or ""))
def _valid_selector(kind, sel):
    try:
        if kind == "ip":   ipaddress.ip_address(sel); return True
        if kind == "cidr": ipaddress.ip_network(sel, strict=False); return True
        if kind == "mac":  return bool(_MAC_RE.fullmatch(sel))
    except ValueError:
        return False
    return False
```
Endpoints write the state files (dedup, one entry per line), `_audit(...)` to `/var/log/secubox/audit.log` (append-only), then `_trigger_reconcile()`. Bad input → `HTTPException(400)`. Country POST replaces the whole list; VPN POST/DELETE add/remove one selector line (`f"{kind}:{sel}"`).

- [ ] **Step 4: Run tests → PASS.**

- [ ] **Step 4b: Bridges endpoints** — also add `GET /tor/bridges`, `POST /tor/bridge {line}`, `DELETE /tor/bridge {line}` writing `/etc/secubox/toolbox/tor-bridges.txt` (validate each line starts `Bridge obfs4 ` with a safe charset, reject else 400), audited + reconcile-triggered. Same validator style as the selectors.

- [ ] **Step 5: Commit** — `feat(toolbox): exit-country + Tor-VPN-client + obfs4-bridge API (validated, audited, reconcile-triggered)`.

---

### Task 5: ②③ Emancipate the webui `.onion`, standalone + persist-on-boot

**Files:**
- Modify: `packages/secubox-exposure/api/main.py`
- Create: `packages/secubox-exposure/sbin/secubox-exposure-tor-reconcile`, `packages/secubox-exposure/systemd/secubox-exposure-tor-reconcile.service` (+ a `.path`/`WantedBy` so it runs on boot / when tor starts)
- Test: `packages/secubox-exposure/tests/test_emancipate_webui.py`

**Interfaces:**
- Consumes: `_tor_add_sync(name, local_port, onion_port)` (@658). Produces: `emancipate_webui(federate=False)` creates HS `name="webui"`, `local_port=9080`, `onion_port=80`; a `federate` flag makes annuaire publishing best-effort (never blocks); `secubox-exposure-tor-reconcile` re-applies every `active` emancipated service from the exposure config to torrc on boot (same `.onion`, idempotent — never re-creates an existing HS dir).

- [ ] **Step 1: Failing tests** — mirror `tests/test_exposure_tor.py` style (stub `_tor_add_sync`):
```python
def test_emancipate_webui_uses_9080_80(monkeypatch, tmp_path):
    m = _load(monkeypatch, tmp_path); calls = []
    monkeypatch.setattr(m, "_tor_add_sync", lambda name, local_port, onion_port: calls.append((name, local_port, onion_port)) or {"success": True, "onion": "abc.onion"})
    m.emancipate_webui(federate=False)
    assert calls == [("webui", 9080, 80)]
def test_emancipate_webui_standalone_skips_federation(monkeypatch, tmp_path):
    m = _load(monkeypatch, tmp_path); fed = []
    monkeypatch.setattr(m, "_tor_add_sync", lambda **k: {"success": True, "onion": "abc.onion"})
    monkeypatch.setattr(m, "_publish", lambda *a, **k: fed.append(a))
    m.emancipate_webui(federate=False)
    assert fed == []           # standalone: no annuaire publish
def test_reconcile_reapplies_active_only(monkeypatch, tmp_path):
    m = _load(monkeypatch, tmp_path); added = []
    monkeypatch.setattr(m, "_tor_add_sync", lambda name, local_port, onion_port: added.append(name))
    monkeypatch.setattr(m, "_hs_dir_exists", lambda n: False)
    m._save_emancipated([{"name":"webui","local_port":9080,"onion_port":80,"active":True},
                         {"name":"old","local_port":80,"onion_port":80,"active":False}])
    m.tor_reconcile_persist()
    assert added == ["webui"]  # inactive 'old' not re-added
```

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement** — add `emancipate_webui(federate=False)` (calls `_tor_add_sync("webui", 9080, 80)`, records `{name,local_port,onion_port,active:True}` in the emancipated config, publishes to annuaire ONLY if `federate` and mesh present — wrap the publish in try/except so it never blocks); a `POST /tor/emancipate_webui` endpoint (JWT-gated, plain/threadpool-offloaded per the module's convention); `tor_reconcile_persist()` that reads the emancipated config and `_tor_add_sync`s each `active` service whose HS dir is absent (idempotent). Add `secubox-exposure-tor-reconcile` (invokes `tor_reconcile_persist` via `python3 -c` or a thin CLI) + a systemd unit `WantedBy=multi-user.target` (and a `.path` on the tor state if desired) so it runs on boot.

- [ ] **Step 4: Run tests → PASS.**

- [ ] **Step 5: Commit** — `feat(exposure): emancipate webui .onion (standalone federate-optional) + persist-on-boot reconcile`.

---

### Task 6: ② Auto-detect all `.onion`s in the tor webui API

**Files:**
- Modify: `packages/secubox-tor/api/main.py` (`/hidden_services` @433) + add `.onion`-DNS status + exit-country/VPN read-through for the UI.
- Test: `packages/secubox-tor/tests/test_hs_autodetect.py`

**Interfaces:**
- Produces: `GET /hidden_services` returns EVERY on-disk `.onion` (scan `/var/lib/tor/**/hostname`), annotated with the configured name/target where known; `GET /onion_dns` returns `{dnsport_up, forward_zone_installed, resolves}`; the UI reads exit-country + VPN state (proxied from toolbox or read from the shared state files).

- [ ] **Step 1: Failing test** — filesystem discovery:
```python
def test_hidden_services_autodiscovers_onion(monkeypatch, tmp_path):
    m = _load(monkeypatch)
    (tmp_path/"hidden_service_webui").mkdir()
    (tmp_path/"hidden_service_webui"/"hostname").write_text("abc123.onion\n")
    monkeypatch.setattr(m, "TOR_DATA", tmp_path)
    svcs = m._discover_hidden_services()
    assert any(s["onion_address"] == "abc123.onion" and s["name"] == "webui" for s in svcs)
```

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement** `_discover_hidden_services()` — glob `TOR_DATA` for `*/hostname`, read each, derive `name` from the dir (strip `hidden_service_` prefix), cross-reference config for `local_port`/`enabled`. Rewrite `/hidden_services` to use it. Add `GET /onion_dns` (checks 9053 listening + `/etc/unbound/unbound.conf.d/48-secubox-onion.conf` present + optional canary resolve). Keep handlers consistent with the file's async/def convention (this module is NOT aggregator-mounted if it has its own uvicorn — verify; if it shells out, offload).

- [ ] **Step 4: Run test → PASS.**

- [ ] **Step 5: Commit** — `feat(tor): auto-discover all on-disk .onion services + .onion-DNS status`.

---

### Task 7: Webui — country picker, VPN-client table, emancipate button, `.onion` list, DNS status

**Files:**
- Modify: `packages/secubox-toolbox/www/toolbox/index.html` — the existing `#tor` tab (`data-tab="tor"`), extending the Tor-egress section
- Test: `node --check` on the extracted script.

**Interfaces:** consumes all Task 4/5/6 endpoints.

- [ ] **Step 1: Implement** — add to the existing toolbox `#tor` tab (`data-tab="tor"` in `www/toolbox/index.html`, alongside the Tor-egress switch; keep skin). The tab calls toolbox's own country/VPN endpoints, plus `/api/v1/exposure/tor/emancipate_webui` and `/api/v1/tor/hidden_services` cross-module (via the aggregator/nginx):
  - **Exit-country** panel: multi-select of ISO countries (static list) → `POST …/exit_country`; shows current + the live exit relay country; a warning banner when `StrictNodes` is on and no circuit has an exit (fail-closed).
  - **Tor-VPN clients** table: add selector (kind ip/cidr/mac + value, client-validated) → `POST …/vpn/client`; per-row remove; shows routed state.
  - **Emancipate** button ("Publish this dashboard as a .onion") → `POST …/emancipate_webui`; shows the resulting `.onion` with copy.
  - **Hidden services** list from `/hidden_services` (auto-detected) + **.onion-DNS status** from `/onion_dns`.
  - **obfs4 bridges** panel: paste/add a `Bridge obfs4 …` line, list, remove (`/tor/bridges`, `/tor/bridge`); a short hint on where to get bridges (Tor Browser moat / BridgeDB).
  - Robustness (mirror nextcloud/openclaw dashboards): `esc()` every rendered `.onion`/country/selector; `data-*`+delegated listeners (no `onclick="${…}"`); `sbx_token` auth; fail-safe fetch, 401→login.

- [ ] **Step 2: Validate** — extract inline `<script>`, `node --check` (must pass); grep no `onclick="…${`; `esc(` wraps rendered values.

- [ ] **Step 3: Commit** — `feat(tor): webui — exit-country, Tor-VPN clients, emancipate, .onion list + DNS status`.

---

### Task 8: ⑥ obfs4 bridges (Niveau-1 entry-side anti-censorship)

**Files:**
- Modify: `packages/secubox-toolbox/sbin/secubox-toolbox-tor-reconcile`
- Modify: `packages/secubox-toolbox/debian/control` (add `obfs4proxy`)
- Test: `packages/secubox-toolbox/tests/test_bridges.py`

**Interfaces:**
- Consumes: reconcile arm/disarm. Produces: `arm` reads `/etc/secubox/toolbox/tor-bridges.txt` (one `Bridge obfs4 …` per line); if any VALID lines, writes `/etc/tor/torrc.d/12-secubox-bridges.conf` with `UseBridges 1` + `ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy` + the bridge lines; empty/all-invalid → no drop-in (direct Tor). Bash helper `_emit_bridges`.

- [ ] **Step 1: Failing test** — `tests/test_bridges.py` (drives the helper via a hidden `__emit_bridges` subcommand):
```python
import subprocess
from pathlib import Path
CTL = Path(__file__).resolve().parents[1] / "sbin" / "secubox-toolbox-tor-reconcile"
def _emit(lines, tmp_path):
    f = tmp_path / "b.txt"; f.write_text(lines)
    return subprocess.run(["bash", str(CTL), "__emit_bridges", str(f)],
                          capture_output=True, text=True).stdout
def test_valid_bridge_emits_usebridges(tmp_path):
    out = _emit("Bridge obfs4 192.0.2.3:80 ABCD cert=xyz iat-mode=0\n", tmp_path)
    assert "UseBridges 1" in out
    assert "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy" in out
    assert "Bridge obfs4 192.0.2.3:80 ABCD cert=xyz iat-mode=0" in out
def test_empty_emits_nothing(tmp_path):
    assert _emit("\n", tmp_path).strip() == ""
def test_injection_line_skipped(tmp_path):
    # a line not starting with 'Bridge obfs4 ' (torrc-injection attempt) is dropped
    out = _emit("HiddenServiceDir /evil\nBridge obfs4 192.0.2.3:80 AB cert=x iat-mode=0\n", tmp_path)
    assert "HiddenServiceDir" not in out
    assert "192.0.2.3:80" in out
```

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement `_emit_bridges` + dispatch + arm/disarm** — in the reconcile:
```bash
BRIDGES_STATE=/etc/secubox/toolbox/tor-bridges.txt
BRIDGES_DROPIN=/etc/tor/torrc.d/12-secubox-bridges.conf
# Emit a UseBridges stanza from a file of `Bridge obfs4 …` lines. Only lines
# beginning `Bridge obfs4 ` and containing no torrc-breaking chars are kept.
# Empty result → emit nothing (direct Tor).
_emit_bridges() {
  local f="$1" line valid=""
  [ -f "$f" ] || return 0
  while IFS= read -r line; do
    [[ "$line" =~ ^Bridge\ obfs4\ [][A-Za-z0-9:._=+/,-]+$ ]] || continue
    valid="${valid}${line}"$'\n'
  done < "$f"
  [ -n "$valid" ] || return 0
  printf 'UseBridges 1\nClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy\n%s' "$valid"
}
```
Add dispatch arm BEFORE `*)`: `__emit_bridges) _emit_bridges "${2:-}"; exit 0 ;;`. In `arm()` (after exit-country):
```bash
  local br; br="$(_emit_bridges "$BRIDGES_STATE")"
  if [ -n "$br" ]; then printf '# SecuBox obfs4 bridges\n%s' "$br" > "$BRIDGES_DROPIN"; else rm -f "$BRIDGES_DROPIN"; fi
```
In `disarm()`: `rm -f "$BRIDGES_DROPIN"`.

- [ ] **Step 4: control dep** — add `obfs4proxy` to `packages/secubox-toolbox/debian/control` `Depends:` (or `Recommends:` if you prefer soft — `Depends` is fine, it's small).

- [ ] **Step 5: Run tests → PASS**; `bash -n`; full toolbox suite has no NEW failures (same 3 pre-existing).

- [ ] **Step 5c: Reapply-when-armed (fixes edits not applying live)** — currently `main()` no-ops when already armed (`table_present && exit 0`), so exit-country/VPN/bridge edits made while Tor is ON don't apply until a disarm→arm cycle. Add a `reapply()` that (only when armed) re-emits the country + bridges torrc drop-ins, flushes + re-populates the nft sets (`nft flush set inet toolbox_tor tor_vpn_src; populate_vpn_clients; nft flush set inet toolbox_tor tor_exempt; populate_exempt`), and `systemctl reload tor 2>/dev/null || systemctl restart tor` (torrc drop-in changes need a reload). Change `main()`'s armed branch from no-op to `reapply`. VERIFY the API trigger path (`set_filters({})` → `.path` → `reconcile`) still evaluates `want=true` when armed (it must NOT disarm on an edit — confirm `set_filters({})` preserves `tor_mode`; if it doesn't, have the reconcile's `reconcile` action treat "table present" as want=true regardless, so an edit reapplies rather than disarms). Add a test that a second `reconcile` while armed re-runs the emit helpers (stub them, assert called).

- [ ] **Step 6: Commit** — `feat(toolbox): obfs4 bridges drop-in + reapply-when-armed (edits apply live)`.

**Note:** the bridge **API** (add/list/remove validated `Bridge` lines → writes `tor-bridges.txt` + triggers reconcile) folds into Task 4's toolbox API, and the bridge **webui panel** folds into Task 7's `/toolbox/#tor` tab — those tasks' scope includes bridges (see their bullets).

---

### Task 9: Live end-to-end on gk2

**Files:** none (integration). Packaging note: bump changelogs + build the three debs; deploy; restore prior Tor-egress state at the end.

- [ ] **Step 1: Build + deploy** the three debs (`secubox-toolbox`, `secubox-exposure`, `secubox-tor`) to gk2; install; restart the aggregator once (for the in-process modules).
  - **MUST-FIX before build:** wire `packages/secubox-exposure/debian/rules` to install the new `sbin/secubox-exposure-tor-reconcile` (0755, `/usr/sbin/`) + `systemd/secubox-exposure-tor-reconcile.service`, and enable the unit in `debian/postinst` (`systemctl enable secubox-exposure-tor-reconcile.service`) — Task 5's persist-on-boot is inert until this ships. Also confirm the toolbox `obfs4proxy` dep + new confs (Task 1/8) install.
- [ ] **Step 2: Arm egress + verify DNSPort move** — set `tor_mode` on (or `secubox-toolbox-tor-reconcile arm`); confirm `ss -lunp | grep 9053` (tor DNSPort, not avahi), `nft list table inet toolbox_tor` shows `prerouting_vpn` + `tor_vpn_src`, and `/etc/unbound/unbound.conf.d/48-secubox-onion.conf` present + `unbound-checkconf` clean.
- [ ] **Step 3: Exit-country** — write `DE` to `tor-exit-country.txt`, reconcile, confirm `11-secubox-exit-country.conf` has `ExitNodes {de} StrictNodes 1`; check a Tor circuit exits via DE (`tor_control` GETINFO / a curl through the transport geolocating to DE). If DE has no exit, confirm the fail-closed state is visible.
- [ ] **Step 4: Tor-VPN client** — add a throwaway test client IP to `tor-vpn-clients.txt`, reconcile, confirm that source is in `tor_vpn_src` and its 80/443 redirects (a non-listed client stays direct). Remove it after.
- [ ] **Step 5: Emancipate + persist + .onion DNS** — `POST /emancipate_webui`; confirm a `.onion` appears and the webui loads over it (via `torsocks curl` or the tor SOCKS); `systemctl restart tor`, confirm the `.onion` is unchanged (persist); resolve a known `.onion` through the box resolver → automap IP.
- [ ] **Step 5b: obfs4 bridges** — add a (test) obfs4 `Bridge` line to `tor-bridges.txt`, reconcile, confirm `12-secubox-bridges.conf` has `UseBridges 1` + `ClientTransportPlugin obfs4 …` and `obfs4proxy` is installed; a bad line is rejected. Remove the test bridge after.

- [ ] **Step 6: Restore** — return the box to its prior Tor-egress state (disarm if it started disarmed); confirm no residual drop-ins leak. Record `.claude/HISTORY.md`.
- [ ] **Step 7: Commit** tracking — `docs(tor): Phase-1 enhancement live-verified on gk2`.

---

## Phase 2 (STUB — not implemented in this plan)

Per-service exit-country override. `ExitNodes` is global to a tor instance and hidden services are inbound (no exit), so this needs a **separate tor SOCKS instance per exit-country policy** (or SOCKSPort isolation with per-instance `ExitNodes`) and routing each outbound-egressing service to the matching instance, plus a per-service override UI atop the global default. Design it in its own spec when Phase 1 is validated.

---

## Notes for the executor

- **Order matters:** Task 1 (DNSPort 9053) is foundational — the nft (Task 3) and Unbound both target 9053; do not leave any `5353` behind (grep both configs).
- **Reconcile is the single privileged choke point** — the APIs (Task 4) only write state files + trigger it; never let an API escalate directly.
- **`nft -c -f`** validates the nft file offline; use it in Tasks 1/3 before the live arm.
- **Live tasks must restore state** — the box's Tor egress was OFF at start; leave it as found unless the operator asks otherwise.
- **The toolbox API is `secubox_toolbox/api.py`; its trigger mechanism** (Task 4): mirror exactly how the existing egress arm/disarm flag (`filters.json` `tor_mode`) is written + path-triggered (`secubox-toolbox-tor.path`); do not invent a new privilege path. The Tor UI is the `/toolbox/#tor` tab, calling toolbox + exposure + secubox-tor endpoints cross-module.
