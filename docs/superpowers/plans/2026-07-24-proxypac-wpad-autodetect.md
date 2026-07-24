# ProxyPAC WPAD/DHCP autodetect + transparent `.onion` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Router `.onion` de bout en bout (transparent pour wg-toolbox+LAN, PAC/WPAD en fallback), avec autodétection de rôle DHCP master/slave et distribution best-effort, panneau fini.

**Architecture:** Deux paquets. `secubox-tor` fournit les endpoints Tor (SocksPort LAN + machinerie transparente TransPort/DNSPort + Unbound onion-forward + nft redirect) pilotés par `torctl`. `secubox-proxypac` (le sous-système PAC déjà mergé/déployé) gagne la détection de rôle, la distribution WPAD, le repoint de la règle onion vers le SOCKS LAN, et un panneau complet qui expose/toggle tout via API déléguant à des ctl root scopés.

**Tech Stack:** Debian bookworm arm64, Tor 0.4.9, Unbound, nftables (dropins isolés `table inet secubox-*`), FastAPI (servi in-process par l'aggregator), bash ctl + sudoers scopés, pytest + node.

## Global Constraints

- **Jamais de `SocksPolicy`** dans un dropin torrc (option GLOBALE → casse le SocksPort mesh). Confinement = bind IP + nft.
- **`TransPort 9040` / `DNSPort 9053` ne se déclarent qu'UNE fois** dans `tor@default` : `torctl transparent on` réutilise un dropin existant (toolbox), ne duplique jamais. `off` ne retire que ce que `on` a posé.
- **Ne JAMAIS chown les parents partagés** `/run/secubox`, `/etc/secubox`, `/var/log/secubox` (chmod only).
- **`#DEBHELPER#` seul sur sa ligne** (jamais en commentaire).
- **Pas de `.bak` dans `sites-enabled/`**.
- nftables **DEFAULT DROP** ; dropins en `table inet secubox-<mod>` isolée, préfixe d'ordre correct dans `/etc/nftables.d/`.
- Endpoint SOCKS/LAN-IP **jamais codé en dur** dans le code : détecté + overridable via `/etc/secubox/proxypac/proxypac.toml`. gk2 = `192.168.1.200`.
- API délègue toute action privilégiée à un ctl via **sudo scopé** (jamais d'action root in-process). Jeton webui = `sbx_token` en localStorage.
- Commits : `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`, **aucune** référence IA.
- Best-effort partout : une étape réseau qui échoue est loggée, n'interrompt pas les autres, ne laisse rien de cassé.

## File Structure

**secubox-tor** (endpoints Tor + réseau)
- `conf/torrc.d/50-secubox-socks-lan.conf` — SocksPort LAN (substitué au postinst)
- `conf/torrc.d/60-secubox-transparent.conf` — TransPort/DNSPort/Automap/VirtualAddr (posé par torctl si pas déjà présent)
- `conf/unbound/secubox-onion-forward.conf` — forward-zone `onion.` → 127.0.0.1@9053 + private-domain
- `nft.d/secubox-tor-transparent.nft` — redirect 10.192.0.0/10 → 127.0.0.1:9040 (iif wg-toolbox+LAN)
- `sbin/torctl` — `socks-lan {ensure}` , `transparent {on|off|status}`, `detect-lan-ip`
- `sbin/tor-lan-ip` — helper détection IP LAN (partagé)
- `tests/test_torctl_transparent.py`, `tests/test_socks_lan_dropin.py`, `tests/test_onion_forward.py`, `tests/test_nft_transparent.py`

**secubox-proxypac** (PAC + rôle + WPAD + panneau)
- `conf/proxypac.toml` — conffile (role/wpad_domain/pac_url/socks_endpoint/transparent)
- `conf/rules.d/00-onion.rules` — `*.onion socks5 __LAN_SOCKS__` (substitué à la génération)
- `proxypac/config.py` — lecture proxypac.toml + résolution socks_endpoint (auto|override)
- `proxypac/role.py` — détection passive master/slave + résolveur DNS + IP LAN
- `sbin/proxypac-wpad` — applique l'échelon (dnsmasq 252 / DNS wpad), idempotent
- `api/main.py` — + /status, /wpad/apply, /transparent, /wpad/state
- `www/proxypac/index.html` — panneau réécrit (navbar + statut + candidats + runbook)
- `debian/secubox-proxypac.sudoers` — sudo scopé (proxypac-wpad, torctl transparent)
- `tests/test_config.py`, `tests/test_role.py`, `tests/test_wpad.py`, `tests/test_api_status.py`, `tests/test_panel.py`

---

### Task 1: secubox-tor — helper détection IP LAN + SocksPort LAN dropin

**Files:**
- Create: `packages/secubox-tor/sbin/tor-lan-ip`
- Create: `packages/secubox-tor/conf/torrc.d/50-secubox-socks-lan.conf`
- Create: `packages/secubox-tor/sbin/torctl`
- Test: `packages/secubox-tor/tests/test_socks_lan_dropin.py`

**Interfaces:**
- Produces: `tor-lan-ip` prints one IPv4 (the LAN IP) to stdout; used by torctl and proxypac postinst. `torctl socks-lan ensure` writes `50-secubox-socks-lan.conf` with `SocksPort <LAN_IP>:9050` (substituting `__LAN_IP__`), no SocksPolicy, then `systemctl reload tor@default`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-tor/tests/test_socks_lan_dropin.py
import subprocess, re, os
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def test_socks_lan_template_has_no_socks_policy():
    tpl = (ROOT / "conf/torrc.d/50-secubox-socks-lan.conf").read_text()
    assert "SocksPort" in tpl
    assert "SocksPolicy" not in tpl, "SocksPolicy est GLOBALE — casserait le port mesh"
    assert "__LAN_IP__" in tpl, "l'IP doit être un placeholder substitué au postinst"
    assert "0.0.0.0" not in tpl

def test_lan_ip_helper_prints_a_private_ipv4():
    out = subprocess.run(["bash", str(ROOT / "sbin/tor-lan-ip")],
                         capture_output=True, text=True)
    ip = out.stdout.strip()
    assert re.match(r"^(192\.168|10|172)\.\d+\.\d+\.\d+$", ip), f"got {ip!r}"
    # ne doit jamais renvoyer une IP wg/docker/mesh
    assert not ip.startswith(("10.99.", "10.100.", "10.10.", "172.17.")), ip
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-tor && python3 -m pytest tests/test_socks_lan_dropin.py -q`
Expected: FAIL (fichiers absents).

- [ ] **Step 3: Write the LAN-IP helper**

```bash
# packages/secubox-tor/sbin/tor-lan-ip
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Détecte l'IP LAN du box : override explicite sinon best-effort.
# Override : /etc/secubox/proxypac/proxypac.toml socks_endpoint="ip:port"
# ou variable SECUBOX_LAN_IP. Sinon : première IPv4 globale privée sur une
# interface physique, en excluant wg*/docker*/br-*/lo et les ranges internes.
set -euo pipefail
if [ -n "${SECUBOX_LAN_IP:-}" ]; then echo "$SECUBOX_LAN_IP"; exit 0; fi
TOML=/etc/secubox/proxypac/proxypac.toml
if [ -r "$TOML" ]; then
  ip_from_toml=$(sed -n 's/^[[:space:]]*socks_endpoint[[:space:]]*=[[:space:]]*"\{0,1\}\([0-9.]\+\):[0-9]\+"\{0,1\}.*/\1/p' "$TOML" | head -1)
  if [ -n "$ip_from_toml" ]; then echo "$ip_from_toml"; exit 0; fi
fi
ip -o -4 addr show scope global 2>/dev/null \
  | grep -vE '\b(wg-|docker|br-|veth|lo)\w*' \
  | awk '{print $2" "$4}' \
  | grep -vE '^(wg-|docker|br-|veth)' \
  | awk '{print $2}' | cut -d/ -f1 \
  | grep -E '^(192\.168|10|172)\.' \
  | grep -vE '^(10\.99\.|10\.100\.|10\.10\.|172\.17\.)' \
  | head -1
```

- [ ] **Step 4: Write the SocksPort LAN template**

```
# packages/secubox-tor/conf/torrc.d/50-secubox-socks-lan.conf
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SOCKS LAN pour clients LAN / wg-toolbox (PAC .onion -> Tor).
# PAS de SocksPolicy : l'option est GLOBALE dans Tor et casserait le
# SocksPort mesh (secubox-macro). Confinement = bind IP LAN + nft.
SocksPort __LAN_IP__:9050
```

- [ ] **Step 5: Write torctl (socks-lan ensure + detect-lan-ip stubs used later)**

```bash
# packages/secubox-tor/sbin/torctl
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: torctl — pilote les endpoints Tor (SOCKS LAN + transparent).
set -euo pipefail
SHARE=/usr/share/secubox/tor
TORRC_D=/etc/tor/torrc.d
UNBOUND_D=/etc/unbound/unbound.conf.d
NFT_D=/etc/nftables.d
lan_ip() { /usr/sbin/tor-lan-ip; }

socks_lan_ensure() {
  local ip; ip="$(lan_ip)"; [ -n "$ip" ] || { echo "pas d'IP LAN détectée" >&2; return 1; }
  sed "s/__LAN_IP__/$ip/g" "$SHARE/50-secubox-socks-lan.conf" > "$TORRC_D/50-secubox-socks-lan.conf"
  systemctl reload tor@default 2>/dev/null || systemctl restart tor@default || true
  echo "SocksPort LAN $ip:9050"
}

case "${1:-}" in
  detect-lan-ip) lan_ip ;;
  socks-lan) [ "${2:-}" = "ensure" ] && socks_lan_ensure ;;
  *) echo "usage: torctl {detect-lan-ip|socks-lan ensure|transparent {on|off|status}}" >&2; exit 2 ;;
esac
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd packages/secubox-tor && chmod +x sbin/tor-lan-ip sbin/torctl && python3 -m pytest tests/test_socks_lan_dropin.py -q`
Expected: PASS (2 tests). *(Le test IP tourne sur la machine de dev — s'il n'a pas d'IP LAN privée, il détecte le skip via une IP absente ; documenter si l'env de test n'a pas d'IPv4 privée, auquel cas valider la regex sur une entrée simulée.)*

- [ ] **Step 7: Commit**

```bash
git add packages/secubox-tor/sbin packages/secubox-tor/conf/torrc.d/50-secubox-socks-lan.conf packages/secubox-tor/tests/test_socks_lan_dropin.py
git commit -m "feat(tor): SocksPort LAN dropin (no SocksPolicy) + LAN-IP detect helper + torctl"
```

---

### Task 2: secubox-tor — transparent `.onion` (Unbound forward + tor TransPort + nft redirect + torctl transparent)

**Files:**
- Create: `packages/secubox-tor/conf/torrc.d/60-secubox-transparent.conf`
- Create: `packages/secubox-tor/conf/unbound/secubox-onion-forward.conf`
- Create: `packages/secubox-tor/nft.d/secubox-tor-transparent.nft`
- Modify: `packages/secubox-tor/sbin/torctl`
- Test: `packages/secubox-tor/tests/test_torctl_transparent.py`, `tests/test_onion_forward.py`, `tests/test_nft_transparent.py`

**Interfaces:**
- Consumes: `tor-lan-ip` (Task 1).
- Produces: `torctl transparent on|off|status`. `on` = (a) si aucun `TransPort 9040` actif dans `$TORRC_D`, poser `60-secubox-transparent.conf` ; (b) poser le forward Unbound ; (c) poser le nft dropin ; (d) reload tor + unbound + nft ; idempotent. `off` = retirer uniquement les fichiers posés par nous + reload. `status` = imprime `on`/`off` + détail (JSON).

- [ ] **Step 1: Write the failing tests**

```python
# packages/secubox-tor/tests/test_onion_forward.py
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
def test_onion_forward_targets_tor_dnsport_and_keeps_automap_range():
    c = (ROOT / "conf/unbound/secubox-onion-forward.conf").read_text()
    assert 'forward-zone:' in c and 'name: "onion."' in c
    assert '127.0.0.1@9053' in c
    # sinon Unbound strippe le range automap privé 10.192.0.0/10 :
    assert 'private-domain: "onion."' in c
```

```python
# packages/secubox-tor/tests/test_nft_transparent.py
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
def test_nft_redirects_only_automap_range_to_transport():
    n = (ROOT / "nft.d/secubox-tor-transparent.nft").read_text()
    assert "table inet secubox-tor-transparent" in n
    assert "10.192.0.0/10" in n
    assert "9040" in n
    # portée : wg-toolbox + LAN, hook prerouting dstnat
    assert "wg-toolbox" in n
    assert "type nat hook prerouting" in n
```

```python
# packages/secubox-tor/tests/test_torctl_transparent.py
import subprocess, os, json, stat
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def _run(env, *args):
    return subprocess.run(["bash", str(ROOT/"sbin/torctl"), *args],
                          capture_output=True, text=True, env=env)

def test_on_skips_transport_dropin_when_one_already_exists(tmp_path):
    torrc = tmp_path/"torrc.d"; torrc.mkdir()
    (torrc/"torrc-toolbox-egress.conf").write_text("TransPort 127.0.0.1:9040\nDNSPort 127.0.0.1:9053\n")
    env = {**os.environ, "TORCTL_TORRC_D": str(torrc), "TORCTL_UNBOUND_D": str(tmp_path/"u"),
           "TORCTL_NFT_D": str(tmp_path/"n"), "TORCTL_DRYRUN": "1"}
    (tmp_path/"u").mkdir(); (tmp_path/"n").mkdir()
    r = _run(env, "transparent", "on")
    assert r.returncode == 0
    assert not (torrc/"60-secubox-transparent.conf").exists(), "ne doit pas dupliquer TransPort"

def test_off_removes_only_our_files(tmp_path):
    torrc = tmp_path/"torrc.d"; torrc.mkdir()
    ext = torrc/"torrc-toolbox-egress.conf"; ext.write_text("TransPort 127.0.0.1:9040\n")
    (torrc/"60-secubox-transparent.conf").write_text("x")
    env = {**os.environ, "TORCTL_TORRC_D": str(torrc), "TORCTL_UNBOUND_D": str(tmp_path/"u"),
           "TORCTL_NFT_D": str(tmp_path/"n"), "TORCTL_DRYRUN": "1"}
    (tmp_path/"u").mkdir(); (tmp_path/"n").mkdir()
    _run(env, "transparent", "off")
    assert not (torrc/"60-secubox-transparent.conf").exists()
    assert ext.exists(), "off ne doit jamais retirer le dropin d'un autre paquet"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/secubox-tor && python3 -m pytest tests/test_torctl_transparent.py tests/test_onion_forward.py tests/test_nft_transparent.py -q`
Expected: FAIL.

- [ ] **Step 3: Write the tor transparent dropin**

```
# packages/secubox-tor/conf/torrc.d/60-secubox-transparent.conf
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Egress transparent .onion : DNSPort automap + TransPort. Posé par torctl
# UNIQUEMENT si aucun TransPort/DNSPort n'est déjà déclaré (coordination avec
# torrc-toolbox-egress.conf du toolbox — mêmes ports, une seule déclaration).
TransPort 127.0.0.1:9040
DNSPort 127.0.0.1:9053
AutomapHostsOnResolve 1
VirtualAddrNetworkIPv4 10.192.0.0/10
```

- [ ] **Step 4: Write the Unbound onion-forward dropin**

```
# packages/secubox-tor/conf/unbound/secubox-onion-forward.conf
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Résout *.onion via Tor DNSPort (automap -> 10.192.0.0/10). private-domain
# empêche Unbound de stripper la réponse d'adresse privée (le range automap).
server:
    private-domain: "onion."
    do-not-query-localhost: no
forward-zone:
    name: "onion."
    forward-addr: 127.0.0.1@9053
```

- [ ] **Step 5: Write the nft transparent dropin**

Note: `redirect` cible l'IP locale de l'iface entrante ; comme Tor TransPort est sur 127.0.0.1, on DNAT explicitement vers 127.0.0.1:9040 et le postinst pose `net.ipv4.conf.all.route_localnet=1` (Task 8) pour autoriser le DNAT loopback depuis une iface non-lo.

```
# packages/secubox-tor/nft.d/secubox-tor-transparent.nft
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Redirige le trafic vers les IP virtuelles automap Tor (10.192.0.0/10) vers
# le TransPort local. Portée stricte : seul ce range, seules les ifaces
# force-routées (wg-toolbox + LAN eth2). Nécessite route_localnet=1.
table inet secubox-tor-transparent {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname { "wg-toolbox", "eth2" } ip daddr 10.192.0.0/10 tcp dport 1-65535 dnat ip to 127.0.0.1:9040 comment "onion-transparent-tcp"
    }
}
```

- [ ] **Step 6: Extend torctl with transparent {on|off|status}**

```bash
# append to packages/secubox-tor/sbin/torctl (before the case), and add cases
# Env overrides for tests: TORCTL_TORRC_D / TORCTL_UNBOUND_D / TORCTL_NFT_D / TORCTL_DRYRUN
TORRC_D="${TORCTL_TORRC_D:-/etc/tor/torrc.d}"
UNBOUND_D="${TORCTL_UNBOUND_D:-/etc/unbound/unbound.conf.d}"
NFT_D="${TORCTL_NFT_D:-/etc/nftables.d}"
DRYRUN="${TORCTL_DRYRUN:-0}"
_reload() { [ "$DRYRUN" = "1" ] && return 0; "$@" || true; }

transport_already_declared() {
  grep -rqiE '^[[:space:]]*TransPort[[:space:]]+127\.0\.0\.1:9040' "$TORRC_D"/*.conf 2>/dev/null
}
transparent_on() {
  if transport_already_declared; then
    echo "TransPort 9040 déjà déclaré (toolbox) — réutilisé, pas de dropin dupliqué"
  else
    cp "$SHARE/60-secubox-transparent.conf" "$TORRC_D/60-secubox-transparent.conf"
  fi
  cp "$SHARE/secubox-onion-forward.conf" "$UNBOUND_D/secubox-onion-forward.conf"
  cp "$SHARE/secubox-tor-transparent.nft" "$NFT_D/secubox-tor-transparent.nft"
  _reload sysctl -q -w net.ipv4.conf.all.route_localnet=1
  _reload systemctl reload tor@default
  _reload systemctl restart unbound
  _reload nft -f "$NFT_D/secubox-tor-transparent.nft"
  echo "transparent on"
}
transparent_off() {
  rm -f "$TORRC_D/60-secubox-transparent.conf" "$UNBOUND_D/secubox-onion-forward.conf" "$NFT_D/secubox-tor-transparent.nft"
  _reload systemctl reload tor@default
  _reload systemctl restart unbound
  _reload nft delete table inet secubox-tor-transparent 2>/dev/null
  echo "transparent off"
}
transparent_status() {
  local on=false
  [ -f "$UNBOUND_D/secubox-onion-forward.conf" ] && [ -f "$NFT_D/secubox-tor-transparent.nft" ] && on=true
  echo "{\"transparent\": $on}"
}
```
Add to the `case`: `transparent) case "${2:-}" in on) transparent_on;; off) transparent_off;; status) transparent_status;; esac;;`

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd packages/secubox-tor && python3 -m pytest tests/test_torctl_transparent.py tests/test_onion_forward.py tests/test_nft_transparent.py -q`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add packages/secubox-tor/conf packages/secubox-tor/nft.d packages/secubox-tor/sbin/torctl packages/secubox-tor/tests/test_torctl_transparent.py packages/secubox-tor/tests/test_onion_forward.py packages/secubox-tor/tests/test_nft_transparent.py
git commit -m "feat(tor): transparent .onion — unbound onion-forward + TransPort dropin + nft redirect + torctl on/off (port-coord, route_localnet)"
```

---

### Task 3: secubox-proxypac — config + repoint règle onion vers SOCKS LAN

**Files:**
- Create: `packages/secubox-proxypac/conf/proxypac.toml`
- Create: `packages/secubox-proxypac/proxypac/config.py`
- Modify: `packages/secubox-proxypac/conf/rules.d/00-onion.rules`
- Modify: `packages/secubox-proxypac/proxypac/generator.py`
- Test: `packages/secubox-proxypac/tests/test_config.py`

**Interfaces:**
- Produces: `config.load()` → dict avec `socks_endpoint` (résolu : override toml sinon `<lan-ip>:9050`), `role`, `wpad_domain`, `pac_url`, `transparent` (bool). `generator.run_once` substitue `__LAN_SOCKS__` dans les règles par `config.load()['socks_endpoint']`.
- Consumes: `tor-lan-ip` (via subprocess) pour l'IP par défaut.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-proxypac/tests/test_config.py
import sys; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from proxypac import config

def test_socks_endpoint_prefers_toml_override(tmp_path, monkeypatch):
    t = tmp_path/"proxypac.toml"
    t.write_text('socks_endpoint = "192.168.5.9:9050"\nrole = "auto"\n')
    c = config.load(str(t))
    assert c["socks_endpoint"] == "192.168.5.9:9050"
    assert c["role"] == "auto"

def test_onion_rule_uses_placeholder_not_hardcoded_mesh():
    r = (ROOT/"conf/rules.d/00-onion.rules").read_text()
    assert "__LAN_SOCKS__" in r
    assert "10.10.0.1:9050" not in r, "plus de SOCKS mesh injoignable en dur"

def test_defaults_when_no_toml(tmp_path):
    c = config.load(str(tmp_path/"absent.toml"))
    assert c["role"] == "auto"
    assert isinstance(c["transparent"], bool)
    assert ":9050" in c["socks_endpoint"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-proxypac && python3 -m pytest tests/test_config.py -q`
Expected: FAIL.

- [ ] **Step 3: Write config.py**

```python
# packages/secubox-proxypac/proxypac/config.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: proxypac.config — lit proxypac.toml, résout le socks_endpoint."""
import subprocess
try:
    import tomllib
except ModuleNotFoundError:  # py<3.11
    import tomli as tomllib

DEFAULTS = {"role": "auto", "wpad_domain": "", "pac_url": "", "transparent": True}


def _detect_lan_ip():
    try:
        out = subprocess.run(["/usr/sbin/tor-lan-ip"], capture_output=True, text=True, timeout=5)
        ip = out.stdout.strip()
        return ip or "127.0.0.1"
    except Exception:
        return "127.0.0.1"


def load(path="/etc/secubox/proxypac/proxypac.toml"):
    data = dict(DEFAULTS)
    try:
        with open(path, "rb") as f:
            data.update(tomllib.load(f))
    except (OSError, tomllib.TOMLDecodeError):
        pass
    ep = data.get("socks_endpoint")
    if not ep:
        ep = f"{_detect_lan_ip()}:9050"
    data["socks_endpoint"] = ep
    data.setdefault("transparent", True)
    return data
```

- [ ] **Step 4: Update the onion rule to a placeholder**

```
# packages/secubox-proxypac/conf/rules.d/00-onion.rules
# secubox-proxypac seed: route .onion via le SOCKS Tor LAN du box.
# __LAN_SOCKS__ est substitué à la génération par proxypac.config.socks_endpoint
# (override proxypac.toml, sinon IP LAN détectée:9050). Plus de SOCKS mesh en dur.
*.onion socks5 __LAN_SOCKS__
```

- [ ] **Step 5: Substitute the placeholder in generator.run_once**

In `packages/secubox-proxypac/proxypac/generator.py`, after `overrides = parse_rules_dir(rules_dir)` add substitution of `__LAN_SOCKS__` in each override directive:

```python
    from .config import load as _load_cfg
    ep = _load_cfg().get("socks_endpoint", "127.0.0.1:9050")
    for r in overrides:
        r.directive = r.directive.replace("__LAN_SOCKS__", ep)
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd packages/secubox-proxypac && python3 -m pytest tests/test_config.py tests/test_generator.py -q`
Expected: PASS (nouveau + non-régression du générateur existant).

- [ ] **Step 7: Commit**

```bash
git add packages/secubox-proxypac/conf/proxypac.toml packages/secubox-proxypac/proxypac/config.py packages/secubox-proxypac/conf/rules.d/00-onion.rules packages/secubox-proxypac/proxypac/generator.py packages/secubox-proxypac/tests/test_config.py
git commit -m "feat(proxypac): onion rule -> LAN SOCKS via proxypac.toml (placeholder subst, plus de mesh en dur)"
```

Créer aussi `conf/proxypac.toml` :
```toml
# SecuBox ProxyPAC — configuration (conffile). Tout est optionnel.
role = "auto"          # auto | master | slave | off
wpad_domain = ""       # ex: gk2.secubox.in (vide = auto depuis le hostname)
pac_url = ""           # override de l'URL PAC affichée (vide = auto)
# socks_endpoint = "192.168.1.200:9050"   # override ; sinon IP LAN détectée:9050
transparent = true      # .onion transparent pour clients force-routés (wg-toolbox+LAN)
```

---

### Task 4: secubox-proxypac — détection de rôle passive (`role.py`)

**Files:**
- Create: `packages/secubox-proxypac/proxypac/role.py`
- Test: `packages/secubox-proxypac/tests/test_role.py`

**Interfaces:**
- Produces: `role.detect(probe=<injectable>)` → dict `{"role": "master"|"slave", "dns_resolver": bool, "lan_ip": str, "tier": 1|2|3}`. Détection passive : master si un DHCP écoute UDP/67 sur l'IP LAN ; dns_resolver si UDP/53 lié à l'IP LAN ; tier = 1 si master, 2 si dns_resolver, 3 sinon. Les sondes (listeners) sont injectables pour test (aucune I/O réseau réelle en test).

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-proxypac/tests/test_role.py
import sys; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from proxypac import role

def probe(dhcp=False, dns=False, lan="192.168.1.200"):
    return {"lan_ip": lan,
            "dhcp_on_lan": dhcp,
            "dns_on_lan": dns}

def test_master_when_dhcp_listens_on_lan():
    r = role.detect(probe(dhcp=True, dns=True))
    assert r["role"] == "master" and r["tier"] == 1

def test_slave_with_dns_is_tier2():
    r = role.detect(probe(dhcp=False, dns=True))
    assert r["role"] == "slave" and r["tier"] == 2 and r["dns_resolver"] is True

def test_slave_without_dns_is_tier3():
    r = role.detect(probe(dhcp=False, dns=False))
    assert r["role"] == "slave" and r["tier"] == 3
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-proxypac && python3 -m pytest tests/test_role.py -q`
Expected: FAIL.

- [ ] **Step 3: Write role.py**

```python
# packages/secubox-proxypac/proxypac/role.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: proxypac.role — détection passive master/slave (read-only)."""
import subprocess


def _live_probe():
    """Lecture d'état seulement : aucun paquet DHCP émis."""
    lan_ip = ""
    try:
        lan_ip = subprocess.run(["/usr/sbin/tor-lan-ip"], capture_output=True,
                                text=True, timeout=5).stdout.strip()
    except Exception:
        pass
    ss = ""
    try:
        ss = subprocess.run(["ss", "-ulnp"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        pass
    dhcp = bool(lan_ip) and (f"{lan_ip}:67" in ss or "0.0.0.0:67" in ss)
    dns = bool(lan_ip) and (f"{lan_ip}:53" in ss)
    return {"lan_ip": lan_ip, "dhcp_on_lan": dhcp, "dns_on_lan": dns}


def detect(probe=None):
    p = probe if probe is not None else _live_probe()
    if p.get("dhcp_on_lan"):
        return {"role": "master", "dns_resolver": p.get("dns_on_lan", False),
                "lan_ip": p.get("lan_ip", ""), "tier": 1}
    if p.get("dns_on_lan"):
        return {"role": "slave", "dns_resolver": True, "lan_ip": p.get("lan_ip", ""), "tier": 2}
    return {"role": "slave", "dns_resolver": False, "lan_ip": p.get("lan_ip", ""), "tier": 3}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/secubox-proxypac && python3 -m pytest tests/test_role.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-proxypac/proxypac/role.py packages/secubox-proxypac/tests/test_role.py
git commit -m "feat(proxypac): détection passive de rôle master/slave + résolveur DNS (tier 1/2/3)"
```

---

### Task 5: secubox-proxypac — actuateur WPAD (`proxypac-wpad`)

**Files:**
- Create: `packages/secubox-proxypac/sbin/proxypac-wpad`
- Test: `packages/secubox-proxypac/tests/test_wpad.py`

**Interfaces:**
- Consumes: `role.detect()`, `config.load()`.
- Produces: `proxypac-wpad apply` applique l'échelon détecté (respecte l'override `role` du toml) : master → dropin dnsmasq option 252 ; tier2 → local-data wpad dans Unbound ; tier3 → no-op. Idempotent, best-effort. `proxypac-wpad state` imprime le JSON de l'état.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-proxypac/tests/test_wpad.py
import subprocess, os, json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def _run(env, *args):
    return subprocess.run(["bash", str(ROOT/"sbin/proxypac-wpad"), *args],
                          capture_output=True, text=True, env=env)

def _env(tmp, role="master"):
    return {**os.environ, "WPAD_DRYRUN": "1", "WPAD_ROLE": role,
            "WPAD_DNSMASQ_D": str(tmp/"dnsmasq"), "WPAD_UNBOUND_D": str(tmp/"unbound"),
            "WPAD_DOMAIN": "gk2.secubox.in", "WPAD_LAN_IP": "192.168.1.200"}

def test_master_writes_dhcp_option_252(tmp_path):
    (tmp_path/"dnsmasq").mkdir(); (tmp_path/"unbound").mkdir()
    r = _run(_env(tmp_path, "master"), "apply")
    assert r.returncode == 0
    f = tmp_path/"dnsmasq"/"secubox-wpad.conf"
    assert f.exists() and "dhcp-option=252" in f.read_text() and "wpad.gk2.secubox.in" in f.read_text()

def test_slave_tier2_writes_unbound_wpad_record(tmp_path):
    (tmp_path/"dnsmasq").mkdir(); (tmp_path/"unbound").mkdir()
    r = _run(_env(tmp_path, "slave-dns"), "apply")
    assert r.returncode == 0
    f = tmp_path/"unbound"/"secubox-wpad.conf"
    assert f.exists() and "wpad.gk2.secubox.in" in f.read_text() and "192.168.1.200" in f.read_text()
    assert not (tmp_path/"dnsmasq"/"secubox-wpad.conf").exists()

def test_idempotent(tmp_path):
    (tmp_path/"dnsmasq").mkdir(); (tmp_path/"unbound").mkdir()
    e = _env(tmp_path, "master")
    _run(e, "apply"); a = (tmp_path/"dnsmasq"/"secubox-wpad.conf").read_text()
    _run(e, "apply"); b = (tmp_path/"dnsmasq"/"secubox-wpad.conf").read_text()
    assert a == b
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-proxypac && python3 -m pytest tests/test_wpad.py -q`
Expected: FAIL.

- [ ] **Step 3: Write proxypac-wpad**

```bash
# packages/secubox-proxypac/sbin/proxypac-wpad
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: proxypac-wpad — applique l'échelon WPAD selon le rôle détecté.
set -euo pipefail
DRYRUN="${WPAD_DRYRUN:-0}"
DNSMASQ_D="${WPAD_DNSMASQ_D:-/etc/dnsmasq.d}"
UNBOUND_D="${WPAD_UNBOUND_D:-/etc/unbound/unbound.conf.d}"
DOMAIN="${WPAD_DOMAIN:-$(hostname -d 2>/dev/null || echo local)}"
LAN_IP="${WPAD_LAN_IP:-$(/usr/sbin/tor-lan-ip 2>/dev/null || echo 127.0.0.1)}"
# rôle : override explicite (WPAD_ROLE) sinon détection python
role() {
  if [ -n "${WPAD_ROLE:-}" ]; then echo "$WPAD_ROLE"; return; fi
  python3 - <<'PY'
import sys; sys.path.insert(0, "/usr/lib/secubox/proxypac")
from proxypac.role import detect
r = detect()
print("master" if r["tier"]==1 else ("slave-dns" if r["tier"]==2 else "slave"))
PY
}
_reload(){ [ "$DRYRUN" = "1" ] && return 0; "$@" || true; }

apply() {
  local r; r="$(role)"
  # nettoyage : on retire nos deux dropins puis on repose celui du tier courant
  rm -f "$DNSMASQ_D/secubox-wpad.conf" "$UNBOUND_D/secubox-wpad.conf"
  case "$r" in
    master)
      printf '# secubox-proxypac WPAD (auto)\ndhcp-option=252,"http://wpad.%s/wpad.dat"\n' "$DOMAIN" > "$DNSMASQ_D/secubox-wpad.conf"
      _reload systemctl reload dnsmasq ;;
    slave-dns)
      printf '# secubox-proxypac WPAD via DNS (auto)\nserver:\n    local-data: "wpad.%s. A %s"\n' "$DOMAIN" "$LAN_IP" > "$UNBOUND_D/secubox-wpad.conf"
      _reload unbound-control reload ;;
    *) : ;;  # tier3 : no-op réseau
  esac
  echo "wpad applied role=$r domain=$DOMAIN"
}
state() {
  local r; r="$(role)"
  printf '{"role":"%s","domain":"%s","lan_ip":"%s","pac_url":"http://wpad.%s/wpad.dat"}\n' "$r" "$DOMAIN" "$LAN_IP" "$DOMAIN"
}
case "${1:-}" in apply) apply;; state) state;; *) echo "usage: proxypac-wpad {apply|state}" >&2; exit 2;; esac
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/secubox-proxypac && chmod +x sbin/proxypac-wpad && python3 -m pytest tests/test_wpad.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-proxypac/sbin/proxypac-wpad packages/secubox-proxypac/tests/test_wpad.py
git commit -m "feat(proxypac): actuateur WPAD best-effort (dnsmasq 252 / DNS wpad / no-op) idempotent"
```

---

### Task 6: secubox-proxypac — API `/status` + `/wpad/apply` + `/transparent`

**Files:**
- Modify: `packages/secubox-proxypac/api/main.py`
- Test: `packages/secubox-proxypac/tests/test_api_status.py`

**Interfaces:**
- Consumes: `role.detect()`, `config.load()`, ctl via sudo (`proxypac-wpad`, `torctl transparent`).
- Produces: `GET /status` → `{role, tier, lan_ip, socks_endpoint, transparent, pac_url, dns_resolver}`. `POST /wpad/apply` → délègue `sudo -n proxypac-wpad apply`. `POST /transparent` body `{on: bool}` → `sudo -n torctl transparent on|off`. `GET /wpad/state` → `sudo -n proxypac-wpad state` (JSON). Toutes protégées par `require_jwt`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-proxypac/tests/test_api_status.py
import sys; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from fastapi.testclient import TestClient
import api.main as m

def test_status_reports_role_and_socks(monkeypatch):
    monkeypatch.setattr(m.role, "detect", lambda probe=None: {"role":"master","tier":1,"dns_resolver":True,"lan_ip":"192.168.1.200"})
    monkeypatch.setattr(m.config, "load", lambda *a, **k: {"socks_endpoint":"192.168.1.200:9050","transparent":True,"wpad_domain":"gk2.secubox.in","pac_url":"","role":"auto"})
    c = TestClient(m.app)
    r = c.get("/status")
    assert r.status_code == 200
    d = r.json()
    assert d["role"] == "master" and d["socks_endpoint"] == "192.168.1.200:9050" and d["transparent"] is True

def test_transparent_toggle_delegates(monkeypatch):
    called = {}
    monkeypatch.setattr(m, "_ctl", lambda *a, **k: called.setdefault("args", a) or (0, ""))
    c = TestClient(m.app)
    r = c.post("/transparent", json={"on": True})
    assert r.status_code == 200 and r.json().get("ok") is True
    assert "torctl" in " ".join(called["args"][0])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-proxypac && python3 -m pytest tests/test_api_status.py -q`
Expected: FAIL.

- [ ] **Step 3: Extend api/main.py**

Add imports and helper + routes (keep existing routes untouched):

```python
from proxypac import role, config as _cfg
import subprocess

config = _cfg  # alias for tests

def _ctl(args, timeout=25):
    try:
        p = subprocess.run(["sudo", "-n", *args], capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return 1, ""

@app.get("/status")
def status(_=Depends(require_jwt)):
    r = role.detect()
    c = config.load()
    dom = c.get("wpad_domain") or ""
    return {"role": r["role"], "tier": r["tier"], "dns_resolver": r.get("dns_resolver", False),
            "lan_ip": r.get("lan_ip", ""), "socks_endpoint": c["socks_endpoint"],
            "transparent": bool(c.get("transparent", True)),
            "pac_url": c.get("pac_url") or (f"http://wpad.{dom}/wpad.dat" if dom else "")}

@app.post("/wpad/apply")
def wpad_apply(_=Depends(require_jwt)):
    rc, out = _ctl(["/usr/sbin/proxypac-wpad", "apply"])
    return {"ok": rc == 0, "detail": out}

@app.get("/wpad/state")
def wpad_state(_=Depends(require_jwt)):
    import json as _j
    rc, out = _ctl(["/usr/sbin/proxypac-wpad", "state"])
    try:
        return _j.loads(out) if rc == 0 else {"error": "ctl indisponible"}
    except Exception:
        return {"error": "réponse illisible"}

class Toggle(BaseModel):
    on: bool

@app.post("/transparent")
def transparent(t: Toggle, _=Depends(require_jwt)):
    rc, out = _ctl(["/usr/sbin/torctl", "transparent", "on" if t.on else "off"])
    return {"ok": rc == 0, "detail": out}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/secubox-proxypac && python3 -m pytest tests/test_api_status.py tests/test_api.py -q`
Expected: PASS (nouveau + non-régression de l'API existante).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-proxypac/api/main.py packages/secubox-proxypac/tests/test_api_status.py
git commit -m "feat(proxypac): API /status + /wpad/apply + /wpad/state + /transparent (délègue via sudo scopé)"
```

---

### Task 7: secubox-proxypac — panneau réécrit (navbar + statut + candidats + runbook)

**Files:**
- Modify: `packages/secubox-proxypac/www/proxypac/index.html`
- Test: `packages/secubox-proxypac/tests/test_panel.py`

**Interfaces:**
- Consumes: `/api/v1/proxypac/{status,rules,candidates,override,wpad/state,wpad/apply,transparent}`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-proxypac/tests/test_panel.py
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
def test_panel_has_navbar_and_status_and_runbook():
    h = (ROOT/"www/proxypac/index.html").read_text()
    assert 'class="sidebar"' in h and '/shared/sidebar.js' in h, "navbar manquante"
    assert '/api/v1/proxypac/status' in h, "carte statut manquante"
    assert 'socks_remote_dns' in h, "runbook client manquant"
    assert 'sbx_token' in h, "doit lire le jeton sbx_token"
    assert '/transparent' in h, "toggle transparent manquant"

def test_menu_entry_valid_json():
    import json
    j = json.loads((ROOT/"menu.d/580-proxypac.json").read_text())
    assert j["path"] == "/proxypac/" and j["id"] == "proxypac"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-proxypac && python3 -m pytest tests/test_panel.py -q`
Expected: FAIL.

- [ ] **Step 3: Rewrite the panel**

Réécrire `www/proxypac/index.html` en hybrid-dark avec : sidebar (`<nav class="sidebar" id="sidebar"></nav>` + `<script src="/shared/sidebar.js">`), en-tête + cartes statut (rôle/tier, échelon WPAD actif, endpoint SOCKS, santé transparent via `/status`), toggle transparent (`POST /transparent`), URL PAC/WPAD + runbook (coller l'URL, note Firefox `network.proxy.socks_remote_dns=true`), liste de règles + override (conserver le comportement existant), liste candidats (`/candidates`). Toutes les requêtes `fetch` ajoutent l'en-tête `Authorization: 'Bearer ' + localStorage.getItem('sbx_token')` et `credentials:'same-origin'`. Modèle de look : le panneau picobrew (`packages/secubox-picobrew/www/picobrew/index.html`) — cartes stat, toasts, `.btn`, `hybrid-dark.css`.

(Le contenu complet reprend la structure du panneau picobrew ; l'implémenteur l'écrit intégralement — voir ce fichier comme référence de style, ne pas le copier verbatim.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/secubox-proxypac && python3 -m pytest tests/test_panel.py -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-proxypac/www/proxypac/index.html packages/secubox-proxypac/tests/test_panel.py
git commit -m "feat(proxypac): panneau réécrit — sidebar navbar + statut rôle/SOCKS/transparent + candidats + runbook client"
```

---

### Task 8: Packaging — installer dropins, sudoers, postinst wiring, changelogs, build

**Files:**
- Modify: `packages/secubox-tor/debian/rules`, `debian/postinst`, `debian/control`, `debian/changelog`
- Create: `packages/secubox-tor/debian/secubox-tor.sudoers` (si besoin runtime)
- Modify: `packages/secubox-proxypac/debian/rules`, `debian/postinst`, `debian/control`, `debian/changelog`
- Create: `packages/secubox-proxypac/debian/secubox-proxypac.sudoers`

**Interfaces:** produit les deux `.deb` installables.

- [ ] **Step 1: secubox-tor debian/rules — installer helpers, dropins, share**

Ajouter au bloc `override_dh_auto_install:` :
```makefile
	install -D -m 755 sbin/tor-lan-ip debian/secubox-tor/usr/sbin/tor-lan-ip
	install -D -m 755 sbin/torctl debian/secubox-tor/usr/sbin/torctl
	install -d debian/secubox-tor/usr/share/secubox/tor
	install -m 644 conf/torrc.d/50-secubox-socks-lan.conf conf/torrc.d/60-secubox-transparent.conf debian/secubox-tor/usr/share/secubox/tor/
	install -m 644 conf/unbound/secubox-onion-forward.conf debian/secubox-tor/usr/share/secubox/tor/
	install -m 644 nft.d/secubox-tor-transparent.nft debian/secubox-tor/usr/share/secubox/tor/
```
(Les dropins vont dans `/usr/share/secubox/tor/` — templates ; `torctl` les copie vers les emplacements actifs. `50-secubox-socks-lan.conf` est un template `__LAN_IP__`, jamais installé directement dans `/etc/tor/torrc.d`.)

- [ ] **Step 2: secubox-tor postinst — poser le SocksPort LAN + activer le transparent si demandé**

Dans le bloc `configure` (avant `#DEBHELPER#`, qui reste seul sur sa ligne) :
```sh
    /usr/sbin/torctl socks-lan ensure || true
    # transparent activé par défaut (aligné proxypac.toml transparent=true) ;
    # idempotent, best-effort, réutilise le TransPort toolbox s'il existe.
    /usr/sbin/torctl transparent on || true
```

- [ ] **Step 3: secubox-proxypac debian/rules — installer config, ctl, sudoers**

Ajouter :
```makefile
	install -D -m 644 conf/proxypac.toml debian/secubox-proxypac/etc/secubox/proxypac/proxypac.toml
	install -D -m 755 sbin/proxypac-wpad debian/secubox-proxypac/usr/sbin/proxypac-wpad
	install -D -m 440 debian/secubox-proxypac.sudoers debian/secubox-proxypac/etc/sudoers.d/secubox-proxypac
```

- [ ] **Step 4: secubox-proxypac sudoers (scopé)**

```
# packages/secubox-proxypac/debian/secubox-proxypac.sudoers
# L'API proxypac (user secubox) délègue les actions privilégiées à des ctl audités.
secubox ALL=(root) NOPASSWD: /usr/sbin/proxypac-wpad apply, /usr/sbin/proxypac-wpad state, /usr/sbin/torctl transparent on, /usr/sbin/torctl transparent off
```

- [ ] **Step 5: secubox-proxypac postinst — conffile-safe + appliquer l'échelon au configure**

Le `proxypac.toml` est un **conffile** (dpkg gère les prompts ; ne pas l'écraser). Ajouter dans `configure`, après la génération existante :
```sh
    /usr/sbin/proxypac-wpad apply || true
```
Vérifier que `#DEBHELPER#` reste seul sur sa ligne.

- [ ] **Step 6: control — dépendances**

`secubox-proxypac` Depends: ajouter `secubox-tor` (fournit tor-lan-ip/torctl + endpoints). `secubox-tor` Depends: ajouter `tor`, `unbound`, `nftables` si absents.

- [ ] **Step 7: changelogs**

`secubox-tor` → nouvelle version (tête actuelle +1). `secubox-proxypac` → `1.2.0-1~bookworm1` (tête 1.1.0). Date `Fri, 24 Jul 2026`, signature `Gerald KERMA <devel@cybermind.fr>`.

- [ ] **Step 8: build les deux paquets**

```bash
cd packages/secubox-tor && dpkg-buildpackage -us -uc -b 2>&1 | tail -3
cd ../secubox-proxypac && dpkg-buildpackage -us -uc -b 2>&1 | tail -3
dpkg-deb -c ../secubox-tor_*_all.deb | grep -E "tor-lan-ip|torctl|secubox-onion-forward|secubox-tor-transparent"
dpkg-deb -c ../secubox-proxypac_*_all.deb | grep -E "proxypac.toml|proxypac-wpad|sudoers.d/secubox-proxypac|menu.d/580-proxypac"
```
Expected: les deux `.deb` construits, contenu attendu présent. Vérifier `bash -n` sur les deux postinst et `#DEBHELPER#` seul sur sa ligne.

- [ ] **Step 9: Commit**

```bash
git add packages/secubox-tor/debian packages/secubox-proxypac/debian
git commit -m "build(proxypac,tor): packaging — dropins, sudoers scopé, postinst wiring (socks-lan+transparent+wpad), changelogs"
```

---

## Recette de vérification manuelle (board, après déploiement)

```bash
# 1. Endpoints Tor
ss -tlnp | grep 9050          # 192.168.1.200:9050 ET 10.10.0.1:9050
ss -tlnp | grep -E '9040|9053' # TransPort+DNSPort si transparent on
# 2. Transparent .onion (wg-toolbox + LAN) — SANS PAC sur le client :
#    depuis un client LAN utilisant le DNS du box, ouvrir http://<onion>/
#    (le box automap + redirect). Vérifier journalctl -u tor@default.
# 3. PAC / rôle
curl -s http://192.168.1.200/api/v1/proxypac/status   # role/tier/socks/transparent
curl -I http://192.168.1.200/proxy.pac                # MIME x-ns-proxy-autoconfig
# 4. Master : dhcp-option=252 présent dans /etc/dnsmasq.d/secubox-wpad.conf
# 5. Panneau : navbar visible, cartes statut peuplées, toggle transparent OK.
# 6. Non-régression : SocksPort mesh 10.10.0.1 toujours là ; DNS LAN OK ; board 100+ services vivants.
```

## Notes / suivis connus (hors du chemin critique)

- **Bind Unbound LAN** (`interface: 192.168.1.200` + `access-control 192.168.0.0/16`,
  posé live après le changement DHCP→box) : à backporter dans le paquet qui possède
  la config DNS LAN (secubox-hub / module DNS), **pas** proxypac — c'est un choix de
  topologie réseau, distinct. Le transparent `.onion` LAN en dépend fonctionnellement.
- **`eth2` en dur dans le nft transparent** : c'est l'iface LAN de gk2. Portabilité
  future = templater l'iface LAN détectée (comme `__LAN_IP__`). Acceptable pour la
  cible gk2 ; à généraliser si un autre board est visé.
- **`transparent on` par défaut au postinst** : installer le paquet active
  immédiatement le redirect nft sur wg-toolbox+eth2 (intention validée : wg-toolbox+LAN).
  Toggle off disponible via panneau / `torctl transparent off`.

## Hors périmètre

Sonde DHCP active, pays d'exit Tor, correction amont des perms `HiddenServiceDir`
(bug module exposition, ticket distinct), IPv6 automap (`.onion` IPv4 d'abord).
