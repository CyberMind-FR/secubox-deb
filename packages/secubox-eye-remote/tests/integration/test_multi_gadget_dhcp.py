# packages/secubox-eye-remote/tests/integration/test_multi_gadget_dhcp.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: multi-gadget DHCP integration test.

Skipped if not run as root (needs CAP_NET_ADMIN to set up netns + veth).
Spins up a single network namespace containing a bridge `br0`, runs
dnsmasq with an overlay of the packaged config inside it, simulates two
`dhclient` clients with distinct MACs, and asserts that each gets a
distinct lease.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

requires_root = pytest.mark.skipif(
    os.geteuid() != 0, reason="needs root for netns + dnsmasq + dhclient"
)
needs_tools = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("ip", "dnsmasq", "dhclient")),
    reason="ip / dnsmasq / dhclient must be installed",
)


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


@requires_root
@needs_tools
def test_two_clients_get_distinct_leases(tmp_path: Path):
    ns = "eye-test"
    leasefile = tmp_path / "leases"
    confdir = tmp_path / "conf.d"
    confdir.mkdir()
    res = tmp_path / "reservations.conf"
    res.write_text("")
    pkg_conf = Path(
        os.environ.get(
            "SECUBOX_EYE_DNSMASQ_CONF",
            "packages/secubox-eye-remote/dnsmasq.d/eye-remote.conf",
        )
    )

    # 1. Build an overlay config that retargets the packaged conf at our
    #    tmp paths and the test netns interface.
    overlay = confdir / "eye-remote.conf"
    overlay.write_text(
        pkg_conf.read_text()
        .replace("interface=eye-br0", "interface=br0")
        .replace(
            "dhcp-leasefile=/var/lib/misc/dnsmasq-eye-remote.leases",
            f"dhcp-leasefile={leasefile}",
        )
        .replace(
            "conf-file=/etc/secubox/eye-remote/reservations.conf",
            f"conf-file={res}",
        )
        .replace(
            "dhcp-script=/usr/lib/secubox/eye-remote-leasewatch.sh",
            "# dhcp-script disabled for netns test",
        )
        .replace(
            "log-facility=/var/log/secubox/eye-remote-dhcp.log",
            f"log-facility={tmp_path}/dnsmasq.log",
        )
    )

    # 2. Stand up the netns + bridge + two veth pairs.
    try:
        _run(["ip", "netns", "del", ns])  # clean any prior state
    except subprocess.CalledProcessError:
        pass
    _run(["ip", "netns", "add", ns])
    try:
        _run(["ip", "netns", "exec", ns, "ip", "link", "add", "br0", "type", "bridge"])
        _run(
            ["ip", "netns", "exec", ns, "ip", "addr", "add", "10.55.0.1/24", "dev", "br0"]
        )
        _run(["ip", "netns", "exec", ns, "ip", "link", "set", "br0", "up"])

        for i, mac in enumerate(("02:fb:00:00:11:03", "02:fb:00:00:d2:7f"), start=1):
            _run(
                [
                    "ip", "netns", "exec", ns,
                    "ip", "link", "add", f"v{i}a", "type", "veth", "peer", "name", f"v{i}b",
                ]
            )
            _run(["ip", "netns", "exec", ns, "ip", "link", "set", f"v{i}a", "master", "br0"])
            _run(["ip", "netns", "exec", ns, "ip", "link", "set", f"v{i}a", "up"])
            _run(["ip", "netns", "exec", ns, "ip", "link", "set", f"v{i}b", "address", mac])
            _run(["ip", "netns", "exec", ns, "ip", "link", "set", f"v{i}b", "up"])

        # 3. Launch dnsmasq inside the namespace.
        dnsmasq = subprocess.Popen(
            ["ip", "netns", "exec", ns, "dnsmasq", "--keep-in-foreground",
             "--conf-file=" + str(overlay)]
        )
        time.sleep(1.0)

        # 4. Issue DHCP requests from both peers.
        for i in (1, 2):
            _run(
                ["ip", "netns", "exec", ns, "dhclient", "-1", "-v", "-pf",
                 str(tmp_path / f"dhclient-{i}.pid"), f"v{i}b"]
            )

        # 5. Inspect the lease file.
        leases = leasefile.read_text()
        assert "02:fb:00:00:11:03" in leases, f"rpiz lease missing in:\n{leases}"
        assert "02:fb:00:00:d2:7f" in leases, f"pi4b lease missing in:\n{leases}"
        ips = [line.split()[2] for line in leases.strip().splitlines()]
        assert len(set(ips)) == 2, f"expected two distinct IPs, got: {ips}"

        dnsmasq.terminate()
        dnsmasq.wait(timeout=5)
    finally:
        try:
            _run(["ip", "netns", "del", ns])
        except subprocess.CalledProcessError:
            pass
