# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

from api import dpkg_backing

def fake_runner(ok, out=""):
    class R: pass
    def run(cmd, **kw):
        r = R(); r.returncode = 0 if ok else 1; r.stdout = out; r.stderr = ""
        return r
    return run

def test_resolve_pkg_backed():
    # dpkg -S prints "pkg: /path"
    r = fake_runner(True, "secubox-yacy: /usr/bin/yacy\n")
    assert dpkg_backing.resolve_pkg("/usr/bin/yacy", runner=r) == "secubox-yacy"

def test_resolve_pkg_unbacked():
    r = fake_runner(False, "dpkg-query: no path found matching pattern /usr/local/bin/notwork-monitoring\n")
    assert dpkg_backing.resolve_pkg("/usr/local/bin/notwork-monitoring", runner=r) is None

def test_resolve_pkg_diversion():
    # dpkg -S prints "pkg, diverting-pkg: /path" for a diverted file
    r = fake_runner(True, "secubox-yacy, dpkg-divert: /usr/bin/yacy\n")
    assert dpkg_backing.resolve_pkg("/usr/bin/yacy", runner=r) == "secubox-yacy"

def test_is_backed_true_false():
    assert dpkg_backing.is_backed("/usr/bin/yacy", runner=fake_runner(True, "secubox-yacy: /usr/bin/yacy\n")) is True
    assert dpkg_backing.is_backed("/usr/local/bin/x", runner=fake_runner(False)) is False
