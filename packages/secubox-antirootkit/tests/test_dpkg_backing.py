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


def test_merged_usr_alias_resolves():
    """merged-usr: audit reports /usr/bin/grep but dpkg owns /bin/grep. The
    resolver must try the alias and find it (else a legit binary looks
    non-dpkg -> false-positive flood). Regression guard, gk2 2026-07-28."""
    from api.dpkg_backing import resolve_pkg

    class FakeRun:
        def __init__(self):
            self.calls = []

        def __call__(self, argv, **kw):
            path = argv[-1]
            self.calls.append(path)
            import types
            if path == "/bin/grep":
                return types.SimpleNamespace(returncode=0, stdout="grep: /bin/grep\n")
            return types.SimpleNamespace(returncode=1, stdout="")

    fake = FakeRun()
    assert resolve_pkg("/usr/bin/grep", runner=fake) == "grep"
    assert "/usr/bin/grep" in fake.calls and "/bin/grep" in fake.calls


def test_truly_unbacked_stays_none():
    from api.dpkg_backing import resolve_pkg
    import types

    def none_runner(argv, **kw):
        return types.SimpleNamespace(returncode=1, stdout="")

    assert resolve_pkg("/usr/local/bin/notwork", runner=none_runner) is None


def test_dpkg_index_membership_and_merged_usr(tmp_path):
    """DpkgIndex answers is_backed from an in-memory set (no subprocess) and
    honours merged-usr aliasing."""
    from api.dpkg_backing import DpkgIndex
    # dpkg records /bin/grep; audit reports /usr/bin/grep
    idx = DpkgIndex(paths={"/bin/grep", "/usr/lib/x/foo.so"})
    assert idx.is_backed("/usr/bin/grep") is True   # via merged-usr alias
    assert idx.is_backed("/bin/grep") is True
    assert idx.is_backed("/usr/local/bin/notwork") is False
    assert idx.is_backed("") is False
    assert idx.is_backed(None) is False


def test_load_dpkg_paths_reads_list_files(tmp_path):
    from api.dpkg_backing import _load_dpkg_paths
    (tmp_path / "coreutils.list").write_text("/bin/ls\n/usr/share/doc/coreutils\n")
    (tmp_path / "grep.list").write_text("/bin/grep\n")
    paths = _load_dpkg_paths(str(tmp_path / "*.list"))
    assert "/bin/ls" in paths and "/bin/grep" in paths
    assert len(paths) == 3
