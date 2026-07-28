# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests for api.policy — enforce flag + jail_dirs scope, fail-safe loading."""

from api.policy import DEFAULT_JAIL_DIRS, load_policy, should_jail, under_jail_dir


def test_load_missing_file_is_safe_default(tmp_path):
    enforce, dirs = load_policy(str(tmp_path / "nope.toml"))
    assert enforce is False
    assert dirs == DEFAULT_JAIL_DIRS


def test_load_no_policy_table_is_safe_default(tmp_path):
    f = tmp_path / "a.toml"
    f.write_text("[allowlist]\nexec_paths = []\n")
    enforce, dirs = load_policy(str(f))
    assert enforce is False
    assert dirs == DEFAULT_JAIL_DIRS


def test_load_enforce_true_and_custom_dirs(tmp_path):
    f = tmp_path / "a.toml"
    f.write_text('[policy]\nenforce = true\njail_dirs = ["/tmp", "/opt/"]\n')
    enforce, dirs = load_policy(str(f))
    assert enforce is True
    # trailing slash normalised away for unambiguous prefix matching
    assert dirs == ["/tmp", "/opt"]


def test_corrupt_toml_never_enables_enforcement(tmp_path):
    f = tmp_path / "bad.toml"
    f.write_text("this is not = valid = toml [[[")
    enforce, dirs = load_policy(str(f))
    assert enforce is False
    assert dirs == DEFAULT_JAIL_DIRS


def test_under_jail_dir_boundary():
    dirs = ["/usr/local/bin", "/tmp"]
    assert under_jail_dir("/usr/local/bin/evil", dirs) is True
    assert under_jail_dir("/tmp/x", dirs) is True
    # boundary: /usr/local/binary is NOT under /usr/local/bin
    assert under_jail_dir("/usr/local/binary", dirs) is False
    assert under_jail_dir("/usr/bin/curl", dirs) is False
    assert under_jail_dir(None, dirs) is False


def test_should_jail_alert_only_never_jails():
    # enforce=False => even an exe squarely under a jail_dir is not jailed
    assert should_jail("/tmp/evil", enforce=False, jail_dirs=["/tmp"]) is False


def test_should_jail_enforce_respects_scope():
    dirs = ["/tmp", "/usr/local/bin"]
    assert should_jail("/tmp/evil", True, dirs) is True
    assert should_jail("/usr/local/bin/notwork", True, dirs) is True
    # enforce on, but exe outside every jail_dir => still not jailed
    assert should_jail("/usr/sbin/legit-nondpkg-tool", True, dirs) is False
