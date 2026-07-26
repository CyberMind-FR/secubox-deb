# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from release import repo


def test_copy_argv_is_list_no_shell():
    argv = repo.copy_argv("draft", "internal", ["secubox-dpi"])
    assert argv[0] == "reprepro" and "copy" in argv and "secubox-dpi" in argv
    assert not any(";" in a for a in argv)
    with pytest.raises(repo.RepoError):
        repo.copy_argv("draft", "internal", [])
    with pytest.raises(repo.RepoError):
        repo.copy_argv("draft", "prod", ["x"])


def test_plan_promote_refuses_amd64_only():
    evo_ok = {"artifacts": [{"kind": "deb", "name": "secubox-dpi", "arch": "arm64"}]}
    evo_bad = {"artifacts": [{"kind": "deb", "name": "secubox-dpi", "arch": "amd64"}]}
    assert repo.plan_promote(evo_ok, "draft", "internal")
    with pytest.raises(repo.RepoError):
        repo.plan_promote(evo_bad, "draft", "internal")
