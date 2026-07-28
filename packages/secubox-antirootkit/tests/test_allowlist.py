# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

from api import allowlist


def test_allowed_exact_and_glob(tmp_path):
    f = tmp_path / "a.toml"
    f.write_text('[allowlist]\nexec_paths = ["/usr/local/bin/certbot", "/usr/local/bin/acme-*"]\n')
    al = allowlist.load(str(f))
    assert allowlist.allowed("/usr/local/bin/certbot", al) is True
    assert allowlist.allowed("/usr/local/bin/acme-renew-batch.sh", al) is True
    assert allowlist.allowed("/usr/local/bin/notwork-monitoring", al) is False
