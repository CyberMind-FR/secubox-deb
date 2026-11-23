# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3896 : Redis dans la LXC PeerTube (trixie, non privilégiée) — surcharge sans espaces de noms, Redis vérifié avant la suite."""
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "lib" / "peertube" / "install-lxc.sh"


def test_surcharge_redis_sans_espaces_de_noms_puis_ping():
    s = SCRIPT.read_text(encoding="utf-8")
    bloc = s[s.index("redis-server.service.d/lxc.conf <<'DROPIN'"):s.index("DROPIN\n", s.index("<<'DROPIN'") + 10)]
    for option in ("PrivateUsers=false", "PrivateTmp=false", "ProtectSystem=false", "ReadWritePaths=", "ExecPaths=", "NoExecPaths="):
        assert option in bloc, option
    assert s.index("lxc.conf <<'DROPIN'") < s.index("service redis-server start")
    assert "redis-cli ping | grep -q PONG ||" in s
