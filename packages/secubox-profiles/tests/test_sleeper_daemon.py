# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.



# ── Peremption des signaux (#1001) ──────────────────────────────────────────

def test_stale_snapshot_is_treated_as_absent(tmp_path):
    """Un fichier FIGE est plus dangereux qu'un fichier absent.

    Absent => {} => aucun Signal => rien ne dort : deja sur. Mais un fichier
    PRESENT et fige rend des horodatages anciens, qui ressemblent exactement a
    de l'inactivite — et l'inactivite fait STOPPER.

    Constate le 2026-08-07 : le fichier datait de ONZE JOURS car
    /var/cache/secubox/waf appartenait a `secubox` alors que sbxwaf tourne en
    `secubox-waf`. Tous les vhosts y paraissaient inactifs ; le sleeper aurait
    eteint la board entiere."""
    import json as _json
    import os
    import time as _time
    from api import sleeper_daemon as sd

    p = tmp_path / "vhost-signals.json"
    p.write_text(_json.dumps({"a.gk2": {"last_request_ts": 1, "active_conns": 0}}))
    old = _time.time() - 11 * 86400
    os.utime(p, (old, old))
    assert sd._read_snapshot_file(p) == {}, "un snapshot perime doit etre ignore"


def test_fresh_snapshot_is_read(tmp_path):
    """La garde ne doit pas tout refuser : un fichier frais passe."""
    import json as _json
    from api import sleeper_daemon as sd

    p = tmp_path / "vhost-signals.json"
    p.write_text(_json.dumps({"a.gk2": {"last_request_ts": 1, "active_conns": 0}}))
    assert "a.gk2" in sd._read_snapshot_file(p)


def test_threshold_is_below_the_idle_decision():
    """On ne peut pas endormir sur la foi de donnees plus vieilles que la
    decision elle-meme."""
    from types import SimpleNamespace
    from api.lifecycle import idle_threshold
    from api import sleeper_daemon as sd
    assert sd.SIGNALS_MAX_AGE_S < idle_threshold(SimpleNamespace(wake_class="normal"))
