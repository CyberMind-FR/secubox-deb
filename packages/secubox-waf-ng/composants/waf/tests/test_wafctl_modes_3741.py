# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3741 : wafctl leurres-modes / php-hotes — validation, écriture atomique, audit de CHAQUE issue."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]


@pytest.fixture
def ctl(tmp_path):
    (tmp_path / "auth").mkdir()
    (tmp_path / "audit.log").touch()
    shutil.copy(ICI / "config" / "vhost_profiles.json", tmp_path / "vp.json")
    (tmp_path / "routes.json").write_text(json.dumps({"a.exemple.fr": ["127.0.0.1", 80]}))
    s = (ICI / "scripts" / "wafctl").read_text()
    for var, val in (("PROFILS_VHOST", tmp_path / "vp.json"), ("LEURRES_MODES", tmp_path / "auth" / "lm.json"),
                     ("ROUTES_HAPROXY", tmp_path / "routes.json"), ("AUDIT_SECUBOX", tmp_path / "audit.log")):
        s = re.sub(rf'^{var}=.*$', f'{var}="{val}"', s, count=1, flags=re.M)
    (tmp_path / "wafctl").write_text(s)

    def lance(*args, entree=b""):
        r = subprocess.run(["bash", str(tmp_path / "wafctl"), *args], input=entree, capture_output=True, timeout=30, check=False)
        return r.returncode, json.loads(r.stdout.decode().strip().splitlines()[-1])
    lance.dossier = tmp_path
    lance.audits = lambda: [json.loads(x) for x in (tmp_path / "audit.log").read_text().splitlines()]
    return lance


def test_leurres_modes_ok_refus_echec_audites(ctl):
    rc, d = ctl("leurres-modes", "ecrire", entree=json.dumps({"acteur": "admin", "modes": {"rdp": "observer"}}).encode())
    assert rc == 0 and d["modes"] == {"rdp": "observer"}
    rc, d = ctl("leurres-modes", "ecrire", entree=b'{"modes": {"x": "observer"}}')
    assert rc == 2
    shutil.rmtree(ctl.dossier / "auth")                    # dossier absent : jamais créé par wafctl
    rc, d = ctl("leurres-modes", "ecrire", entree=b'{"modes": {"vnc": "bannir"}}')
    assert rc == 3 and not (ctl.dossier / "auth").exists()
    a = ctl.audits()
    assert [(x["action"], x["result"]) for x in a] == [("waf-leurres-modes", "ok"), ("waf-leurres-modes", "refus"),
                                                       ("waf-leurres-modes", "echec")]
    assert a[0]["acteur"] == "admin" and a[1]["acteur"] == "local"
    rc, d = ctl("leurres-modes", "lister")
    assert rc == 0 and d["modes"] == {}


def test_php_hotes_ok_refus_audites_motifs_gardes(ctl):
    rc, d = ctl("php-hotes", "ecrire", entree=json.dumps({"acteur": "admin", "hotes": ["blog.exemple.fr"]}).encode())
    assert rc == 0 and "^blog\\.exemple\\.fr$" in d["php_hotes"] and "^(nc|nextcloud|cloud)\\." in d["php_hotes"]
    rc, d = ctl("php-hotes", "ecrire", entree=b'{"hotes": ["a;b"]}')
    assert rc == 2
    rc, d = ctl("php-hotes", "ecrire", entree=b'{"hotes": []}')
    assert rc == 0 and "^blog\\.exemple\\.fr$" not in d["php_hotes"]
    assert [x["result"] for x in ctl.audits()] == ["ok", "refus", "ok"]
    rc, d = ctl("php-hotes", "lister")
    assert rc == 0 and d["vhosts"] == ["a.exemple.fr"]


def test_php_hotes_tous_pose_et_retire_le_motif_global(ctl):
    rc, d = ctl("php-hotes", "ecrire", entree=json.dumps({"acteur": "admin", "hotes": ["blog.exemple.fr"]}).encode())
    assert rc == 0
    rc, d = ctl("php-hotes", "ecrire", entree=json.dumps({"acteur": "admin", "tous": True}).encode())
    assert rc == 0 and d["tous"] is True and "^.*$" in d["php_hotes"]
    assert "^blog\\.exemple\\.fr$" in d["php_hotes"]          # les explicites restent
    rc, d = ctl("php-hotes", "ecrire", entree=json.dumps({"acteur": "admin", "tous": False}).encode())
    assert rc == 0 and d["tous"] is False and "^.*$" not in d["php_hotes"]
    assert "^blog\\.exemple\\.fr$" in d["php_hotes"]
    rc, d = ctl("php-hotes", "ecrire", entree=b'{"tous": "oui"}')
    assert rc == 2
