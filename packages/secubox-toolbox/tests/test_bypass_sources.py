# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import re, pathlib

PKG = pathlib.Path(__file__).resolve().parents[1]
SEED = PKG / "conf" / "mitm-bypass-seed.conf"


def _patterns(path):
    out = []
    for ln in path.read_text().splitlines():
        s = ln.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def test_seed_file_exists_and_nonempty():
    assert SEED.exists()
    assert len(_patterns(SEED)) >= 15


def test_seed_patterns_form_valid_ignore_hosts_alternation():
    pats = _patterns(SEED)
    alt = re.compile("(?:" + "|".join(pats) + ")")
    assert alt.search("api.whatsapp.net")
    assert alt.search("gateway.icloud.com")
