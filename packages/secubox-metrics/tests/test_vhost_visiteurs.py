# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# #1176 : les visiteurs uniques ne comptent QUE les IP publiques (pas
# 127.0.0.1 / prive interne) — sinon « 1 visiteur unique » sur des sites vides.
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
import vhost_stats as vs


def _feed(s, ip):
    line = (f'x.gk2.secubox.in {ip} - - [01/Jan/2026:00:00:00 +0000] '
            f'"GET /page HTTP/1.1" 200 100 "-" "Mozilla/5.0"')
    m = vs.LIGNE_HOTE.match(line) or vs.LIGNE.match(line)
    assert m, f"regex should match: {line}"
    vs._compter(s, m)


def test_publique():
    assert vs._publique("8.8.8.8") is True
    assert vs._publique("82.67.100.75") is True
    assert vs._publique("127.0.0.1") is False
    assert vs._publique("192.168.1.200") is False
    assert vs._publique("10.100.0.5") is False
    assert vs._publique("::1") is False


def test_visiteurs_excluent_loopback_et_prive():
    s = vs._vierge()
    for ip in ["127.0.0.1", "192.168.1.200", "10.100.0.5", "8.8.8.8", "82.67.100.75"]:
        _feed(s, ip)
    assert s["requetes"] == 5            # toutes les requetes comptent
    assert len(s["ips"]) == 2            # mais 2 visiteurs PUBLICS seulement
    assert "8.8.8.8" in s["ips"]
    assert "127.0.0.1" not in s["ips"]
    assert "192.168.1.200" not in s["ips"]
