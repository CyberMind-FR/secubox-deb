# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import json

from webfilter import voisins

SORTIE = json.dumps([
    {"dst": "192.168.1.50", "lladdr": "AA:BB:CC:DD:EE:01", "state": ["REACHABLE"]},
    {"dst": "2a01:db8::50", "lladdr": "aa:bb:cc:dd:ee:01", "state": ["STALE"]},
    {"dst": "fe80::1", "lladdr": "aa:bb:cc:dd:ee:01", "state": ["STALE"]},
    {"dst": "192.168.1.60", "state": ["FAILED"]},
    {"dst": "192.168.1.61", "lladdr": "aa:bb:cc:dd:ee:03", "state": ["FAILED"]},
    {"dst": "224.0.0.1", "lladdr": "01:00:5e:00:00:01", "state": ["PERMANENT"]},
    {"dst": "pas-une-ip", "lladdr": "aa:bb:cc:dd:ee:02", "state": ["REACHABLE"]},
    {"dst": "192.168.1.50", "lladdr": "aa:bb:cc:dd:ee:01", "state": ["STALE"]},
    {"dst": "fe80::1%eth0", "lladdr": "aa:bb:cc:dd:ee:04", "state": ["STALE"]},
    {"dst": "192.168.1.70", "lladdr": "pas-une-mac", "state": ["STALE"]},
    "pas un dict",
])


def test_lecture_de_la_table_de_voisinage():
    assert voisins.lire(SORTIE) == {"aa:bb:cc:dd:ee:01": ["192.168.1.50", "2a01:db8::50"]}


def test_sortie_illisible_donne_une_table_vide():
    assert voisins.lire("pas du json") == {} and voisins.lire("{}") == {} and voisins.lire("") == {} and voisins.lire("null") == {}
