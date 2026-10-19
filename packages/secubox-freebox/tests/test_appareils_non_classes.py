# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Import des appareils Freebox non classes (#2940) : suggestions seulement, jamais appliquees."""
from tests.test_pare_feu_ecriture import _pret


def _lecture_hotes(hotes):
    # Ruling (ref #2940, Tache 4) : le brief omettait le tuple (statut, corps) attendu par le
    # faux transport (cf. ok() de test_pare_feu_ecriture) ; sans lui, _envoyer deballe le dict
    # comme (statut, d) et "d" devient la chaine "result" -> AttributeError plus loin.
    return [(200, {"success": True, "result": hotes})]


def test_filtre_les_macs_deja_connues(tmp_path):
    hotes = [{"l2ident": {"id": "AA:BB:CC:00:00:01"}, "names": [{"name": "tv"}], "host_type": "television"},
             {"l2ident": {"id": "AA:BB:CC:00:00:02"}, "names": [{"name": "pc"}], "host_type": "workstation"}]
    svc, f, _ = _pret(tmp_path, _lecture_hotes(hotes))
    r = svc.appareils_non_classes(macs_connues={"aa:bb:cc:00:00:01"})
    assert len(r) == 1 and r[0]["mac"] == "aa:bb:cc:00:00:02" and r[0]["host_type"] == "workstation"


def test_macs_connues_vide_rend_tout(tmp_path):
    hotes = [{"l2ident": {"id": "AA:BB:CC:00:00:01"}, "names": [{"name": "tv"}], "host_type": "television"}]
    svc, f, _ = _pret(tmp_path, _lecture_hotes(hotes))
    assert len(svc.appareils_non_classes(macs_connues=set())) == 1


def test_hote_sans_adresse_mac_ignore(tmp_path):
    hotes = [{"l2ident": {}, "names": [{"name": "?"}], "host_type": "workstation"}]
    svc, f, _ = _pret(tmp_path, _lecture_hotes(hotes))
    assert svc.appareils_non_classes(macs_connues=set()) == []
