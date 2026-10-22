# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2996 — un module API seule (pas de page, donc pas de menu.d : Éphéméride, IPv6 Guardian) se déclare au registre du
Hall par un fichier `/usr/share/secubox/registre.d/<id>.json` livré par son paquet. Le registre le traite comme une entrée
du menu : socket présente ⇒ en ligne, unité en échec ⇒ alarme. Une entrée déjà au menu n'est pas doublée ; un fichier
illisible est ignoré. Sans cela, leurs cartes du Hall disaient « aucune source » alors qu'elles répondaient."""
import json
from pathlib import Path

from api.registry import charger_registre_d, normalize_services

PAQUETS = Path(__file__).resolve().parents[2]
MENU = {"categories": [{"id": "mind", "items": [{"id": "radio", "name": "Radio", "category": "mind", "path": "/radio/"}]}]}


def test_un_supplement_entre_au_registre_avec_le_statut_de_sa_socket():
    sup = [{"id": "ephemeride", "name": "Éphéméride", "category": "mind", "description": "Date, soleil, lune"}]
    svcs = {s.id: s for s in normalize_services(MENU, {}, {}, sockets=frozenset({"ephemeride"}), supplements=sup)}
    assert "ephemeride" in svcs and svcs["ephemeride"].health.state == "online" and svcs["ephemeride"].status == "active"
    assert svcs["ephemeride"].name == "Éphéméride" and svcs["ephemeride"].category == "mind"
    # sans socket ni unité : aucune source, comme une entrée de menu
    svcs = {s.id: s for s in normalize_services(MENU, {}, {}, supplements=sup)}
    assert svcs["ephemeride"].status == "nosource"
    # unité en échec : alarme, jamais masquée par une socket
    svcs = {s.id: s for s in normalize_services(MENU, {"ephemeride": {"status": "error"}}, {}, sockets=frozenset({"ephemeride"}), supplements=sup)}
    assert svcs["ephemeride"].health.state == "offline"


def test_une_entree_deja_au_menu_n_est_pas_doublee():
    sup = [{"id": "radio", "name": "Radio bis"}]
    svcs = normalize_services(MENU, {}, {}, supplements=sup)
    assert [s.id for s in svcs] == ["radio"] and svcs[0].name == "Radio"


def test_lecture_du_dossier_registre_d(tmp_path):
    (tmp_path / "ipv6guard.json").write_text(json.dumps({"id": "ipv6guard", "name": "IPv6 Guardian", "category": "wall"}), encoding="utf-8")
    (tmp_path / "casse.json").write_text("{pas du json", encoding="utf-8")
    (tmp_path / "sans-id.json").write_text("{}", encoding="utf-8")
    sup = charger_registre_d(str(tmp_path))
    assert [s["id"] for s in sup] == ["ipv6guard"]
    assert charger_registre_d(str(tmp_path / "absent")) == []


def test_ephemeride_et_ipv6guard_livrent_leur_fiche():
    for paquet, ident in (("secubox-ephemeride", "ephemeride"), ("secubox-ipv6guard", "ipv6guard")):
        f = PAQUETS / paquet / "registre.d" / f"{ident}.json"
        d = json.loads(f.read_text(encoding="utf-8"))
        assert d["id"] == ident and d["name"] and d["category"], f
        assert f"registre.d/{ident}.json" in (PAQUETS / paquet / "debian" / "rules").read_text(encoding="utf-8")
