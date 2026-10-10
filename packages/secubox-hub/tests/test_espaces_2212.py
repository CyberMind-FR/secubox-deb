# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2212 : les six espaces de l'administration — table complète et sans reste, menu enrichi sans rien casser."""
import json
from pathlib import Path

from api import main as hub

RACINE = Path(__file__).resolve().parents[3]
TABLE = json.loads((Path(__file__).resolve().parents[1] / "espaces.json").read_text(encoding="utf-8"))
SIX = ["apercu", "protection", "surveillance", "services", "identite", "systeme"]


# Entrées de menu écrites par debian/rules et non versionnées en menu.d/ : vues sur gk2 (« autre »), le glob ne les voit pas.
MENUS_GENERES = {"acces"}


def test_les_menus_generes_existent_toujours_dans_les_regles():
    assert "26-acces.json" in (RACINE / "packages" / "secubox-auth" / "debian" / "rules").read_text(encoding="utf-8")


def ids_menu():
    ids = set()
    for motif in ("packages/*/menu.d/*.json", "packages/*/composants/*/menu.d/*.json"):
        for f in RACINE.glob(motif):
            if "/debian/" not in str(f):
                ids.add(json.loads(f.read_text(encoding="utf-8"))["id"])
    return ids | MENUS_GENERES


def test_les_six_espaces_dans_l_ordre():
    assert [e["id"] for e in TABLE["espaces"]] == SIX and [e["ordre"] for e in TABLE["espaces"]] == [1, 2, 3, 4, 5, 6]
    assert all(e["nom"] and e["icone"] for e in TABLE["espaces"])


def test_chaque_entree_de_menu_a_son_espace_et_aucune_ligne_n_est_perimee():
    mod = set(TABLE["modules"])
    assert ids_menu() - mod == set(), f"à classer dans espaces.json : {sorted(ids_menu() - mod)}"
    assert mod - ids_menu() == set(), f"lignes de espaces.json sans entrée de menu : {sorted(mod - ids_menu())}"


def test_valeurs_valides():
    for k, v in TABLE["modules"].items():
        assert v["espace"] in SIX, k
        assert v["objet"] is None or v["objet"] in TABLE["objets"], k


def test_la_vue_d_ensemble_ne_devient_pas_une_page_de_configuration():
    dedans = [k for k, v in TABLE["modules"].items() if v["espace"] == "apercu"]
    assert sorted(dedans) == ["apercu", "health", "hub"]


def test_les_identites_humaines_restent_dans_identite_et_pas_dans_systeme():
    """Séparation comptes Linux / identités SBXOS : aucune gestion d'identité n'est rangée dans Système."""
    for k in ("auth", "users", "sbxid", "vault", "annuaire", "avatar"):
        assert TABLE["modules"][k]["espace"] == "identite", k


# ── API du menu ───────────────────────────────────────────────────────────────────────────────────────────
def _calcule(monkeypatch, entrees, installes):
    monkeypatch.setattr(hub, "_load_menu_definitions", lambda: entrees)
    monkeypatch.setattr(hub, "_epingles_off", lambda: set())
    monkeypatch.setattr(hub, "_check_module_installed", lambda m: m in installes)
    monkeypatch.setattr(hub, "_check_module_active", lambda m: m in installes)
    return hub._compute_menu_sync()


ENTREES = [{"id": "waf", "name": "WAF", "category": "wall", "order": 105, "theme": "bouclier"},
           {"id": "dpi", "name": "DPI", "category": "mind", "order": 210, "theme": "bouclier"},
           {"id": "nac", "name": "NAC", "category": "auth", "order": 130, "theme": "reseau"},
           {"id": "backup", "name": "Backup", "category": "boot", "order": 550, "theme": "socle"},
           {"id": "inconnu", "name": "Neuf", "category": "wall", "order": 300}]


def test_le_menu_expose_les_espaces_et_ne_perd_aucune_entree(monkeypatch):
    res = _calcule(monkeypatch, ENTREES, {"waf", "dpi", "nac", "backup", "inconnu"})
    esp = {e["id"]: [i["id"] for i in e["items"]] for e in res["espaces"]}
    assert esp["protection"] == ["waf"] and esp["surveillance"] == ["nac", "dpi"] and esp["systeme"] == ["backup"]      # triés par ordre
    assert esp["autre"] == ["inconnu"]                                                                                    # une entrée non classée n'est jamais perdue
    assert [e["id"] for e in res["espaces"]][-1] == "autre"
    nac = [i for e in res["espaces"] for i in e["items"] if i["id"] == "nac"][0]
    assert nac["espace"] == "surveillance" and nac["objet"] == "DEVICE"


def test_la_compatibilite_est_conservee(monkeypatch):
    res = _calcule(monkeypatch, ENTREES, {"waf", "nac"})
    assert {c["id"] for c in res["categories"]} == {"wall", "auth"} and {t["id"] for t in res["themes"]} == {"bouclier", "reseau"}
    assert res["total_installed"] == 2


def test_un_espace_vide_n_apparait_pas(monkeypatch):
    res = _calcule(monkeypatch, ENTREES, {"waf"})
    assert [e["id"] for e in res["espaces"]] == ["protection"]


def test_les_metadonnees_des_espaces_viennent_de_la_table(monkeypatch):
    res = _calcule(monkeypatch, ENTREES, {"waf"})
    e = res["espaces"][0]
    assert (e["nom"], e["icone"], e["ordre"]) == ("Protection", "🛡️", 2)
