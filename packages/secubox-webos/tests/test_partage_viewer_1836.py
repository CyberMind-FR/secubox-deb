# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Bouton Partager du viewer : le lecteur radio donne un lien, un refus de copie est dit (#1836)."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

HALL = (Path(__file__).resolve().parents[1] / "www" / "hall" / "index.html").read_text()
pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="node absent")


def _fonctions() -> str:
    m = re.search(r"  function lienAPartager\(\)\{.*?\n  function copierLien\(lien\)\{.*?\n  \}\n", HALL, re.S)
    assert m, "lienAPartager / copierLien introuvables"
    return m.group(0)


def _joue(scenario: dict) -> dict:
    """Exécute les deux fonctions dans Node avec un navigateur simulé ; renvoie lien et copie."""
    js = r"""
const sc = %s;
let copie = null, prompts = [];
const iframe = sc.iframe ? { src: sc.iframe } : null;
const media = { querySelector: () => iframe };
let courant = sc.courant || null, lecteurId = sc.lecteurId || null;
const pisteLecteur = () => (sc.piste ? { url: sc.piste } : null);
global.SBX_DOMAINE = { partageable: u => /^https?:/.test(u) ? u : 'https://hall.exemple.test' + u };
global.window = { SBX_DOMAINE: global.SBX_DOMAINE };   // dans un navigateur, window.X est aussi la globale X
global.document = { createElement: () => ({ setAttribute(){}, style:{}, select(){}, value:'' }),
  body: { appendChild(){}, removeChild(){} }, execCommand: () => sc.repliOk };
Object.defineProperty(global, 'navigator', { configurable: true, value: sc.sansClipboard ? {} : { clipboard: { writeText: l => sc.refus ? Promise.reject(new Error('refus')) : (copie = l, Promise.resolve()) } } });   // Node 22 : navigator est en lecture seule, d'où defineProperty
%s
(async () => {
  const lien = lienAPartager();
  const ok = lien ? await copierLien(lien) : null;
  console.log(JSON.stringify({ lien, ok, copie }));
})();
""" % (json.dumps(scenario), _fonctions())
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True, timeout=20)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_radio_sans_courant_partage_le_morceau_annonce():
    r = _joue({"courant": None, "lecteurId": "radio", "piste": "https://radio.gk2.secubox.in/titre/42"})
    assert r["lien"] == "https://radio.gk2.secubox.in/titre/42" and r["ok"] is True and r["copie"] == r["lien"]


def test_radio_sans_piste_partage_l_adresse_du_lecteur():
    r = _joue({"courant": None, "lecteurId": "radio", "iframe": "https://radio.gk2.secubox.in/micro"})
    assert r["lien"] == "https://radio.gk2.secubox.in/micro" and r["ok"] is True


def test_media_courant_inchange_et_chemin_interne_rendu_absolu():
    r = _joue({"courant": "/api/v1/ytsas/stream/abc"})
    assert r["lien"].startswith("https://") and r["lien"].endswith("/api/v1/ytsas/stream/abc")


def test_rien_a_partager_ne_dit_pas_fait():
    r = _joue({"courant": None, "lecteurId": None})
    assert r["lien"] == "" and r["ok"] is None and r["copie"] is None


def test_refus_du_presse_papiers_passe_au_repli():
    r = _joue({"courant": "https://exemple.test/v", "refus": True, "repliOk": True})
    assert r["ok"] is True                                  # le repli a copié


def test_refus_total_est_signale_pas_avale():
    r = _joue({"courant": "https://exemple.test/v", "refus": True, "repliOk": False})
    assert r["ok"] is False                                 # le bouton affichera le lien, jamais « fait »
    r = _joue({"courant": "https://exemple.test/v", "sansClipboard": True, "repliOk": False})
    assert r["ok"] is False


def test_le_bouton_n_allume_que_sur_une_copie_reussie():
    gestionnaire = HALL[HALL.index("E('viewer-share').addEventListener"):HALL.index("E('viewer-cast').addEventListener")]
    assert "copierLien(lien).then(function(ok){" in gestionnaire
    assert gestionnaire.index("if(ok)") < gestionnaire.index("classList.add('on')")
    assert "prompt('Copiez ce lien :', lien)" in gestionnaire
    assert "if(!courant) return;" not in gestionnaire       # la cause : la radio n'a pas de `courant`
