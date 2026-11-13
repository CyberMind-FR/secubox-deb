# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3670 — la console du kiosque ne demande jamais le mot de passe parce que l'agrégateur démarre encore : le jeton de
console est redemandé tant que le service répond 5xx ou ne répond pas ; un refus (4xx) rend le formulaire aussitôt."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "login.html"
SRC = PAGE.read_text(encoding="utf-8")


def _bloc_console() -> str:
    debut = SRC.index("// CONSOLE LOCALE DU KIOSQUE")
    fin = SRC.index("})();", debut) + len("})();")
    return SRC[debut:fin]


HARNAIS = r"""
const reponses = %s;
let appels = 0, jeton = null, redirige = null, message = null;
const formulaire = {style: {display: ''}};
global.location = {hostname: 'admin.localhost', port: '9078', replace: (u) => { redirige = u; }};
global.window = {location: global.location};
global.sessionStorage = {getItem: () => null, setItem: () => {}};
global.document = {getElementById: (id) => id === 'login-form' ? formulaire : null};
global.showMsg = (t, c) => { message = c + ':' + t; };
global.finalizeToken = (t) => { jeton = t; };
global._sbxRedirect = () => '/';
let _username;
let attentes = 0;
global.setTimeout = (f) => { if (++attentes <= 8) f(); };
global.fetch = () => {
  const r = reponses[Math.min(appels++, reponses.length - 1)];
  if (r === 'reseau') return Promise.reject(new Error('reseau'));
  return Promise.resolve({ok: r >= 200 && r < 300, status: r, json: () => Promise.resolve({access_token: 'jeton-console'})});
};
%s
setImmediate(() => setImmediate(() => setImmediate(() => setImmediate(() => setImmediate(() => setImmediate(() => {
  console.log(JSON.stringify({appels, jeton, redirige, message, affiche: formulaire.style.display}));
}))))));
"""


def _executer(reponses):
    node = shutil.which("node")
    if not node:
        pytest.skip("node absent")
    code = HARNAIS % (json.dumps(reponses), _bloc_console())
    sortie = subprocess.run([node, "-e", code], capture_output=True, text=True, timeout=30, check=True).stdout
    return json.loads(sortie.strip().splitlines()[-1])


def test_service_qui_demarre_puis_session_sans_mot_de_passe():
    r = _executer([502, "reseau", 503, 200])
    assert r["appels"] == 4 and r["jeton"] == "jeton-console" and r["redirige"] == "/"


def test_refus_rend_le_formulaire_sans_reessai():
    r = _executer([403])
    assert r["appels"] == 1 and r["jeton"] is None and r["affiche"] == ""


def test_formulaire_masque_pendant_l_attente():
    r = _executer([503, 503, 503])
    # Le harnais s'arrête avant la fin du délai : formulaire masqué, message d'attente, aucun mot de passe demandé.
    assert r["jeton"] is None and r["affiche"] == "none" and r["message"].startswith("info:")
