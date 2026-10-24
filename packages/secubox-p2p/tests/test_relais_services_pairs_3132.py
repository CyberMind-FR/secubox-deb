# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3132 — relais du maillage : les services propres à un pair sont publiés (réglage services_des_pairs), et un nom
relayé vers un pair qui ne le publie plus est retiré. Le script exige root : on teste son Python réel (noms_perimes)
et le texte de la synchronisation."""
import json
import re
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "secubox-relais-maillage"
TEXTE = SCRIPT.read_text()


def _python_de(fonction):
    debut = TEXTE.index(fonction + "() {")
    return re.search(r"<<'PY'\n(.*?)\nPY\n", TEXTE[debut:], re.S).group(1)


def _execute(tmp_path, fonction, *args):
    code = tmp_path / (fonction + ".py")
    code.write_text(_python_de(fonction))
    return subprocess.run([sys.executable, "-I", str(code), *map(str, args)], capture_output=True, text=True)


ROUTES = {
    "bbs.gk1.secubox.in": ["10.10.0.8", 9080],          # gk1 ne le publie plus : périmé
    "hall.gk1.secubox.in": ["10.10.0.8", 9080],         # publié : gardé
    "socialrelay.gk1.secubox.in": ["10.10.0.8", 9080],  # retiré du parc : périmé
    "wpad.gk1.secubox.in": ["10.10.0.8", 9080],         # libellé exclu : posé à la main, jamais retiré
    "a.b.gk1.secubox.in": ["10.10.0.8", 9080],          # plusieurs niveaux : posé à la main, jamais retiré
    "hall.gk3.secubox.in": ["10.10.0.5", 9080],         # autre pair : jamais touché
    "hall.gk2.secubox.in": ["127.0.0.1", 9080],         # le relais lui-même : jamais touché
    "x.autre.fr": ["10.10.0.8", 9080],                  # même IP, autre domaine : jamais touché
}


def _perimes(tmp_path, publies, etat=None, communs="*"):
    f = tmp_path / "routes.json"
    f.write_text(json.dumps(ROUTES))
    e = tmp_path / "etat.json"
    if etat is not None:
        e.write_text(json.dumps(etat))
    r = _execute(tmp_path, "noms_perimes", f, e, "10.10.0.8", "gk1.secubox.in", "wpad,boot", communs, *publies)
    assert r.returncode == 0, r.stderr
    return r.stdout.split(), json.loads(e.read_text())


def test_perime_retire_seulement_au_second_releve(tmp_path):
    # 1er relevé : candidats notés, rien retiré (un webos au cache vide ne vide pas le relais d'un coup)
    a_retirer, etat = _perimes(tmp_path, ["hall.gk1.secubox.in"])
    assert a_retirer == []
    assert etat["10.10.0.8"] == ["bbs.gk1.secubox.in", "socialrelay.gk1.secubox.in"]
    # 2e relevé identique : retirés
    a_retirer, etat = _perimes(tmp_path, ["hall.gk1.secubox.in"], etat=etat)
    assert a_retirer == ["bbs.gk1.secubox.in", "socialrelay.gk1.secubox.in"]


def test_nom_republie_entre_deux_releves_n_est_pas_retire(tmp_path):
    _, etat = _perimes(tmp_path, ["hall.gk1.secubox.in"])
    a_retirer, etat = _perimes(tmp_path, ["hall.gk1.secubox.in", "bbs.gk1.secubox.in"], etat=etat)
    assert a_retirer == ["socialrelay.gk1.secubox.in"] and etat["10.10.0.8"] == ["socialrelay.gk1.secubox.in"]


def test_mode_communs_ne_retire_que_les_libelles_communs(tmp_path):
    _, etat = _perimes(tmp_path, [], communs="hall,bbs")
    assert etat["10.10.0.8"] == ["bbs.gk1.secubox.in", "hall.gk1.secubox.in"]


def test_routes_illisibles_rien_n_est_perime(tmp_path):
    f = tmp_path / "routes.json"
    f.write_text("{pas du json")
    r = _execute(tmp_path, "noms_perimes", f, tmp_path / "etat.json", "10.10.0.8", "gk1.secubox.in", "wpad", "*")
    assert r.returncode == 0 and r.stdout.strip() == ""


def test_domaine_d_un_autre_pair_refuse(tmp_path):
    f = tmp_path / "routes.json"
    f.write_text(json.dumps(ROUTES))
    # 10.10.0.8 annonce le domaine de gk3 (routé vers 10.10.0.5) : refusé
    assert _execute(tmp_path, "domaine_tenu_par_autre", f, "10.10.0.8", "gk3.secubox.in").returncode == 0
    # son propre domaine, ou un domaine neuf : accepté
    assert _execute(tmp_path, "domaine_tenu_par_autre", f, "10.10.0.8", "gk1.secubox.in").returncode == 1
    assert _execute(tmp_path, "domaine_tenu_par_autre", f, "10.10.0.8", "gk9.secubox.in").returncode == 1


def test_liste_de_noms_illisible_fait_echouer_l_extraction(tmp_path):
    for corps, rc in (('{"noms": ["a.gk1.secubox.in"]}', 0), ('{"noms": []}', 0), ('{"noms": null}', 1),
                      ('{"noms": [1]}', 1), ('{"noms": "x"}', 1), ('pas du json', 1), ('{}', 1)):
        r = subprocess.run([sys.executable, "-I", "-c", _extraction()], input=corps, capture_output=True, text=True)
        assert r.returncode == rc, corps


def _extraction():
    s = TEXTE[TEXTE.index("noms_du_pair() {"):]
    return re.search(r"python3 -c '(.*?)'", s, re.S).group(1)


def test_synchronisation_publie_les_services_propres_et_retire_les_perimes():
    s = TEXTE[TEXTE.index("cmd_synchroniser() {"):TEXTE.index("cmd_retirer() {")]
    assert "reglage services_des_pairs" in s and '[ "$mode" = "communs" ]' in s
    assert "domaine_tenu_par_autre" in s                 # domaine d'un autre pair refusé
    assert "route_etrangere" in s                        # jamais écraser une route vers une autre cible
    assert "noms_du_pair" in s and "RELAIS_EN_LOT=1 cmd_retirer" in s
    assert 'if [ "$retires" -gt 0 ]; then' in s           # --allow-shrink seulement s'il y a eu des retraits
    assert s.count("audit_relais") >= 3


def test_retirer_reduit_vraiment_haproxy():
    r = TEXTE[TEXTE.index("cmd_retirer() {"):]
    r = r[:r.index("\n}\n")]
    assert "haproxyctl generate --allow-shrink" in r and "RELAIS_EN_LOT" in r
    assert "génération HAProxy refusée" in r


def test_sous_domaine_d_un_autre_pair_refuse(tmp_path):
    f = tmp_path / "routes.json"
    f.write_text(json.dumps(ROUTES))
    # 10.10.0.5 annonce sub.gk1.secubox.in : le joker *.gk1 du pair gk1 le couvrirait
    assert _execute(tmp_path, "domaine_tenu_par_autre", f, "10.10.0.5", "sub.gk1.secubox.in").returncode == 0
    assert _execute(tmp_path, "domaine_tenu_par_autre", f, "10.10.0.8", "sub.gk1.secubox.in").returncode == 1


def test_audit_en_utc_rfc3339():
    a = TEXTE[TEXTE.index("audit_relais() {"):]
    a = a[:a.index("\n}\n")]
    assert "date -u +%Y-%m-%dT%H:%M:%SZ" in a


def test_exclusions_sans_xargs_et_etat_ecrit_par_fichier_unique():
    s = TEXTE[TEXTE.index("cmd_synchroniser() {"):TEXTE.index("cmd_retirer() {")]
    assert "xargs" not in s
    assert "mkstemp" in _python_de("noms_perimes")
