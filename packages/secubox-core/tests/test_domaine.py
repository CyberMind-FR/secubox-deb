# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox-domaine — un nom de service se dérive du domaine de la box (#1723).

Sur gk3, trente paquets écrivaient des noms de gk2 : jitsi pour meet.gk2,
peertube figé sur peertube.gk2, la carlette d'accès renvoyée vers hall.gk2.
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "usr" / "bin" / "secubox-domaine"


def lancer(*args, dom="gk3.secubox.in", racine=None):
    env = dict(os.environ, SECUBOX_DOMAINE=dom)
    if racine is not None:
        env["SECUBOX_DOMAINE_RACINE"] = str(racine)
    return subprocess.run([sys.executable, str(SCRIPT), *args], env=env,
                          capture_output=True, text=True)


def test_domaine_et_prefixe():
    assert lancer().stdout.strip() == "gk3.secubox.in"
    assert lancer("meet").stdout.strip() == "meet.gk3.secubox.in"


def test_prefixe_invalide_refuse():
    assert lancer("a b").returncode == 2
    assert lancer("-x").returncode == 2


def test_migration_reecrit_les_noms_gk2(tmp_path):
    (tmp_path / "proxypac").mkdir()
    (tmp_path / "jitsi.toml").write_text(
        '# domaine de gk2 : meet.gk2.secubox.in\n'
        'domain = "meet.gk2.secubox.in"\n'
        'url = "https://hall.gk2.secubox.in/acces/"  # carlette\n'
        'default_domain = "gk2.secubox.in"\n'
        'cookie = ".gk2.secubox.in"\n'
        'mail = "gk2@secubox.in"\n'
        'autre = "xgk2.secubox.in gk2.secubox.info"\n')
    (tmp_path / "proxypac" / "p.toml").write_text('h = "wpad.gk2.secubox.in"\n')
    (tmp_path / "jitsi.toml.example").write_text('domain = "meet.gk2.secubox.in"\n')
    os.chmod(tmp_path / "jitsi.toml", 0o640)

    r = lancer("--migrer", racine=tmp_path)
    assert r.returncode == 0, r.stderr
    t = (tmp_path / "jitsi.toml").read_text()
    assert t.startswith("# domaine de gk2 : meet.gk2.secubox.in\n")  # commentaire intact
    assert 'domain = "meet.gk3.secubox.in"' in t
    assert 'url = "https://hall.gk3.secubox.in/acces/"  # carlette' in t
    assert 'default_domain = "gk3.secubox.in"' in t
    assert 'cookie = ".gk3.secubox.in"' in t
    assert 'mail = "gk2@secubox.in"' in t                      # une adresse, pas un nom
    assert 'autre = "xgk2.secubox.in gk2.secubox.info"' in t   # d'autres noms
    assert (tmp_path / "proxypac" / "p.toml").read_text() == 'h = "wpad.gk3.secubox.in"\n'
    assert "gk2" in (tmp_path / "jitsi.toml.example").read_text()   # exemples ignorés
    assert (os.stat(tmp_path / "jitsi.toml").st_mode & 0o777) == 0o640
    assert list(tmp_path.glob("jitsi.toml.avant-domaine-*"))        # copie gardée
    # Idempotent : rien à refaire.
    assert lancer("--etat", racine=tmp_path).stdout == ""


def test_migration_sans_effet_sur_gk2(tmp_path):
    f = tmp_path / "jitsi.toml"
    f.write_text('domain = "meet.gk2.secubox.in"\n')
    assert lancer("--migrer", dom="gk2.secubox.in", racine=tmp_path).returncode == 0
    assert f.read_text() == 'domain = "meet.gk2.secubox.in"\n'
    assert not list(tmp_path.glob("*.avant-domaine-*"))


# ── secubox_core.auth : le nom qu'on sert, et celui qu'on consomme ──────────

def test_hote_box_et_hote_parc(monkeypatch, tmp_path):
    from secubox_core import auth
    monkeypatch.setattr(auth, "domaine_box", lambda: "gk3.secubox.in")
    assert auth.hote_box("meet") == "meet.gk3.secubox.in"
    # Paquet absent : le nœud de référence du maillage.
    monkeypatch.setattr(auth, "_DPKG_INFO", tmp_path)
    assert auth.hote_parc("peertube", "secubox-peertube") == "peertube.gk2.secubox.in"
    # Paquet installé ici : le service de cette box.
    (tmp_path / "secubox-peertube.list").write_text("")
    assert auth.hote_parc("peertube", "secubox-peertube") == "peertube.gk3.secubox.in"
    # Domaine inconnu : jamais « peertube. » — la référence.
    monkeypatch.setattr(auth, "domaine_box", lambda: "")
    assert auth.hote_box("x") == ""
    assert auth.hote_parc("peertube", "secubox-peertube") == "peertube.gk2.secubox.in"


# ── Le cookie de session suit le domaine de la box (#1723) ─────────────────
# gk3 n'avait pas `[api] sso_cookie_domain` : la session ouverte sur admin.gk3
# restait à admin.gk3, le Hall ne voyait personne.

def _req(origin=None, host="localhost"):
    from types import SimpleNamespace
    h = {"host": host}
    if origin:
        h["origin"] = origin
    return SimpleNamespace(headers=h)


def _conf(monkeypatch, api=None, glob=None):
    from secubox_core import auth
    monkeypatch.delenv("SECUBOX_SSO_COOKIE_DOMAIN", raising=False)
    monkeypatch.setattr(auth, "get_config",
                        lambda s: {"api": api or {}, "global": glob or {}}.get(s, {}))
    return auth


def test_cookie_prend_le_domaine_de_la_box(monkeypatch):
    auth = _conf(monkeypatch, glob={"domain": "gk3.secubox.in"})
    assert auth._cookie_domain(_req("https://admin.gk3.secubox.in")) == ".gk3.secubox.in"
    assert auth._cookie_domain(_req("https://hall.gk3.secubox.in")) == ".gk3.secubox.in"


def test_cookie_reste_a_l_hote_hors_du_domaine(monkeypatch):
    # Kiosque (hall.localhost:9078) et accès par IP : un Domain étranger serait
    # rejeté par le navigateur — plus de cookie du tout.
    auth = _conf(monkeypatch, glob={"domain": "gk3.secubox.in"})
    assert auth._cookie_domain(_req("http://hall.localhost:9078")) is None
    assert auth._cookie_domain(_req("https://192.168.1.9")) is None
    assert auth._cookie_domain(_req(None, host="192.168.1.9")) is None


def test_reglage_explicite_et_appel_sans_requete_inchanges(monkeypatch):
    auth = _conf(monkeypatch, api={"sso_cookie_domain": ".gk2.secubox.in"},
                 glob={"domain": "gk2.secubox.in"})
    assert auth._cookie_domain() == ".gk2.secubox.in"
    assert auth._cookie_domain(_req("https://hall.gk2.secubox.in")) == ".gk2.secubox.in"
    auth = _conf(monkeypatch, glob={"domain": "gk3.secubox.in"})
    assert auth._cookie_domain() is None          # pas de requête : pas de dérivation
    auth = _conf(monkeypatch)
    assert auth._cookie_domain(_req("https://hall.gk3.secubox.in")) is None  # domaine inconnu
