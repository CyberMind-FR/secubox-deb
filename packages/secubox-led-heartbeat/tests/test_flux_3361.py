# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Collecteur secubox-led-flux de la LED de supervision (ref #3361)."""
import json
import os
import re
import stat
from pathlib import Path

import flux
from reference import Reference

PAQUET = Path(__file__).resolve().parents[1]
T0 = 1793509200.0  # 2026-11 : après T_MIN_PLAUSIBLE


def test_compteur_remis_a_zero_ignore():
    ref = Reference()
    prec = {}
    planchers = dict(flux.PLANCHERS_DEFAUT)
    n = flux.pas_de_collecte(ref, prec, {"waf.blocages": 1000.0}, T0, planchers)
    assert n["waf.blocages"] is None  # premier relevé : pas de débit
    for i in range(1, 30):
        n = flux.pas_de_collecte(ref, prec, {"waf.blocages": 1000.0 + 10 * i}, T0 + 10 * i, planchers)
    assert n["waf.blocages"] is not None
    avant = json.dumps(ref.vers_dict(), sort_keys=True)
    # module redémarré : compteur à 3 → débit négatif, ni niveau ni observation
    n = flux.pas_de_collecte(ref, prec, {"waf.blocages": 3.0}, T0 + 300, planchers)
    assert n["waf.blocages"] is None
    assert json.dumps(ref.vers_dict(), sort_keys=True) == avant
    # le relevé suivant repart de la nouvelle base, sans pic
    n = flux.pas_de_collecte(ref, prec, {"waf.blocages": 4.0}, T0 + 310, planchers)
    assert n["waf.blocages"] in (0, 1)


def test_debit_par_minute():
    ref = Reference()
    prec = {}
    flux.pas_de_collecte(ref, prec, {"fw.bloques": 0.0}, T0, {})
    flux.pas_de_collecte(ref, prec, {"fw.bloques": 60.0}, T0 + 10, {})
    assert ref.vers_dict()["cles"]["fw.bloques"]["court"]["m"] == 360.0


def test_niveau_4_service_arrete():
    ref = Reference()
    n = flux.pas_de_collecte(ref, {}, {"services.arretes": 1.0, "actor.critiques": 2.0,
                                       "services.actifs": 30.0}, T0, flux.PLANCHERS_DEFAUT)
    assert n["services.arretes"] == 4
    assert n["actor.critiques"] == 4
    assert n["services.actifs"] is None  # jauge jamais vue : inconnue
    n = flux.pas_de_collecte(ref, {}, {"services.arretes": 0.0}, T0 + 10, flux.PLANCHERS_DEFAUT)
    assert n["services.arretes"] in (0, 1)


def test_niveau_avant_observer():
    ref = Reference()
    for i in range(10):
        flux.pas_de_collecte(ref, {}, {"reseau.connexions": 10.0}, T0 + 10 * i, {"reseau.connexions": 1.0})
    n = flux.pas_de_collecte(ref, {}, {"reseau.connexions": 1000.0}, T0 + 100, {"reseau.connexions": 1.0})
    assert n["reseau.connexions"] == 1  # plafonné par l'apprentissage, mais pas jugé contre lui-même


def test_ecriture_atomique(tmp_path, monkeypatch):
    cible = tmp_path / "flux.json"
    cible.write_text('{"ancien": 1}')
    vus = []
    vrai_replace = os.replace

    def espion(src, dst):
        vus.append((Path(src), Path(dst)))
        # au moment du remplacement, la cible est encore l'ancienne, le .tmp est complet
        assert json.loads(Path(dst).read_text()) == {"ancien": 1}
        assert json.loads(Path(src).read_text()) == {"nouveau": 2}
        vrai_replace(src, dst)

    monkeypatch.setattr(flux.os, "replace", espion)
    flux.ecrire_atomique(cible, {"nouveau": 2}, 0o644)
    assert vus and vus[0][1] == cible and vus[0][0].name.endswith(".tmp")
    assert json.loads(cible.read_text()) == {"nouveau": 2}
    assert stat.S_IMODE(cible.stat().st_mode) == 0o644
    assert not list(tmp_path.glob("*.tmp"))
    monkeypatch.setattr(flux.os, "replace", vrai_replace)
    flux.ecrire_atomique(tmp_path / "ref.json", {}, 0o640)
    assert stat.S_IMODE((tmp_path / "ref.json").stat().st_mode) == 0o640


def _collecteur(tmp_path, valeurs=None):
    return flux.Collecteur(
        chemin_flux=tmp_path / "run" / "flux.json",
        chemin_ref=tmp_path / "lib" / "reference.json",
        lire=lambda: dict(valeurs or {"reseau.connexions": 5.0, "fw.bloques": 7.0}))


def test_reference_sauvee_toutes_les_15_min(tmp_path, monkeypatch):
    (tmp_path / "run").mkdir()
    (tmp_path / "lib").mkdir()
    c = _collecteur(tmp_path)
    sauvegardes = []
    vrai = c.sauver_reference
    monkeypatch.setattr(c, "sauver_reference", lambda t: (sauvegardes.append(t), vrai(t)))
    c.demarrer(T0)
    assert sauvegardes == [T0]
    for i in range(1, 181):  # 30 min à 10 s
        c.passage(T0 + 10 * i)
    assert sauvegardes == [T0, T0 + 900, T0 + 1800]
    c.arreter(T0 + 1805)
    assert sauvegardes[-1] == T0 + 1805
    assert Reference.depuis_dict(json.loads((tmp_path / "lib" / "reference.json").read_text())) \
        .vers_dict()["cles"]["reseau.connexions"]


def test_flux_json(tmp_path):
    (tmp_path / "run").mkdir()
    (tmp_path / "lib").mkdir()
    c = _collecteur(tmp_path)
    c.demarrer(T0)
    c.passage(T0 + 10)
    c.passage(T0 + 20)
    d = json.loads((tmp_path / "run" / "flux.json").read_text())
    assert d["genere_le"] == T0 + 20
    assert d["apprentissage"] == sorted(d["apprentissage"])
    assert "reseau.connexions" in d["apprentissage"]
    assert d["niveaux"]["reseau.connexions"] == 0
    assert "fw.bloques" in d["niveaux"]


def test_apprentissage_par_cle(tmp_path):
    (tmp_path / "run").mkdir()
    (tmp_path / "lib").mkdir()
    valeurs = {"reseau.connexions": 5.0}
    c = flux.Collecteur(chemin_flux=tmp_path / "run" / "flux.json",
                        chemin_ref=tmp_path / "lib" / "reference.json",
                        lire=lambda: dict(valeurs))
    c.demarrer(T0)
    c.passage(T0 + 10)
    t = T0 + 90000  # > 24 h, sans saut > 6 h : on rejoue toutes les heures
    for h in range(1, 26):
        c.passage(T0 + 10 + 3600 * h)
    valeurs["adguard.trackers"] = 2.0  # source apparue tard
    c.passage(t + 100)
    d = json.loads((tmp_path / "run" / "flux.json").read_text())
    assert d["apprentissage"] == ["adguard.trackers"]
    assert "fw.bloques" not in d["niveaux"]
    assert d["niveaux"]["reseau.connexions"] == 0


def test_reference_corrompue_demarre_vide(tmp_path):
    (tmp_path / "run").mkdir()
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "reference.json").write_text('{"version": 1, "cles": [tronq')
    c = _collecteur(tmp_path)
    c.demarrer(T0)
    assert c.ref.vers_dict()["cles"] == {}


def _sortie_nft(paquets):
    return json.dumps({"nftables": [{"counter": {"name": "sbx_drop_input", "packets": paquets}}]})


def test_nft_invalide_sans_faux_pic(tmp_path):
    """nft.json valide, puis invalide, puis valide : la sortie illisible ne vaut pas 0 (faux pic)."""
    import releves
    (tmp_path / "run").mkdir()
    (tmp_path / "lib").mkdir()
    nft = tmp_path / "box" / "run/secubox-led-nft/nft.json"
    nft.parent.mkdir(parents=True)
    # un relevé par heure (sorti de l'apprentissage après 24 h), 60 blocages par heure
    sorties = iter([_sortie_nft(100000 + 60 * i) for i in range(40)] + ["pas du json"]
                   + [_sortie_nft(100000 + 60 * i) for i in range(41, 51)])

    def lire():
        nft.write_text(next(sorties))
        return releves.releves(tmp_path / "box")
    c = flux.Collecteur(chemin_flux=tmp_path / "run" / "flux.json",
                        chemin_ref=tmp_path / "lib" / "reference.json", lire=lire)
    c.demarrer(T0)
    for i in range(1, 52):
        c.passage(T0 + 3600 * i)
        n = json.loads((tmp_path / "run" / "flux.json").read_text())["niveaux"]
        assert (n.get("fw.bloques") or 0) < 2


def test_reference_illisible_message(tmp_path, capsys):
    p = tmp_path / "reference.json"
    p.write_text("{tronq")
    assert flux.charger_reference(p).vers_dict()["cles"] == {}
    assert "référence illisible, réapprentissage" in capsys.readouterr().err


def _unite():
    return (PAQUET / "systemd" / "secubox-led-flux.service").read_text()


def test_unite_confinee():
    u = _unite()
    for ligne in ("User=secubox-leds", "Group=secubox-leds", "SupplementaryGroups=actord-ingest",
                  "Nice=19", "CPUWeight=10", "IOWeight=10",
                  "CapabilityBoundingSet=",
                  "ProtectSystem=strict", "NoNewPrivileges=yes", "RuntimeDirectory=secubox-leds",
                  "StateDirectory=secubox-leds", "ExecStart=/usr/sbin/secubox-led-flux",
                  "ExecCondition=/usr/sbin/secubox-led-board", "AppArmorProfile=secubox-led-flux",
                  "RestrictAddressFamilies=AF_UNIX", "MemoryMax=64M"):
        assert re.search(r"^" + re.escape(ligne) + r"$", u, re.M), ligne
    assert "PrivateNetwork" not in u
    rw = re.findall(r"^ReadWritePaths=(.*)$", u, re.M)
    for r in rw:
        assert set(r.split()) <= {"/run/secubox-leds", "/var/lib/secubox-leds"}


def test_apparmor_flux():
    p = (PAQUET / "apparmor" / "secubox-led-flux").read_text()
    assert "profile secubox-led-flux" in p
    assert "capability" not in p.replace("aucune capacité", "")
    assert "network" not in p
    assert "/usr/sbin/nft" not in p
    assert "deny /etc/secubox/secrets/** r" in p
    assert "flags=(complain)" not in p


def test_rules_installe_les_fichiers():
    rules = (PAQUET / "debian" / "rules").read_text()
    for f in ("usr/lib/secubox-led-heartbeat/reference.py", "usr/lib/secubox-led-heartbeat/releves.py",
              "usr/lib/secubox-led-heartbeat/flux.py", "usr/sbin/secubox-led-flux",
              "systemd/secubox-led-flux.service", "apparmor/secubox-led-flux"):
        assert re.search(r"install -D -m \d+ " + re.escape(f) + r" ", rules), f
        assert (PAQUET / f).exists(), f


def test_postinst_compte_et_activation():
    p = (PAQUET / "debian" / "postinst").read_text()
    garde = p.index("/usr/sbin/secubox-led-board; then")
    assert p.index("adduser --system --group --no-create-home --home /nonexistent") > garde
    assert "systemctl enable --now secubox-led-flux.service secubox-led-nft.service || true" in p
    g = p.index("getent group actord-ingest >/dev/null || addgroup --system actord-ingest")
    assert garde < g < p.index("systemctl enable --now secubox-led-flux.service")
    assert "secubox-led-flux.service" in (PAQUET / "debian" / "prerm").read_text()
