# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: exposure — tout service onion passe par le frontal HAProxy onion-in (#3112, #3123).

Vu en production (gk2) : l'onion du webui livrait à nginx :9080 en direct ; ceux des vhosts et de metablogizer à
http-in :80, qui ne nettoie rien. Tor se connecte depuis 127.0.0.1, adresse que nginx croit et classe LAN : chaque
visiteur onion était « poste du LAN ». Ces tests couvrent la cible des nouveaux onions (webui, vhosts, /tor/add en
liste blanche), la migration de TOUS les onions existants (sur place, même clé, même adresse, idempotente,
atomique), l'inclusion de torrc.d (I1), le signalement bruyant des restes (I2) et l'auteur de l'audit.
"""
import asyncio
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-haproxy" / "composants" / "exposure"))

import api.main as m  # noqa: E402
from fastapi import HTTPException  # noqa: E402

ONION = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"


@pytest.fixture
def box(monkeypatch, tmp_path):
    """Arborescence Tor / exposure / haproxy.toml isolée ; les commandes sont enregistrées, jamais lancées."""
    torrc = tmp_path / "torrc"
    torrc.write_text("SocksPort 9050\n")          # torrc de Debian : PAS de %include torrc.d par défaut
    monkeypatch.setattr(m, "TOR_CONFIG", torrc)
    monkeypatch.setattr(m, "TOR_DROPIN_DIR", tmp_path / "torrc.d")
    monkeypatch.setattr(m, "TOR_METABLOG_DIR", tmp_path / "metablog.d")
    monkeypatch.setattr(m, "TOR_DATA", tmp_path / "hs")
    monkeypatch.setattr(m, "CONFIG_FILE", tmp_path / "exposure.json")
    monkeypatch.setattr(m, "HAPROXY_TOML", tmp_path / "haproxy.toml")
    monkeypatch.setattr(time, "sleep", lambda s: None)   # _tor_add_sync attend l'adresse : inutile ici
    monkeypatch.setattr(m, "_tor_bin", lambda: "")       # pas de `tor --verify-config` sauf test dédié
    cmds, audits = [], []
    monkeypatch.setattr(m, "run_cmd", lambda cmd, *a, **k: cmds.append(cmd) or (True, "", ""))
    monkeypatch.setattr(m, "_audit_write", lambda line: audits.append(line))
    (tmp_path / "hs" / "webui").mkdir(parents=True)
    (tmp_path / "hs" / "webui" / "hostname").write_text(ONION + "\n")
    return {"tmp": tmp_path, "torrc": torrc, "cmds": cmds, "audits": audits,
            "dropin": tmp_path / "torrc.d" / "70-secubox-hs-webui.conf", "hs": tmp_path / "hs" / "webui"}


def _ecrit(f: Path, texte: str) -> Path:
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(texte)
    return f


def _reloads(box):
    return [c for c in box["cmds"] if c == ["systemctl", "reload", "tor"]]


# ── nouveaux onions : une seule cible, le frontal ────────────────────────────────────────────────────────────────
def test_emancipate_webui_vise_le_frontal_et_pose_la_route_waf(box):
    r = m.emancipate_webui(federate=False)
    assert box["dropin"].read_text().splitlines()[-1] == "HiddenServicePort 80 127.0.0.1:9180"
    assert r["output"]["local_port"] == 9180
    assert ["secubox-waf-route", ONION, "9080"] in box["cmds"], "sbxwaf doit connaître l'onion (→ webui)"


def test_l_onion_d_un_vhost_vise_le_frontal_jamais_http_in(box, monkeypatch):
    vus = []
    monkeypatch.setattr(m, "_tor_add_sync", lambda name, local_port, onion_port: vus.append((name, local_port)))
    asyncio.run(m._apply_tor("blog.example.com", True, {"sub": "t"}))
    assert vus == [("blogexamplecom", 9180)]


def test_le_premier_service_ajoute_l_include_de_torrc_d(box):
    """I1 : le torrc de Debian n'inclut pas torrc.d ; y écrire un service sans l'inclure ne servirait à rien."""
    m._tor_add_sync("x", local_port=9180, onion_port=80)
    t = box["torrc"].read_text()
    assert f"%include {box['tmp'] / 'torrc.d'}/*.conf" in t and t.startswith("SocksPort 9050\n")
    m._tor_add_sync("y", local_port=9180, onion_port=80)
    assert box["torrc"].read_text() == t, "idempotent : une seule ligne %include"


def test_le_port_suit_haproxy_toml_mais_jamais_une_entree_directe(box):
    (box["tmp"] / "haproxy.toml").write_text('mode = "native"\nonion_in_port = 9280\n')
    assert m._port_onion_in() == 9280
    for interdit in (80, 9080):
        (box["tmp"] / "haproxy.toml").write_text(f"onion_in_port = {interdit}\n")
        assert m._port_onion_in() == 9180


@pytest.mark.parametrize("port", [80, 9080, 8080, 22])
def test_tor_add_n_accepte_que_le_frontal(box, port):
    """I3 : liste blanche, pas seulement un refus de 9080."""
    with pytest.raises(HTTPException) as e:
        asyncio.run(m.tor_add(m.TorAddRequest(service="bidule", local_port=port), {"sub": "t"}))
    assert e.value.status_code == 400 and "onion-in" in e.value.detail


def test_tor_add_sans_port_ou_avec_le_frontal_vise_le_frontal(box, monkeypatch):
    vus = []
    monkeypatch.setattr(m, "_tor_add_sync", lambda name, local_port, onion_port: vus.append(local_port) or {})
    asyncio.run(m.tor_add(m.TorAddRequest(service="a"), {"sub": "t"}))
    asyncio.run(m.tor_add(m.TorAddRequest(service="b", local_port=9180), {"sub": "t"}))
    assert vus == [9180, 9180]


def test_la_route_waf_n_accepte_qu_une_adresse_onion(box):
    for faux in ("", "admin.gk2.secubox.in", "x; rm -rf /.onion"):
        assert m._route_waf_onion(faux) is False
    assert box["cmds"] == []


# ── migration de TOUS les onions existants ───────────────────────────────────────────────────────────────────────
def test_la_migration_reecrit_sur_place_webui_vhost_et_metablogizer(box):
    torrc_avant = "SocksPort 9050\n%include /etc/tor/torrc.d/*.conf\n"
    box["torrc"].write_text(torrc_avant + f"# Hidden service: vieux\nHiddenServiceDir {box['tmp']}/hs/vieux/\n"
                            "HiddenServicePort 80 127.0.0.1:80\n")
    webui = _ecrit(box["dropin"], f"HiddenServiceDir {box['hs']}\nHiddenServicePort 80 127.0.0.1:9080\n")
    vhost = _ecrit(box["tmp"] / "torrc.d" / "70-secubox-hs-blogexamplecom.conf",
                   f"HiddenServiceDir {box['tmp']}/hs/blogexamplecom  # commentaire\nHiddenServicePort 80\n")
    blog = _ecrit(box["tmp"] / "metablog.d" / "site.conf",
                  "# metablogizer site\nHiddenServiceDir /var/lib/tor/secubox-metablogizer/site\n"
                  "HiddenServicePort 80 localhost:80\n")
    cle = box["hs"] / "hs_ed25519_secret_key"
    cle.write_bytes(b"cle")

    r = m.migrer_onions(user="postinst")

    assert len(r["services"]) == 4
    assert webui.read_text() == f"HiddenServiceDir {box['hs']}\nHiddenServicePort 80 127.0.0.1:9180\n"
    assert vhost.read_text().splitlines()[1] == "HiddenServicePort 80 127.0.0.1:9180"
    assert blog.read_text().splitlines()[-1] == "HiddenServicePort 80 127.0.0.1:9180"
    t = box["torrc"].read_text()
    assert t.startswith(torrc_avant) and t.endswith("HiddenServicePort 80 127.0.0.1:9180\n"), "réécrit SUR PLACE"
    assert f"HiddenServiceDir {box['tmp']}/hs/vieux/" in t, "HiddenServiceDir inchangé : même clé, même adresse"
    assert cle.read_bytes() == b"cle"
    assert len(_reloads(box)) == 1, "un seul rechargement de Tor"
    migr = [a for a in box["audits"] if "action=migrate_onion" in a]
    assert len(migr) == 4 and all("by=postinst" in a for a in migr)
    assert any(f"dir={box['tmp']}/hs/vieux " in a for a in migr), "HiddenServiceDir normalisé (sans « / » final)"
    assert any(f"dir={box['tmp']}/hs/blogexamplecom " in a for a in migr), "commentaire de fin ignoré"
    assert not list(box["tmp"].rglob(".*.tmp")), "écriture atomique"


def test_la_migration_ne_deplace_rien_vers_un_fichier_non_lu(box):
    """I1 : un bloc du torrc est réécrit là où il est ; aucun fichier de torrc.d n'est créé pour lui."""
    box["torrc"].write_text(f"SocksPort 9050\nHiddenServiceDir {box['hs']}\nHiddenServicePort 80 127.0.0.1:9080\n")
    m.migrer_onions()
    assert box["torrc"].read_text().splitlines()[-1] == "HiddenServicePort 80 127.0.0.1:9180"
    assert not box["dropin"].exists()


def test_la_migration_est_idempotente(box):
    _ecrit(box["dropin"], f"HiddenServiceDir {box['hs']}\nHiddenServicePort 80 127.0.0.1:9080\n")
    m.migrer_onions()
    avant = box["dropin"].read_text()
    box["cmds"].clear()
    box["audits"].clear()
    r = m.migrer_onions()
    assert r["migrated"] is False and box["dropin"].read_text() == avant
    assert _reloads(box) == [] and box["audits"] == []


def test_la_migration_met_a_jour_les_entrees_enregistrees(box):
    m._save_emancipated([{"name": "webui", "local_port": 9080, "onion_port": 80, "active": True},
                         {"name": "site", "local_port": 80, "onion_port": 80, "active": True},
                         {"name": "ssh", "local_port": 22, "onion_port": 22, "active": True}])
    m.migrer_onions()
    ports = {s["name"]: s["local_port"] for s in m._load_emancipated()}
    assert ports == {"webui": 9180, "site": 9180, "ssh": 22}


def test_un_onion_restant_hors_du_frontal_est_signale_bruyamment(box, capsys):
    """I2 : jamais en silence — stderr et audit `onion_non_migre` avec le HiddenServiceDir."""
    _ecrit(box["tmp"] / "torrc.d" / "80-autre.conf",
           "HiddenServiceDir /var/lib/tor/autre/  # posé à la main\nHiddenServicePort 443 127.0.0.1:443\n")
    restes = m.signaler_onions_non_migres(user="postinst")
    assert restes == [{"fichier": str(box["tmp"] / "torrc.d" / "80-autre.conf"),
                       "dir": "/var/lib/tor/autre", "cible": "127.0.0.1:443"}]
    assert "ERREUR #3112" in capsys.readouterr().err
    assert any("action=onion_non_migre dir=/var/lib/tor/autre cible=127.0.0.1:443" in a and "by=postinst" in a
               for a in box["audits"])


def test_rien_a_signaler_apres_migration(box, capsys):
    _ecrit(box["dropin"], f"HiddenServiceDir {box['hs']}\nHiddenServicePort 80 127.0.0.1:9080\n")
    m.migrer_onions()
    assert m.signaler_onions_non_migres() == []
    assert "ERREUR" not in capsys.readouterr().err


def test_la_persistance_au_demarrage_migre_et_ne_reapplique_jamais_une_entree_directe(box, monkeypatch):
    """Torrc remis à zéro, entrées encore à 9080 / 80 : la réparation doit viser le frontal."""
    m._save_emancipated([{"name": "webui", "local_port": 9080, "onion_port": 80, "active": True},
                         {"name": "site", "local_port": 80, "onion_port": 80, "active": True}])
    ajouts = []
    monkeypatch.setattr(m, "_tor_add_sync",
                        lambda name, local_port, onion_port: ajouts.append((name, local_port, onion_port)))
    r = m.tor_reconcile_persist(user="reconcile")
    assert sorted(ajouts) == [("site", 9180, 80), ("webui", 9180, 80)]
    assert r["waf_route"] is True and r["non_migres"] == []
    assert ["secubox-waf-route", ONION, "9080"] in box["cmds"]


# ── jamais deux déclarations du même service (round 2) ───────────────────────────────────────────────────────────
def _declarations(box, hs_dir) -> int:
    """Nombre de HiddenServiceDir déclarant ce répertoire, tous fichiers lus par la migration confondus."""
    n = 0
    for f in m._fichiers_tor():
        for ligne in f.read_text().splitlines():
            md = m._RE_HS_DIR.match(ligne)
            if md and m._norm_dir(md.group(1)) == m._norm_dir(str(hs_dir)):
                n += 1
    return n


def _torrc_avec_bloc_webui(box):
    box["torrc"].write_text("SocksPort 9050\n%include /etc/tor/torrc.d/*.conf\n"
                            f"# Hidden service: webui\nHiddenServiceDir {box['hs']}/  # ancien\n"
                            "HiddenServicePort 80 127.0.0.1:9180\nControlPort 9051\n")


def test_publier_alors_qu_un_bloc_reste_dans_le_torrc_ne_double_pas_le_service(box):
    _torrc_avec_bloc_webui(box)
    _ecrit(box["tmp"] / "metablog.d" / "x.conf", f"HiddenServiceDir {box['hs']}\nHiddenServicePort 80 127.0.0.1:80\n")
    m.emancipate_webui(federate=False)
    assert _declarations(box, box["hs"]) == 1
    assert box["dropin"].read_text().splitlines()[-1] == "HiddenServicePort 80 127.0.0.1:9180"
    t = box["torrc"].read_text()
    assert "SocksPort 9050" in t and "ControlPort 9051" in t, "le reste du torrc est intact"


def test_la_persistance_au_demarrage_ne_double_pas_le_service(box, monkeypatch):
    """Clé absente mais bloc encore dans le torrc : la réparation écrit torrc.d ET retire l'ancien bloc."""
    _torrc_avec_bloc_webui(box)
    monkeypatch.setattr(m, "_hs_dir_exists", lambda n: False)
    m._save_emancipated([{"name": "webui", "local_port": 9180, "onion_port": 80, "active": True}])
    r = m.tor_reconcile_persist()
    assert r["applied"] == ["webui"]
    assert _declarations(box, box["hs"]) == 1


# Sorties réelles de tor sur gk2 (round 3) : rc=0 dans LES DEUX cas — le verdict se lit sur la sortie.
SORTIE_VALIDE = ("Oct 24 18:00:00.000 [notice] Tor 0.4.8.16 running on Linux.\n"
                 "Oct 24 18:00:00.000 [notice] Read configuration file \"/etc/tor/torrc\".\n"
                 "Configuration was valid\n")
SORTIE_REFUS = ("Oct 24 18:00:00.000 [notice] Read configuration file \"/etc/tor/torrc\".\n"
                "Oct 24 18:00:00.000 [warn] Directory /var/lib/tor/hidden_services/webui cannot be read: "
                "Permission denied\n"
                "Oct 24 18:00:00.000 [err] Failed to configure rendezvous options. See logs for details.\n"
                "Oct 24 18:00:00.000 [err] Reading config failed--see warnings above.\n")


def _faux_tor(box, monkeypatch, sortie_sans_defauts, sortie_avec_defauts=None, rc=0):
    """Faux binaire tor : rend `sortie_avec_defauts` si --defaults-torrc est passé, sinon `sortie_sans_defauts`
    (comme sur gk2), toujours avec le code `rc`, et journalise ses arguments."""
    journal = box["tmp"] / "tor-args.log"
    (box["tmp"] / "sans.txt").write_text(sortie_sans_defauts)
    (box["tmp"] / "avec.txt").write_text(sortie_avec_defauts if sortie_avec_defauts is not None
                                         else sortie_sans_defauts)
    faux = box["tmp"] / "tor"
    faux.write_text("#!/bin/sh\n"
                    f'echo "$*" >> "{journal}"\n'
                    'case " $* " in *" --defaults-torrc "*) f=avec ;; *) f=sans ;; esac\n'
                    f'cat "{box["tmp"]}/$f.txt"\n'
                    f"exit {rc}\n")
    faux.chmod(0o755)
    monkeypatch.setattr(m, "_tor_bin", lambda: str(faux))
    return journal


def test_la_verification_passe_la_configuration_debian_et_lit_la_sortie(box, monkeypatch):
    """gk2 : sans --defaults-torrc, tor échoue (rc=0 !) ; avec, « Configuration was valid »."""
    defauts = _ecrit(box["tmp"] / "tor-service-defaults-torrc", "User debian-tor\n")
    monkeypatch.setattr(m, "TOR_DEFAULTS", defauts)
    journal = _faux_tor(box, monkeypatch, SORTIE_REFUS, SORTIE_VALIDE, rc=0)
    m._tor_add_sync("webui", local_port=9180, onion_port=80)
    assert box["dropin"].exists(), "configuration valide : le service reste écrit"
    assert f"--verify-config --defaults-torrc {defauts} -f {box['torrc']}" in journal.read_text()
    assert not any("torrc_refuse" in a for a in box["audits"])


@pytest.mark.parametrize("sortie", [SORTIE_REFUS, "", "Oct 24 [notice] Read configuration file\n",
                                    SORTIE_VALIDE + "Oct 24 [err] autre chose\n"])
def test_un_refus_de_tor_restaure_tout_meme_avec_rc_0(box, monkeypatch, sortie):
    """rc=0 en échec : seule la sortie décide. Sans « Configuration was valid », ou avec un [err] : refus."""
    _torrc_avec_bloc_webui(box)
    avant = {f: f.read_text() for f in m._fichiers_tor()}
    _faux_tor(box, monkeypatch, sortie, rc=0)
    with pytest.raises(RuntimeError):
        m._tor_add_sync("webui", local_port=9180, onion_port=80)
    assert {f: f.read_text() for f in m._fichiers_tor()} == avant
    assert not box["dropin"].exists()
    assert _reloads(box) == [], "jamais recharger une config refusée"
    assert any("action=torrc_refuse" in a for a in box["audits"])


def test_sans_fichier_de_defauts_la_verification_reste_possible(box, monkeypatch):
    monkeypatch.setattr(m, "TOR_DEFAULTS", box["tmp"] / "absent")
    journal = _faux_tor(box, monkeypatch, SORTIE_VALIDE)
    m._tor_add_sync("webui", local_port=9180, onion_port=80)
    assert "--defaults-torrc" not in journal.read_text() and box["dropin"].exists()


def test_une_migration_refusee_par_tor_restaure_aussi_exposure_json(box, monkeypatch):
    f = _ecrit(box["dropin"], f"HiddenServiceDir {box['hs']}\nHiddenServicePort 80 127.0.0.1:9080\n")
    avant = f.read_text()
    m._save_emancipated([{"name": "webui", "local_port": 9080, "onion_port": 80, "active": True}])
    json_avant = (box["tmp"] / "exposure.json").read_text()
    _faux_tor(box, monkeypatch, SORTIE_REFUS, rc=0)
    r = m.migrer_onions(user="postinst")
    assert r["success"] is False and f.read_text() == avant
    assert (box["tmp"] / "exposure.json").read_text() == json_avant, "ports enregistrés rendus aussi"
    assert _reloads(box) == []
    assert any("action=torrc_refuse" in a and "by=postinst" in a for a in box["audits"])


def test_un_echec_d_ecriture_apres_le_retrait_du_bloc_restaure_le_torrc(box, monkeypatch):
    """Entre le retrait de l'ancien bloc et l'écriture du nouveau fichier, un échec ne doit pas faire
    disparaître le service."""
    _torrc_avec_bloc_webui(box)
    torrc_avant = box["torrc"].read_text()
    vrai = m._ecrit_atomique

    def ecrit(f, texte):
        if f == box["dropin"]:
            raise OSError("disque plein")
        vrai(f, texte)

    monkeypatch.setattr(m, "_ecrit_atomique", ecrit)
    with pytest.raises(OSError):
        m._tor_add_sync("webui", local_port=9180, onion_port=80)
    monkeypatch.setattr(m, "_ecrit_atomique", vrai)
    assert box["torrc"].read_text() == torrc_avant


def test_la_persistance_force_toute_cible_http_par_le_frontal(box, monkeypatch):
    m._save_emancipated([{"name": "app", "local_port": 8080, "onion_port": 80, "active": True},
                         {"name": "ssh", "local_port": 22, "onion_port": 22, "active": True}])
    ajouts = []
    monkeypatch.setattr(m, "_tor_add_sync",
                        lambda name, local_port, onion_port: ajouts.append((name, local_port)))
    m.tor_reconcile_persist()
    assert sorted(ajouts) == [("app", 9180), ("ssh", 22)]
