# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 — projection lisible des pairs ENRÔLÉS pour le pilotage (défaut du banc gk2 du 2026-10-30).

/var/lib/secubox/p2p est 0700 secubox : le compte secubox-pilotage ne peut pas lire peers.json. p2p publie donc, à chaque écriture
de peers.json, `pairs-enroles.json` (nom, mesh_ip, empreinte, mode de jonction ; rien d'autre) dans /var/lib/secubox/p2p-public (0755),
par renommage atomique. Les découvertes mDNS (sans empreinte ni jonction) n'y figurent jamais."""
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from api import pairs_enroles as PE

RACINE = Path(__file__).resolve().parents[1]

PEERS = {"peers": [
    {"id": "sb-1", "name": "gk5", "mesh_ip": "10.10.0.10", "fingerprint": "fp5", "joined_via": "master-link",
     "wg_public_key": "PUB", "private_key": "SECRET-PRIV", "token": "SECRET-TOK", "address": "192.168.1.5", "status": "online"},
    {"id": "sb-2", "name": "voisin", "mesh_ip": "10.10.0.20", "address": "192.168.1.20", "status": "online"},  # mDNS, non enrôlé
    {"id": "sb-3", "name": "gk6", "mesh_ip": "10.10.0.11", "fingerprint": "fp6", "joined_via": "master-link"},
    "pas-un-dict",
]}


def test_projection_ne_garde_que_les_enroles_et_les_champs_utiles():
    p = PE.projection(PEERS)
    assert p["version"] == 1
    assert p["pairs"] == [
        {"name": "gk5", "mesh_ip": "10.10.0.10", "fingerprint": "fp5", "joined_via": "master-link"},
        {"name": "gk6", "mesh_ip": "10.10.0.11", "fingerprint": "fp6", "joined_via": "master-link"}]
    brut = json.dumps(p)
    for secret in ("SECRET", "PUB", "192.168.1", "voisin", "token", "private"):
        assert secret not in brut


def test_projection_doc_inutilisable_liste_vide():
    for doc in (None, [], {"peers": "x"}, 42):
        assert PE.projection(doc)["pairs"] == []
    assert len(PE.projection([PEERS["peers"][0]])["pairs"]) == 1  # ancienne forme : liste nue


def test_publier_atomique_0644_dans_un_dossier_0755(tmp_path):
    d = tmp_path / "p2p-public"
    d.mkdir(mode=0o755)
    chemin = PE.publier(PEERS, d)
    assert chemin == d / "pairs-enroles.json"
    assert stat.S_IMODE(chemin.stat().st_mode) == 0o644
    assert [x["name"] for x in json.loads(chemin.read_text())["pairs"]] == ["gk5", "gk6"]
    ino = chemin.stat().st_ino
    PE.publier({"peers": [PEERS["peers"][2]]}, d)  # mise à jour : remplacement par renommage (nouvel inode)
    assert [x["name"] for x in json.loads(chemin.read_text())["pairs"]] == ["gk6"]
    assert chemin.stat().st_ino != ino
    assert sorted(os.listdir(d)) == ["pairs-enroles.json"]  # aucun temporaire laissé


def test_publier_remplace_un_lien_sans_le_suivre(tmp_path):
    d = tmp_path / "p2p-public"
    d.mkdir(mode=0o755)
    cible = tmp_path / "cible"
    cible.write_text("intact")
    (d / "pairs-enroles.json").symlink_to(cible)
    PE.publier(PEERS, d)
    assert cible.read_text() == "intact" and not (d / "pairs-enroles.json").is_symlink()


@pytest.mark.parametrize("cas", ["lien", "inscriptible", "absent"])
def test_publier_refuse_un_dossier_douteux(tmp_path, cas):
    d = tmp_path / "p2p-public"
    if cas == "lien":
        (tmp_path / "ailleurs").mkdir()
        d.symlink_to(tmp_path / "ailleurs")
    elif cas == "inscriptible":
        d.mkdir()
        d.chmod(0o777)
    with pytest.raises(PE.ProjectionErreur):
        PE.publier(PEERS, d)
    if cas == "lien":
        assert not os.listdir(tmp_path / "ailleurs")


def test_save_json_de_peers_publie_la_projection(tmp_path, monkeypatch):
    from api import main
    peers = tmp_path / "p2p" / "peers.json"
    peers.parent.mkdir()
    public = tmp_path / "p2p-public"
    public.mkdir(mode=0o755)
    monkeypatch.setattr(main, "P2P_DIR", peers.parent)
    monkeypatch.setattr(main, "PEERS_FILE", peers)
    monkeypatch.setattr(main, "PAIRS_ENROLES_DIR", public)
    main.save_json(main.PEERS_FILE, PEERS)
    assert [x["name"] for x in json.loads((public / "pairs-enroles.json").read_text())["pairs"]] == ["gk5", "gk6"]
    main.save_json(peers.parent / "services.json", [])  # autre fichier : la projection ne bouge pas
    assert len(json.loads((public / "pairs-enroles.json").read_text())["pairs"]) == 2


def test_save_json_projection_impossible_n_empeche_pas_l_ecriture(tmp_path, monkeypatch):
    from api import main
    peers = tmp_path / "peers.json"
    monkeypatch.setattr(main, "P2P_DIR", tmp_path)
    monkeypatch.setattr(main, "PEERS_FILE", peers)
    monkeypatch.setattr(main, "PAIRS_ENROLES_DIR", tmp_path / "absent")
    main.save_json(main.PEERS_FILE, PEERS)
    assert json.loads(peers.read_text()) == PEERS


def test_commande_republie_depuis_peers_json(tmp_path):
    peers = tmp_path / "peers.json"
    peers.write_text(json.dumps(PEERS))
    d = tmp_path / "p2p-public"
    d.mkdir(mode=0o755)
    r = subprocess.run([sys.executable, "-I", str(RACINE / "api" / "pairs_enroles.py"), "--peers", str(peers), "--dossier", str(d)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert len(json.loads((d / "pairs-enroles.json").read_text())["pairs"]) == 2


def test_postinst_cree_le_dossier_public_et_republie():
    p = (RACINE / "debian" / "postinst").read_text()
    assert "install -d -o secubox -g secubox -m 0755 /var/lib/secubox/p2p-public" in p
    assert "runuser -u secubox -- python3 -I /usr/lib/secubox/p2p/api/pairs_enroles.py" in p
    # le dossier privé reste privé (#2475) : la projection ne l'ouvre pas
    assert "install -d -m 0700 -o secubox -g secubox /var/lib/secubox/p2p " in p
