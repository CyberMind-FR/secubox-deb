# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Exposition des médias : conf/meet.nft et le verbe media-expose (nft simulé)."""
import json
import shutil
from pathlib import Path

from conftest import run_ctl, run_ctl_rc

NFT = Path(__file__).resolve().parents[1] / "conf" / "meet.nft"


def _prepare(tmp_path):
    shutil.copy(NFT, tmp_path / "meet.nft")
    return tmp_path / "nftables.d" / "secubox-meet-dnat.nft"


def test_fichier_nft_deux_regles_vers_le_conteneur():
    t = NFT.read_text()
    assert "table inet secubox-meet" in t
    assert 'iifname != "br-lxc" fib daddr type local tcp dport 7881 counter dnat ip to 10.100.0.195:7881 comment "meet-livekit-tcp"' in t
    assert 'iifname != "br-lxc" fib daddr type local udp dport 7882 counter dnat ip to 10.100.0.195:7882 comment "meet-livekit-udp"' in t
    assert "type nat hook prerouting priority dstnat; policy accept;" in t
    assert "input" not in t.split("table inet secubox-meet")[1]


def test_apply_pose_le_fichier_dans_nftables_d(tmp_path):
    dst = _prepare(tmp_path)
    d = json.loads(run_ctl(tmp_path, "media-expose", "--apply", nft_ok=True))
    assert d == {"success": True, "applied": str(dst), "tcp_port": 7881, "udp_port": 7882}
    assert dst.exists()


def test_apply_deux_fois_supprime_la_table_avant(tmp_path):
    _prepare(tmp_path)
    run_ctl(tmp_path, "media-expose", "--apply", nft_ok=True)
    run_ctl(tmp_path, "media-expose", "--apply", nft_ok=True)
    appels = (tmp_path / "nft-appels").read_text().splitlines()
    assert appels.count("delete table inet secubox-meet") == 2
    assert all(a.startswith(("delete", "-f", "list")) for a in appels)
    assert [a.split()[0] for a in appels if not a.startswith("list")] == ["delete", "-f", "delete", "-f"]


def test_apply_refuse_par_nft_ne_laisse_rien(tmp_path):
    dst = _prepare(tmp_path)
    rc, out = run_ctl_rc(tmp_path, "media-expose", "--apply", nft_ok=False)
    assert rc == 1 and not dst.exists()
    assert json.loads(out) == {"success": False, "error": "nft a refusé la règle — rien appliqué"}


def test_apply_sans_source_refuse(tmp_path):
    rc, out = run_ctl_rc(tmp_path, "media-expose", "--apply", nft_ok=True)
    assert rc == 1
    d = json.loads(out)
    assert d["success"] is False and d["error"] == f"règle absente: {tmp_path / 'meet.nft'}"


def test_revoke_retire_table_et_fichier(tmp_path):
    dst = _prepare(tmp_path)
    run_ctl(tmp_path, "media-expose", "--apply", nft_ok=True)
    d = json.loads(run_ctl(tmp_path, "media-expose", "--revoke", nft_ok=True))
    assert d == {"success": True, "revoked": True} and not dst.exists()
    assert "delete table inet secubox-meet" in (tmp_path / "nft-appels").read_text()


def test_sans_argument_rapporte_l_etat(tmp_path):
    dst = _prepare(tmp_path)
    avant = json.loads(run_ctl(tmp_path, "media-expose", nft_ok=True))
    assert avant["file_installed"] is False and avant["rule_live"] is False
    assert avant["tcp_port"] == 7881 and avant["udp_port"] == 7882
    assert avant["file"] == str(dst) and avant["hint"] == "meetctl media-expose --apply | --revoke"
    run_ctl(tmp_path, "media-expose", "--apply", nft_ok=True)
    apres = json.loads(run_ctl(tmp_path, "media-expose", nft_ok=True))
    assert apres["file_installed"] is True and apres["rule_live"] is True
    assert json.loads(run_ctl(tmp_path, "status"))["media"]["exposed"] is True


def test_apply_publie_les_ports_pour_le_relais_du_maitre(tmp_path):
    _prepare(tmp_path)
    run_ctl(tmp_path, "media-expose", "--apply", nft_ok=True)
    f = tmp_path / "ports-publics.d" / "meet.json"
    assert json.loads(f.read_text()) == {"module": "meet", "ports": [{"proto": "tcp", "port": 7881}, {"proto": "udp", "port": 7882}]}
    assert f.stat().st_mode & 0o777 == 0o644


def test_revoke_depublie_les_ports(tmp_path):
    _prepare(tmp_path)
    run_ctl(tmp_path, "media-expose", "--apply", nft_ok=True)
    run_ctl(tmp_path, "media-expose", "--revoke", nft_ok=True)
    assert not (tmp_path / "ports-publics.d" / "meet.json").exists()


def test_apply_refuse_par_nft_ne_publie_rien(tmp_path):
    _prepare(tmp_path)
    run_ctl_rc(tmp_path, "media-expose", "--apply", nft_ok=False)
    assert not (tmp_path / "ports-publics.d" / "meet.json").exists()


def test_apply_publication_impossible_renvoie_du_json_et_ne_laisse_rien(tmp_path):
    dst = _prepare(tmp_path)
    (tmp_path / "fichier").write_text("x")
    rc, out = run_ctl_rc(tmp_path, "media-expose", "--apply", nft_ok=True, env_extra={"SECUBOX_PORTS_PUBLICS_DIR": str(tmp_path / "fichier" / "d")})
    assert rc == 1 and json.loads(out)["success"] is False and not dst.exists()


def test_apply_ne_touche_pas_le_dossier_partage_des_publications(tmp_path):
    """C1 : ports-publics.d est commun à tous les modules qui publient : jamais de mode imposé s'il existe."""
    _prepare(tmp_path)
    d = tmp_path / "ports-publics.d"
    d.mkdir()
    d.chmod(0o751)
    run_ctl(tmp_path, "media-expose", "--apply", nft_ok=True)
    assert (d / "meet.json").exists() and d.stat().st_mode & 0o777 == 0o751
