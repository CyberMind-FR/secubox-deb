# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2415 — chaque identité de client est rattachée à son APPAREIL RÉEL (NAC) ; une identité sans tunnel n'est pas un appareil."""
import hashlib
import pathlib
import sqlite3
import subprocess

from secubox_toolbox import appareils, wg


def _h(cle):
    return hashlib.sha256(cle.encode()).hexdigest()[:16]


def _dump(monkeypatch, pairs, now):
    lignes = ["privkey\tpubkey\t51820\toff"] + [f"{k}\t(none)\t{ep}\t{ips}\t{hs}\t1\t2\toff" for k, ep, ips, hs in pairs]
    monkeypatch.setattr(wg, "_now_ts", lambda: now)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, "\n".join(lignes) + "\n", ""))


def test_etat_du_tunnel_par_pair(monkeypatch):
    now = 1_800_000_000
    _dump(monkeypatch, [("actif", "192.168.1.89:49780", "10.99.1.75/32", now - 60),
                        ("calme", "(none)", "10.99.1.76/32", now - 90000),
                        ("fantome", "(none)", "(none)", 0)], now)
    p = wg.wg_pairs(900)
    assert p[_h("actif")] == {"tunnel": "actif", "endpoint_ip": "192.168.1.89", "handshake": now - 60}
    assert p[_h("calme")]["tunnel"] == "inactif"
    assert p[_h("fantome")]["tunnel"] == "aucun" and p[_h("fantome")]["endpoint_ip"] is None


def _nac(tmp_path, monkeypatch, lignes):
    db = pathlib.Path(tmp_path / "devices.db")
    with sqlite3.connect(db) as c:
        c.execute("CREATE TABLE devices(mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, oui_vendor TEXT, os TEXT, device_type TEXT)")
        c.executemany("INSERT INTO devices VALUES (?,?,?,?,?,?)", lignes)
    monkeypatch.setattr(appareils, "NAC_DB", db)
    appareils._cache.update(t=0.0, d={})


def test_rattachement_sur_adresse_locale_sans_jamais_rendre_la_mac(tmp_path, monkeypatch):
    _nac(tmp_path, monkeypatch, [("aa:bb:cc:dd:ee:01", "192.168.1.89, 2001:db8::1", "iphone-exemple", "Apple", "iOS", "phone"),
                                 ("aa:bb:cc:dd:ee:02", "8.8.8.8", "public", "X", "", "unknown")])
    a = appareils.rattacher([None, "192.168.1.89"])
    assert a["nom"] == "iphone-exemple" and a["fabricant"] == "Apple" and a["os"] == "iOS"
    assert "aa:bb" not in str(a) and len(a["cle"]) == 12          # condensat, pas la MAC
    assert appareils.rattacher(["192.168.1.250", "?", None]) is None   # aucune preuve : rien n'est deviné
    assert appareils.rattacher(["8.8.8.8"]) is None                    # une adresse publique ne prouve rien


def test_nac_absent_ne_leve_rien(tmp_path, monkeypatch):
    monkeypatch.setattr(appareils, "NAC_DB", pathlib.Path(tmp_path / "absent.db"))
    appareils._cache.update(t=0.0, d={})
    assert appareils.rattacher(["192.168.1.89"]) is None


def test_page_ecarte_les_identites_sans_tunnel_et_regroupe_par_appareil():
    src = (pathlib.Path(__file__).resolve().parents[1] / "www" / "toolbox" / "clients.html").read_text(encoding="utf-8")
    assert "function base()" in src and "c.tunnel==='aucun'" in src
    assert "appareil_cle" in src and "Identités sans tunnel" in src


def test_cle_d_appareil_figee_identique_a_celle_du_nac(tmp_path, monkeypatch):
    # Même valeur figée dans packages/secubox-nac/tests/test_clients_reels_2423.py : la jonction NAC ↔ Toolbox repose dessus.
    _nac(tmp_path, monkeypatch, [("aa:bb:cc:dd:ee:01", "192.168.1.89", "iphone-exemple", "Apple", "iOS", "phone")])
    assert appareils.rattacher(["192.168.1.89"])["cle"] == "077a24919e64"
