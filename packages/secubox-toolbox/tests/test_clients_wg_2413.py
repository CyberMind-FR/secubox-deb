# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2413 — après « Oublier tous », les clients se recréent depuis l'activité du tunnel WireGuard."""
import hashlib
import pathlib
import subprocess
import time

from secubox_toolbox import clients_wg, store, wg


def _db(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", pathlib.Path(tmp_path / "toolbox.db"))
    store.upsert_client("amorce", "10.0.0.9", level="r1")   # crée le schéma
    with store._conn() as c:
        c.execute("DELETE FROM clients")


def _dump(monkeypatch, pairs, now):
    """pairs : [(cle, ips, handshake)] ; première ligne = l'interface, comme `wg show dump`."""
    lignes = ["privkey\tpubkey\t51820\toff"] + [f"{k}\t(none)\t1.2.3.4:5000\t{ips}\t{hs}\t10\t20\toff" for k, ips, hs in pairs]
    monkeypatch.setattr(wg, "_now_ts", lambda: now)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, "\n".join(lignes) + "\n", ""))


def _h(cle):
    return hashlib.sha256(cle.encode()).hexdigest()[:16]


def test_seuls_les_pairs_a_poignee_de_main_recente_sont_actifs(monkeypatch):
    now = 1_800_000_000
    _dump(monkeypatch, [("actif", "10.99.1.5/32", now - 60), ("vieux", "10.99.1.6/32", now - 7200),
                        ("jamais", "10.99.1.7/32", 0), ("sans-ip", "(none)", now - 10)], now)
    assert wg.wg_actifs(900) == {_h("actif"): ("10.99.1.5", now - 60)}


def test_ensure_client_cree_puis_ne_touche_pas_au_niveau(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    assert store.ensure_client("c1", "10.99.1.5", "r3") is True
    store.set_client_level("c1", "r2")                       # le client a choisi r2
    assert store.ensure_client("c1", "10.99.1.8", "r3") is False
    with store._conn() as c:
        ip, niveau = c.execute("SELECT ip, level FROM clients WHERE mac_hash='c1'").fetchone()
    assert (ip, niveau) == ("10.99.1.8", "r2")               # adresse à jour, niveau choisi conservé


def test_la_table_se_reconstruit_apres_oublier_tous(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    now = int(time.time())
    _dump(monkeypatch, [("alice", "10.99.1.5/32", now - 30), ("bob", "10.99.1.6/32", now - 100000)], now)
    store.upsert_client(_h("alice"), "10.99.1.5", level="r3")
    store.forget_clients(inactive_days=0)                    # « Oublier tous »
    with store._conn() as c:
        assert c.execute("SELECT COUNT(*) FROM clients").fetchone()[0] == 0
    assert clients_wg.synchroniser() == 1                    # alice est active, bob non
    with store._conn() as c:
        assert [r[0] for r in c.execute("SELECT mac_hash FROM clients")] == [_h("alice")]
    assert clients_wg.synchroniser() == 0                    # idempotent


def test_wg_absent_ne_leve_rien(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError("wg")
    monkeypatch.setattr(subprocess, "run", boom)
    assert wg.wg_actifs() == {} and clients_wg.synchroniser() == 0
