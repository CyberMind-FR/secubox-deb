# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#3930 : toute levée (`wafctl unban`, `unban-liste`) écrit un `unban` au journal de sbxwaf AVANT le retrait nft.

wafctl réel, faux `nft` qui note ses appels et l'état du journal à cet instant. Rien ne touche un pare-feu.
"""
from __future__ import annotations

import getpass
import json
import os
import subprocess
import threading
import time
from pathlib import Path

import pytest

COMPOSANT = Path(__file__).resolve().parent.parent
WAFCTL = COMPOSANT / "scripts" / "wafctl"
BAN = '{"ip":"198.51.100.7","cat":"leurre:x","sev":"high","at":1,"exp":9999999999,"action":"ban"}\n'


class Banc:
    def __init__(self, tmp: Path, proprio: str):
        self.tmp = tmp
        bin_ = tmp / "bin"
        bin_.mkdir()
        nft = bin_ / "nft"
        nft.write_text(f'#!/bin/bash\n'
                       f'echo "$*" >> {tmp}/nft.log\n'
                       f'cp {tmp}/waf/bans.jsonl {tmp}/journal-au-retrait 2>/dev/null\n'
                       f'if [ "$1" = -f ]; then cat >> {tmp}/lot.nft; [ ! -e {tmp}/lot-ko ]; exit; fi\n'
                       f'if [ "$1" = -j ]; then cat {tmp}/reste.json 2>/dev/null || exit 1; exit 0; fi\n'
                       f'if [ "$1" = get ]; then exit 1; fi\n'
                       f'if [ "$1" = delete ] && [ -e {tmp}/absent ]; then exit 1; fi\nexit 0\n')
        nft.chmod(0o755)
        (tmp / "waf").mkdir()
        self.journal = tmp / "waf" / "bans.jsonl"
        self.audit = tmp / "audit.log"
        self.audit.write_text("")
        texte = WAFCTL.read_text()
        for avant, apres in (('BANS_JOURNAL="/var/lib/secubox/waf/bans.jsonl"', f'BANS_JOURNAL="{self.journal}"'),
                             ('BANS_PROPRIO="secubox-waf"', f'BANS_PROPRIO="{proprio}"'),
                             ('AUDIT_SECUBOX="/var/log/secubox/audit.log"', f'AUDIT_SECUBOX="{self.audit}"')):
            assert texte.count(avant) == 1
            texte = texte.replace(avant, apres)
        self.script = tmp / "wafctl"
        self.script.write_text(texte)
        self.env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}"}

    def lancer(self, *args):
        return subprocess.run(["bash", str(self.script), *args], check=False, timeout=60, capture_output=True,
                              text=True, env=self.env)

    def nft(self):
        f = self.tmp / "nft.log"
        return f.read_text().splitlines() if f.exists() else []

    def unbans(self, fichier=None):
        lignes = [json.loads(x) for x in (fichier or self.journal).read_text().splitlines() if x]
        return [x["ip"] for x in lignes if x["action"] == "unban"]

    def audits(self):
        return [json.loads(x) for x in self.audit.read_text().splitlines()]


@pytest.fixture
def b(tmp_path):
    banc = Banc(tmp_path, getpass.getuser())
    banc.journal.write_text(BAN)
    banc.journal.chmod(0o640)
    return banc


@pytest.mark.parametrize("saisie,attendu,ensemble", [
    ("198.51.100.7", "198.51.100.7", "waf_ban"),
    ("::ffff:198.51.100.7", "198.51.100.7", "waf_ban"),
    ("2001:DB8:0:0::7", "2001:db8::7", "waf_ban6"),
])
def test_unban_au_journal_avant_le_retrait(b, saisie, attendu, ensemble):
    avant = b.journal.stat()
    r = b.lancer("unban", saisie)
    assert r.returncode == 0, r.stderr
    assert b.nft() == [f"delete element inet secubox {ensemble} {{ {attendu} }}"]
    assert b.unbans(b.tmp / "journal-au-retrait") == [attendu]         # déjà écrit quand nft est appelé
    assert b.journal.read_text().startswith(BAN)
    e = json.loads(b.journal.read_text().splitlines()[-1])
    assert list(e) == ["ip", "cat", "sev", "at", "exp", "action"] and abs(e["at"] - time.time()) < 30 and e["exp"] == 0
    apres = b.journal.stat()
    assert (apres.st_mode, apres.st_uid, apres.st_ino) == (avant.st_mode, avant.st_uid, avant.st_ino)
    (a,) = b.audits()
    assert a["action"] == "waf-unban" and a["result"] == "ok" and attendu in a["detail"]


def test_unban_d_un_absent_de_nft_journalise_quand_meme(b):
    (b.tmp / "absent").touch()
    assert b.lancer("unban", "198.51.100.7").returncode == 0
    assert b.unbans() == ["198.51.100.7"]


def test_journal_absent_rien_n_est_cree(b):
    b.journal.unlink()
    assert b.lancer("unban", "198.51.100.7").returncode == 0
    assert not b.journal.exists() and any(x.startswith("delete") for x in b.nft())


@pytest.mark.parametrize("ip", ["192.168.1.1", "::ffff:10.0.0.1", "::1", "nimp", "", "2001:db8::1%eth0",
                                "198.51.100.7 }; flush ruleset", "198.51.100.0/24"])
def test_adresse_refusee_rien_n_est_fait(b, ip):
    assert b.lancer("unban", ip).returncode != 0
    assert b.journal.read_text() == BAN and b.nft() == []


def _lien(b):
    cible = b.tmp / "cible"
    b.journal.rename(cible)
    b.journal.symlink_to(cible)
    return cible


def _lien_dur(b):
    os.link(b.journal, b.tmp / "autre")
    return b.journal


def _fifo(b):
    b.journal.unlink()
    os.mkfifo(b.journal)
    return None


def _dossier(b):
    b.journal.unlink()
    b.journal.mkdir()
    return None


def _dossier_lien(b):
    vrai = b.tmp / "vrai"
    b.journal.parent.rename(vrai)
    (b.tmp / "waf").symlink_to(vrai)
    return vrai / "bans.jsonl"


@pytest.mark.parametrize("piege", [_lien, _lien_dur, _fifo, _dossier, _dossier_lien])
def test_journal_douteux_refus_et_rien_n_est_leve(b, piege):
    cible = piege(b)
    r = b.lancer("unban", "198.51.100.7")
    assert r.returncode == 1 and "refus:journal" in r.stderr
    assert b.nft() == []
    if cible is not None:
        assert cible.read_text() == BAN
    assert b.audits()[-1]["result"] == "refus"


@pytest.mark.parametrize("proprio", ["nobody", "compte-inexistant-3930"])
def test_journal_d_un_autre_compte_refuse(tmp_path, proprio):
    banc = Banc(tmp_path, proprio)
    banc.journal.write_text(BAN)
    r = banc.lancer("unban", "198.51.100.7")
    assert r.returncode == 1 and "refus:journal" in r.stderr and banc.nft() == [] and banc.journal.read_text() == BAN


def test_fin_sans_saut_de_ligne(b):
    b.journal.write_text(BAN + '{"ip":"203.0.1')
    assert b.lancer("unban", "198.51.100.7").returncode == 0
    assert json.loads(b.journal.read_text().splitlines()[-1])["ip"] == "198.51.100.7"


def test_couvert_rien_n_est_journalise(b):
    (b.tmp / "reste.json").write_text(json.dumps({"nftables": [{"set": {"name": "waf_ban", "elem": [
        {"elem": {"val": "198.51.100.7", "expires": 90000}}]}}]}))
    r = b.lancer("unban", "198.51.100.7", str(int(time.time()) + 60))
    assert r.returncode == 1 and "refus:couvert" in r.stderr
    assert b.unbans() == [] and not any(x.startswith("delete") for x in b.nft())


def test_compactage_pendant_l_ecriture_rien_ne_se_perd(b):
    """Le journal est remplacé sans cesse, comme par sbxwaf (recopie, rename, puis recopie des lignes tardives)."""
    fin = threading.Event()

    def compacter():
        while not fin.is_set():
            with open(b.journal, "rb") as vieux:
                tmp = b.tmp / "waf" / "bans.jsonl.tmp-1"
                tmp.write_bytes(vieux.read())
                time.sleep(0.002)
                os.replace(tmp, b.journal)
                tardif = vieux.read()
                if tardif:
                    with open(b.journal, "ab") as neuf:
                        neuf.write(tardif)
            time.sleep(0.2)
    t = threading.Thread(target=compacter)
    t.start()
    try:
        ips = [f"203.0.113.{i}" for i in range(1, 25)]
        for ip in ips:
            assert b.lancer("unban", ip).returncode == 0
    finally:
        fin.set()
        t.join()
    assert set(b.unbans()) == set(ips)


# ── unban-liste ────────────────────────────────────────────────────────
def test_unban_liste(b):
    liste = b.tmp / "liste"
    v4 = [f"203.0.{i >> 8}.{i & 255}" for i in range(1, 2301)]
    liste.write_text("# à lever\n\n" + "\r\n".join(v4) + "\n2001:DB8::1\n::ffff:203.0.0.1\n10.0.0.1\nnimp\n203.0.0.2 }\n")
    r = b.lancer("unban-liste", str(liste))
    assert r.returncode == 0, r.stderr
    assert "2301 adresse(s) levée(s), 3 ligne(s) invalide(s)" in r.stdout
    assert b.unbans() == v4 + ["2001:db8::1"]
    assert b.nft() == ["-f -"] * 4
    lot = (b.tmp / "lot.nft").read_text().splitlines()
    assert len(lot) == 8 and lot[0].startswith("add element inet secubox waf_ban { 203.0.0.1 timeout 60s, ")
    assert lot[1].startswith("delete element inet secubox waf_ban { 203.0.0.1, ") and lot[1].count(",") == 999
    assert lot[-1] == "delete element inet secubox waf_ban6 { 2001:db8::1 }"
    assert set(b.unbans(b.tmp / "journal-au-retrait")) == set(v4) | {"2001:db8::1"}
    (a,) = b.audits()
    assert a["action"] == "waf-unban-liste" and "2301" in a["detail"]


def test_unban_liste_refus(b):
    assert b.lancer("unban-liste").returncode == 1
    assert b.lancer("unban-liste", str(b.tmp / "absente")).returncode == 1
    assert b.lancer("unban-liste", str(b.tmp)).returncode == 1
    vide = b.tmp / "vide"
    vide.write_text("10.0.0.1\n")
    assert b.lancer("unban-liste", str(vide)).returncode == 1
    assert b.journal.read_text() == BAN and b.nft() == []
    (b.tmp / "lot-ko").touch()
    ok = b.tmp / "ok"
    ok.write_text("203.0.113.1\n")
    r = b.lancer("unban-liste", str(ok))
    assert r.returncode == 1 and "1 lot(s) refusé(s)" in r.stderr


def test_unban_liste_hors_sudoers():
    texte = (COMPOSANT / "sudoers" / "secubox-waf").read_text()
    assert "unban-liste" not in texte and "/usr/sbin/wafctl unban *" in texte
