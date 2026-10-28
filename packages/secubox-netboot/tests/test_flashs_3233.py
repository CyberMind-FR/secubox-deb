# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3233 — suivre un flash (et le chargement d'un live) depuis la page : octets acquittés par la carte sur la connexion
:8099 (ss -ti), fichier demandé (journal du vhost, la sonde HEAD de sbx-netflash est journalisée tout de suite), taille
publiée → pourcentage, débit réel, temps restant."""
import importlib
import sys
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))
sys.path.insert(0, str(ICI.parents[1] / "common"))

SS = ("0      8285500 192.168.1.200:8099 192.168.42.161:60968\n"
      "\t bbr wscale:7,9 rto:3264 bytes_sent:259437676 bytes_retrans:37155596 bytes_acked:221442580 bytes_received:146"
      " delivery_rate 416804536bps\n"
      "0      0 192.168.1.200:8099 192.168.1.3:50172\n"
      "\t cubic bytes_acked:1 bytes_received:300\n")
JOURNAL = ('192.168.42.161 - - [28/Oct/2026:10:13:57 +0100] "GET /espressobin-live/filesystem.squashfs HTTP/1.1" 200 140124160 "-" "x"\n'
           '192.168.42.161 - - [28/Oct/2026:10:13:57 +0100] "GET /espressobin-live/x.img.gz.sig HTTP/1.1" 200 256 "-" "curl"\n'
           '192.168.42.161 - - [28/Oct/2026:10:13:57 +0100] "HEAD /espressobin-live/x.img.gz HTTP/1.1" 200 0 "-" "curl"\n'
           '192.168.1.3 - - [28/Oct/2026:10:13:58 +0100] "GET /../etc/passwd HTTP/1.1" 403 0 "-" "x"\n')
TAILLES = {("espressobin-live", "x.img.gz"): 1013595631, ("espressobin-live", "filesystem.squashfs"): 140124160}


def _main():
    sys.modules.pop("api.lot", None)
    sys.modules.pop("api.main", None)
    return importlib.import_module("api.main")


def test_pourcentage_du_flash_en_cours():
    m = _main()
    t = m.analyse_transferts(SS, JOURNAL, lambda live, f: TAILLES.get((live, f)), 100.0, {})
    assert t == [{"ip": "192.168.42.161", "live": "espressobin-live", "fichier": "x.img.gz", "type": "image",
                  "octets": 221442580, "taille": 1013595631, "pourcent": 21, "debit": None, "reste_s": None}]


def test_debit_et_reste_au_second_releve():
    m = _main()
    memo = {}
    m.analyse_transferts(SS, JOURNAL, lambda live, f: TAILLES.get((live, f)), 100.0, memo)
    plus = SS.replace("bytes_acked:221442580", "bytes_acked:231442580")
    t = m.analyse_transferts(plus, JOURNAL, lambda live, f: TAILLES.get((live, f)), 105.0, memo)[0]
    assert t["debit"] == 2000000 and t["reste_s"] == (1013595631 - 231442580) // 2000000


def test_chargement_du_live_reconnu_comme_tel():
    m = _main()
    journal = '192.168.42.170 - - [x] "GET /espressobin-live/filesystem.squashfs HTTP/1.1" 200 0 "-" "x"\n'
    ss = "0 0 192.168.1.200:8099 192.168.42.170:40000\n\t bytes_acked:70062080\n"
    t = m.analyse_transferts(ss, journal, lambda live, f: TAILLES.get((live, f)), 1.0, {})
    assert t[0]["type"] == "live" and t[0]["pourcent"] == 50


def test_fichier_inconnu_ou_chemin_douteux_ignore():
    m = _main()
    ss = "0 0 192.168.1.200:8099 192.168.1.3:50172\n\t bytes_acked:5000000\n"
    assert m.analyse_transferts(ss, JOURNAL, lambda live, f: TAILLES.get((live, f)), 1.0, {}) == []


def test_route_flashs(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    m = _main()
    journal = tmp_path / "netboot-access.log"
    journal.write_text(JOURNAL)
    (tmp_path / "http" / "espressobin-live").mkdir(parents=True)
    (tmp_path / "http" / "espressobin-live" / "x.img.gz").write_bytes(b"\0" * 1000)
    m.JOURNAL_8099, m.HTTP_ROOT = journal, tmp_path / "http"

    async def faux_run(*argv, timeout=60):
        assert argv[0] == "ss"
        return {"rc": 0, "stdout": SS.replace("221442580", "500"), "stderr": ""}
    monkeypatch.setattr(m, "_run", faux_run)
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "admin"}
    r = TestClient(m.app).get("/flashs").json()
    assert r["transferts"][0]["pourcent"] == 50 and r["transferts"][0]["fichier"] == "x.img.gz"


def test_le_flasheur_montre_sa_progression_sur_la_console():
    s = (ICI / "installer" / "sbx-netflash").read_text()
    assert 'pv -f -s "$taille"' in s and 'st=("${PIPESTATUS[0]}" "${PIPESTATUS[2]}")' in s


playwright = pytest.importorskip("playwright.sync_api")
from test_netboot_aurora_2597 import API, LIVE_EBIN, navigateur, ouvre  # noqa: E402,F401


def test_la_page_montre_le_flash_en_cours(navigateur):  # noqa: F811
    flashs = {"transferts": [{"ip": "192.168.42.161", "live": "espressobin-live", "fichier": "x.img.gz", "type": "image",
                              "octets": 221442580, "taille": 1013595631, "pourcent": 21, "debit": 1900000, "reste_s": 416}]}
    boards = {"boards": [{"model": "espressobin-v7", "live_nom": "espressobin-live", "titre": "ESPRESSObin v7",
                          "console": "ttyMV0,115200"}]}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/netboot/",
                           {**API, "/live": (200, LIVE_EBIN), "/boards": (200, boards), "/flashs": (200, flashs)})
    p.wait_for_selector("#lives .barre", state="attached")
    texte = p.inner_text("#lives")
    assert "Flash en cours" in texte and "21 %" in texte and "192.168.42.161" in texte and "6 min 56 s" in texte
    assert err == []
    ctx.close()


# ── Banc du 2026-10-28 : téléchargement coupé à 51 % (519 Mo sur 1 013) pendant un flash en flux ──────────────────
# La carte (1 Go, eMMC lente) cessait de lire plus de 60 s pendant les vidages du cache d'écriture : curl
# (--speed-time 60) ou nginx (send_timeout 60 s) coupait. Écriture directe sur l'eMMC (débit régulier) et tolérance
# portée à 10 min en flux ; un serveur réellement figé reste détecté.
def test_ecriture_directe_vers_l_emmc_seulement():
    s = (ICI.parents[1] / "image" / "sbin" / "secubox-flash-emmc").read_text()
    corps = s[s.index("ecrit_corps() {"):s.index("ecrit_corps() {") + 900]
    assert 'if [ -b "$1" ]' in corps and "oflag=direct" in corps and "iflag=fullblock" in corps


def test_flux_tolere_les_pauses_de_l_emmc():
    s = (ICI / "installer" / "sbx-netflash").read_text()
    fonction = s[s.index("telecharge_flux()"):].split("\n}")[0]
    assert "--speed-limit 1024 --speed-time 600" in fonction and "--timeout=600" in fonction
    assert "--speed-limit 4096 --speed-time 60 -o" in s                 # téléchargement vers la RAM : inchangé


def test_vhost_de_boot_tolere_un_lecteur_lent():
    s = (ICI / "nginx" / "boot-vhost.conf").read_text()
    bloc = s[s.index("location / {"):]
    assert "send_timeout 900s;" in bloc[:bloc.index("}")]
