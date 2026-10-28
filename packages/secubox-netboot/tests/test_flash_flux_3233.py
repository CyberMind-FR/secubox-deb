# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3233 — ESPRESSObin (1 Go de RAM) : l'image ne tient pas en mémoire. Le flash écrit en flux et vérifie la signature
et l'empreinte PENDANT l'écriture ; un échec invalide ce qui vient d'être écrit. Un faux eMMC (fichier) sert de cible."""
import gzip
import hashlib
import lzma
import os
import subprocess
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
FLASH_EMMC = ICI.parents[1] / "image" / "sbin" / "secubox-flash-emmc"
NETFLASH = ICI / "installer" / "sbx-netflash"
MOTIF = b"\xaa" * (8 * 1048576)


def _cle(d, nom):
    priv, pub = d / f"{nom}.pem", d / f"{nom}.pub"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(priv)],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(priv), "-pubout", "-out", str(pub)], check=True, capture_output=True)
    return priv, pub


def _signe(priv, fichier):
    sig = fichier.with_name(fichier.name + ".sig")
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(priv), "-out", str(sig), str(fichier)], check=True)
    return sig


@pytest.fixture(scope="module")
def cles(tmp_path_factory):
    d = tmp_path_factory.mktemp("cles")
    return _cle(d, "bonne"), _cle(d, "autre")


@pytest.fixture
def banc(tmp_path, cles):
    (priv, pub), (autre_priv, _) = cles
    brut = os.urandom(3 * 1048576)
    gz = tmp_path / "minimal.img.gz"
    gz.write_bytes(gzip.compress(brut))
    cible = tmp_path / "emmc"
    cible.write_bytes(MOTIF)
    return {"brut": brut, "gz": gz, "cible": cible, "priv": priv, "pub": pub, "autre": autre_priv, "d": tmp_path}


def _flux(cible, fmt, sig, pub, sha, entree):
    """Charge secubox-flash-emmc sans l'exécuter, puis écrit le flux `entree` sur `cible`."""
    script = 'SBX_FLASH_EMMC_SOURCE=1 source "$0"; ecrit_flux_verifie "$1" "$2" "$3" "$4" "$5" < "$6"'
    return subprocess.run(["bash", "-c", script, str(FLASH_EMMC), str(cible), fmt, str(sig), str(pub), sha, str(entree)],
                          capture_output=True, text=True)


def _sha(f):
    return hashlib.sha256(Path(f).read_bytes()).hexdigest()


def test_une_image_signee_est_ecrite_en_flux(banc):
    sig = _signe(banc["priv"], banc["gz"])
    r = _flux(banc["cible"], "gz", sig, banc["pub"], _sha(banc["gz"]), banc["gz"])
    assert r.returncode == 0, r.stderr
    assert banc["cible"].read_bytes()[: len(banc["brut"])] == banc["brut"]


def test_le_format_xz_de_la_release_est_accepte(banc):
    xz = banc["d"] / "minimal.img.xz"
    xz.write_bytes(lzma.compress(banc["brut"], format=lzma.FORMAT_XZ))
    sig = _signe(banc["priv"], xz)
    r = _flux(banc["cible"], "xz", sig, banc["pub"], _sha(xz), xz)
    assert r.returncode == 0, r.stderr
    assert banc["cible"].read_bytes()[: len(banc["brut"])] == banc["brut"]


@pytest.mark.parametrize("cas", ["autre_cle", "tronquee", "empreinte", "alteree"])
def test_un_flux_refuse_invalide_la_cible(banc, cas):
    gz, sha = banc["gz"], _sha(banc["gz"])
    sig = _signe(banc["autre"] if cas == "autre_cle" else banc["priv"], gz)
    entree = gz
    if cas == "tronquee":                      # téléchargement coupé en route
        entree = banc["d"] / "coupe.gz"
        entree.write_bytes(gz.read_bytes()[: gz.stat().st_size // 2])
    elif cas == "empreinte":                   # signature juste, mais pas l'image de la liste
        sha = "0" * 64
    elif cas == "alteree":                     # un octet changé après la signature
        entree = banc["d"] / "alteree.gz"
        b = bytearray(gz.read_bytes())
        b[len(b) // 2] ^= 0xFF
        entree.write_bytes(bytes(b))
    r = _flux(banc["cible"], "gz", sig, banc["pub"], sha, entree)
    assert r.returncode != 0
    assert banc["cible"].read_bytes() == b"\x00" * len(MOTIF)     # rien d'amorçable ne reste


def test_format_inconnu_refuse_sans_toucher_la_cible(banc):
    sig = _signe(banc["priv"], banc["gz"])
    r = _flux(banc["cible"], "zip", sig, banc["pub"], _sha(banc["gz"]), banc["gz"])
    assert r.returncode != 0 and banc["cible"].read_bytes() == MOTIF


def _netflash(expr):
    return subprocess.run(["bash", "-c", f'SBX_NETFLASH_SOURCE=1 source "$0"; {expr}', str(NETFLASH)],
                          capture_output=True, text=True)


def test_netflash_passe_en_flux_quand_la_ram_manque():
    mo = 1048576
    assert _netflash(f"mode_ecriture {800 * mo} {700 * mo}").stdout.strip() == "flux"     # ESPRESSObin, 1 Go
    assert _netflash(f"mode_ecriture {800 * mo} {6000 * mo}").stdout.strip() == "ram"     # MOCHAbin, 8 Go


def test_netflash_format_d_apres_le_nom():
    assert _netflash("format_image minimal.img.gz").stdout.strip() == "gz"
    assert _netflash("format_image secubox-minimal-espressobin-v7-trixie.img.xz").stdout.strip() == "xz"
    assert _netflash("format_image minimal.img.zip").returncode != 0


def test_le_flux_passe_par_les_gardes_de_secubox_flash_emmc():
    s = NETFLASH.read_text()
    assert 'opts=(--stdin "$format" --sig "$TRAVAIL/$image.sig" --pub "$PUB" --sha256 "$sha" --auto)' in s
    assert 'telecharge_flux "$BASE/$image" | secubox-flash-emmc "${opts[@]}"' in s
    corps = s[s.index("telecharge_flux()"):].split("\n")[1]          # pas de reprise : un flux recommencé serait corrompu
    assert 'curl -fsS "$1"' in corps and "--retry" not in corps
    f = FLASH_EMMC.read_text()
    assert "--stdin exige --auto" in f          # l'entrée standard porte l'image : la confirmation vient de l'appelant
    g = f.index("SAFETY STOP")
    assert g < f.index('ecrit_flux_verifie "$EMMC_DEVICE"')      # jamais d'écriture avant la garde du démarrage


def test_le_depot_du_lot_vise_l_emmc_detectee():
    s = NETFLASH.read_text()
    assert 'dev="${SBX_EMMC:-/dev/mmcblk0}"' not in s           # eMMC = mmcblk1 quand une carte SD est présente
    assert "boot0" in s
