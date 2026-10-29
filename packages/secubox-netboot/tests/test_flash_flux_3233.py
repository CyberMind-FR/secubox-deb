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
                   check=True, capture_output=True, timeout=60)
    subprocess.run(["openssl", "pkey", "-in", str(priv), "-pubout", "-out", str(pub)], check=True, capture_output=True,
                   timeout=60)
    return priv, pub


def _signe(priv, fichier):
    sig = fichier.with_name(fichier.name + ".sig")
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(priv), "-out", str(sig), str(fichier)], check=True, timeout=60)
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
                          capture_output=True, text=True, timeout=60)


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
                          capture_output=True, text=True, timeout=60)


def test_netflash_ecrit_toujours_en_flux():
    # #3271 : plus de mode « ram » (tmpfs à la taille de l'image), même sur une MOCHAbin de 8 Go
    s = NETFLASH.read_text()
    assert "mode_ecriture" not in s and "mount -t tmpfs" not in s


def test_netflash_format_d_apres_le_nom():
    assert _netflash("format_image minimal.img.gz").stdout.strip() == "gz"
    assert _netflash("format_image secubox-minimal-espressobin-v7-trixie.img.xz").stdout.strip() == "xz"
    assert _netflash("format_image minimal.img.zip").returncode != 0


def test_le_flux_passe_par_les_gardes_de_secubox_flash_emmc():
    s = NETFLASH.read_text()
    assert 'opts=(--stdin "$format" --sig "$TRAVAIL/$image.sig" --pub "$PUB" --sha256 "$sha" --auto)' in s
    assert 'telecharge_flux "$BASE/$image" | secubox-flash-emmc "${opts[@]}"' in s
    fonction = s[s.index("telecharge_flux()"):].split("\n}")[0]
    corps = next(x for x in fonction.split("\n") if "curl -fsS " in x)  # pas de reprise : un flux recommencé serait corrompu
    assert corps.rstrip().endswith('"$1"') and "--retry" not in corps
    f = FLASH_EMMC.read_text()
    assert "--stdin exige --auto" in f          # l'entrée standard porte l'image : la confirmation vient de l'appelant
    g = f.index("SAFETY STOP")
    assert g < f.index('ecrit_flux_verifie "$EMMC_DEVICE"')      # jamais d'écriture avant la garde du démarrage


def test_le_depot_du_lot_vise_l_emmc_detectee():
    s = NETFLASH.read_text()
    assert 'dev="${SBX_EMMC:-/dev/mmcblk0}"' not in s           # eMMC = mmcblk1 quand une carte SD est présente
    assert "boot0" in s


# ── Relecture de sécurité : interruption, tête écrite en dernier, injection, invalidation sûre ─────────────────
import signal  # noqa: E402
import time  # noqa: E402

TETE = 2 * 1048576


def test_un_flux_tue_en_route_ne_laisse_aucune_tete_lisible(banc):
    # SIGKILL (ni trap ni nettoyage) : la tête (table de partitions + début de p1) n'est écrite qu'APRÈS vérification
    sig = _signe(banc["priv"], banc["gz"])
    script = 'SBX_FLASH_EMMC_SOURCE=1 source "$0"; ecrit_flux_verifie "$1" gz "$2" "$3" "$4"'
    p = subprocess.Popen(["bash", "-c", script, str(FLASH_EMMC), str(banc["cible"]), str(sig), str(banc["pub"]),
                          _sha(banc["gz"])], stdin=subprocess.PIPE, start_new_session=True)
    donnees = banc["gz"].read_bytes()
    p.stdin.write(donnees[: len(donnees) * 3 // 4])
    p.stdin.flush()
    time.sleep(1.0)
    os.killpg(p.pid, signal.SIGKILL)
    p.wait(timeout=30)
    assert banc["cible"].read_bytes()[:TETE] == b"\x00" * TETE


def test_un_flux_interrompu_par_sigterm_invalide_la_cible(banc):
    sig = _signe(banc["priv"], banc["gz"])
    script = 'SBX_FLASH_EMMC_SOURCE=1 source "$0"; ecrit_flux_verifie "$1" gz "$2" "$3" "$4"'
    p = subprocess.Popen(["bash", "-c", script, str(FLASH_EMMC), str(banc["cible"]), str(sig), str(banc["pub"]),
                          _sha(banc["gz"])], stdin=subprocess.PIPE)
    donnees = banc["gz"].read_bytes()
    p.stdin.write(donnees[: len(donnees) // 2])
    p.stdin.flush()
    time.sleep(1.0)
    p.send_signal(signal.SIGTERM)
    assert p.wait(timeout=30) != 0
    assert banc["cible"].read_bytes() == b"\x00" * len(MOTIF)


def test_la_fin_d_une_grande_cible_est_effacee(tmp_path, banc):
    # ancienne GPT de secours au dernier Mo d'une eMMC : effacée (cible creuse de 200 Mo)
    grande = tmp_path / "grande"
    with open(grande, "wb") as f:
        f.truncate(200 * 1048576)
        f.seek(200 * 1048576 - 4096)
        f.write(b"\xbb" * 4096)
    sig = _signe(banc["autre"], banc["gz"])                         # signature refusée
    r = _flux(grande, "gz", sig, banc["pub"], _sha(banc["gz"]), banc["gz"])
    assert r.returncode != 0
    with open(grande, "rb") as f:
        f.seek(200 * 1048576 - 1048576)
        assert f.read() == b"\x00" * 1048576


def test_executer_avec_la_variable_de_test_est_refuse(banc):
    r = subprocess.run(["bash", str(FLASH_EMMC), "--help"], capture_output=True, text=True, timeout=60,
                       env={**os.environ, "SBX_FLASH_EMMC_SOURCE": "1"})
    assert r.returncode == 2


@pytest.mark.parametrize("taille,sha,brut", [
    ("a[$(touch {piege})]", "a" * 64, ""),
    ("12", "a" * 64, "b[$(touch {piege})]"),
    ("12", "z" * 64, ""),
    ("1" * 16, "a" * 64, ""),
])
def test_les_champs_d_images_txt_sont_valides_avant_tout_calcul(tmp_path, taille, sha, brut):
    piege = tmp_path / "piege"
    t, b = taille.format(piege=piege), brut.format(piege=piege)
    r = _netflash(f"champs_valides '{t}' '{sha}' '{b}'")
    assert r.returncode != 0 and not piege.exists()
    assert _netflash(f"champs_valides 2669000177 {'a' * 64} 7516192768").returncode == 0
    assert _netflash(f"champs_valides 2669000177 {'a' * 64} ''").returncode == 0


def test_sbx_dir_hostile_refuse():
    s = NETFLASH.read_text()
    assert 'case "$dir" in *[!A-Za-z0-9._-]*|.*) fail' in s


def test_telechargements_bornes_dans_le_temps():
    s = NETFLASH.read_text()
    assert "--connect-timeout 20 --speed-limit 4096 --speed-time 60" in s
    assert "--tries=1 --timeout=60" in s
    assert 'curl -fsSI' in s                                            # image joignable AVANT la confirmation
