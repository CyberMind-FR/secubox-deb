# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3167 — ancre DNSSEC d'Unbound vide : réparée au démarrage au lieu d'une boucle de redémarrages.

gk1, 2026-10-25 : /var/lib/unbound/root.key faisait 0 octet ; le helper Debian ne recopie la clé de dns-root-data que si
le fichier manque ou est plus ancien, Unbound échouait (« failed to read ») et redémarrait sans fin (5 388 fois)."""
import os
import subprocess
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
SCRIPT = RACINE / "sbin" / "secubox-unbound-ancre"
DROPIN = RACINE / "conf" / "unbound-ancre.conf"
CLE = ". IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3\n"


def _lance(tmp_path, contenu):
    src = tmp_path / "share-root.key"
    src.write_text(CLE)
    ancre = tmp_path / "root.key"
    if contenu is not None:
        ancre.write_text(contenu)
    env = dict(os.environ, SECUBOX_ANCRE=str(ancre), SECUBOX_ANCRE_SOURCE=str(src), SECUBOX_ANCRE_SANS_SETPRIV="1")
    r = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, env=env)
    return r, ancre


def test_ancre_vide_recopiee(tmp_path):
    r, ancre = _lance(tmp_path, "")
    assert r.returncode == 0 and ancre.read_text() == CLE and "recopiée" in r.stderr


def test_ancre_sans_cle_recopiee(tmp_path):
    r, ancre = _lance(tmp_path, "; autotrust trust anchor file\n;;id: . 1\n")
    assert ancre.read_text() == CLE


def test_ancre_absente_laissee_au_helper_debian(tmp_path):
    # absente : le helper Debian la crée lui-même ; la garde ne double pas son travail
    r, ancre = _lance(tmp_path, None)
    assert r.returncode == 0 and not ancre.exists()


def test_ancre_valide_intacte(tmp_path):
    valide = ";;state=2\n.\t3600\tIN\tDNSKEY\t257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv\n"
    r, ancre = _lance(tmp_path, valide)
    assert r.returncode == 0 and ancre.read_text() == valide and r.stderr == ""


def test_dropin_lance_la_garde_sans_bloquer_unbound():
    d = DROPIN.read_text()
    assert "[Service]" in d and "ExecStartPre=-/usr/sbin/secubox-unbound-ancre" in d
