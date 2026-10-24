# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3100 — sbx-netflash --nom : vérifie le lot signé puis dépose code, ancre et profil sur la box flashée."""
import base64
import json
import os
import stat
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
RACINE = ICI.parents[1]
FLASH = ICI / "installer" / "sbx-netflash"
PROFIL = ICI / "installer" / "sbx-netflash-profil"
ARGON = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"
CODE = "sbxmesh1." + "a" * 40
ANCRE = {"cle_publique": "KEY=", "adresse": "10.0.0.1", "nom": "gk2", "empreinte": "ff" * 8}


def bash(script, env=None, **kw):
    e = dict(os.environ, SBX_NETFLASH_SOURCE="1", **(env or {}))
    return subprocess.run(["bash", "-c", f'source "{FLASH}"\n{script}'], capture_output=True, text=True, env=e, **kw)


@pytest.fixture
def lot(tmp_path):
    cle, pub = tmp_path / "k.key", tmp_path / "k.pub"
    subprocess.run(["openssl", "genrsa", "-out", str(cle), "2048"], check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", str(cle), "-pubout", "-out", str(pub)], check=True, capture_output=True)
    texte = json.dumps({"version": 1, "nom": "gk1", "domaine": "gk1.example.org", "code": CODE, "ancre": ANCRE,
                        "emis": "2026-10-24T10:00:00+00:00", "admin_empreinte": ARGON}, ensure_ascii=False)
    t = tmp_path / "lot.txt"
    t.write_text(texte)
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(cle), str(t)], capture_output=True, check=True).stdout
    rep = tmp_path / "reponse.json"
    rep.write_text(json.dumps({"lot": texte, "signature": base64.b64encode(sig).decode()}))
    return {"rep": rep, "pub": pub, "tmp": tmp_path, "texte": texte}


def test_profil_genere_valide_par_premier_pas():
    sys.path.insert(0, str(RACINE / "packages" / "secubox-premier-pas"))
    from premier_pas import profil as pp
    out = subprocess.run([sys.executable, str(PROFIL), "--nom", "gk1", "--domaine", "gk1.example.org",
                          "--empreinte", ARGON], capture_output=True, text=True, check=True).stdout
    p = tomllib.loads(out)
    assert p["maillage"]["mode"] == "automesh" and p["services"]["profil"] == "actuel"
    assert p["admin"]["mot_de_passe"] == ARGON and p["admin"]["totp"] == "enroler"
    ex = pp.examine(p, profils_connus=[])
    assert ex.complet, (ex.manquantes, ex.erreurs)


def test_profil_refuse_clair():
    r = subprocess.run([sys.executable, str(PROFIL), "--nom", "gk1", "--domaine", "gk1.example.org",
                        "--empreinte", "motdepasse"], capture_output=True, text=True)
    assert r.returncode != 0 and r.stdout == ""


def test_lot_signature_valide(lot):
    r = bash(f'PUB="{lot["pub"]}"; verifie_lot "{lot["rep"]}" "{lot["tmp"]}/ok.json"')
    assert r.returncode == 0, r.stderr
    assert json.loads((lot["tmp"] / "ok.json").read_text())["code"] == CODE


def test_lot_signature_invalide_rien_ecrit(lot):
    rep = json.loads(lot["rep"].read_text())
    rep["lot"] = rep["lot"].replace("gk1.example.org", "evil.example.org")   # falsifié après signature
    lot["rep"].write_text(json.dumps(rep))
    racine, boot = lot["tmp"] / "p2", lot["tmp"] / "p1"
    racine.mkdir(); boot.mkdir()
    r = bash(f'PUB="{lot["pub"]}"; verifie_lot "{lot["rep"]}" "{lot["tmp"]}/ok.json" && '
             f'depose_dans "{racine}" "{boot}" "{lot["tmp"]}/ok.json" /dev/null')
    assert r.returncode != 0
    assert not (lot["tmp"] / "ok.json").exists()
    assert list(racine.rglob("*")) == [] and list(boot.rglob("*")) == []


def test_depot_ecrit_code_ancre_profil_avec_droits(lot):
    racine, boot = lot["tmp"] / "p2", lot["tmp"] / "p1"
    racine.mkdir(); boot.mkdir()
    (lot["tmp"] / "lot.json").write_text(lot["texte"])
    (lot["tmp"] / "profil.toml").write_text('[box]\nnom = "gk1"\n')
    r = bash(f'depose_dans "{racine}" "{boot}" "{lot["tmp"]}/lot.json" "{lot["tmp"]}/profil.toml"')
    assert r.returncode == 0, r.stderr
    code = racine / "var/lib/secubox/p2p/automesh.code"
    anc = racine / "etc/secubox/p2p/ancre-maitre.json"
    prof = boot / "secubox/profil.toml"
    assert code.read_text() == CODE
    assert stat.S_IMODE(code.stat().st_mode) == 0o600
    assert json.loads(anc.read_text()) == ANCRE and stat.S_IMODE(anc.stat().st_mode) == 0o644
    assert prof.read_text().startswith("[box]")
    assert stat.S_IMODE((racine / "etc/secubox/p2p").stat().st_mode) == 0o755


def test_sans_nom_comportement_inchange():
    src = FLASH.read_text()
    assert "exec secubox-flash-emmc" in src            # chemin sans --nom : exec direct, avec reboot
    r = subprocess.run(["bash", "-n", str(FLASH)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    r = subprocess.run(["bash", str(FLASH), "--help"], capture_output=True, text=True)
    assert r.returncode == 0 and "--nom" in r.stdout


def test_echec_montage_ne_detruit_rien(lot):
    stub = lot["tmp"] / "bin"
    stub.mkdir()
    (stub / "mount").write_text("#!/bin/sh\nexit 32\n")
    (stub / "mount").chmod(0o755)
    (lot["tmp"] / "lot.json").write_text(lot["texte"])
    (lot["tmp"] / "profil.toml").write_text("x\n")
    r = bash(f'depose_sur_emmc /dev/null /dev/null "{lot["tmp"]}/lot.json" "{lot["tmp"]}/profil.toml"',
             env={"PATH": f"{stub}:{os.environ['PATH']}", "SBX_TRAVAIL_DEPOT": str(lot["tmp"] / "mnt")})
    assert r.returncode != 0
    assert "montage" in (r.stdout + r.stderr)
    assert not list((lot["tmp"] / "mnt").rglob("*.code")) if (lot["tmp"] / "mnt").exists() else True


def test_argon2_absent_refus_avant_ecriture(lot):
    # lot sans admin_empreinte et python3 sans argon2 : refus net, rien d'écrit
    r = bash('python3() { return 1; }; export -f python3; verifie_hacheur_ou_refuse ""')
    assert r.returncode != 0 and "argon2" in (r.stdout + r.stderr)


def _rep_signee(lot, **retire):
    """Réponse signée avec la même clé que la fixture, après retrait de champs du lot."""
    d = json.loads(lot["texte"])
    for k in retire:
        d.pop(k)
    texte = json.dumps(d)
    t = lot["tmp"] / "x.txt"
    t.write_text(texte)
    cle = lot["tmp"] / "k.key"
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(cle), str(t)], capture_output=True, check=True).stdout
    rep = lot["tmp"] / "x.json"
    rep.write_text(json.dumps({"lot": texte, "signature": base64.b64encode(sig).decode()}))
    return rep


@pytest.mark.parametrize("champ", ["code", "ancre"])
def test_lot_sans_code_ou_ancre_refuse_avant_ecriture(lot, champ):
    rep = _rep_signee(lot, **{champ: 1})
    r = bash(f'PUB="{lot["pub"]}"; verifie_lot "{rep}" "{lot["tmp"]}/ok.json" && lot_complet "{lot["tmp"]}/ok.json"')
    assert r.returncode != 0
    racine, boot = lot["tmp"] / "p2", lot["tmp"] / "p1"
    racine.mkdir(); boot.mkdir()
    r = bash(f'depose_dans "{racine}" "{boot}" "{lot["tmp"]}/ok.json" /dev/null')
    assert r.returncode != 0
    assert list(racine.rglob("ancre*")) == []


def test_lot_sans_code_refuse_avant_ecriture(lot):
    test_lot_sans_code_ou_ancre_refuse_avant_ecriture(lot, "code")


def test_lot_sans_ancre_refuse_avant_ecriture(lot):
    test_lot_sans_code_ou_ancre_refuse_avant_ecriture(lot, "ancre")


def test_lot_code_mauvais_format_refuse(lot):
    d = json.loads(lot["texte"]); d["code"] = "abc"
    (lot["tmp"] / "l.json").write_text(json.dumps(d))
    assert bash(f'lot_complet "{lot["tmp"]}/l.json"').returncode != 0


def test_saisie_sans_console_echoue_sans_boucler(tmp_path):
    r = bash('saisit_empreinte', env={"SBX_TTY": str(tmp_path / "absent")}, timeout=15, stdin=subprocess.DEVNULL)
    assert r.returncode != 0


def test_mot_de_passe_espaces_conserves(tmp_path):
    argon2 = pytest.importorskip("argon2")
    tty = tmp_path / "tty"
    tty.write_text("  a b  \n  a b  \n")
    r = bash('saisit_empreinte', env={"SBX_TTY": str(tty)}, timeout=30)
    assert r.returncode == 0, r.stderr
    h = r.stdout.strip()
    assert argon2.PasswordHasher().verify(h, "  a b  ")


@pytest.mark.parametrize("nom,ok", [("gk1", True), ("a", True), ("a-b2", True), ("a" * 31, True),
                                    ("a" * 32, False), ("gk-", False), ("1gk", False), ("GK1", False),
                                    ("a_b", False), ("gk1\n../x", False)])
def test_motif_de_nom_identique_partout(nom, ok):
    """Lot du maître, sbx-netflash-profil et sbx-netflash acceptent exactement les mêmes noms."""
    import importlib.util
    import re
    spec = importlib.util.spec_from_file_location("lot_3100", ICI / "api" / "lot.py")
    lot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lot)
    assert lot.nom_valide(nom) is ok
    r = subprocess.run([sys.executable, str(PROFIL), "--nom", nom, "--domaine", "gk1.example.org",
                        "--empreinte", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"], capture_output=True, text=True)
    assert (r.returncode == 0) is ok
    src = (ICI / "installer" / "sbx-netflash").read_text()
    motif = re.search(r"NOM_RE='([^']+)'", src).group(1)
    b = subprocess.run(["bash", "-c", 'NOM_RE="$1"; [[ "$2" =~ $NOM_RE ]]', "_", motif, nom])
    assert (b.returncode == 0) is ok
