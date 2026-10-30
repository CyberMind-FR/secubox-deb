# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L5, tâche 4 : secubox-pilotage-www, ctl root qui extrait les pages d'une version de paquet du dépôt apt local.

Le ctl réel est lancé sans root sous une racine substituée (SBX_RACINE, honorée parce que l'appelant est le processus
lui-même). Les .deb de test sont construits ici (ar + tar) pour pouvoir y placer des entrées hostiles."""
import hashlib
import io
import json
import os
import stat
import subprocess
import tarfile
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
CTL = PKG / "sbin" / "secubox-pilotage-www"
WWW = "usr/share/secubox/www/"
JOUR = 86400


def _ar(membres):
    out = io.BytesIO()
    out.write(b"!<arch>\n")
    for nom, data in membres:
        out.write(f"{nom:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode())
        out.write(data)
        if len(data) % 2:
            out.write(b"\n")
    return out.getvalue()


def faire_deb(entrees, compression="xz"):
    """entrees : liste de (nom, type, contenu|cible, mode). type ∈ f, d, l (symbolique), h (dur), c (car.), p (tube)."""
    tb = io.BytesIO()
    with tarfile.open(fileobj=tb, mode=f"w:{compression}" if compression else "w", format=tarfile.GNU_FORMAT) as t:
        for nom, typ, val, mode in entrees:
            ti = tarfile.TarInfo(nom)
            ti.mode = mode
            ti.mtime = 1_700_000_000
            if typ == "f":
                ti.size = len(val)
                t.addfile(ti, io.BytesIO(val))
                continue
            ti.type = {"d": tarfile.DIRTYPE, "l": tarfile.SYMTYPE, "h": tarfile.LNKTYPE, "c": tarfile.CHRTYPE,
                       "p": tarfile.FIFOTYPE}[typ]
            if typ in "lh":
                ti.linkname = val
            t.addfile(ti)
    ext = {"xz": ".xz", "gz": ".gz", "": ""}[compression]
    ctrl = io.BytesIO()
    with tarfile.open(fileobj=ctrl, mode="w:gz"):
        pass
    return _ar([("debian-binary", b"2.0\n"), ("control.tar.gz", ctrl.getvalue()), (f"data.tar{ext}", tb.getvalue())])


def pages_normales():
    return [
        ("./", "d", None, 0o755),
        ("./usr/", "d", None, 0o755),
        ("./usr/share/secubox/www/", "d", None, 0o755),
        ("./usr/share/secubox/www/dns/", "d", None, 0o755),
        ("./usr/share/secubox/www/dns/index.html", "f", b"<html>dns</html>", 0o644),
        ("./usr/share/secubox/www/dns/app.js", "f", b"console.log(1)", 0o755),
        ("./usr/share/secubox/www/dns-provider/", "d", None, 0o700),
        ("./usr/share/secubox/www/dns-provider/index.html", "f", b"<html>p</html>", 0o600),
        ("./usr/lib/secubox/dns/api/main.py", "f", b"print('api')", 0o644),
        ("./etc/secubox/dns.toml", "f", b"x = 1", 0o644),
    ]


class Banc:
    def __init__(self, tmp: Path):
        self.r = tmp / "racine"
        self.apt = self.r / "data/apt"
        (self.r / "var/log/secubox").mkdir(parents=True)
        (self.r / "var/lib/secubox/pilotage").mkdir(parents=True)
        (self.r / "etc/secubox").mkdir(parents=True)
        self.www = self.r / "var/lib/secubox/pilotage/www"
        self.stanzas = {}

    def publier(self, paquet, version, deb: bytes, somme=None, arch="arm64"):
        nom = f"pool/main/{paquet[0]}/{paquet}/{paquet}_{version}_all.deb"
        f = self.apt / nom
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(deb)
        s = somme or hashlib.sha256(deb).hexdigest()
        self.stanzas.setdefault(arch, []).append(
            f"Package: {paquet}\nVersion: {version}\nArchitecture: all\nFilename: {nom}\nSize: {len(deb)}\nSHA256: {s}\n")
        for a, st in self.stanzas.items():
            p = self.apt / f"dists/trixie/main/binary-{a}/Packages"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("\n".join(st))
        return f

    def ctl(self, *args, entree=None, maintenant=None, env=None):
        e = {"PATH": os.environ["PATH"], "SBX_RACINE": str(self.r), "SUDO_USER": "secubox-pilotage"}
        if maintenant is not None:
            e["SBX_MAINTENANT"] = str(int(maintenant))
        e.update(env or {})
        return subprocess.run([str(CTL), *args], input=entree, capture_output=True, text=True, env=e, timeout=60)

    def audit(self):
        p = self.r / "var/log/secubox/audit.log"
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    def residus(self, paquet):
        d = self.www / paquet
        return sorted(x.name for x in d.iterdir()) if d.exists() else []


@pytest.fixture
def banc(tmp_path):
    return Banc(tmp_path)


def test_extraction_limitee_aux_pages(banc):
    banc.publier("secubox-dns", "1.2.0-1~trixie1", faire_deb(pages_normales()))
    r = banc.ctl("extraire", "secubox-dns", "1.2.0-1~trixie1")
    assert r.returncode == 0, r.stderr
    v = banc.www / "secubox-dns" / "1.2.0-1~trixie1"
    fichiers = sorted(str(p.relative_to(v)) for p in v.rglob("*"))
    assert fichiers == ["dns", "dns-provider", "dns-provider/index.html", "dns/app.js", "dns/index.html"]
    assert (v / "dns/index.html").read_bytes() == b"<html>dns</html>"
    assert not list(banc.www.rglob("main.py")) and not list(banc.www.rglob("dns.toml"))
    sortie = json.loads(r.stdout)
    assert sortie["ok"] is True and sortie["fichiers"] == 3
    assert str(banc.r) not in r.stdout and "/data/apt" not in r.stdout     # aucun chemin dans la sortie
    a = banc.audit()
    assert a[-1]["evenement"] == "pilotage_www_extraire" and a[-1]["paquet"] == "secubox-dns"
    assert a[-1]["resultat"] == "ok" and a[-1]["acteur"] == "secubox-pilotage"


def test_droits_des_fichiers_extraits(banc):
    deb = faire_deb(pages_normales())
    banc.publier("secubox-dns", "1.0", deb)
    assert banc.ctl("extraire", "secubox-dns", "1.0").returncode == 0
    v = banc.www / "secubox-dns" / "1.0"
    for p in [v, *v.rglob("*")]:
        m = stat.S_IMODE(p.lstat().st_mode)
        assert m == (0o755 if p.is_dir() else 0o644), (p, oct(m))
    for p in (banc.www, banc.www / "secubox-dns"):
        assert stat.S_IMODE(p.stat().st_mode) == 0o755


def test_acteur_explicite_audite(banc):
    banc.publier("secubox-dns", "1.0", faire_deb(pages_normales()))
    assert banc.ctl("extraire", "--acteur", "alice", "secubox-dns", "1.0").returncode == 0
    assert banc.audit()[-1]["acteur"] == "alice"
    assert banc.ctl("extraire", "--acteur", "al ice;rm", "secubox-dns", "1.0").returncode == 2


def test_somme_erronee_refusee_rien_sur_disque(banc):
    banc.publier("secubox-dns", "1.0", faire_deb(pages_normales()), somme="0" * 64)
    r = banc.ctl("extraire", "secubox-dns", "1.0")
    assert r.returncode == 1
    assert "somme" in json.loads(r.stdout)["erreur"]
    assert banc.residus("secubox-dns") == []
    assert banc.audit()[-1]["resultat"] == "refus"


def test_deb_modifie_apres_publication_refuse(banc):
    f = banc.publier("secubox-dns", "1.0", faire_deb(pages_normales()))
    f.write_bytes(f.read_bytes()[:-3] + b"xyz")
    assert banc.ctl("extraire", "secubox-dns", "1.0").returncode == 1
    assert banc.residus("secubox-dns") == []


def test_version_absente_du_depot(banc):
    banc.publier("secubox-dns", "1.0", faire_deb(pages_normales()))
    r = banc.ctl("extraire", "secubox-dns", "9.9")
    assert r.returncode == 1 and "absent" in json.loads(r.stdout)["erreur"]


def test_filename_hors_pool_refuse(banc):
    deb = faire_deb(pages_normales())
    banc.publier("secubox-dns", "1.0", deb)
    p = banc.apt / "dists/trixie/main/binary-arm64/Packages"
    p.write_text(p.read_text().replace("Filename: pool/", "Filename: pool/../../"))
    assert banc.ctl("extraire", "secubox-dns", "1.0").returncode == 1


@pytest.mark.parametrize("hostile", [
    ("./usr/share/secubox/www/dns/../../../../etc/x", "f", b"x", 0o644),
    ("/usr/share/secubox/www/dns/abs.html", "f", b"x", 0o644),
    ("./usr/share/secubox/www/dns/lien", "l", "/etc/shadow", 0o777),
    ("./usr/share/secubox/www/dns/lien", "l", "../../../../../etc/shadow", 0o777),
    ("./usr/share/secubox/www/dns/dur", "h", "./etc/secubox/dns.toml", 0o644),
    ("./usr/share/secubox/www/dns/tube", "p", None, 0o644),
    ("./usr/share/secubox/www/dns/car", "c", None, 0o644),
    ("./usr/share/secubox/www/dns/suid", "f", b"x", 0o4755),
    ("./usr/share/secubox/www/dns/sgid/", "d", None, 0o2755),
    ("./usr/share/secubox/www/dns/ctl\x07.html", "f", b"x", 0o644),
], ids=["point-point", "absolu", "symlink-absolu", "symlink-sortant", "dur-sortant", "tube", "caractere", "setuid",
        "setgid", "controle"])
def test_entrees_hostiles_refusees(banc, hostile):
    banc.publier("secubox-dns", "1.0", faire_deb(pages_normales() + [hostile]))
    r = banc.ctl("extraire", "secubox-dns", "1.0")
    assert r.returncode == 1, r.stdout
    assert banc.residus("secubox-dns") == []
    assert banc.audit()[-1]["resultat"] == "refus"


def test_nom_non_utf8_refuse(banc):
    tb = io.BytesIO()
    with tarfile.open(fileobj=tb, mode="w", format=tarfile.GNU_FORMAT, encoding="latin-1") as t:
        ti = tarfile.TarInfo("./usr/share/secubox/www/dns/é.html")
        ti.size = 1
        t.addfile(ti, io.BytesIO(b"x"))
    ctrl = io.BytesIO()
    with tarfile.open(fileobj=ctrl, mode="w:gz"):
        pass
    deb = _ar([("debian-binary", b"2.0\n"), ("control.tar.gz", ctrl.getvalue()), ("data.tar", tb.getvalue())])
    banc.publier("secubox-dns", "1.0", deb)
    assert banc.ctl("extraire", "secubox-dns", "1.0").returncode == 1
    assert banc.residus("secubox-dns") == []


def test_liens_internes_acceptes(banc):
    e = pages_normales() + [("./usr/share/secubox/www/dns/alias.html", "l", "index.html", 0o777),
                            ("./usr/share/secubox/www/dns/copie.html", "h", "./usr/share/secubox/www/dns/index.html",
                             0o644)]
    banc.publier("secubox-dns", "1.0", faire_deb(e, compression="gz"))
    r = banc.ctl("extraire", "secubox-dns", "1.0")
    assert r.returncode == 0, r.stdout + r.stderr
    v = banc.www / "secubox-dns/1.0/dns"
    assert os.readlink(v / "alias.html") == "index.html"
    assert (v / "copie.html").read_bytes() == b"<html>dns</html>" and (v / "copie.html").stat().st_nlink == 1


@pytest.mark.parametrize("paquet,version", [
    ("dns", "1.0"), ("secubox-../x", "1.0"), ("secubox-DNS", "1.0"), ("secubox-dns", "../1.0"),
    ("secubox-dns", "1.0/x"), ("secubox-dns", "a1.0"), ("secubox-dns", ""), ("secubox-dns", "1" * 64),
])
def test_paquet_version_invalides(banc, paquet, version):
    r = banc.ctl("extraire", paquet, version)
    assert r.returncode == 2
    assert not banc.www.exists() or not any(banc.www.iterdir())


def test_verbe_inconnu(banc):
    assert banc.ctl("installer", "secubox-dns", "1.0").returncode == 2


def test_idempotence(banc):
    banc.publier("secubox-dns", "1.0", faire_deb(pages_normales()))
    assert banc.ctl("extraire", "secubox-dns", "1.0").returncode == 0
    v = banc.www / "secubox-dns/1.0"
    ino = v.stat().st_ino
    r = banc.ctl("extraire", "secubox-dns", "1.0")
    assert r.returncode == 0 and json.loads(r.stdout)["deja"] is True
    assert v.stat().st_ino == ino
    # altérée : ré-extraite
    (v / "dns/index.html").write_bytes(b"pirate")
    r = banc.ctl("extraire", "secubox-dns", "1.0")
    assert r.returncode == 0 and json.loads(r.stdout)["deja"] is False
    assert (v / "dns/index.html").read_bytes() == b"<html>dns</html>"
    assert sorted(banc.residus("secubox-dns")) == [".1.0.json", "1.0"]


def test_interruption_temporaire_nettoye(banc):
    banc.publier("secubox-dns", "1.0", faire_deb(pages_normales()))
    # un temporaire laissé par un arrêt brutal précédent
    vieux = banc.www / "secubox-dns" / ".tmp-1.0-99999"
    (vieux / "dns").mkdir(parents=True)
    (vieux / "dns/x").write_text("x")
    r = banc.ctl("extraire", "secubox-dns", "1.0", env={"SBX_INTERROMPRE": "1"})
    assert r.returncode != 0
    assert banc.residus("secubox-dns") == []
    assert banc.ctl("extraire", "secubox-dns", "1.0").returncode == 0
    assert banc.residus("secubox-dns") == [".1.0.json", "1.0"]


def test_limite_de_taille(banc):
    (banc.r / "etc/secubox/pilotage-www.toml").write_text("taille_max_mio = 1\n")
    e = pages_normales() + [("./usr/share/secubox/www/dns/gros.bin", "f", b"\0" * (1024 * 1024 + 1), 0o644)]
    banc.publier("secubox-dns", "1.0", faire_deb(e))
    r = banc.ctl("extraire", "secubox-dns", "1.0")
    assert r.returncode == 1 and "taille" in json.loads(r.stdout)["erreur"]
    assert banc.residus("secubox-dns") == []


def test_limite_de_nombre(banc):
    (banc.r / "etc/secubox/pilotage-www.toml").write_text("fichiers_max = 4\n")
    e = pages_normales() + [(f"./usr/share/secubox/www/dns/f{i}", "f", b"x", 0o644) for i in range(3)]
    banc.publier("secubox-dns", "1.0", faire_deb(e))
    r = banc.ctl("extraire", "secubox-dns", "1.0")
    assert r.returncode == 1 and "nombre" in json.loads(r.stdout)["erreur"]
    assert banc.residus("secubox-dns") == []


def test_depot_configurable(banc, tmp_path):
    ailleurs = Banc(tmp_path / "b")
    ailleurs.publier("secubox-dns", "1.0", faire_deb(pages_normales()))
    (banc.r / "etc/secubox/pilotage-www.toml").write_text(f'depot_apt = "{ailleurs.apt}"\n')
    assert banc.ctl("extraire", "secubox-dns", "1.0").returncode == 0
    (banc.r / "etc/secubox/pilotage-www.toml").write_text('depot_apt = "relatif/apt"\n')
    assert banc.ctl("extraire", "secubox-dns", "1.0").returncode == 2


def test_lister(banc):
    banc.publier("secubox-dns", "1.0", faire_deb(pages_normales()))
    banc.ctl("extraire", "secubox-dns", "1.0")
    r = banc.ctl("lister")
    assert r.returncode == 0
    v = json.loads(r.stdout)["versions"]
    assert len(v) == 1 and v[0]["paquet"] == "secubox-dns" and v[0]["version"] == "1.0"
    assert v[0]["taille"] == len(b"<html>dns</html>console.log(1)<html>p</html>") and v[0]["date"]


def _en_usage(*paires):
    return json.dumps({"en_usage": [{"paquet": p, "version": v} for p, v in paires]})


def test_purge_des_seules_versions_inutilisees_depuis_7_jours(banc):
    for v in ("1.0", "1.1", "1.2"):
        banc.publier("secubox-dns", v, faire_deb(pages_normales()))
    t0 = time.time()
    for v in ("1.0", "1.1", "1.2"):
        assert banc.ctl("extraire", "secubox-dns", v, maintenant=t0).returncode == 0
    # J+3 : 1.1 et 1.2 déclarées ; J+8 : seule 1.2 déclarée
    assert banc.ctl("purger", entree=_en_usage(("secubox-dns", "1.1"), ("secubox-dns", "1.2")),
                    maintenant=t0 + 3 * JOUR).returncode == 0
    r = banc.ctl("purger", entree=_en_usage(("secubox-dns", "1.2")), maintenant=t0 + 8 * JOUR)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["purgees"] == [{"paquet": "secubox-dns", "version": "1.0"}]
    assert sorted(banc.residus("secubox-dns")) == [".1.1.json", ".1.2.json", "1.1", "1.2"]
    assert banc.audit()[-1]["evenement"] == "pilotage_www_purger"
    # J+10 : 1.1 non déclarée depuis 7 jours → purgée
    r = banc.ctl("purger", entree=_en_usage(("secubox-dns", "1.2")), maintenant=t0 + 10 * JOUR + 1)
    assert json.loads(r.stdout)["purgees"] == [{"paquet": "secubox-dns", "version": "1.1"}]
    assert banc.residus("secubox-dns") == [".1.2.json", "1.2"]


def test_purge_entree_invalide_refusee(banc):
    banc.publier("secubox-dns", "1.0", faire_deb(pages_normales()))
    banc.ctl("extraire", "secubox-dns", "1.0", maintenant=0)
    for mauvaise in ("pas du json", '{"en_usage": [{"paquet": "../x", "version": "1"}]}', '{"autre": []}',
                     "x" * (2 * 1024 * 1024)):
        r = banc.ctl("purger", entree=mauvaise, maintenant=30 * JOUR)
        assert r.returncode == 2
    assert banc.residus("secubox-dns") == [".1.0.json", "1.0"]


def test_www_lien_symbolique_refuse(banc, tmp_path):
    cible = tmp_path / "ailleurs"
    cible.mkdir()
    banc.www.symlink_to(cible)
    banc.publier("secubox-dns", "1.0", faire_deb(pages_normales()))
    assert banc.ctl("extraire", "secubox-dns", "1.0").returncode == 1
    assert list(cible.iterdir()) == []


def test_sudoers_et_paquet():
    s = (PKG / "sudoers.d/secubox-pilotage-www").read_text()
    assert "secubox-pilotage ALL=(root) NOPASSWD: /usr/sbin/secubox-pilotage-www *" in s
    assert "ALL=(ALL)" not in s
    rules = (PKG / "debian/rules").read_text()
    assert "install -D -m 755 sbin/secubox-pilotage-www $(P)/usr/sbin/secubox-pilotage-www" in rules
    assert "install -D -m 0440 sudoers.d/secubox-pilotage-www $(P)/etc/sudoers.d/secubox-pilotage-www" in rules
    assert "SPDX-License-Identifier" in CTL.read_text()


@pytest.mark.skipif(not __import__("shutil").which("zstd"), reason="zstd absent")
def test_data_tar_zst_comme_les_paquets_du_depot(banc):
    """Les .deb du dépôt sont construits avec data.tar.zst (dpkg-deb de trixie) : décompressés par zstd, sans dpkg."""
    tb = io.BytesIO()
    with tarfile.open(fileobj=tb, mode="w", format=tarfile.GNU_FORMAT) as t:
        for nom, _, val, mode in pages_normales():
            ti = tarfile.TarInfo(nom)
            ti.mode = mode
            if val is None:
                ti.type = tarfile.DIRTYPE
                t.addfile(ti)
            else:
                ti.size = len(val)
                t.addfile(ti, io.BytesIO(val))
    zst = subprocess.run(["zstd", "-q", "-c"], input=tb.getvalue(), capture_output=True, check=True).stdout
    ctrl = io.BytesIO()
    with tarfile.open(fileobj=ctrl, mode="w:gz"):
        pass
    deb = _ar([("debian-binary", b"2.0\n"), ("control.tar.zst", ctrl.getvalue()), ("data.tar.zst", zst)])
    banc.publier("secubox-dns", "1.0", deb)
    r = banc.ctl("extraire", "secubox-dns", "1.0")
    assert r.returncode == 0, r.stdout + r.stderr
    assert (banc.www / "secubox-dns/1.0/dns/index.html").read_bytes() == b"<html>dns</html>"
