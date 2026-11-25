# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3932 : une seule relance de sbxwaf par mise à jour, après vérification du nouveau binaire ; surcharge locale signalée ; CGNAT."""
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
POSTINST = PKG / "debian" / "postinst"
COMPOSANT = PKG / "composants" / "waf" / "debian" / "postinst"
UNITE = PKG / "systemd" / "secubox-waf-ng.service"
RELANCE = "systemctl restart secubox-waf-ng.service"


def _bloc(nom):
    t = POSTINST.read_text(encoding="utf-8")
    d, f = f"# >>> {nom} (#3932)", f"# <<< {nom} (#3932)"
    assert t.count(d) == 1 and t.count(f) == 1, nom
    return t[t.index(d):t.index(f)]


def _drapeaux(fichier):
    m = re.search(r"^ExecStart=(/usr/sbin/sbxwaf\b.*?)(?:\n(?!\s)|\Z)", Path(fichier).read_text(encoding="utf-8"), re.S | re.M)
    return " ".join(re.sub(r"\\\n", " ", m.group(1)).split())


def _execstart(ligne):
    return f"{{ path=/usr/sbin/sbxwaf ; argv[]={ligne} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}"


def _lancer(tmp_path, corps, ligne, actif=True, verifier=0):
    """Exécute un morceau du postinst sous `set -e`, faux systemctl, logger, setpriv et binaire ; rend (résultat, journal)."""
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    journal = tmp_path / "appels"
    journal.write_text("")
    (tmp_path / "execstart").write_text(_execstart(ligne) + "\n" if ligne else "")

    def faux(nom, texte):
        p = bin_ / nom
        p.write_text("#!/bin/sh\n" + texte)
        p.chmod(0o755)
    faux("systemctl", f'echo "systemctl $*" >> {journal}\ncase "$1" in show) cat {tmp_path}/execstart;; is-active) exit {0 if actif else 3};; esac\nexit 0\n')
    faux("logger", f'echo "logger $*" >> {journal}\n')
    faux("setpriv", 'while [ "$1" != -- ]; do shift; done\nshift\nexec "$@"\n')
    faux("sbxwaf", f'for a in "$@"; do printf "[%s]" "$a" >> {journal}; done\necho >> {journal}\n[ {verifier} = 0 ] || echo "flag provided but not defined: -nouveau"\nexit {verifier}\n')
    env = {"PATH": f"{bin_}:/usr/bin:/bin", "WAF_UNITE": str(UNITE), "WAF_BINAIRE": str(bin_ / "sbxwaf")}
    r = subprocess.run(["sh", "-c", "set -e\n" + corps], check=False, capture_output=True, text=True, env=env, timeout=30)
    return r, journal.read_text()


# ── une seule relance ────────────────────────────────────────────────────────

def test_une_seule_relance_dans_les_scripts_du_paquet():
    assert POSTINST.read_text().count("restart secubox-waf-ng") == 1
    assert "secubox-waf-ng.service" not in COMPOSANT.read_text() and "restart secubox-waf-ng" not in COMPOSANT.read_text()
    for s in ("preinst", "prerm"):
        assert not re.search(r"(restart|stop|try-restart)[^\n]*secubox-waf-ng\.service", (PKG / "debian" / s).read_text()), s


def test_regles_et_profils_avant_la_relance():
    t = POSTINST.read_text()
    assert t.index("/usr/sbin/waf-rules-sync") < t.index(RELANCE) and t.index("/usr/sbin/waf-profils-fusion") < t.index(RELANCE)
    assert "waf-rules-sync --version" not in COMPOSANT.read_text()


@pytest.mark.skipif(shutil.which("dh_installsystemd") is None, reason="debhelper absent")
def test_l_extrait_debhelper_ne_relance_pas(tmp_path):
    """Le second redémarrage du 2026-11-24 (16:48) : `deb-systemd-invoke restart` de dh_installsystemd."""
    commande = re.findall(r"^\tdh_installsystemd (--name=secubox-waf-ng(?: .*)?)$", (PKG / "debian" / "rules").read_text(), re.M)
    assert len(commande) == 1
    for options, relances in ((["--name=secubox-waf-ng"], 1), (commande[0].split(), 0)):
        d = tmp_path / str(relances)
        unites = d / "debian" / "secubox-waf-ng" / "lib" / "systemd" / "system"
        unites.mkdir(parents=True)
        shutil.copy(UNITE, unites)
        for f in ("control", "changelog"):
            shutil.copy(PKG / "debian" / f, d / "debian" / f)
        subprocess.run(["dh_installsystemd", *options], cwd=d, check=True, timeout=60, capture_output=True, text=True)
        generes = {f.name: f.read_text() for f in (d / "debian" / ".debhelper").rglob("*") if f.is_file()}
        texte = "\n".join(generes.values())
        assert texte.count("_dh_action=restart") == relances, generes.keys()
        if not relances:
            assert "deb-systemd-invoke start 'secubox-waf-ng.service'" in texte      # première installation
            assert re.search(r'"\$1" = remove.*\n\s*deb-systemd-invoke stop', texte)   # retrait
            assert not re.search(r'"\$1" = upgrade.*\n\s*deb-systemd-invoke stop', texte)


# ── vérification avant la relance ────────────────────────────────────────────

VERIF = "avertir", "vérification avant la relance"


def _verif(tmp_path, **k):
    corps = "".join(_bloc(n) for n in VERIF) + '\necho "relancer=$sbx_relancer"\n'
    return _lancer(tmp_path, corps, k.pop("ligne", _drapeaux(UNITE)), **k)


def test_verifie_la_ligne_de_commande_effective(tmp_path):
    r, j = _verif(tmp_path, ligne=_drapeaux(PKG / "conf" / "honeypot.conf"))
    assert r.returncode == 0 and "relancer=1" in r.stdout and "ATTENTION" not in r.stderr, r.stderr
    argv = re.findall(r"\[(.*?)\]", [x for x in j.splitlines() if x.startswith("[")][0])
    assert argv[0] == "--verifier"                                      # en tête : jamais ignoré après un mot sans tiret
    assert argv[argv.index("--actor-ban-protegees") + 1] == ""          # la variable de systemd n'est pas passée telle quelle
    assert "--leurre-ban" in argv and argv[argv.index("--listen") + 1] == "127.0.0.1:8085"


def test_binaire_refuse_l_ancien_continue_de_servir(tmp_path):
    r, j = _verif(tmp_path, verifier=2)
    assert r.returncode == 0 and "relancer=\n" in r.stdout
    assert "ne peut pas démarrer (flag provided but not defined: -nouveau)" in r.stderr and "logger -t secubox-waf-ng" in j
    assert "systemctl restart" not in j


def test_binaire_refuse_mais_rien_ne_tourne_on_essaie(tmp_path):
    r, _ = _verif(tmp_path, verifier=2, actif=False)
    assert r.returncode == 0 and "relancer=1" in r.stdout


@pytest.mark.parametrize("ligne", ["", "/usr/local/bin/enrobage /usr/sbin/sbxwaf --listen 127.0.0.1:8085"])
def test_execstart_inconnu_rien_a_verifier(tmp_path, ligne):
    r, j = _verif(tmp_path, ligne=ligne, verifier=2)
    assert r.returncode == 0 and "relancer=1" in r.stdout and "[" not in j


# ── surcharge locale signalée, jamais modifiée ───────────────────────────────

def _surcharge(tmp_path, ligne):
    return _lancer(tmp_path, _bloc("avertir") + _bloc("drapeaux de la surcharge"), ligne)


@pytest.mark.parametrize("fichier", [UNITE, PKG / "conf" / "honeypot.conf"])
def test_unite_et_modele_du_leurre_rien_a_signaler(tmp_path, fichier):
    r, j = _surcharge(tmp_path, _drapeaux(fichier))
    assert r.returncode == 0 and r.stderr == "" and "logger" not in j


def test_surcharge_en_retard_signalee(tmp_path):
    ligne = _drapeaux(PKG / "conf" / "honeypot.conf").replace(" --rotation propose", "").replace(" --rotation-verdict differe", "").replace("--nft-ban", "-nft-ban")
    r, j = _surcharge(tmp_path, ligne)
    assert r.returncode == 0
    assert ": --rotation --rotation-verdict —" in r.stderr and "--nft-ban" not in r.stderr and "honeypot.conf" in r.stderr
    assert "logger -t secubox-waf-ng -p daemon.warning" in j


def test_le_paquet_ne_touche_jamais_la_surcharge():
    for s in (POSTINST, COMPOSANT, PKG / "debian" / "preinst"):
        for ligne in s.read_text().splitlines():
            if "secubox-waf-ng.service.d" in ligne and not ligne.lstrip().startswith("#"):
                assert s.name == "preinst" and ligne.startswith("UNITES="), ligne    # lecture seule (plages protégées, #3450)


# ── démarrage de l'unité ─────────────────────────────────────────────────────

def test_le_cache_n_est_plus_recrit_en_entier_a_chaque_demarrage():
    t = UNITE.read_text()
    assert "chown -R secubox-waf:secubox-waf /var/cache/secubox/waf" not in t
    assert "! -user secubox-waf -o ! -group secubox-waf" in t


def test_le_postinst_attend_la_chaine_apres_le_port():
    t = POSTINST.read_text()
    assert t.index("127.0.0.1:8085 '") < t.index("nft list chain inet secubox waf_drop") and "for _i in 1 2 3" in t[t.index("--nft-ban'"):]


# ── CGNAT (100.64.0.0/10) : jamais banni par wafctl, toujours levable ────────

WAFCTL = PKG / "composants" / "waf" / "scripts" / "wafctl"


def _valide(ip, geste=""):
    t = WAFCTL.read_text()
    corps = t[t.index("_valide_ip() {"):t.index("# _secondes <durée>")]
    return subprocess.run(["bash", "-c", corps + f'\n_valide_ip "{ip}" {geste}'], check=False, capture_output=True, text=True, timeout=30)


@pytest.mark.parametrize("ip,ban,leve", [("100.64.0.1", 2, 0), ("100.127.255.255", 2, 0), ("100.63.255.255", 0, 0), ("100.128.0.1", 0, 0),
                                         ("192.168.1.1", 2, 2), ("203.0.113.7", 0, 0), ("2001:db8::1", 0, 0), ("x", 1, 1)])
def test_valide_ip_cgnat(ip, ban, leve):
    assert _valide(ip, "ban").returncode == ban and _valide(ip).returncode == leve


def test_les_bans_de_wafctl_refusent_le_cgnat_pas_les_levees():
    t = WAFCTL.read_text()
    for f, ban in (("cmd_ban", True), ("cmd_prolonger", True), ("cmd_limiter_lever", False), ("cmd_leurre_lever", False)):
        corps = t[t.index(f"{f}() {{"):]
        corps = corps[:corps.index("\n}\n")]
        assert ('_valide_ip "$ip" ban' in corps) is ban, f
    levee = t[t.index("WAFCTL_PY_IP='"):]
    assert "100.64" not in levee[:levee.index("\n'\n")]           # unban, unban-liste


def test_waf_blocs_refuse_le_cgnat():
    import importlib.machinery
    import importlib.util
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    ch = importlib.machinery.SourceFileLoader("waf_blocs_3932", str(PKG / "composants" / "waf" / "scripts" / "waf-blocs"))
    wb = importlib.util.module_from_spec(importlib.util.spec_from_loader("waf_blocs_3932", ch))
    ch.exec_module(wb)
    for cible, motif in (("100.64.0.1", "privee"), ("100.100.3.0/24", "privee"), ("100.63.255.0/24", None), ("100.128.0.1", None)):
        assert wb.motif_refus(wb.normaliser_cible(cible), [], set(), set()) == motif, cible
