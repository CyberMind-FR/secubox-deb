# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3716, tâche 5 : paquets (versions, dépendance), installation de waf-blocs et de ses unités, postinst (plages
protégées semées sans rien écraser, tmpfiles avant les unités, rejeu et veille activés, profil AppArmor en complain),
routes /ai/* servies par le seul agrégateur, documentation."""
import importlib.machinery
import importlib.util
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

PAQUET = Path(__file__).resolve().parents[1]
DEPOT = PAQUET.parents[1]
CHANGELOG_WAF = PAQUET / "debian" / "changelog"
CONTROL_WAF = PAQUET / "debian" / "control"
CHANGELOG_CORE = DEPOT / "packages" / "secubox-core" / "debian" / "changelog"
RULES = PAQUET / "debian" / "rules"
POSTINST = PAQUET / "debian" / "postinst"
README = PAQUET / "README.md"
README_COMPOSANT = PAQUET / "composants" / "waf" / "README.md"
WIKI = DEPOT / "wiki" / "WAF-FR.md"
PROFIL = PAQUET / "apparmor" / "usr.sbin.waf-blocs"
DROPIN = PAQUET / "systemd" / "secubox-aggregator-gestes-ia.conf"
UNITE_API = PAQUET / "composants" / "waf" / "debian" / "secubox-waf.service"
UNITE_AGREGATEUR = DEPOT / "packages" / "secubox-aggregator" / "systemd" / "secubox-aggregator.service"
WAF_BLOCS = PAQUET / "composants" / "waf" / "scripts" / "waf-blocs"


def _configure():
    """Le corps de `configure)` du postinst (jusqu'au `;;` qui le ferme), sans le reste."""
    t = POSTINST.read_text()
    debut = t.index("  configure)")
    return t[debut:t.index("\n    ;;\n", debut)]


# ── versions, dépendance, installation ─────────────────────────────────
def test_versions_et_dependance():
    assert CHANGELOG_WAF.read_text().startswith("secubox-waf-ng (1.35.0-1~trixie1) trixie;")
    assert "secubox-core (>= 1.8.32~)" in CONTROL_WAF.read_text()
    assert CHANGELOG_CORE.read_text().startswith("secubox-core (1.8.32-1~trixie1) trixie;")


def test_changelogs_dates_du_jour_et_issue():
    for chemin in (CHANGELOG_WAF, CHANGELOG_CORE):
        entree = chemin.read_text().split("\n\n -- ", 1)
        assert "(ref #3716)" in entree[0] and "closes" not in entree[0].lower()
        assert re.match(r"Gérald Kerma <devel@cybermind\.fr>  Sat, 14 Nov 2026 \d\d:\d\d:\d\d \+0100\n", entree[1])


def test_rules_installe_waf_blocs_et_l_unite():
    r = RULES.read_text()
    assert "waf-blocs" in r and "secubox-waf-blocs" in r


def test_rules_installe_profil_et_dropin():
    r = RULES.read_text()
    assert re.search(r"install -D -m 0644 apparmor/usr\.sbin\.waf-blocs\s+\\\s*\n\s*"
                     r"debian/secubox-waf-ng/etc/apparmor\.d/usr\.sbin\.waf-blocs", r)
    assert re.search(r"install -D -m 0644 systemd/secubox-aggregator-gestes-ia\.conf\s+\\\s*\n\s*debian/secubox-waf-ng/"
                     r"usr/lib/systemd/system/secubox-aggregator\.service\.d/secubox-waf-gestes-ia\.conf", r)


# ── documentation ──────────────────────────────────────────────────────
def test_readme_documente_ai_ban():
    t = README.read_text()
    assert "/ai/ban" in t and "cle-ai-ban" in t and "secubox_waf_blocs" in t
    for mot in ("/ai/unban", "/ai/etat", "ban-bloc", "unban-bloc", "wafctl blocs", "protegees.env",
                "SECUBOX_WAF_GESTES_IA", "retirer --toutes"):
        assert mot in t, mot


def test_readme_composant_et_wiki():
    c = README_COMPOSANT.read_text()
    for route in ("POST /api/v1/waf/ai/ban", "POST /api/v1/waf/ai/unban", "GET /api/v1/waf/ai/etat"):
        assert route in c, route
    w = WIKI.read_text()
    assert "## Bans de bloc et compte ai-ban" in w
    assert "secubox_waf_blocs" in w and "cle-ai-ban" in w


# ── plages protégées : semées sans jamais rien écraser ─────────────────
def _semer(tmp_path, cible):
    t = POSTINST.read_text()
    bloc = t[t.index("# >>> plages protégées (#3716)"):t.index("# <<< plages protégées (#3716)")]
    subprocess.run(["sh", "-euc", bloc], check=True, timeout=10,
                   env={"PATH": "/usr/bin:/bin", "WAF_PROTEGEES_ENV": str(cible)})


def _waf_blocs():
    chargeur = importlib.machinery.SourceFileLoader("waf_blocs_paquet", str(WAF_BLOCS))
    spec = importlib.util.spec_from_loader("waf_blocs_paquet", chargeur)
    module = importlib.util.module_from_spec(spec)
    chargeur.exec_module(module)
    return module


def test_postinst_seme_un_fichier_commente_qui_refuse_les_blocs(tmp_path):
    env = tmp_path / "waf" / "protegees.env"
    env.parent.mkdir()
    _semer(tmp_path, env)
    texte = env.read_text()
    assert stat.S_IMODE(env.stat().st_mode) == 0o644
    utiles = [x for x in texte.splitlines() if x.strip() and not x.lstrip().startswith("#")]
    assert utiles == []                                          # rien n'est déclaré à la place de l'administrateur
    assert "SECUBOX_WAF_PROTEGEES=" in texte                      # il dit quoi écrire, en commentaire
    wb = _waf_blocs()
    assert wb.lire_protegees(env) == []                          # adresse seule : inchangée
    with pytest.raises(wb.GardeIllisible):                       # bloc : refusé tant que rien n'est déclaré (P2)
        wb.lire_protegees(env, exiger=True)


def test_postinst_n_ecrase_jamais_les_plages_de_la_box(tmp_path):
    env = tmp_path / "protegees.env"
    for contenu in ("SECUBOX_WAF_PROTEGEES=192.0.2.1/32,2001:db8::/48\n", "# notes de l'administrateur\n", ""):
        env.write_text(contenu)
        env.chmod(0o600)
        _semer(tmp_path, env)
        assert env.read_text() == contenu and stat.S_IMODE(env.stat().st_mode) == 0o600
    env.unlink()
    env.symlink_to(tmp_path / "ailleurs")                       # lien pendant : jamais suivi, jamais remplacé
    _semer(tmp_path, env)
    assert env.is_symlink() and not (tmp_path / "ailleurs").exists()


def test_postinst_seme_avant_tout_demarrage():
    c = _configure()
    assert c.index("# >>> plages protégées (#3716)") < c.index("systemctl restart secubox-waf-ng.service")


# ── tmpfiles avant les unités, rejeu et veille activés ─────────────────
def test_postinst_tmpfiles_avant_les_unites():
    c = _configure()
    i = c.index("systemd-tmpfiles --create secubox-waf-ng.conf")
    assert i < c.index("systemctl restart secubox-waf-ng.service")
    assert "/var/lib/secubox-waf-blocs" in c[i:i + 1200]          # le dossier d'état est vérifié, l'échec signalé
    assert POSTINST.read_text().index("#DEBHELPER#") > POSTINST.read_text().index(c)   # dh démarre les unités APRÈS


def test_postinst_active_le_rejeu_et_la_veille():
    c = _configure()
    boucle = re.search(r"for _u in ([^;]+); do\n\s+if deb-systemd-helper --quiet was-enabled", c).group(1).split()
    for unite in ("secubox-waf-blocs.service", "secubox-waf-blocs-veille.timer"):
        assert unite in boucle, unite
    r = RULES.read_text()
    assert "dh_installsystemd --name=secubox-waf-blocs\n" in r
    assert "dh_installsystemd --name=secubox-waf-blocs-veille.timer" in r


def test_postinst_demarre_la_veille_apres_les_dossiers():
    c = _configure()
    assert c.index("systemd-tmpfiles --create secubox-waf-ng.conf") < c.index("systemctl start secubox-waf-blocs-veille.timer")
    prerm = (PAQUET / "debian" / "prerm").read_text()
    assert re.search(r'if \[ "\$1" = "remove" \]; then\n\s+systemctl stop secubox-waf-blocs-veille\.timer', prerm)


def test_un_seul_marqueur_debhelper():
    """debhelper remplace CHAQUE occurrence du marqueur, commentaires compris : une seconde copie des extraits
    démarrerait les unités au milieu du postinst."""
    for script in ("postinst", "prerm", "preinst"):
        assert (PAQUET / "debian" / script).read_text().count("#DEBHELPER#") == 1, script


def test_postinst_ne_redemarre_jamais_l_agregateur():
    for ligne in POSTINST.read_text().splitlines():
        if "secubox-aggregator" in ligne and not ligne.lstrip().startswith("#"):
            assert not re.search(r"systemctl\s+(try-)?(restart|reload|start|stop|try-reload-or-restart)", ligne), ligne


def test_postinst_syntaxe():
    assert subprocess.run(["sh", "-n", str(POSTINST)], check=False, timeout=10).returncode == 0


# ── AppArmor de waf-blocs : complain jusqu'au banc gk6 ─────────────────
def test_profil_waf_blocs_en_complain_jusqu_au_banc():
    p = PROFIL.read_text()
    assert p.startswith("# SPDX-License-Identifier: LicenseRef-CMSD-1.0")
    assert re.search(r"^profile waf-blocs /usr/sbin/waf-blocs flags=\(complain\) \{", p, re.M)
    assert "enforce" in p and "gk6" in p                         # la bascule est écrite, avec sa condition
    for regle in ("/usr/sbin/nft ix,", "/usr/bin/ip ix,", "/usr/bin/wg ix,", "/etc/secubox/waf/protegees.env r,",
                  "/usr/share/secubox/waf/blocs.nft r,", "/var/lib/secubox-waf-blocs/ rk,",
                  "/var/log/secubox/audit.log a,", "capability net_admin,", "network netlink raw,",
                  "deny /etc/secubox/secrets/** rwklx,"):
        assert regle in p, regle
    assert "Ux" not in p and "/bin/sh" not in p and "/usr/bin/bash" not in p


def test_postinst_charge_le_profil_sans_l_imposer():
    c = _configure()
    assert "apparmor_parser -r /etc/apparmor.d/usr.sbin.waf-blocs" in c
    assert "aa-enforce /etc/apparmor.d/usr.sbin.waf-blocs" not in c


@pytest.mark.skipif(not shutil.which("apparmor_parser") or not Path("/etc/apparmor.d/abstractions/python").exists(),
                    reason="apparmor_parser et ses abstractions requis")
def test_profil_waf_blocs_compile():
    r = subprocess.run(["apparmor_parser", "-Q", "-K", "-T", str(PROFIL)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr


# ── /ai/* : UN seul processus, l'agrégateur ────────────────────────────
def test_seul_l_agregateur_porte_le_drapeau_des_gestes_ia():
    d = DROPIN.read_text()
    assert d.startswith("# SPDX-License-Identifier: LicenseRef-CMSD-1.0")
    assert re.search(r"^\[Service\]\nEnvironment=SECUBOX_WAF_GESTES_IA=1$", d, re.M)
    assert "SECUBOX_WAF_GESTES_IA" not in UNITE_API.read_text()   # l'unité de waf.sock les refuse
    assert re.search(r"--workers 1\b", UNITE_AGREGATEUR.read_text())   # une mémoire de rejeu, un processus
