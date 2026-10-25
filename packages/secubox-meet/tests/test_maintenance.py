# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Scripts de maintenance de secubox-meet (#3154), EXÉCUTÉS sur une racine simulée.

Les chemins absolus (/etc, /var, /usr/share/doc, /usr/lib/systemd, /sys) sont réécrits sous un dossier de test ;
systemctl, meetctl, adduser, id, getent, visudo, chown sont simulés (journal des appels), `install` est le vrai
programme, appelé sans -o/-g (pas de root) après journalisation de son argv complet."""
import re
import subprocess
from pathlib import Path

from conftest import _ecrire_exec

RACINE = Path(__file__).resolve().parents[1]
POSTINST = RACINE / "debian" / "postinst"
PRERM = RACINE / "debian" / "prerm"

# Parents partagés avec d'autres modules : jamais de mode ni de propriétaire imposé s'ils existent.
PARENTS = ("etc/secubox", "etc/secubox/secrets", "var/lib/secubox", "var/cache/secubox",
           "var/lib/secubox/ports-publics.d")


def _lancer(script: Path, tmp_path: Path, *args, prepare=None):
    """Exécute le script de maintenance sur <tmp>/racine ; renvoie (résultat, journal des appels, racine)."""
    r_ = tmp_path / "racine"
    r_.mkdir(exist_ok=True)
    if prepare:
        prepare(r_)
    texte = re.sub(r"(?<![\w./-])/(etc|var|usr/share/doc|usr/lib/systemd|sys)/",
                   lambda m: f"{r_}/{m.group(1)}/", script.read_text())
    copie = tmp_path / script.name
    copie.write_text(texte)
    journal = tmp_path / "journal"
    bin_ = tmp_path / "bin"
    bin_.mkdir(exist_ok=True)
    for nom in ("systemctl", "meetctl", "adduser", "getent", "visudo", "chown", "apparmor_parser", "id"):
        code = "exit 0"
        if nom == "systemctl":
            code = 'case "$1" in is-active) exit 3 ;; esac; exit 0'
        if nom == "meetctl":
            code = 'echo \'{"success": true}\'; exit 0'
        _ecrire_exec(bin_ / nom, f'#!/bin/bash\necho "{nom} $*" >> "{journal}"\n{code}\n')
    _ecrire_exec(bin_ / "install", f"""#!/bin/bash
echo "install $*" >> "{journal}"
a=()
while [ $# -gt 0 ]; do case "$1" in -o|-g) shift 2 ;; *) a+=("$1"); shift ;; esac; done
exec /usr/bin/install "${{a[@]}}"
""")
    interprete = "bash" if script.read_text().startswith("#!/bin/bash") else "sh"
    res = subprocess.run([interprete, str(copie), *args], capture_output=True, text=True, timeout=60,
                         env={"PATH": f"{bin_}:/usr/bin:/bin", "HOME": str(tmp_path)})
    appels = journal.read_text().splitlines() if journal.exists() else []
    return res, appels, r_


def _parents_existants(r_):
    for p in PARENTS:
        (r_ / p).mkdir(parents=True, exist_ok=True)
    for p in PARENTS:              # mode distinctif : 0751 (le vrai /etc/secubox/secrets est 751 root:secubox + ACL)
        (r_ / p).chmod(0o751)


def _mode(p: Path) -> int:
    return p.stat().st_mode & 0o777


# ── C1 : les parents partagés ne sont jamais resserrés ni réattribués ────────────────────────────────

def test_postinst_configure_ne_touche_pas_les_parents_partages_existants(tmp_path):
    res, appels, r_ = _lancer(POSTINST, tmp_path, "configure", prepare=_parents_existants)
    assert res.returncode == 0, res.stderr
    for p in PARENTS:
        assert _mode(r_ / p) == 0o751, p
    cibles = [a.split()[-1] for a in appels if a.startswith(("install ", "chown ", "chmod "))]
    for p in PARENTS:
        assert str(r_ / p) not in cibles, p
    # Seules les feuilles du module sont créées (et resserrées) : secrets/meet en 0700.
    assert _mode(r_ / "etc/secubox/secrets/meet") == 0o700
    assert (r_ / "etc/secubox/meet").is_dir() and (r_ / "var/cache/secubox/meet").is_dir()


def test_postinst_configure_cree_les_parents_absents_dans_l_etat_du_socle(tmp_path):
    res, appels, r_ = _lancer(POSTINST, tmp_path, "configure")
    assert res.returncode == 0, res.stderr
    secrets = str(r_ / "etc/secubox/secrets")
    assert f"install -d -o root -g secubox -m 0750 {secrets}" in appels
    assert _mode(r_ / "etc/secubox/secrets") == 0o750
    assert not any(a.startswith("install") and a.endswith(" " + str(r_ / "etc/secubox")) and "root -g root" in a
                   for a in appels)


def test_postinst_aucune_commande_ne_vise_un_parent_partage_hors_garde():
    """Analyse du texte : toute commande qui nomme un parent partagé est gardée par `[ -d <parent> ] ||`."""
    parents = ["/" + p for p in PARENTS] + ["/run/secubox"]
    for ligne in POSTINST.read_text().splitlines():
        code = ligne.split(" #", 1)[0]
        if ligne.lstrip().startswith("#") or not re.search(r"\b(install|chown|chmod|chgrp|mkdir|setfacl)\b", code):
            continue
        for p in parents:
            if re.search(re.escape(p) + r"(?=$|[\s;\"'])", code):
                assert re.match(r"\s*\[ -d " + re.escape(p) + r" \] \|\| install -d ", code), ligne


# ── I2 : une mise à jour relance le rendu en arrière-plan ; I3 : une réinstallation réarme l'autostart ──

def _provisionne(r_):
    (r_ / "etc/secubox/meet").mkdir(parents=True)
    (r_ / "etc/secubox/meet/.lxc-provisioned").write_text("2026-10-25\n")


def test_postinst_mise_a_jour_relance_le_rendu_sans_bloquer(tmp_path):
    res, appels, _ = _lancer(POSTINST, tmp_path, "configure", "0.1.0-1~trixie1", prepare=_provisionne)
    assert res.returncode == 0, res.stderr
    assert "systemctl start --no-block secubox-meet-rerendu.service" in appels
    assert not any("secubox-meet-rerendu" in a and "--no-block" not in a and " start " in f" {a} " for a in appels)


def test_postinst_reinstallation_rearme_l_autostart_et_demarre_le_conteneur(tmp_path):
    res, appels, _ = _lancer(POSTINST, tmp_path, "configure", "0.1.0-1~trixie1", prepare=_provisionne)
    assert res.returncode == 0, res.stderr
    assert appels.index("meetctl autostart on") < appels.index("meetctl start")


def test_postinst_premiere_installation_ni_rerendu_ni_autostart(tmp_path):
    res, appels, _ = _lancer(POSTINST, tmp_path, "configure")
    assert res.returncode == 0, res.stderr
    assert not any("rerendu" in a for a in appels) and not any(a.startswith("meetctl") for a in appels)
    assert "systemctl start --no-block secubox-meet-provision.service" in appels


def test_postinst_mise_a_jour_sans_sentinelle_laisse_faire_le_provisionnement(tmp_path):
    res, appels, _ = _lancer(POSTINST, tmp_path, "configure", "0.1.0-1~trixie1")
    assert res.returncode == 0, res.stderr
    assert not any("rerendu" in a for a in appels) and "meetctl autostart on" not in appels


def test_postinst_rerendu_apres_le_bloc_debhelper():
    t = POSTINST.read_text()
    assert t.index("#DEBHELPER" + "#") < t.index("secubox-meet-rerendu.service") < t.rindex("exit 0")
    assert t.index("#DEBHELPER" + "#") < t.index("meetctl autostart on")


def test_unite_de_rerendu_oneshot_sans_condition():
    u = (RACINE / "debian" / "secubox-meet-rerendu.service").read_text()
    assert "Type=oneshot" in u and "ExecStart=/usr/lib/secubox/meet/install-lxc.sh" in u
    assert "ConditionPathExists" not in u and "[Install]" not in u and "SPDX-License-Identifier" in u


def test_prerm_remove_coupe_l_autostart_desactive_et_arrete(tmp_path):
    res, appels, _ = _lancer(PRERM, tmp_path, "remove")
    assert res.returncode == 0, res.stderr
    assert appels.index("meetctl autostart off") < appels.index("meetctl stop")
    desactive = [a for a in appels if a.startswith("systemctl disable")]
    assert desactive and "secubox-meet-provision.service" in desactive[0] and "secubox-meet.service" in desactive[0]
    assert any(a.startswith("systemctl stop") and "secubox-meet-rerendu.service" in a for a in appels)


def test_prerm_mise_a_jour_ne_coupe_rien(tmp_path):
    res, appels, _ = _lancer(PRERM, tmp_path, "upgrade", "0.1.1-1~trixie1")
    assert res.returncode == 0, res.stderr
    assert "meetctl autostart off" not in appels and not any(a.startswith("systemctl disable") for a in appels)
