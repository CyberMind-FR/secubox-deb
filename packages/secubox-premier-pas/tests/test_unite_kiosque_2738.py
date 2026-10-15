# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2738 — le kiosque d'une box RPi passe par le lanceur (URL d'administration, assistant prioritaire), pas par l'ancienne unité `startx`.

CONSTAT (RPi400, 2026-10-15, SSH) : `/etc/systemd/system/secubox-kiosk.service`, écrite par build-rpi-usb.sh, lançait `startx -- :0 vt7` et un `.xinitrc` à
`http://localhost/`. Le lanceur moderne n'était utilisé que lancé à la main depuis `tty1` : Chromium tournait hors de systemd (unité « inactive (dead) »), sans
redémarrage possible. Le paquet livrait le lanceur (#1542) mais pas l'unité."""
import subprocess
from pathlib import Path


PKG = Path(__file__).resolve().parents[1]
RACINE = PKG.parents[1]
UNITE_IMAGE = RACINE / "image" / "systemd" / "secubox-kiosk.service"
AIDE = PKG / "sbin" / "premier-pas-retire-unite-kiosque"

# L'unité que build-rpi-usb.sh écrivait (copie de ce qu'a trouvé la box).
UNITE_STARTX = """[Unit]
Description=SecuBox Kiosk (chromium fullscreen → http://127.0.0.1/)
After=multi-user.target network-online.target
Wants=network-online.target
Conflicts=getty@tty7.service

[Service]
Type=simple
User=root
Environment=HOME=/root
ExecStart=/usr/bin/startx -- :0 vt7
Restart=on-failure
RestartSec=5
StandardInput=tty
StandardOutput=tty
TTYPath=/dev/tty7
TTYReset=yes
TTYVHangup=yes

[Install]
WantedBy=graphical.target
"""


# ---------- l'unité livrée par le paquet ----------

def test_le_paquet_livre_l_unite_du_lanceur_depuis_la_source_unique_de_l_image():
    lien = PKG / "kiosque" / "secubox-kiosk.service"
    assert lien.is_symlink() and lien.resolve() == UNITE_IMAGE.resolve(), "une seule source : image/systemd/, jamais une copie"
    texte = UNITE_IMAGE.read_text()
    assert "ExecStart=/usr/sbin/secubox-kiosk-launcher" in texte and "startx" not in texte


def test_les_regles_installent_l_unite_et_l_aide():
    rules = (PKG / "debian" / "rules").read_text()
    assert "kiosque/secubox-kiosk.service" in rules and "usr/lib/systemd/system/secubox-kiosk.service" in rules
    assert "premier-pas-retire-unite-kiosque" in rules


# ---------- retirer SEULEMENT l'unité périmée ----------

def lance(unite: Path):
    return subprocess.run(["sh", str(AIDE), str(unite)], capture_output=True, text=True)


def test_l_unite_startx_de_l_image_est_retiree_et_le_dit(tmp_path):
    u = tmp_path / "secubox-kiosk.service"
    u.write_text(UNITE_STARTX)
    r = lance(u)
    assert r.returncode == 10 and not u.exists(), (r.returncode, r.stdout, r.stderr)


def test_une_unite_qui_appelle_le_lanceur_est_conservee(tmp_path):
    u = tmp_path / "secubox-kiosk.service"
    u.write_text("[Service]\nExecStart=/usr/sbin/secubox-kiosk-launcher\n")
    r = lance(u)
    assert r.returncode == 0 and u.exists()


def test_une_unite_d_operateur_est_conservee(tmp_path):
    """Un `startx` sans la description de l'image, ou une autre commande : ce n'est pas la nôtre, on n'y touche pas."""
    for texte in ("[Service]\nExecStart=/usr/bin/startx -- :0 vt7\n", "[Unit]\nDescription=Mon kiosque\n[Service]\nExecStart=/opt/mon-kiosque\n"):
        u = tmp_path / "secubox-kiosk.service"
        u.write_text(texte)
        r = lance(u)
        assert r.returncode == 0 and u.exists(), texte
        u.unlink()


def test_pas_d_unite_pas_d_erreur(tmp_path):
    assert lance(tmp_path / "absente.service").returncode == 0


def test_l_unite_retiree_ne_contient_pas_de_demande_a_l_operateur():
    """Le script tourne dans un postinst : jamais interactif."""
    assert "read " not in AIDE.read_text().replace("# ", "")


# ---------- le postinst ----------

POST = (PKG / "debian" / "postinst").read_text()


def bloc_kiosque():
    d = POST.index("    # KIOSQUE : l'ancienne unité")
    f = POST.index("    systemctl enable secubox-premier-pas.service")
    return POST[d:f]


def execute_bloc(tmp_path, avec_unite_perimee=False, lien_orphelin=False):
    """Exécute le VRAI bloc du postinst sous `set -e`, avec un faux systemctl : c'est `set -e` qui a fait échouer le premier essai sur le RPi400 (l'aide rend 10)."""
    sysd = tmp_path / "etc-systemd"
    (sysd / "graphical.target.wants").mkdir(parents=True)
    if avec_unite_perimee:
        (sysd / "secubox-kiosk.service").write_text(UNITE_STARTX)
        (sysd / "graphical.target.wants" / "secubox-kiosk.service").symlink_to("../secubox-kiosk.service")
    if lien_orphelin:
        (sysd / "graphical.target.wants" / "secubox-kiosk.service").symlink_to("../secubox-kiosk.service")
    journal = tmp_path / "systemctl.log"
    faux = tmp_path / "bin"
    faux.mkdir()
    (faux / "systemctl").write_text(f"#!/bin/sh\necho \"$*\" >> {journal}\ncase \"$1\" in is-enabled|is-active) exit 0;; esac\nexit 0\n")
    (faux / "systemctl").chmod(0o755)
    script = tmp_path / "bloc.sh"
    script.write_text("set -e\n" + bloc_kiosque() + "echo FIN\n")
    r = subprocess.run(["sh", str(script)], capture_output=True, text=True,
                       env={"PATH": f"{faux}:/usr/bin:/bin", "PREMIER_PAS_SYSTEMD_ETC": str(sysd), "PREMIER_PAS_RETIRE_UNITE": str(AIDE)})
    return r, sysd, (journal.read_text() if journal.exists() else "")


def test_le_postinst_ne_s_arrete_pas_quand_l_aide_rend_10(tmp_path):
    """RÉGRESSION RPi400 : sous `set -e`, le code 10 (« unité retirée ») faisait échouer toute la configuration du paquet."""
    r, sysd, appels = execute_bloc(tmp_path, avec_unite_perimee=True)
    assert r.returncode == 0 and "FIN" in r.stdout, (r.returncode, r.stdout, r.stderr)
    assert not (sysd / "secubox-kiosk.service").exists()
    assert not (sysd / "graphical.target.wants" / "secubox-kiosk.service").is_symlink(), "le lien d'activation orphelin doit être remplacé"
    lignes = appels.splitlines()
    assert "daemon-reload" in lignes and "enable secubox-kiosk.service" in lignes and "restart secubox-kiosk.service" in lignes


def test_un_lien_orphelin_laisse_par_un_essai_interrompu_est_traite_meme_sans_unite(tmp_path):
    r, sysd, appels = execute_bloc(tmp_path, lien_orphelin=True)
    assert r.returncode == 0 and "FIN" in r.stdout
    assert not (sysd / "graphical.target.wants" / "secubox-kiosk.service").is_symlink()
    assert "enable secubox-kiosk.service" in appels.splitlines() and "restart secubox-kiosk.service" in appels.splitlines()


def test_rien_a_faire_sur_une_box_deja_a_jour(tmp_path):
    r, _, appels = execute_bloc(tmp_path)
    assert r.returncode == 0 and "FIN" in r.stdout
    assert "daemon-reload" not in appels and "restart secubox-kiosk.service" not in appels.splitlines()


def test_postinst_et_aide_sont_du_shell_valide():
    assert subprocess.run(["sh", "-n", str(PKG / "debian" / "postinst")]).returncode == 0
    assert subprocess.run(["sh", "-n", str(AIDE)]).returncode == 0
    assert "graphical.target.wants/secubox-kiosk.service" in POST and "systemctl enable secubox-kiosk.service" in POST


# ---------- le constructeur d'image RPi ----------

BUILDER = (RACINE / "image" / "build-rpi-usb.sh").read_text()


def test_le_constructeur_rpi_n_ecrit_plus_l_unite_startx():
    assert "ExecStart=/usr/bin/startx -- :0 vt7" not in BUILDER
    assert 'systemd/secubox-kiosk.service' in BUILDER and "${ROOTFS}/etc/systemd/system/secubox-kiosk.service" in BUILDER
    assert subprocess.run(["bash", "-n", str(RACINE / "image" / "build-rpi-usb.sh")]).returncode == 0
