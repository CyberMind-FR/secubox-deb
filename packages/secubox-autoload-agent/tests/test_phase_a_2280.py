# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2280 — Auto-Load phase A : jeton installé depuis /boot, unité de premier démarrage, atelier qui compose, valide et signe, trousseau livré."""
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RACINE))
sys.path.insert(0, str(RACINE.parent / "secubox-premier-pas"))

from autoload_agent import atelier as A, demarrage as D  # noqa: E402

JETON = "gk2_" + "0123456789abcdef" * 2
EXEMPLE = RACINE.parent / "secubox-premier-pas" / "exemples" / "reponses-autoload.toml"


# ── Installation du jeton au démarrage ───────────────────────────────────────────────────────────────────────────────────────────────────────
def test_le_jeton_est_installe_en_0600_puis_efface_de_boot(tmp_path):
    src, dest = tmp_path / "boot" / "jeton", tmp_path / "secrets" / "autoload-jeton"
    src.parent.mkdir()
    src.write_text(JETON + "\n")
    assert D.installer_jeton(src, dest) == "installe"
    assert dest.read_text().strip() == JETON and stat.S_IMODE(dest.stat().st_mode) == 0o600
    assert not src.exists()                                     # le jeton ne reste pas sur la partition de démarrage, lisible par tous


@pytest.mark.parametrize("mauvais", ["", "gk2_court", "GK2_" + "0" * 32, "gk2_" + "z" * 32, JETON + "\nautre", "gk2_" + "0" * 32 + " x"])
def test_un_jeton_mal_forme_n_est_jamais_installe(tmp_path, mauvais):
    src, dest = tmp_path / "jeton", tmp_path / "secrets" / "autoload-jeton"
    src.write_text(mauvais)
    assert D.installer_jeton(src, dest) == "refuse" and not dest.exists()


def test_sans_jeton_sur_boot_rien_ne_change_et_un_jeton_deja_installe_est_conserve(tmp_path):
    dest = tmp_path / "secrets" / "autoload-jeton"
    assert D.installer_jeton(tmp_path / "absent", dest) == "absent"
    dest.parent.mkdir()
    dest.write_text("gk2_" + "a" * 32 + "\n")
    os.chmod(dest, 0o600)
    src = tmp_path / "jeton"
    src.write_text(JETON)
    assert D.installer_jeton(src, dest) == "deja_present"
    assert dest.read_text().strip() == "gk2_" + "a" * 32       # la reprise ne remplace pas le jeton d'un enrôlement en cours
    assert not src.exists()                                     # mais la copie sur /boot disparaît


def test_un_lien_symbolique_n_est_jamais_suivi(tmp_path):
    cible = tmp_path / "ailleurs"
    cible.write_text(JETON)
    src = tmp_path / "jeton"
    src.symlink_to(cible)
    assert D.installer_jeton(src, tmp_path / "s" / "autoload-jeton") == "refuse"
    assert cible.exists()                                       # ni lu, ni effacé


# ── Unité de premier démarrage ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
UNITE = (RACINE / "systemd" / "secubox-autoload-agent.service").read_text()


def test_l_unite_ne_demarre_que_avec_un_fichier_de_reponses_et_pas_deux_fois():
    assert "ConditionPathExists=/boot/secubox/autoload/reponses.toml" in UNITE
    assert "ConditionPathExists=!/var/lib/secubox/autoload-agent/rapport.json" in UNITE      # un parcours terminé ne recommence pas
    assert "ConditionPathExists=/usr/share/secubox/autoload/provisioning.gpg" in UNITE        # pas de trousseau, pas de démarrage


def test_l_unite_attend_le_reseau_installe_le_jeton_puis_lance_le_parcours():
    assert "Wants=network-online.target" in UNITE and "After=network-online.target" in UNITE
    assert re.search(r"^ExecStartPre=/usr/sbin/autoload-agent-demarrage$", UNITE, re.M)
    assert re.search(r"^ExecStart=/usr/sbin/autoload-agentctl run$", UNITE, re.M)


def test_l_unite_reprend_apres_un_echec_sans_boucler_et_n_a_pas_de_delai_de_demarrage():
    assert "Restart=on-failure" in UNITE and re.search(r"^RestartSec=\d+", UNITE, re.M)
    assert re.search(r"^StartLimitBurst=\d+", UNITE, re.M) and "StartLimitIntervalSec=" in UNITE
    assert "TimeoutStartSec=infinity" in UNITE                  # le délai de grâce zero-touch peut durer jusqu'à 24 h


def test_l_unite_est_durcie_autant_que_root_le_permet():
    for d in ("NoNewPrivileges=true", "ProtectHome=true", "PrivateTmp=true", "ProtectKernelModules=true", "RestrictNamespaces=true", "LockPersonality=true"):
        assert d in UNITE, d
    assert "User=" not in UNITE or "User=root" in UNITE         # apt, wg et profilectl exigent root : le durcissement compense


def test_l_unite_ne_s_active_qu_au_demarrage_normal():
    assert "WantedBy=multi-user.target" in UNITE


# ── Atelier : composer, valider, signer, écrire ──────────────────────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def gnupg(tmp_path):
    home = tmp_path / "gnupg"
    pub = tmp_path / "provisioning.gpg"
    fpr = A.cle_init(home, pub)
    return home, pub, fpr


def test_cle_init_cree_une_cle_privee_0700_et_exporte_la_publique(gnupg):
    home, pub, fpr = gnupg
    assert stat.S_IMODE(home.stat().st_mode) == 0o700 and re.fullmatch(r"[0-9A-F]{40}", fpr)
    sortie = subprocess.run(["gpg", "--show-keys", "--with-colons", str(pub)], capture_output=True, text=True).stdout
    assert "SecuBox Provisioning" in sortie and "sec:" not in sortie       # la partie privée ne sort jamais
    with pytest.raises(A.AtelierErreur):
        A.cle_init(home, pub)                                              # jamais d'écrasement d'une clé existante


def test_preparer_ecrit_reponses_signature_et_jeton_et_la_box_les_accepte(tmp_path, gnupg):
    home, pub, _ = gnupg
    boot = tmp_path / "boot"
    boot.mkdir()
    A.preparer(EXEMPLE, boot, home, pub, jeton=JETON)
    dossier = boot / "secubox" / "autoload"
    assert (dossier / "reponses.toml").is_file() and (dossier / "reponses.toml.sig").is_file()
    assert stat.S_IMODE((dossier / "jeton").stat().st_mode) == 0o600 and (dossier / "jeton").read_text().strip() == JETON
    # ce que fait la box : validation stricte + signature contre SON trousseau
    from premier_pas import provision as PV
    PV.charger_signe(dossier / "reponses.toml", dossier / "reponses.toml.sig", pub)


def test_un_fichier_modifie_apres_signature_est_refuse_par_la_box(tmp_path, gnupg):
    home, pub, _ = gnupg
    boot = tmp_path / "boot"
    boot.mkdir()
    A.preparer(EXEMPLE, boot, home, pub, jeton=JETON)
    f = boot / "secubox" / "autoload" / "reponses.toml"
    f.write_text(f.read_text().replace('profil = "lite"', 'profil = "full"'))
    from premier_pas import provision as PV
    with pytest.raises(PV.SignatureInvalide):
        PV.charger_signe(f, f.with_name("reponses.toml.sig"), pub)


def test_une_signature_d_une_autre_cle_est_refusee(tmp_path, gnupg):
    home, pub, _ = gnupg
    autre_home, autre_pub = tmp_path / "autre", tmp_path / "autre.gpg"
    A.cle_init(autre_home, autre_pub)
    boot = tmp_path / "boot"
    boot.mkdir()
    A.preparer(EXEMPLE, boot, autre_home, autre_pub, jeton=JETON)             # signé par un inconnu
    f = boot / "secubox" / "autoload" / "reponses.toml"
    from premier_pas import provision as PV
    with pytest.raises(PV.SignatureInvalide):
        PV.charger_signe(f, f.with_name("reponses.toml.sig"), pub)             # la box ne connaît que SA clé


def test_preparer_refuse_un_fichier_invalide_avant_de_signer(tmp_path, gnupg):
    home, pub, _ = gnupg
    mauvais = tmp_path / "r.toml"
    mauvais.write_text(EXEMPLE.read_text().replace("[box]", "[inconnue]\nx = 1\n\n[box]"))
    boot = tmp_path / "boot"
    boot.mkdir()
    with pytest.raises(A.AtelierErreur):
        A.preparer(mauvais, boot, home, pub, jeton=JETON)
    assert not (boot / "secubox").exists()                                    # rien n'est écrit, rien n'est signé


def test_preparer_exige_la_reference_de_jeton_que_l_agent_installe(tmp_path, gnupg):
    home, pub, _ = gnupg
    autre = tmp_path / "r.toml"
    autre.write_text(EXEMPLE.read_text().replace("ref:/etc/secubox/secrets/autoload-jeton", "ref:/etc/secubox/secrets/autre"))
    boot = tmp_path / "boot"
    boot.mkdir()
    with pytest.raises(A.AtelierErreur):
        A.preparer(autre, boot, home, pub, jeton=JETON)


def test_preparer_refuse_un_jeton_mal_forme_et_ne_l_affiche_jamais(tmp_path, gnupg, capsys):
    home, pub, _ = gnupg
    boot = tmp_path / "boot"
    boot.mkdir()
    with pytest.raises(A.AtelierErreur):
        A.preparer(EXEMPLE, boot, home, pub, jeton="gk2_trop_court")
    A.preparer(EXEMPLE, boot, home, pub, jeton=JETON)
    assert JETON not in capsys.readouterr().out


def test_le_trousseau_livre_par_le_paquet_est_une_cle_publique_secubox_provisioning():
    ring = RACINE / "keyring" / "provisioning.gpg"
    assert ring.is_file(), "le paquet doit livrer le trousseau, sinon l'agent refuse tout"
    sortie = subprocess.run(["gpg", "--show-keys", "--with-colons", str(ring)], capture_output=True, text=True).stdout
    assert "SecuBox Provisioning" in sortie and "sec:" not in sortie and "ssb:" not in sortie       # aucune partie privée dans le dépôt


def test_le_paquet_installe_unite_scripts_trousseau_et_dossier_de_boot():
    rules = (RACINE / "debian" / "rules").read_text()
    for chemin in ("secubox-autoload-agent.service", "autoload-agent-demarrage", "autoload-atelier", "keyring/provisioning.gpg", "usr/share/secubox/autoload"):
        assert chemin in rules, chemin
    postinst = (RACINE / "debian" / "postinst").read_text()
    assert "/boot/secubox/autoload" in postinst and "systemctl enable secubox-autoload-agent.service" in postinst
    assert "gpgv" in (RACINE / "debian" / "control").read_text() and "gnupg" in (RACINE / "debian" / "control").read_text()
