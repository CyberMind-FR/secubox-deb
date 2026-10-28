# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3233 — seconde relecture de sécurité : clé USB finale (signature exigée, montage sûr, autoflash annoncé et annulable,
empreinte publiée, unité durcie) et mineurs du flux."""
import os
import subprocess
from pathlib import Path

ICI = Path(__file__).resolve().parents[1]
RACINE = ICI.parents[1]
CLE = ICI / "scripts" / "build-cle-finale.sh"
AUTO = ICI / "installer" / "sbx-autoflash"
UNITE = ICI / "installer" / "sbx-autoflash.service"
FLASH = RACINE / "image" / "sbin" / "secubox-flash-emmc"
NETFLASH = ICI / "installer" / "sbx-netflash"
LEGER = ICI / "scripts" / "build-live-leger.sh"
PAGE = ICI / "www" / "netboot" / "index.html"


def _auto(expr, entree=None):
    return subprocess.run(["bash", "-c", f'SBX_AUTOFLASH_SOURCE=1 source "$0"; {expr}', str(AUTO)],
                          input=entree, capture_output=True, text=True, timeout=60)


# ── I1 : jamais de signature implicite ──────────────────────────────────────────────────────────────────────────
def test_cle_finale_exige_une_signature_fournie_ou_explicite():
    s = CLE.read_text()
    assert "--signer-ici)" in s
    assert '[ -n "$sig" ] || [ "$signer_ici" -eq 1 ] || die' in s
    assert "cle-finale image=" in s and "sha256=" in s                   # audit de l'image, toujours


# ── I2 : l'image est une donnée non sûre ────────────────────────────────────────────────────────────────────────
def test_image_montee_sans_execution_et_sans_lien_sortant():
    s = CLE.read_text()
    assert s.count("-o nodev,nosuid,noexec") >= 3
    assert "refuse_liens" in s
    for chemin in ("etc", "etc/fstab", "etc/secubox", "etc/systemd/system", "usr/local/sbin"):
        assert chemin in s[s.index("refuse_liens() {"):s.index("refuse_liens() {") + 900], chemin


# ── I3 : autoflash annoncé, compte à rebours annulable ──────────────────────────────────────────────────────────
def test_autoflash_annulable_par_une_touche():
    assert _auto("attend_annulation 5", entree="x").returncode == 1


def test_autoflash_continue_sans_touche():
    r = subprocess.run(["bash", "-c", f'SBX_AUTOFLASH_SOURCE=1 source "$0"; attend_annulation 1 < <(sleep 3)', str(AUTO)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0


def test_autoflash_annonce_cible_contenu_et_empreinte():
    s = AUTO.read_text()
    m = s[s.index("main() {"):]
    assert "lsblk" in m and "box déjà installée" in m.lower() or "BOX DÉJÀ INSTALLÉE" in m
    assert m.index("attend_annulation") < m.index("secubox-flash-emmc --stdin")
    u = UNITE.read_text()
    assert "StandardInput=tty" in u and "TTYPath=/dev/@CONSOLE@" in u and "Before=getty.target" in u
    assert "@CONSOLE@" in CLE.read_text()


def test_autoflash_lit_sa_propre_partition_et_l_empreinte_gravee():
    s = AUTO.read_text()
    assert "LABEL=SBXFLASH" not in s                                      # jamais « la première clé venue »
    assert "PKNAME" in s and "/etc/secubox/autoflash.sha256" in s
    assert "autoflash.sha256" in CLE.read_text()


# ── I4 : empreinte publiée, vérification documentée ─────────────────────────────────────────────────────────────
def test_empreinte_et_cle_publique_publiees():
    s = CLE.read_text()
    assert "sha256\\t" in s and "netboot-image.pub" in s
    p = PAGE.read_text()
    assert "openssl dgst -sha256 -verify" in p and "usb.sha256" in p


# ── I5 : unité durcie, exception écrite ─────────────────────────────────────────────────────────────────────────
def test_unite_autoflash_durcie_et_exception_ecrite():
    u = UNITE.read_text()
    for o in ("ProtectSystem=strict", "UMask=0027", "ProtectKernelTunables=yes", "RestrictSUIDSGID=yes",
              "CapabilityBoundingSet=", "ReadWritePaths=/run/sbx-autoflash"):
        assert o in u, o
    regles = (RACINE / ".claude" / "RULES-CODE.md").read_text()
    assert "sbx-autoflash.service" in regles


# ── Mineurs ─────────────────────────────────────────────────────────────────────────────────────────────────────
def test_flux_trap_pose_avant_la_tache_et_dd_final_remplace_le_sous_shell():
    s = FLASH.read_text()
    f = s[s.index("ecrit_flux_verifie() {"):s.index("# Chargeable sans exécuter")]
    assert f.index("trap ") < f.index(") 0<&0 &")
    assert 'exec dd of="$1"' in s
    assert "rc=3" in f[f.index("trap "):f.index(") 0<&0 &")]           # le trap distingue l'invalidation ratée


def test_flash_refuse_une_emmc_dont_une_partition_est_montee():
    s = FLASH.read_text()
    assert "MOUNTPOINTS" in s


def test_sonde_bornee_et_repli_wget():
    s = NETFLASH.read_text()
    assert "curl -fsSI --connect-timeout 20 --max-time 30" in s and "wget -q --spider" in s
    assert "tr ' ' '\\n' <<<\"$CMDLINE\"" in s


def test_cle_finale_carte_publication_atomique_et_place():
    s = CLE.read_text()
    assert '[ "$carte" = espressobin-v7 ] || die' in s
    assert "[[:space:]]" in s                                             # fstab : espaces ou tabulations
    assert "df --output=avail" in s
    assert '.tmp" "$h/cle-usb.img.gz"' in s or 'mv -f "$h/cle-usb.img.gz.sig.tmp"' in s


def test_live_avec_mises_a_jour_de_securite():
    assert "-security" in LEGER.read_text()


def test_suggests_complets():
    c = (ICI / "debian" / "control").read_text()
    assert "openssh-client" in c and "binfmt-support" in c


def test_api_recoupe_role_et_commande():
    s = (ICI / "api" / "main.py").read_text()
    assert "boot-usb.scr" in s and "autoflash.scr" in s
    assert "is_symlink()" in s[s.index("def _cle_usb"):s.index("def live_infos")]
