# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Garde des ports de backend (#1306) : lecture de la règle livrée et des écoutes."""
import importlib.util
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "wan_guard", Path(__file__).parent.parent / "api" / "wan_guard.py")
wg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wg)

LIVREE = Path(__file__).parent.parent / "nft" / "secubox-wan-guard.nft"


def test_regle_livree_lue():
    iface, ports = wg.ports_gardes(LIVREE.read_text())
    assert iface == "eth2"
    assert {8088, 8900, 9080, 8910} <= set(ports)
    assert not set(ports) & wg.LEURRES            # leurres OUVERTS (#3728) : ils doivent pouvoir être touchés
    assert 445 not in ports                       # vrai SMB, cantonné par secubox-smb
    assert not set(ports) & wg.FRONTAUX          # jamais couper SSH / HAProxy


def test_commentaires_ignores():
    assert wg.ports_gardes('# iifname "eth2" tcp dport { 1 } drop') == ("", [])


def test_ecoutes_hors_boucle_locale():
    ss = ("LISTEN 0 511 0.0.0.0:8088 0.0.0.0:*\n"
          "LISTEN 0 511 127.0.0.1:8085 0.0.0.0:*\n"
          "LISTEN 0 511 [::]:9080 [::]:*\n"
          "LISTEN 0 511 [::1]:3000 [::]:*\n")
    assert wg.ports_en_ecoute(ss) == {8088: "0.0.0.0", 9080: "::"}


def test_tunnels_non_signales():
    assert wg.joignable_depuis_lan("0.0.0.0") and wg.joignable_depuis_lan("192.168.1.200")
    assert not wg.joignable_depuis_lan("10.99.1.1") and not wg.joignable_depuis_lan("192.168.255.1")


BASE = Path(__file__).parent.parent / "nft" / "nftables.conf"


def test_base_geree_sans_interface_en_dur():
    texte = BASE.read_text()
    assert "SecuBox-managed: secubox-hardening" in texte     # marqueur de la postinst
    assert "table inet filter" in texte                      # les fragments nftables.d y ajoutent des règles
    assert "policy drop" in texte
    # Aucune interface de confiance en dur : elles viennent de nft-input-trust.d.
    assert not [l for l in texte.splitlines() if l.strip().startswith('iif "')]
    assert 'nft-site.d' in texte                              # NAT propre à la box
    for port in ('51820', '51822', '8799', 'udp dport 68', 'ipv6-icmp'):   # héritage firstboot / gk3
        assert port in texte
    assert "nft-input-trust.d" in texte
    assert 'include "/etc/nftables.d/*.nft"' in texte


def test_jonction_du_maillage_ouverte_au_lan_fermee_a_internet():
    # #3103 : eth2 de gk2 porte le WAN ET le LAN (réseau de la Freebox). 7331 dans la liste coupée rendait toute
    # jonction au maillage impossible depuis le LAN (gk1 : curl 000, sbx-mesh-join en échec).
    texte = LIVREE.read_text()
    _, ports = wg.ports_gardes(texte)
    assert 7331 not in ports
    regles = [l.strip() for l in texte.splitlines() if "7331" in l and not l.lstrip().startswith("#")]
    v4 = [l for l in regles if "ip saddr !=" in l]
    assert v4, "7331 doit rester coupé sur eth2 pour les adresses non privées"
    for reseau in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
        assert reseau in v4[0]
    assert "drop" in v4[0]
    assert any("nfproto ipv6" in l and "drop" in l for l in regles)     # jamais en IPv6 depuis eth2


def test_lan_route_meme_garde_que_eth2():
    """#3206 : netmodes accepte br-lan en entrée comme eth2 ; sans la même garde, l'admin nginx :9080 (sans HAProxy ni
    sbxwaf), les statistiques HAProxy :8404 et les leurres seraient joignables depuis le LAN du mode routeur."""
    import re
    texte = LIVREE.read_text()
    listes = {}
    for ligne in texte.splitlines():
        m = re.search(r'iifname "(\w[\w-]*)" tcp dport \{ ([\d, ]+) \} counter drop', ligne)
        if m and not ligne.lstrip().startswith("#"):
            listes[m.group(1)] = sorted(int(p) for p in m.group(2).split(","))
    assert set(listes) == {"eth2", "br-lan"}
    assert listes["br-lan"] == listes["eth2"]                      # une seule liste, jamais deux qui divergent
    assert 9080 in listes["br-lan"] and 8404 in listes["br-lan"]
    assert re.search(r'iifname "br-lan" meta nfproto ipv6 tcp dport 7331 counter drop', texte)


def test_leurres_ouverts_et_reconnus_comme_voulus():
    """#3728 : les écoutes de leurre de sbx-authwatch ne sont plus coupées (102 123 paquets jetés sur gk2, 0 touche) et
    la page ne les signale pas comme backends exposés : elles sont listées à part."""
    assert wg.LEURRES == {23, 110, 143, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 18025, 18465, 18587, 18993, 18995, 27017}
    ss = "LISTEN 0 8192 *:3389 *:*\nLISTEN 0 511 0.0.0.0:8123 0.0.0.0:*\n"
    expose, leurres = wg.classer(wg.ports_en_ecoute(ss), gardes=[8088], )
    assert list(expose) == [8123] and leurres == [3389]


def test_leurres_fermes_en_ipv6():
    """#3728 (relecture) : la table est `inet` ; sans règle v6, ouvrir les leurres les ouvrait aussi en IPv6."""
    import re
    texte = LIVREE.read_text()
    for iface in ("eth2", "br-lan"):
        m = re.search(rf'iifname "{iface}" meta nfproto ipv6 tcp dport \{{ ([\d, ]+) \}} counter drop', texte)
        assert m and set(int(p) for p in m.group(1).split(",")) == wg.LEURRES, iface


def test_leurres_de_messagerie_par_redirection_seulement():
    """#3924 : la base en `policy drop` n'accepte les ports locaux que si la connexion y arrive par DNAT, en IPv4."""
    import re
    racine = LIVREE.parent.parent
    texte = (racine / "nft" / "secubox-leurres-mail.nft").read_text(encoding="utf-8")
    regles = [ln.strip() for ln in texte.splitlines() if "accept" in ln and not ln.startswith("#")]
    assert len(regles) == 1
    assert "meta nfproto ipv4" in regles[0] and "ct status dnat" in regles[0]
    locaux, publics = (set(map(int, m.split(","))) for m in re.findall(r"\{([\d, ]+)\}", regles[0]))
    assert locaux == {18025, 18465, 18587, 18993, 18995} <= wg.LEURRES
    assert publics == {25, 465, 587, 993, 995}
    assert "flush chain inet filter leurres_mail" in texte and texte.count("flush ") == 1   # sa chaîne, rien d'autre
    rules = (racine / "debian" / "rules").read_text(encoding="utf-8")
    assert "usr/share/secubox/hardening/secubox-leurres-mail.nft" in rules        # jamais conffile dans /etc/nftables.d
    assert "etc/nftables.d/secubox-leurres-mail.nft" not in rules


def _nft_reel():
    import shutil
    import subprocess
    if not shutil.which("nft") or not shutil.which("unshare"):
        return False
    return subprocess.run(["unshare", "-rn", "nft", "list", "ruleset"], capture_output=True, timeout=20).returncode == 0


sans_nft = pytest.mark.skipif(not _nft_reel(), reason="nft ou unshare -rn indisponible")
LEURRES_MAIL = LIVREE.parent / "secubox-leurres-mail.nft"


def _base_locale(tmp_path):
    """La base livrée, ses trois inclusions ramenées sous tmp_path."""
    texte = BASE.read_text(encoding="utf-8")
    for d, sous in (("/etc/secubox/hardening/nft-input-trust.d", "trust"), ("/etc/secubox/hardening/nft-site.d", "site"),
                    ("/etc/nftables.d", "nftables.d")):
        (tmp_path / sous).mkdir()
        assert d in texte
        texte = texte.replace(d, str(tmp_path / sous))
    base = tmp_path / "nftables.conf"
    base.write_text(texte, encoding="utf-8")
    return base


@sans_nft
def test_leurres_de_messagerie_valides_et_rejouables(tmp_path):
    """I6, M7 : vrai nft ; base + fragment acceptés, le fragment rejoué trois fois ne double ni règle ni saut."""
    import subprocess
    base = _base_locale(tmp_path)
    (tmp_path / "nftables.d" / LEURRES_MAIL.name).write_text(LEURRES_MAIL.read_text(encoding="utf-8"), encoding="utf-8")
    r = subprocess.run(["unshare", "-rn", "sh", "-ec",
                        'nft -c -f "$1"; nft -f "$1"; nft -f "$2"; nft -f "$2"; nft list chain inet filter leurres_mail; '
                        'nft list chain inet filter input', "sh", str(base), str(LEURRES_MAIL)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert r.stdout.count("ct status dnat") == 1 and r.stdout.count("jump leurres_mail") == 1


@sans_nft
def test_leurres_de_messagerie_sans_base_inertes(tmp_path):
    """Base plus ancienne (pas de saut) : accepté, sans effet."""
    import subprocess
    r = subprocess.run(["unshare", "-rn", "nft", "-c", "-f", str(LEURRES_MAIL)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr


SBIN = LIVREE.parent.parent / "sbin" / "secubox-fragment-leurres"


def _poser(src, base, dest, faux_nft=None):
    """Le script de la postinst, vrai nft dans un espace de noms ; `faux_nft` : dossier placé en tête du PATH."""
    import os
    import subprocess
    env = dict(os.environ, SBX_FRAGMENT_SRC=str(src), SBX_FRAGMENT_BASE=str(base), SBX_FRAGMENT_DEST=str(dest))
    if faux_nft:
        env["PATH"] = f"{faux_nft}:{env['PATH']}"
    return subprocess.run(["unshare", "-rn", "bash", str(SBIN)], capture_output=True, text=True, timeout=30, env=env)


@sans_nft
def test_postinst_pose_le_fragment_valide(tmp_path):
    base = _base_locale(tmp_path)
    dest = tmp_path / "nftables.d" / "secubox-leurres-mail.nft"
    for _ in range(2):
        r = _poser(LEURRES_MAIL, base, dest)
        assert r.returncode == 0 and not r.stderr, r.stderr
        assert dest.read_text(encoding="utf-8") == LEURRES_MAIL.read_text(encoding="utf-8")


@sans_nft
def test_postinst_ecarte_un_fragment_refuse(tmp_path):
    """I6 : jamais un pare-feu cassé au démarrage."""
    import subprocess
    base = _base_locale(tmp_path)
    mauvais = tmp_path / "mauvais"
    mauvais.write_text("table inet filter { pas du nft }\n", encoding="utf-8")
    dest = tmp_path / "nftables.d" / "secubox-leurres-mail.nft"
    r = _poser(mauvais, base, dest)
    assert r.returncode == 0 and "écarté" in r.stderr and not dest.exists()
    assert (tmp_path / "nftables.d" / "secubox-leurres-mail.nft.rejete").exists()
    assert subprocess.run(["unshare", "-rn", "nft", "-c", "-f", str(base)], capture_output=True, timeout=30).returncode == 0


@sans_nft
def test_postinst_base_deja_refusee(tmp_path):
    """Une base déjà refusée n'est pas imputée au fragment : il n'est pas posé, et c'est dit."""
    base = _base_locale(tmp_path)
    (tmp_path / "nftables.d" / "autre.nft").write_text("n'importe quoi\n", encoding="utf-8")
    dest = tmp_path / "nftables.d" / "secubox-leurres-mail.nft"
    r = _poser(LEURRES_MAIL, base, dest)
    assert r.returncode == 0 and "sans rapport" in r.stderr and not dest.exists()
    assert (tmp_path / "nftables.d" / "secubox-leurres-mail.nft.non-verifie").exists()      # pas jugé : il attend
    (tmp_path / "nftables.d" / "autre.nft").unlink()
    r = _poser(LEURRES_MAIL, base, dest)
    assert dest.exists() and not (tmp_path / "nftables.d" / "secubox-leurres-mail.nft.non-verifie").exists()


@sans_nft
def test_nft_impossible_ici_puis_valide(tmp_path):
    """N4 : chroot sans nft utilisable ≠ base refusée. Jamais un .nft non vérifié ; la passe suivante le valide."""
    base = _base_locale(tmp_path)
    dest = tmp_path / "nftables.d" / "secubox-leurres-mail.nft"
    attente = tmp_path / "nftables.d" / "secubox-leurres-mail.nft.non-verifie"
    faux = tmp_path / "bin"
    faux.mkdir()
    (faux / "nft").write_text("#!/bin/sh\necho 'netlink: Operation not permitted' >&2\nexit 1\n", encoding="utf-8")
    (faux / "nft").chmod(0o755)
    r = _poser(LEURRES_MAIL, base, dest, faux)
    assert r.returncode == 0 and "non-verifie" in r.stderr and "refusé" not in r.stderr
    assert attente.exists() and not dest.exists()
    assert list((tmp_path / "nftables.d").glob("*.nft")) == []
    r = _poser(LEURRES_MAIL, base, dest)                           # mise à jour suivante
    assert r.returncode == 0 and dest.exists() and not attente.exists()
    r = _poser(LEURRES_MAIL, base, dest, faux)                     # déjà validé, même contenu : rien n'attend
    assert r.returncode == 0 and not r.stderr and dest.exists() and not attente.exists()
    nouveau = tmp_path / "nouveau"
    nouveau.write_text("table inet filter { casse\n", encoding="utf-8")
    r = _poser(nouveau, base, dest, faux)                          # contenu nouveau : l'ancien, validé, reste actif
    assert dest.read_text(encoding="utf-8") == LEURRES_MAIL.read_text(encoding="utf-8") and attente.exists()
    r = _poser(nouveau, base, dest)
    assert "écarté" in r.stderr and not attente.exists()                    # l'ancien, encore valide, reste actif
    assert dest.read_text(encoding="utf-8") == LEURRES_MAIL.read_text(encoding="utf-8")


def test_postinst_seule_appelante_aucune_unite():
    racine = LIVREE.parent.parent
    assert "/usr/sbin/secubox-fragment-leurres || true" in (racine / "debian" / "postinst").read_text(encoding="utf-8")
    assert not list((racine / "systemd").glob("*fragment*"))
    assert "fragment-leurres.service" not in (racine / "debian" / "rules").read_text(encoding="utf-8")


@sans_nft
def test_validation_sur_une_copie(tmp_path):
    """P2 : pendant chaque `nft -c`, le candidat n'est pas dans nftables.d ; il n'y entre qu'ensuite, par renommage."""
    import shutil
    base = _base_locale(tmp_path)
    dest = tmp_path / "nftables.d" / "secubox-leurres-mail.nft"
    journal = tmp_path / "vu"
    faux = tmp_path / "bin"
    faux.mkdir()
    (faux / "nft").write_text(f'#!/bin/sh\nls "{tmp_path}/nftables.d" >> "{journal}"\nexec {shutil.which("nft")} "$@"\n', encoding="utf-8")
    (faux / "nft").chmod(0o755)
    r = _poser(LEURRES_MAIL, base, dest, faux)
    assert r.returncode == 0 and not r.stderr and journal.read_text(encoding="utf-8") == ""
    assert [f.name for f in (tmp_path / "nftables.d").iterdir()] == [dest.name]


@sans_nft
def test_fragment_actif_devenu_refuse_est_retire(tmp_path):
    base = _base_locale(tmp_path)
    mauvais = tmp_path / "mauvais"
    mauvais.write_text("table inet filter { casse\n", encoding="utf-8")
    dest = tmp_path / "nftables.d" / "secubox-leurres-mail.nft"
    dest.write_text(mauvais.read_text(encoding="utf-8"), encoding="utf-8")
    r = _poser(mauvais, base, dest)
    assert r.returncode == 0 and "écarté" in r.stderr and not dest.exists()
