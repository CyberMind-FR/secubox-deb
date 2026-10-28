# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3243 — secubox-renouvelle-secrets : les secrets d'une box sont générés SUR la box.

CONSTAT (2026-10-28) : les images publiées embarquaient les clés d'hôte SSH, la clé de signature OIDC, la clé TLS, la clé
WireGuard du p2p éphémère, le jeton d'appairage et le machine-id générés dans le chroot de CI — identiques sur toutes les box
d'une image, et téléchargeables. L'outil les renouvelle par le générateur de chaque paquet (ssh-keygen -A, secubox-oidcctl
init, postinst de secubox-p2p, openssl, systemd-id128) ; ssh-keygen, openssl et systemd-id128 sont les vrais, le reste est
simulé.

RELECTURE (1.8.6, constats 1 à 19) : jamais de box sans clé d'hôte ; rien n'est écrit en suivant un lien du compte secubox ;
copie HAProxy de l'ancienne clé TLS remplacée ; chaque ancien secret remis si son générateur échoue, et l'audit seulement
après contrôle ; comptes désactivés d'abord, et seulement ceux de construction ; surcharges SBX_* ignorées hors SBX_RACINE."""
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

PKG = Path(__file__).resolve().parents[1]
OUTIL = PKG / "sbin" / "secubox-renouvelle-secrets"
REGLES = PKG / "debian" / "rules"
CONTROLE = PKG / "debian" / "control"
CONSTRUCTEUR = "runnervmtest"
DELAI = 120


def _run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=DELAI, **kw)


def _empreinte(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _mode(p: Path) -> int:
    return stat.S_IMODE(p.lstat().st_mode)


def _cle_publique(pem: Path) -> str:
    return _run(["openssl", "pkey", "-in", str(pem), "-pubout"]).stdout


def _paire_tls(cle: Path, cert: Path) -> None:
    _run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
          "-subj", "/CN=secubox-live", "-keyout", str(cle), "-out", str(cert)])


def _audit(r: Path) -> list:
    a = r / "var/log/secubox/audit.log"
    return [json.loads(ligne) for ligne in a.read_text().splitlines()] if a.exists() else []


def _renouveles(r: Path) -> set:
    return {e["secret"] for e in _audit(r) if e["evenement"] == "secret_renouvele"}


@pytest.fixture
def banc(tmp_path):
    r = tmp_path / "racine"
    ssh = r / "etc/ssh"
    ssh.mkdir(parents=True)
    for t in ("rsa", "ecdsa", "ed25519"):
        _run(["ssh-keygen", "-q", "-t", t, "-N", "", "-C", f"root@{CONSTRUCTEUR}", "-f", str(ssh / f"ssh_host_{t}_key")])
    (r / "etc/secubox/secrets/oidc").mkdir(parents=True)
    (r / "etc/secubox/secrets/oidc/signing.pem").write_text("ANCIEN-OIDC")
    (r / "etc/secubox/secrets/p2p").mkdir(parents=True)
    (r / "etc/secubox/secrets/p2p/pair.token").write_text("ANCIEN-JETON")
    (r / "etc/secubox/secrets/p2p/wg-ephemeral.key").write_text("ANCIENNE-CLE-WG")
    (r / "etc/secubox/tls").mkdir(parents=True)
    (r / "etc/secubox/tls/key.pem").write_text("ANCIENNE-CLE-TLS")
    (r / "etc/secubox/tls/cert.pem").write_text("ANCIEN-CERT")
    (r / "etc/secubox/users.json").write_text(json.dumps({"version": 2, "groups": [], "users": [
        {"username": "admin", "password_hash": "$argon2id$x", "role": "admin"},
        {"username": CONSTRUCTEUR, "password_hash": None, "role": "admin"}]}))
    (r / "etc/machine-id").write_text("0123456789abcdef0123456789abcdef\n")
    (r / "etc/machine-id").chmod(0o444)
    (r / "var/lib/dbus").mkdir(parents=True)
    (r / "var/lib/dbus/machine-id").write_text("0123456789abcdef0123456789abcdef\n")
    (r / "var/log/secubox").mkdir(parents=True)

    faux = tmp_path / "faux"
    faux.mkdir()
    appels = tmp_path / "appels.txt"

    def script(nom, corps):
        p = faux / nom
        p.write_text("#!/bin/sh\n" f"echo \"{nom} $*\" >> {appels}\n" + corps)
        p.chmod(0o755)
        return str(p)

    p2p = f"d={r}/etc/secubox/secrets/p2p\n"
    env = {
        "PATH": "/usr/bin:/bin", "SBX_RACINE": str(r), "SBX_HOSTNAME": "gk5",
        "SBX_SYSTEMCTL": script("systemctl", "exit 0\n"),
        "SBX_NGINX": script("nginx", "exit 0\n"),
        "SBX_SSHD": script("sshd", "exit 0\n"),
        "SBX_USERSCTL": script("usersctl", "exit 0\n"),
        "SBX_DPKG_QUERY": script("dpkg-query", "echo 1.19.3-1~trixie1\n"),
        # sans interface wg-ephemeral : `wg show` échoue
        "SBX_WG": script("wg", 'case "$1" in show) exit 1 ;; pubkey) cat >/dev/null; echo PUB ;; esac\n'),
        "SBX_HAPROXY": script("haproxy", "exit 0\n"),
        "SBX_P2PCTL": script("p2pctl", "exit 0\n"),
        # le vrai `secubox-oidcctl init` crée la clé si elle manque
        "SBX_OIDCCTL": script("oidcctl", f"c={r}/etc/secubox/secrets/oidc/signing.pem\n[ -f $c ] || head -c 32 /dev/urandom | od -An -tx1 > $c\n"),
        # le vrai postinst de secubox-p2p crée jeton et clé s'ils manquent ; perl y râle sur la locale
        "SBX_P2P_POSTINST": script("p2p-postinst", p2p + f"echo \"umask-postinst $(umask)\" >> {appels}\n"
                                   "echo 'perl: warning: Setting locale failed.' >&2\necho 'bavardage du postinst'\n"
                                   "[ -f $d/pair.token ] || head -c 32 /dev/urandom | od -An -tx1 > $d/pair.token\n"
                                   "[ -f $d/wg-ephemeral.key ] || head -c 32 /dev/urandom | od -An -tx1 > $d/wg-ephemeral.key\n"),
    }

    def lance(*args, erreur_attendue=False, delai=DELAI, **surcharges):
        e = {k: v for k, v in {**env, **surcharges}.items() if v is not None}
        res = subprocess.run(["bash", str(OUTIL), *args], capture_output=True, text=True, env=e, timeout=delai)
        if not erreur_attendue:                           # chaque échec prévu est nommé, jamais « erreur inattendue »
            assert "erreur inattendue" not in res.stderr, res.stderr
        return res, (appels.read_text() if appels.exists() else "")
    return SimpleNamespace(r=r, lance=lance, script=script, faux=faux, tmp=tmp_path, p2p=p2p, appels=appels)


@pytest.fixture
def box(banc):
    return banc.r, banc.lance


def _tous(r: Path):
    return sorted([*(r / "etc/ssh").glob("ssh_host_*"), *(r / "etc/secubox").rglob("*.pem"),
                   *(r / "etc/secubox/secrets/p2p").glob("*"), r / "etc/machine-id", r / "etc/secubox/users.json"])


def _etat(r: Path) -> dict:
    return {p: _empreinte(p) for p in _tous(r) if p.is_file()}


def _ssh(r: Path) -> dict:
    return {p.name: _empreinte(p) for p in (r / "etc/ssh").glob("ssh_host_*")}


def _sans_reste(r: Path) -> bool:
    return not list((r / "etc").glob(".secubox-renouvelle.*"))


# ── Comportement de base (1.8.5) ─────────────────────────────────────────────────────────────────────────────────────

def test_constat_par_defaut_ne_change_rien(box):
    r, lance = box
    avant = _etat(r)
    res, appels = lance()
    assert res.returncode == 0, res.stderr
    assert _etat(r) == avant
    assert CONSTRUCTEUR in res.stdout                     # la clé d'hôte vient d'ailleurs : signalé
    for nom in ("ssh", "oidc", "tls", "p2p"):
        assert nom in res.stdout
    assert appels == ""


def test_tout_exige_oui(box):
    r, lance = box
    avant = _etat(r)
    res, _ = lance("--tout")
    assert res.returncode == 2
    assert _etat(r) == avant


def test_tout_renouvelle_chaque_secret_par_son_generateur(box):
    r, lance = box
    ed = r / "etc/ssh/ssh_host_ed25519_key.pub"
    avant_ed = ed.read_text()
    res, appels = lance("--tout", "--oui")
    assert res.returncode == 0, res.stderr + res.stdout
    for t in ("rsa", "ecdsa", "ed25519"):
        assert (r / f"etc/ssh/ssh_host_{t}_key").exists()
        assert _mode(r / f"etc/ssh/ssh_host_{t}_key") == 0o600
        assert _mode(r / f"etc/ssh/ssh_host_{t}_key.pub") == 0o644          # constat 17
    assert ed.read_text() != avant_ed and CONSTRUCTEUR not in ed.read_text()
    assert (r / "etc/secubox/secrets/oidc/signing.pem").read_text() != "ANCIEN-OIDC"
    jeton = (r / "etc/secubox/secrets/p2p/pair.token").read_text()
    assert jeton != "ANCIEN-JETON"
    assert (r / "etc/secubox/secrets/p2p/wg-ephemeral.key").read_text() != "ANCIENNE-CLE-WG"
    cle_tls = r / "etc/secubox/tls/key.pem"
    assert "PRIVATE KEY" in cle_tls.read_text() and _mode(cle_tls) == 0o640
    sujet = _run(["openssl", "x509", "-noout", "-subject", "-in", str(r / "etc/secubox/tls/cert.pem")]).stdout
    assert "gk5" in sujet                                 # le nom de la box, comme secubox-firstboot
    assert "oidcctl init" in appels
    assert "p2p-postinst configure 1.19.3-1~trixie1" in appels
    assert "sshd -t" in appels                            # constat 1 : clés neuves validées par sshd avant le rechargement
    assert "systemctl reload ssh" in appels and "systemctl reload nginx" in appels
    assert f"usersctl disable {CONSTRUCTEUR}" in appels and "usersctl disable admin" not in appels
    assert (r / "etc/machine-id").read_text().startswith("0123456789abcdef")   # pas sans --machine-id
    assert "SHA256:" in res.stdout                        # nouvelle empreinte, pour les known_hosts des clients
    for valeur in (jeton.strip(), (r / "etc/secubox/secrets/oidc/signing.pem").read_text().strip()[:20]):
        assert valeur not in res.stdout + res.stderr and valeur not in appels   # ni sortie, ni argv
    assert "ligne" not in res.stderr and _sans_reste(r)


def test_audit_nomme_les_secrets_sans_jamais_leur_valeur(box):
    r, lance = box
    res, _ = lance("--tout", "--oui")
    assert res.returncode == 0, res.stderr
    texte = (r / "var/log/secubox/audit.log").read_text()
    lignes = _audit(r)
    assert _renouveles(r) >= {"ssh-hote", "tls", "oidc", "p2p"}
    assert any(e["evenement"] == "compte_desactive" and e["compte"] == CONSTRUCTEUR for e in lignes)
    for valeur in ("ANCIEN", (r / "etc/secubox/secrets/p2p/pair.token").read_text().strip(),
                   (r / "etc/secubox/secrets/oidc/signing.pem").read_text().strip()[:20]):
        assert valeur not in texte


def test_absents_demarre_ssh_sans_attendre(banc):
    # r3 : au premier démarrage, firstboot ne doit pas attendre ssh (start --no-block).
    for p in (banc.r / "etc/ssh").glob("ssh_host_*"):
        p.unlink()
    systemctl = banc.script("systemctl-arrete", 'case "$1" in is-active) exit 3 ;; esac\nexit 0\n')
    res, appels = banc.lance("--absents", SBX_SYSTEMCTL=systemctl)
    assert res.returncode == 0, res.stderr
    assert "start --no-block ssh" in appels


def test_absents_ne_cree_que_ce_qui_manque(box):
    r, lance = box
    (r / "etc/secubox/secrets/oidc/signing.pem").unlink()
    for p in (r / "etc/ssh").glob("ssh_host_*"):
        p.unlink()
    res, appels = lance("--absents")
    assert res.returncode == 0, res.stderr
    assert (r / "etc/secubox/secrets/oidc/signing.pem").exists()
    assert (r / "etc/ssh/ssh_host_ed25519_key").exists()
    assert (r / "etc/secubox/secrets/p2p/pair.token").read_text() == "ANCIEN-JETON"
    assert (r / "etc/secubox/tls/key.pem").read_text() == "ANCIENNE-CLE-TLS"
    assert "p2p-postinst" not in appels and "usersctl" not in appels


def test_machine_id_seulement_sur_demande(box):
    r, lance = box
    res, _ = lance("--tout", "--oui", "--machine-id")
    assert res.returncode == 0, res.stderr
    assert not (r / "etc/machine-id").read_text().startswith("0123456789abcdef")
    lien = r / "var/lib/dbus/machine-id"
    assert lien.is_symlink() and os.readlink(lien) == "/etc/machine-id"
    assert "redémarr" in res.stdout


def test_le_paquet_installe_l_outil():
    assert "sbin/secubox-renouvelle-secrets" in REGLES.read_text()


# ── Constat 1 : jamais de box sans clé d'hôte ────────────────────────────────────────────────────────────────────────

def test_generation_ssh_en_echec_laisse_les_anciennes_cles(banc):
    enveloppe = banc.tmp / "enveloppe"
    enveloppe.mkdir()
    (enveloppe / "ssh-keygen").write_text('#!/bin/sh\n[ "$1" = -A ] && exit 1\nexec /usr/bin/ssh-keygen "$@"\n')
    (enveloppe / "ssh-keygen").chmod(0o755)
    avant = _ssh(banc.r)
    res, appels = banc.lance("--tout", "--oui", PATH=f"{enveloppe}:/usr/bin:/bin")
    assert res.returncode == 1
    assert _ssh(banc.r) == avant
    assert "ssh-hote" in res.stderr and "ssh-hote" not in _renouveles(banc.r)
    assert "systemctl reload ssh" not in appels
    assert _sans_reste(banc.r)


def test_coupure_de_session_pendant_la_generation_ne_tue_pas_l_echange(banc):
    # SIGHUP à la coupure de la session SSH, pendant que RSA se génère : l'outil va au bout.
    enveloppe = banc.tmp / "enveloppe"
    enveloppe.mkdir()
    (enveloppe / "ssh-keygen").write_text('#!/bin/sh\n[ "$1" = -A ] && kill -HUP "$PPID"\nexec /usr/bin/ssh-keygen "$@"\n')
    (enveloppe / "ssh-keygen").chmod(0o755)
    res, _ = banc.lance("--tout", "--oui", PATH=f"{enveloppe}:/usr/bin:/bin")
    assert res.returncode == 0, res.stderr
    for t in ("rsa", "ecdsa", "ed25519"):
        assert CONSTRUCTEUR not in (banc.r / f"etc/ssh/ssh_host_{t}_key.pub").read_text()
    assert "ssh-hote" in _renouveles(banc.r)


def test_sshd_refuse_les_cles_posees_anciennes_remises(banc):
    # sshd -t accepte les clés neuves seules (-h) mais refuse la configuration une fois posées : retour arrière.
    sshd = banc.script("sshd-refus", 'case "$*" in *-h*) exit 0 ;; esac\necho "sshd: no hostkeys available" >&2\nexit 255\n')
    avant = _ssh(banc.r)
    res, appels = banc.lance("--tout", "--oui", SBX_SSHD=sshd)
    assert res.returncode == 1
    assert _ssh(banc.r) == avant
    assert "no hostkeys available" in res.stderr
    assert "systemctl reload ssh" not in appels and "ssh-hote" not in _renouveles(banc.r)
    assert _sans_reste(banc.r)


def test_aide_recommande_systemd_run(box):
    _, lance = box
    res, _ = lance("--help")
    assert res.returncode == 0
    assert "systemd-run -E SUDO_USER --wait --pipe --collect" in res.stdout      # r2 : l'acteur de l'audit suit
    assert "--desactiver" in res.stdout and "SBX_RACINE" in res.stdout
    assert "Codes de retour" in res.stdout and "--absents" in res.stdout          # r3 : ce que firstboot peut lire


# ── Constat 2 et 10 : TLS généré hors du dossier du compte secubox, jamais en suivant un lien ───────────────────────────

def test_tls_genere_hors_du_dossier_secubox_sans_suivre_de_lien(banc):
    tls = banc.r / "etc/secubox/tls"
    tls.chmod(0o750)
    victime = banc.tmp / "victime"
    victime.write_text("VICTIME\n")
    victime.chmod(0o644)
    (tls / "key.pem").unlink()
    (tls / "key.pem").symlink_to(victime)
    enveloppe = banc.tmp / "enveloppe"
    enveloppe.mkdir()
    (enveloppe / "openssl").write_text(f'#!/bin/sh\necho "openssl $*" >> {banc.appels}\nexec /usr/bin/openssl "$@"\n')
    (enveloppe / "openssl").chmod(0o755)
    res, appels = banc.lance("--tout", "--oui", PATH=f"{enveloppe}:/usr/bin:/bin")
    assert res.returncode == 0, res.stderr
    req = next(ligne for ligne in appels.splitlines() if ligne.startswith("openssl req"))
    cle_neuve = Path(re.search(r"-keyout (\S+)", req).group(1))
    assert cle_neuve.parent != tls and tls not in cle_neuve.parents
    assert victime.read_text() == "VICTIME\n" and _mode(victime) == 0o644
    assert not (tls / "key.pem").is_symlink() and "PRIVATE KEY" in (tls / "key.pem").read_text()
    assert _mode(tls) == 0o750                            # constat 10 : le mode d'un dossier existant ne change pas
    assert sorted(p.name for p in tls.iterdir()) == ["cert.pem", "key.pem"]


def _bascule_tls(banc, remise: bool):
    """Remplace /etc/secubox/tls par un lien vers un dossier témoin entre les deux poses : par le crochet
    SBX_ENTRE_POSES_TLS (pose par descripteur), ou après le `mv` de la clé (pose par chemin, 1.8.6). Une seule fois."""
    tls = banc.r / "etc/secubox/tls"
    temoin = banc.tmp / "temoin-tls"
    temoin.mkdir()
    marque = banc.tmp / "bascule-faite"
    bascule = banc.script("bascule", f"[ -e {marque} ] && exit 0\n: > {marque}\n"
                          f"/usr/bin/mv {tls} {tls}.vrai && ln -s {temoin} {tls}\n"
                          + (f"rm -f {tls}.vrai/cert.pem && mkdir {tls}.vrai/cert.pem\n" if remise else ""))
    enveloppe = banc.tmp / "enveloppe-mv"
    enveloppe.mkdir()
    (enveloppe / "mv").write_text('#!/bin/sh\n/usr/bin/mv "$@" || exit $?\nfor a in "$@"; do d=$a; done\n'
                                  f'case "$d" in */tls/key.pem) {bascule} ;; esac\n')
    (enveloppe / "mv").chmod(0o755)
    res, _ = banc.lance("--tout", "--oui", SBX_ENTRE_POSES_TLS=bascule, PATH=f"{enveloppe}:/usr/bin:/bin")
    assert marque.exists()                                # la bascule a eu lieu
    return res, temoin, banc.r / "etc/secubox/tls.vrai"


def test_tls_lien_substitue_entre_les_deux_poses_jamais_suivi(banc):
    # B2 : la seconde pose va dans LE dossier ouvert au départ (descripteur), jamais dans la cible du lien.
    res, temoin, vrai = _bascule_tls(banc, remise=False)
    assert list(temoin.iterdir()) == []
    assert "PRIVATE KEY" in (vrai / "key.pem").read_text() and "CERTIFICATE" in (vrai / "cert.pem").read_text()
    assert res.returncode == 0, res.stderr


def test_tls_remise_par_descripteur_ne_suit_pas_le_lien(banc):
    # B2 : seconde pose refusée après la bascule ; l'ancienne clé revient dans le vrai dossier, rien dans le témoin.
    res, temoin, vrai = _bascule_tls(banc, remise=True)
    assert list(temoin.iterdir()) == []
    assert (vrai / "key.pem").read_text() == "ANCIENNE-CLE-TLS"
    assert res.returncode == 1 and "tls" in res.stderr and "tls" not in _renouveles(banc.r)


def test_tls_dossier_qui_est_un_lien_des_le_depart_rien_n_est_pose(banc):
    tls = banc.r / "etc/secubox/tls"
    temoin = banc.tmp / "temoin-tls"
    temoin.mkdir()
    for p in tls.iterdir():
        p.unlink()
    tls.rmdir()
    tls.symlink_to(temoin)
    res, _ = banc.lance("--tout", "--oui")
    assert res.returncode == 1 and "tls" in res.stderr
    assert list(temoin.iterdir()) == [] and tls.is_symlink()


def test_tls_second_renommage_refuse_premier_defait(banc):
    # constat 12 : clé posée, certificat refusé (un dossier à sa place) → l'ancienne clé revient.
    tls = banc.r / "etc/secubox/tls"
    (tls / "cert.pem").unlink()
    (tls / "cert.pem").mkdir()
    res, _ = banc.lance("--tout", "--oui")
    assert res.returncode == 1
    assert (tls / "key.pem").read_text() == "ANCIENNE-CLE-TLS"
    assert "tls" not in _renouveles(banc.r) and "tls" in res.stderr
    assert {"ssh-hote", "oidc", "p2p"} <= _renouveles(banc.r)   # les autres secrets vont au bout


# ── Constat 3 : copie HAProxy de l'ancienne clé TLS ───────────────────────────────────────────────────────────────────

def _haproxy(banc):
    r = banc.r
    tls = r / "etc/secubox/tls"
    _paire_tls(tls / "key.pem", tls / "cert.pem")
    (r / "etc/haproxy/conf.d").mkdir(parents=True)
    (r / "etc/haproxy/haproxy.cfg").write_text(
        "frontend https\n    # bind *:8443 ssl crt /ailleurs/\n    bind *:443 ssl crt /srv/haproxy/certs/\n")
    (r / "etc/haproxy/conf.d/10-lan.cfg").write_text("frontend lan\n    bind 192.168.1.1:9443 ssl crt /data/haproxy/lan.pem\n")
    certs = r / "srv/haproxy/certs"
    certs.mkdir(parents=True)
    defaut = certs / "000-defaut.pem"
    defaut.write_text((tls / "cert.pem").read_text() + (tls / "key.pem").read_text())
    defaut.chmod(0o600)
    autre_cle, autre_cert = banc.tmp / "autre.key", banc.tmp / "autre.crt"
    _paire_tls(autre_cle, autre_cert)
    autre = certs / "nextcloud.pem"
    autre.write_text(autre_cert.read_text() + autre_cle.read_text())
    (r / "data/haproxy").mkdir(parents=True)
    lan = r / "data/haproxy/lan.pem"
    lan.write_text(defaut.read_text())
    lan.chmod(0o640)
    for d in (r / "srv", r / "srv/haproxy", certs, r / "data", r / "data/haproxy"):
        d.chmod(0o755)                                    # comme $CERTS_DIR et ses parents : root 0755, écrits par root seul
    return defaut, autre, lan


def test_haproxy_copie_de_l_ancienne_cle_remplacee(banc):
    defaut, autre, lan = _haproxy(banc)
    avant_autre = _empreinte(autre)
    res, appels = banc.lance("--tout", "--oui")
    assert res.returncode == 0, res.stderr
    neuve = _cle_publique(banc.r / "etc/secubox/tls/key.pem")
    assert _cle_publique(defaut) == neuve and _cle_publique(lan) == neuve
    assert "BEGIN CERTIFICATE" in defaut.read_text()
    assert _mode(defaut) == 0o600 and _mode(lan) == 0o640  # mêmes droits
    assert _empreinte(autre) == avant_autre               # un autre certificat n'est pas touché
    assert "haproxy -c" in appels and "systemctl reload haproxy" in appels
    assert "haproxy-defaut" in _renouveles(banc.r)
    assert not [p for p in defaut.parent.iterdir() if p.name.startswith(".")]


def test_haproxy_refuse_la_configuration_ancien_certificat_remis(banc):
    defaut, _, lan = _haproxy(banc)
    avant = (_empreinte(defaut), _empreinte(lan))
    haproxy = banc.script("haproxy-refus", "echo '[ALERT] unable to load certificate' >&2\nexit 1\n")
    res, appels = banc.lance("--tout", "--oui", SBX_HAPROXY=haproxy)
    assert res.returncode == 1
    assert (_empreinte(defaut), _empreinte(lan)) == avant
    assert "haproxy-defaut" in res.stderr and "unable to load certificate" in res.stderr
    assert "haproxy-defaut" not in _renouveles(banc.r) and "systemctl reload haproxy" not in appels
    assert "tls" in _renouveles(banc.r)


def test_haproxy_ancetre_inscriptible_refuse(banc):
    # m1 : le dossier crt est à root 0755, mais son parent est inscriptible par le groupe : un autre compte pourrait
    # renommer le dossier et le remplacer par un lien.
    defaut, _, lan = _haproxy(banc)
    defaut.parent.parent.chmod(0o775)
    avant = _empreinte(defaut)
    res, _ = banc.lance("--tout", "--oui")
    assert res.returncode == 1 and "root seul" in res.stderr
    assert _empreinte(defaut) == avant
    assert _cle_publique(lan) == _cle_publique(banc.r / "etc/secubox/tls/key.pem")


def test_haproxy_dossier_ecrit_par_un_autre_compte_non_touche(banc):
    defaut, _, lan = _haproxy(banc)
    defaut.parent.chmod(0o775)                            # un autre compte pourrait y substituer un lien
    avant = _empreinte(defaut)
    res, _ = banc.lance("--tout", "--oui")
    assert res.returncode == 1 and "root seul" in res.stderr
    assert _empreinte(defaut) == avant
    assert _cle_publique(lan) == _cle_publique(banc.r / "etc/secubox/tls/key.pem")


# ── Constats 4 et 8 : comptes de construction d'abord, et seulement eux ─────────────────────────────────────────────

def test_users_illisible_rien_n_est_renouvele(box):
    r, lance = box
    (r / "etc/secubox/users.json").write_text("{pas du json")
    avant = _etat(r)
    res, appels = lance("--tout", "--oui")
    assert res.returncode == 1
    assert "users.json" in res.stderr
    assert _etat(r) == avant and "usersctl" not in appels and _audit(r) == []


def test_desactivation_d_abord_son_echec_arrete_tout(banc):
    avant = _etat(banc.r)
    res, appels = banc.lance("--tout", "--oui", SBX_USERSCTL=banc.script("usersctl-refus", "exit 1\n"))
    assert res.returncode == 1
    assert _etat(banc.r) == avant and "oidcctl" not in appels and "p2p-postinst" not in appels


def _machine_atelier(r: Path, compte: dict):
    ed = r / "etc/ssh/ssh_host_ed25519_key"
    for p in (ed, Path(f"{ed}.pub")):
        p.unlink()
    _run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "root@atelier", "-f", str(ed)])
    users = json.loads((r / "etc/secubox/users.json").read_text())
    users["users"].append({"username": "atelier", "password_hash": None, "role": "admin", **compte})
    (r / "etc/secubox/users.json").write_text(json.dumps(users))


def test_compte_legitime_sans_hash_non_desactive(banc):
    # au nom de la machine de la clé, sans hash, mais il s'est déjà connecté (OTP…) : pas un compte de construction
    _machine_atelier(banc.r, {"must_change_password": False, "last_login": "2026-10-01T08:00:00+00:00"})
    res, appels = banc.lance("--tout", "--oui")
    assert res.returncode == 0, res.stderr
    assert "usersctl disable atelier" not in appels and f"usersctl disable {CONSTRUCTEUR}" in appels


def test_desactiver_nomme_un_compte_explicitement(banc):
    _machine_atelier(banc.r, {"must_change_password": False, "last_login": "2026-10-01T08:00:00+00:00"})
    res, appels = banc.lance("--tout", "--oui", "--desactiver", "atelier")
    assert res.returncode == 0, res.stderr
    assert "usersctl disable atelier" in appels
    assert any(e["evenement"] == "compte_desactive" and e["compte"] == "atelier" for e in _audit(banc.r))
    res, _ = banc.lance("--absents", "--desactiver", "atelier")
    assert res.returncode == 2
    res, _ = banc.lance("--tout", "--oui", "--desactiver", "Pas Valide")
    assert res.returncode == 2


def test_compte_de_construction_jamais_servi_desactive(banc):
    _machine_atelier(banc.r, {"must_change_password": True, "last_login": None})
    res, appels = banc.lance("--tout", "--oui")
    assert res.returncode == 0, res.stderr
    assert "usersctl disable atelier" in appels


# ── Constat 5 : OIDC ──────────────────────────────────────────────────────────────────────────────────────────────────

def test_oidcctl_absent_cle_conservee(box):
    r, lance = box
    res, _ = lance("--tout", "--oui", SBX_OIDCCTL="/nulle/part/secubox-oidcctl")
    assert (r / "etc/secubox/secrets/oidc/signing.pem").read_text() == "ANCIEN-OIDC"
    assert res.returncode == 1 and "oidc" in res.stderr and "oidc" not in _renouveles(r)


def test_oidcctl_init_en_echec_ancienne_cle_remise(banc):
    c = banc.r / "etc/secubox/secrets/oidc/signing.pem"
    oidcctl = banc.script("oidcctl-refus", f": > {c}\necho 'PermissionError: secrets' >&2\nexit 1\n")
    res, _ = banc.lance("--tout", "--oui", SBX_OIDCCTL=oidcctl)
    assert res.returncode == 1
    assert c.read_text() == "ANCIEN-OIDC"
    assert "PermissionError" in res.stderr and "oidc" not in _renouveles(banc.r)


# ── Constats 6, 7 et 19 : p2p ─────────────────────────────────────────────────────────────────────────────────────────

def test_postinst_p2p_en_echec_jeton_restaure_sans_audit(banc):
    r = banc.r
    (r / "etc/nginx").mkdir(parents=True)
    (r / "etc/nginx/secubox-p2p-pair.conf").write_text("ANCIENNE-CONF")
    postinst = banc.script("p2p-refus", banc.p2p + "echo 'perl: warning: Setting locale failed.' >&2\n"
                           "echo neuf > $d/pair.token\n"
                           f"echo 'map NEUF' > {r}/etc/nginx/secubox-p2p-pair.conf\n"
                           "echo 'Failed to enable unit: Unit secubox-p2p.service is masked.' >&2\nexit 1\n")
    res, _ = banc.lance("--tout", "--oui", SBX_P2P_POSTINST=postinst)
    assert res.returncode == 1
    assert (r / "etc/secubox/secrets/p2p/pair.token").read_text() == "ANCIEN-JETON"
    assert (r / "etc/secubox/secrets/p2p/wg-ephemeral.key").read_text() == "ANCIENNE-CLE-WG"
    assert (r / "etc/nginx/secubox-p2p-pair.conf").read_text() == "ANCIENNE-CONF"
    assert "p2p" not in _renouveles(r)
    assert "is masked" in res.stderr and "perl" not in res.stderr        # constat 19 : la dernière ligne seulement
    assert _journal_cite_existe(r, res.stderr) and f"journal : /{JOURNAL})" in res.stderr


def test_cle_wg_vide_apres_postinst_restauree(banc):
    postinst = banc.script("p2p-sans-wg", banc.p2p + "[ -f $d/pair.token ] || echo neuf > $d/pair.token\n"
                           ": > $d/wg-ephemeral.key\n")
    res, _ = banc.lance("--tout", "--oui", SBX_P2P_POSTINST=postinst)
    assert res.returncode == 1
    assert (banc.r / "etc/secubox/secrets/p2p/wg-ephemeral.key").read_text() == "ANCIENNE-CLE-WG"
    assert (banc.r / "etc/secubox/secrets/p2p/pair.token").read_text() == "ANCIEN-JETON"
    assert "p2p" not in _renouveles(banc.r)


def test_interface_wg_qui_garde_l_ancienne_cle_pas_d_audit(banc):
    wg = banc.script("wg-ancienne", 'case "$1" in show) echo NOYAU ;; pubkey) cat >/dev/null; echo FICHIER ;; esac\n')
    res, _ = banc.lance("--tout", "--oui", SBX_WG=wg)
    assert res.returncode == 1
    assert "p2p" not in _renouveles(banc.r) and "wg-ephemeral" in res.stderr
    assert "secubox-p2pctl iface-up" in res.stderr


def test_p2p_remis_l_interface_reprend_l_ancienne_cle(banc):
    # m2 : le postinst a monté wg-ephemeral avec la clé neuve, puis échoue ; les anciens fichiers reviennent, et
    # secubox-p2pctl iface-up remet l'ancienne clé dans le noyau.
    d = banc.r / "etc/secubox/secrets/p2p"
    noyau = banc.tmp / "noyau-wg"
    noyau.write_text("ANCIENNE-CLE-WG")
    wg = banc.script("wg-etat", f'case "$1" in show) cat {noyau} ;; pubkey) cat ;; esac\n')
    p2pctl = banc.script("p2pctl", f'[ "$1" = iface-up ] && cat {d}/wg-ephemeral.key > {noyau}\n')
    postinst = banc.script("p2p-iface-puis-refus", banc.p2p + "echo neuf > $d/pair.token\necho NEUVE > $d/wg-ephemeral.key\n"
                           f"cat $d/wg-ephemeral.key > {noyau}\nexit 1\n")
    res, appels = banc.lance("--tout", "--oui", SBX_WG=wg, SBX_P2PCTL=p2pctl, SBX_P2P_POSTINST=postinst)
    assert res.returncode == 1
    assert (d / "wg-ephemeral.key").read_text() == "ANCIENNE-CLE-WG"
    assert "p2pctl iface-up" in appels and noyau.read_text() == "ANCIENNE-CLE-WG"
    assert "p2p" not in _renouveles(banc.r)


def test_postinst_p2p_relance_sous_umask_022(box):
    _, lance = box
    res, appels = lance("--tout", "--oui")
    assert res.returncode == 0, res.stderr
    assert "umask-postinst 0022" in appels


def test_refus_si_apt_ou_dpkg_tourne(box):
    r, lance = box
    (r / "var/lib/dpkg").mkdir(parents=True)
    verrou = r / "var/lib/dpkg/lock-frontend"
    verrou.write_text("")
    avant = _etat(r)
    with open(verrou, "r+") as f:
        fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)     # comme apt : verrou fcntl
        res, appels = lance("--tout", "--oui")
    assert res.returncode == 1 and "dpkg" in res.stderr
    assert _etat(r) == avant and appels == ""


JOURNAL = "var/log/secubox-renouvelle-secrets.log"         # sous /var/log (root), jamais sous /var/log/secubox (secubox)


def test_sortie_du_postinst_au_journal_root(box):
    r, lance = box
    journal = r / JOURNAL
    journal.write_text("ancienne ligne\n")
    journal.chmod(0o644)                                  # remis en 0600 par descripteur
    res, _ = lance("--tout", "--oui")
    assert res.returncode == 0, res.stderr
    assert "perl" not in res.stdout + res.stderr and "bavardage" not in res.stdout + res.stderr
    assert "Setting locale failed" in journal.read_text() and _mode(journal) == 0o600
    assert journal.read_text().startswith("ancienne ligne\n")
    assert not (r / "var/log/secubox/renouvelle-secrets.log").exists()


def _piege(chemin: Path, sorte: str, temoin: Path):
    if sorte == "lien":
        chemin.symlink_to(temoin)
    else:
        os.mkfifo(chemin)


@pytest.mark.parametrize("sorte", ["lien", "fifo"])
def test_journal_piege_sous_var_log_secubox_jamais_suivi(banc, sorte):
    # B1 : /var/log/secubox appartient souvent à secubox ; un lien ou une FIFO posé là ne mène ni n'arrête root.
    temoin = banc.tmp / "temoin"
    temoin.write_text("TEMOIN\n")
    temoin.chmod(0o644)
    _piege(banc.r / "var/log/secubox/renouvelle-secrets.log", sorte, temoin)
    res, _ = banc.lance("--tout", "--oui", delai=60)
    assert res.returncode == 0, res.stderr
    assert temoin.read_text() == "TEMOIN\n" and _mode(temoin) == 0o644
    assert "p2p" in _renouveles(banc.r)


@pytest.mark.parametrize("sorte", ["lien", "fifo"])
def test_journal_root_piege_refuse_avant_de_toucher_au_p2p(banc, sorte):
    temoin = banc.tmp / "temoin"
    temoin.write_text("TEMOIN\n")
    temoin.chmod(0o644)
    _piege(banc.r / JOURNAL, sorte, temoin)
    res, appels = banc.lance("--tout", "--oui", delai=60)
    assert res.returncode == 1 and "journal" in res.stderr
    assert temoin.read_text() == "TEMOIN\n" and _mode(temoin) == 0o644
    assert (banc.r / "etc/secubox/secrets/p2p/pair.token").read_text() == "ANCIEN-JETON"
    assert (banc.r / "etc/secubox/secrets/p2p/wg-ephemeral.key").read_text() == "ANCIENNE-CLE-WG"
    assert "p2p-postinst" not in appels and "p2p" not in _renouveles(banc.r)
    assert {"ssh-hote", "tls", "oidc"} <= _renouveles(banc.r)       # l'outil va au bout pour le reste


def _journal_cite_existe(r: Path, stderr: str) -> bool:
    cite = re.search(r"journal : (\S+?)\)", stderr)
    return bool(cite) and (r / cite.group(1).lstrip("/")).is_file()


def test_journal_cite_dans_un_echec_survit_a_l_outil(banc):
    # m3 : même sans /var/log/secubox, le journal cité par un échec existe encore après l'outil (jamais dans TRAVAIL).
    (banc.r / "var/log/secubox").rmdir()
    postinst = banc.script("p2p-refus-m3", "echo 'Unit secubox-p2p.service is masked.' >&2\nexit 1\n")
    res, _ = banc.lance("--tout", "--oui", SBX_P2P_POSTINST=postinst)
    assert res.returncode == 1 and "is masked" in res.stderr
    assert _journal_cite_existe(banc.r, res.stderr), res.stderr


# ── Constat 9 : machine-id ────────────────────────────────────────────────────────────────────────────────────────────

def test_machine_id_neuf_malgre_le_fichier_dbus_ordinaire(box):
    r, lance = box
    ancien = (r / "etc/machine-id").read_text()
    res, _ = lance("--tout", "--oui", "--machine-id")
    assert res.returncode == 0, res.stderr
    neuf = (r / "etc/machine-id").read_text()
    assert re.fullmatch(r"[0-9a-f]{32}\n", neuf) and neuf != ancien
    assert _mode(r / "etc/machine-id") == 0o444
    assert "machine-id" in _renouveles(r)


# ── Constat 11 : audit ────────────────────────────────────────────────────────────────────────────────────────────────

def test_audit_cree_en_0640_avec_acteur_et_date_utc(box):
    r, lance = box
    res, _ = lance("--tout", "--oui", SUDO_USER="gerald")
    assert res.returncode == 0, res.stderr
    assert _mode(r / "var/log/secubox/audit.log") == 0o640
    for e in _audit(r):
        assert e["acteur"] == "gerald" and e["ts"].endswith("+00:00")


def test_audit_ne_cree_jamais_son_dossier(box):
    r, lance = box
    (r / "var/log/secubox").rmdir()
    res, _ = lance("--tout", "--oui")
    assert not (r / "var/log/secubox").exists()
    assert res.returncode == 1 and "audit" in res.stderr
    assert (r / "etc/secubox/secrets/p2p/pair.token").read_text() != "ANCIEN-JETON"   # les secrets, eux, sont renouvelés


# ── Constats 13 à 17 ──────────────────────────────────────────────────────────────────────────────────────────────────

def test_nginx_t_en_echec_averti_sans_rechargement(banc):
    nginx = banc.script("nginx-refus", "echo 'nginx: [emerg] unknown directive' >&2\nexit 1\n")
    res, appels = banc.lance("--tout", "--oui", SBX_NGINX=nginx)
    assert res.returncode == 1
    assert "nginx" in res.stderr and "unknown directive" in res.stderr
    assert "systemctl reload nginx" not in appels


def test_erreur_inattendue_nommee_par_sa_ligne_anciennes_cles_intactes(box):
    r, lance = box
    avant = _ssh(r)
    (r / "etc/ssh").chmod(0o555)
    try:
        res, _ = lance("--tout", "--oui", erreur_attendue=True)
    finally:
        (r / "etc/ssh").chmod(0o755)
    assert res.returncode != 0
    assert re.search(r"ligne \d+", res.stderr)
    assert _ssh(r) == avant and _sans_reste(r)


def test_arret_en_plein_echange_le_trap_remet_les_anciennes_cles(box):
    # ecdsa et ed25519 déjà échangées quand le .pub de rsa (un dossier à sa place) refuse le renommage : arrêt, et le
    # trap de sortie remet les trois anciennes clés privées et les deux .pub.
    r, lance = box
    ssh = r / "etc/ssh"
    (ssh / "ssh_host_rsa_key.pub").unlink()
    (ssh / "ssh_host_rsa_key.pub").mkdir()
    avant = {p.name: _empreinte(p) for p in ssh.glob("ssh_host_*") if p.is_file()}
    res, appels = lance("--tout", "--oui", erreur_attendue=True)
    assert res.returncode != 0 and "anciens secrets remis" in res.stderr
    assert {p.name: _empreinte(p) for p in ssh.glob("ssh_host_*") if p.is_file()} == avant
    assert "systemctl reload ssh" not in appels and _sans_reste(r)


def test_commentaire_de_cle_filtre_et_nom_d_hote_en_minuscules(banc):
    r = banc.r
    ed = r / "etc/ssh/ssh_host_ed25519_key"
    for p in (ed, Path(f"{ed}.pub")):
        p.unlink()
    _run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "root@runnervm\x1b[31mx", "-f", str(ed)])
    res, _ = banc.lance()
    assert res.returncode == 0, res.stderr
    assert "\x1b" not in res.stdout + res.stderr
    res, _ = banc.lance("--tout", "--oui", SBX_HOSTNAME="GK5")
    assert res.returncode == 0, res.stderr
    sujet = _run(["openssl", "x509", "-noout", "-subject", "-in", str(r / "etc/secubox/tls/cert.pem")]).stdout
    assert "CN=gk5" in sujet.replace(" ", "")


def test_surcharges_sbx_ignorees_hors_racine(banc):
    # Sans SBX_RACINE, c'est une vraie box : un `id` simulé fait croire à root, et l'outil s'arrête faute de --oui.
    banc.script("id", "echo 0\n")
    res, appels = banc.lance("--tout", SBX_RACINE=None, PATH=f"{banc.faux}:/usr/bin:/bin")
    assert res.returncode == 2
    assert "SBX_SYSTEMCTL" in res.stderr and "SBX_OIDCCTL" in res.stderr and "ignor" in res.stderr
    assert str(banc.faux) not in res.stderr                # les noms, jamais les valeurs
    assert "systemctl" not in appels


def test_ssh_keygen_absent_rien_ne_change(banc):
    sans = banc.tmp / "bin-sans-ssh-keygen"
    sans.mkdir()
    for p in Path("/usr/bin").iterdir():
        if p.name != "ssh-keygen":
            (sans / p.name).symlink_to(p)
    avant = _etat(banc.r)
    res, appels = banc.lance("--tout", "--oui", PATH=str(sans))
    assert res.returncode == 1 and "ssh-keygen" in res.stderr
    assert _etat(banc.r) == avant and appels == ""


def test_openssh_client_recommande():
    controle = CONTROLE.read_text()
    recommends = re.search(r"^Recommends:(.*(?:\n .*)*)", controle, re.M).group(1)
    assert "openssh-client" in recommends
