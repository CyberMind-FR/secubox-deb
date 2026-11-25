# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3938 (relecture) — le postinst de secubox-core ne casse pas une box en service : sockets retirés seulement sur preuve, snippet
nginx remplacé d'un coup, dépendances Python jamais relevées quand elles suffisent, journaux masqués sans bloquer dpkg."""
import os
import re
import socket
import subprocess
import sys
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
POST = (PKG / "debian" / "postinst").read_text()


def bloc(debut, fin):
    d = POST.index(debut)
    return POST[d:POST.index(fin, d)]


def executable(p, texte):
    p.write_text(texte)
    p.chmod(0o755)


def lance(tmp_path, texte, **env):
    script = tmp_path / "bloc.sh"
    script.write_text("set -e\n" + texte + "\necho FIN\n")
    return subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=60,
                          env={"PATH": f"{tmp_path}/bin:/usr/bin:/bin", **env})


@pytest.fixture
def faux(tmp_path):
    (tmp_path / "bin").mkdir()
    executable(tmp_path / "bin/systemctl", f'#!/bin/sh\necho "$@" >> {tmp_path}/systemctl.log\n')
    return tmp_path / "bin"


def appels(tmp_path, nom="systemctl"):
    f = tmp_path / f"{nom}.log"
    return f.read_text().splitlines() if f.exists() else []


# ── 1. pip ───────────────────────────────────────────────────────────────────────────────────────────────────

def modules(tmp_path, **versions):
    for nom, v in versions.items():
        (tmp_path / "py" / nom).mkdir(parents=True)
        (tmp_path / "py" / nom / "__init__.py").write_text("" if v != "casse" else "raise ImportError('x')\n")
        d = tmp_path / "py" / f"{nom}-{v}.dist-info"
        d.mkdir()
        (d / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {nom}\nVersion: {v if v != 'casse' else '9.9'}\n")


def lance_pip(tmp_path, faux, rc=0):
    # python3 -I ignorerait PYTHONPATH : le faux l'enlève, le reste est le vrai code du postinst
    executable(faux / "python3", f'#!/bin/sh\nshift\nexec {sys.executable} -S "$@"\n')
    executable(faux / "pip3", f'#!/bin/sh\necho "$@" >> {tmp_path}/pip3.log\necho "pip: raison" >&2\nexit {rc}\n')
    return lance(tmp_path, bloc("    # ── Python dependencies", "    ;;\nesac"), PYTHONPATH=f"{tmp_path}/py")


def test_pip_n_est_pas_appele_quand_les_versions_suffisent(tmp_path, faux):
    modules(tmp_path, pydantic="2.10.6", fastapi="0.115.11", uvicorn="0.32.0")
    r = lance_pip(tmp_path, faux)
    assert r.returncode == 0 and "FIN" in r.stdout, r.stderr
    assert appels(tmp_path, "pip3") == []


@pytest.mark.parametrize("versions", [
    {"pydantic": "1.10.4", "fastapi": "0.115.0", "uvicorn": "0.32.0"},
    {"pydantic": "2.1", "fastapi": "0.92.0", "uvicorn": "0.32.0"},
    {"pydantic": "2.1", "fastapi": "0.115.0"},
    {"pydantic": "2.1", "fastapi": "casse", "uvicorn": "0.32.0"}])
def test_pip_complete_ce_qui_manque_sans_rien_relever(tmp_path, faux, versions):
    modules(tmp_path, **versions)
    r = lance_pip(tmp_path, faux)
    assert r.returncode == 0 and len(appels(tmp_path, "pip3")) == 1
    assert "--upgrade" not in appels(tmp_path, "pip3")[0] and "-U" not in appels(tmp_path, "pip3")[0].split()


def test_echec_de_pip_dit_et_non_bloquant(tmp_path, faux):
    modules(tmp_path, pydantic="1.0")
    r = lance_pip(tmp_path, faux, rc=1)
    assert r.returncode == 0 and "FIN" in r.stdout and "pip: raison" in r.stderr and "secubox-core" in r.stderr


# ── 2. sockets de /run/secubox ───────────────────────────────────────────────────────────────────────────────

DEBUT_SOCK = "    if [ -d /run/secubox ] && command -v ss"
FIN_SOCK = "    # CADENCE (#1650)"


@pytest.fixture
def run(tmp_path, faux):
    """Un /run/secubox d'essai : deux sockets écoutées pour de vrai, une morte. Chemin court (108 octets)."""
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="sbx", dir="/tmp"))
    ouvertes = []
    for nom in ("aggregator", "hub"):
        s = socket.socket(socket.AF_UNIX)
        s.bind(str(d / f"{nom}.sock"))
        s.listen()
        ouvertes.append(s)
    s = socket.socket(socket.AF_UNIX)
    s.bind(str(d / "morte.sock"))
    s.close()
    d.chmod(0o1777)
    yield d
    for s in ouvertes:
        s.close()
    for f in d.iterdir():
        f.unlink()
    d.rmdir()


def lance_sock(tmp_path, faux, d, sortie, rc=0, avant="", remplace=()):
    (tmp_path / "ss.txt").write_text(sortie)
    executable(faux / "ss", f"#!/bin/sh\ncat {tmp_path}/ss.txt\nexit {rc}\n")
    executable(faux / "chown", "#!/bin/sh\nexit 0\n")
    texte = bloc(DEBUT_SOCK, FIN_SOCK).replace("/run/secubox", str(d))
    for a, b in remplace:
        assert a in texte, a
        texte = texte.replace(a, b)
    return lance(tmp_path, f'RT_UNITES="{avant}"\n' + texte)


def ligne(d, nom, pid):
    return f'u_str LISTEN 0 2048 {d}/{nom}.sock 12345 * 0 users:(("uvicorn",pid={pid},fd=3))\n'


def restes(d):
    return sorted(p.name for p in d.iterdir())


TOUT = ["aggregator.sock", "hub.sock", "morte.sock"]


def test_seule_une_socket_morte_est_retiree(tmp_path, faux, run):
    r = lance_sock(tmp_path, faux, run, ligne(run, "aggregator", os.getpid()) + ligne(run, "hub", os.getpid()))
    assert r.returncode == 0 and "FIN" in r.stdout, r.stderr
    assert restes(run) == ["aggregator.sock", "hub.sock"]
    assert not any("restart" in a for a in appels(tmp_path))


@pytest.mark.parametrize("sortie,rc", [("", 0), ("", 1), ("@@", 1), ("u_str LISTEN 0 5 /run/systemd/private 1 * 0\n", 0),
                                       ("u_str LISTEN 0 5 D/inconnue.sock 1 * 0 users:((\"x\",pid=1,fd=3))\n", 0)])
def test_liste_vide_en_echec_ou_sans_socket_connue_rien_n_est_retire(tmp_path, faux, run, sortie, rc):
    sortie = sortie.replace("@@", ligne(run, "aggregator", os.getpid()) + ligne(run, "hub", os.getpid())).replace("D/", f"{run}/")
    r = lance_sock(tmp_path, faux, run, sortie, rc)
    assert r.returncode == 0 and "FIN" in r.stdout
    assert restes(run) == TOUT and not any("restart" in a for a in appels(tmp_path))
    assert "rien n'est retiré" in r.stderr


def test_ss_qui_ne_rend_pas_la_main(tmp_path, faux, run):
    texte = bloc(DEBUT_SOCK, FIN_SOCK)
    assert re.search(r"timeout=\d+", texte)
    executable(faux / "ss", "#!/bin/sh\nexec sleep 30\n")
    r = lance(tmp_path, 'RT_UNITES=""\n' + re.sub(r"timeout=\d+", "timeout=1", texte.replace("/run/secubox", str(run))))
    assert r.returncode == 0 and restes(run) == TOUT and "rien n'est retiré" in r.stderr


def test_liste_partielle_une_socket_vivante_absente_ou_sans_pid_reste(tmp_path, faux, run):
    r = lance_sock(tmp_path, faux, run, ligne(run, "aggregator", os.getpid()))       # hub écoute mais manque à la liste
    assert r.returncode == 0 and "hub.sock" in restes(run)
    r = lance_sock(tmp_path, faux, run, ligne(run, "aggregator", os.getpid()) + f"u_str LISTEN 0 5 {run}/hub.sock 1 * 0\n")
    assert r.returncode == 0 and restes(run) == ["aggregator.sock", "hub.sock"]


def _mauvais_proprietaire(tmp_path, cgroups):
    """Fait lire au code du postinst un /proc d'essai : le processus à l'écoute a un autre uid que la socket."""
    for pid, unite in cgroups.items():
        p = tmp_path / "proc" / str(pid)
        p.mkdir(parents=True, exist_ok=True)
        (p / "status").write_text(f"Name:\tx\nUid:\t{os.getuid() + 1}\t1\t1\t1\n")
        (p / "cgroup").write_text(f"0::/system.slice/{unite}\n")
    return (("/proc/", f"{tmp_path}/proc/"),)


def test_socket_mal_attribuee_seule_son_unite_est_relancee(tmp_path, faux, run):
    rem = _mauvais_proprietaire(tmp_path, {4001: "secubox-aggregator.service", 4002: "secubox-hub.service"})
    r = lance_sock(tmp_path, faux, run, ligne(run, "aggregator", 4003) + ligne(run, "hub", 4002), remplace=rem,
                   avant=" secubox-autre.service")
    assert r.returncode == 0 and restes(run) == ["aggregator.sock"], r.stderr
    # ni l'agrégateur, ni une unité dont aucune socket n'a été retirée
    assert [a for a in appels(tmp_path) if "restart" in a] == ["--no-block try-restart secubox-hub.service"]


def test_agregateur_relance_seulement_pour_sa_propre_socket(tmp_path, faux, run):
    rem = _mauvais_proprietaire(tmp_path, {4001: "secubox-aggregator.service"})
    r = lance_sock(tmp_path, faux, run, ligne(run, "aggregator", os.getpid()) + ligne(run, "hub", 4001), remplace=rem)
    assert r.returncode == 0 and "hub.sock" in restes(run)          # la retirer sans relancer la perdrait
    assert not any("restart" in a for a in appels(tmp_path))
    r = lance_sock(tmp_path, faux, run, ligne(run, "aggregator", 4001) + ligne(run, "hub", os.getpid()), remplace=rem)
    assert r.returncode == 0 and "aggregator.sock" not in restes(run)
    assert [a for a in appels(tmp_path) if "restart" in a] == ["--no-block try-restart secubox-aggregator.service"]


# ── 3. secubox-proxy.conf ────────────────────────────────────────────────────────────────────────────────────

DIRECTIVE = "proxy_set_header   X-SecuBox-LAN     $lan_client;"
MODELE = "# commentaire : proxy_set_header X-SecuBox-LAN $lan_client;\nproxy_set_header   Host $host;\n"


def lance_snip(tmp_path, faux, avant, nginx, modele=MODELE):
    (tmp_path / "modele.conf").write_text(modele)
    d = tmp_path / "snippets"
    d.mkdir(exist_ok=True)
    s = d / "secubox-proxy.conf"
    if avant is not None:
        s.write_text(avant)
    executable(faux / "nginx", f"#!/bin/sh\ncp {s} {tmp_path}/essaye.conf 2>/dev/null\necho t >> {tmp_path}/nginx.log\n" + nginx)
    texte = bloc("    # SNIPPET COMMUN DES RELAIS (#3938)", "    install -m 644 /usr/share/secubox-core/nginx/secubox-api-aggregator.conf") \
        .replace("/usr/share/secubox-core/nginx/secubox-proxy.conf", f"{tmp_path}/modele.conf").replace("/etc/nginx/snippets", str(d))
    r = lance(tmp_path, texte)
    assert r.returncode == 0 and "FIN" in r.stdout, r.stderr
    assert [p.name for p in d.iterdir()] in (["secubox-proxy.conf"], [])          # ni temporaire ni sauvegarde oubliés
    return r, s


def directives(s):
    return [x for x in s.read_text().splitlines() if re.match(r"\s*proxy_set_header\s+X-SecuBox-LAN\s", x)]


OK = "exit 0\n"
KO = 'echo "nginx: [emerg] raison du refus" >&2\nexit 1\n'


def lan_inconnu(tmp_path):
    return (f"grep -qE '^[[:space:]]*proxy_set_header[[:space:]]+X-SecuBox-LAN' {tmp_path}/snippets/secubox-proxy.conf && "
            "{ echo 'nginx: [emerg] unknown \"lan_client\" variable' >&2; exit 1; }\nexit 0\n")


def test_snippet_pose_d_un_coup_avec_la_directive(tmp_path, faux):
    r, s = lance_snip(tmp_path, faux, "ancien\n" + DIRECTIVE + "\n", OK)
    assert s.read_text() == MODELE + DIRECTIVE + "\n" and oct(s.stat().st_mode & 0o777) == "0o644"
    assert appels(tmp_path, "nginx") == ["t"]
    # inchangé : ni écriture, ni nginx -t
    ino = s.stat().st_ino
    r, s = lance_snip(tmp_path, faux, None, OK)
    assert s.stat().st_ino == ino and appels(tmp_path, "nginx") == ["t"]


def test_snippet_neuf_sans_fichier_precedent(tmp_path, faux):
    r, s = lance_snip(tmp_path, faux, None, OK)
    assert directives(s) == [DIRECTIVE]


def test_nginx_refuse_pour_une_autre_raison_l_ancien_reste_avec_sa_directive(tmp_path, faux):
    avant = "ancien\n" + DIRECTIVE + "\n"
    r, s = lance_snip(tmp_path, faux, avant, KO)
    assert s.read_text() == avant
    assert "raison du refus" in r.stderr and "secubox-proxy.conf" in r.stderr
    # idem sans directive avant : rien n'est écrasé
    r, s = lance_snip(tmp_path, faux, "ancien\n", KO)
    assert s.read_text() == "ancien\n"


def test_modele_invalide_mais_ancien_valide_la_directive_reste(tmp_path, faux):
    avant = "ancien\n" + DIRECTIVE + "\n"
    r, s = lance_snip(tmp_path, faux, avant, f"grep -q ancien {tmp_path}/snippets/secubox-proxy.conf || {{ echo 'emerg modele' >&2; exit 1; }}\n")
    assert s.read_text() == avant and directives(s) == [DIRECTIVE] and "emerg modele" in r.stderr


@pytest.mark.parametrize("avant", [None, "ancien\n"])
def test_lan_client_inconnue_modele_sans_la_directive_et_le_dit(tmp_path, faux, avant):
    r, s = lance_snip(tmp_path, faux, avant, lan_inconnu(tmp_path))
    assert s.read_text() == MODELE and "lan_client" in r.stderr


def test_premiere_pose_jamais_absente(tmp_path, faux):
    """Aucun fichier avant et nginx refuse (configuration encore incomplète) : le modèle, sans la directive, est posé — d'autres
    fichiers l'incluent."""
    r, s = lance_snip(tmp_path, faux, None, KO)
    assert s.read_text() == MODELE and "raison du refus" in r.stderr


def test_une_seule_ecriture_du_snippet_dans_le_postinst():
    assert "install -m 644 /usr/share/secubox-core/nginx/secubox-proxy.conf" not in POST
    assert POST.count("X-SecuBox-LAN     $lan_client;") == 1


# ── 4. journaux ──────────────────────────────────────────────────────────────────────────────────────────────

def test_masquage_des_journaux_lance_sans_bloquer_dpkg():
    b = bloc("    # JETONS DÉJÀ ÉCRITS", "    systemctl daemon-reload\n")
    code = "\n".join(x for x in b.splitlines() if not x.strip().startswith("#"))
    assert "systemctl start --no-block secubox-masquer-jetons-journaux.service" in code
    assert "enable --now secubox-masquer-jetons-journaux.timer" in code
    # l'appel direct ne reste que sans systemd (chroot d'image)
    assert code.index("[ -d /run/systemd/system ]") < code.index("--no-block") < code.index("/usr/sbin/secubox-masquer-jetons-journaux")
    # dh_installsystemd relancerait l'oneshot en l'attendant
    rules = (PKG / "debian/rules").read_text()
    assert re.search(r"^override_dh_installsystemd:\n\tdh_installsystemd .*-Xsecubox-masquer-jetons-journaux\.service", rules, re.M)
    unite = (PKG / "systemd/secubox-masquer-jetons-journaux.service").read_text()
    assert "Nice=10" in unite and "IOSchedulingClass=idle" in unite and "[Install]" not in unite


def test_postinst_syntaxe():
    subprocess.run(["bash", "-n", str(PKG / "debian/postinst")], check=True, timeout=30)
