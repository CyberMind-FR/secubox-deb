"""secubox-wait-network.sh — fiabilite du demarrage (#998).

Le 2026-08-06, un redemarrage a laisse la board 53 minutes SANS HTTPS. La
chaine : l'assistant d'attente etait ecrit pour une autre topologie (il
attendait l'adresse de gestion sur `lan0`, un port sans porteuse ici),
echouait, et HAProxy en dependait par `Requires=` — son job etait abandonne
sans la moindre trace au journal.

Ces tests figent les trois regles nees de cette panne.
"""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "usr" / "bin" / "secubox-wait-network.sh"
UNIT = ROOT / "systemd" / "secubox-network-ready.service"
HAPROXY_DROPIN = ROOT / "systemd" / "haproxy.service.d" / "secubox-wait-network.conf"
WAITONLINE = (ROOT / "systemd" / "systemd-networkd-wait-online.service.d"
              / "secubox-any.conf")


def test_script_is_syntactically_valid():
    assert subprocess.run(["bash", "-n", str(SCRIPT)]).returncode == 0


def test_no_interface_is_hardcoded():
    """L'ancienne version attendait `lan0`, absent du cablage de cette board.

    Une interface codee en dur rend le script juste sur une topologie et faux
    sur toutes les autres."""
    src = SCRIPT.read_text()
    body = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
    for bad in ("lan0", "lan1", "eth2"):
        assert not re.search(rf"\b{bad}\b", body), \
            f"interface codee en dur dans le code : {bad}"


def test_never_assigns_the_management_ip_to_a_guessed_interface():
    """Le repli precedent faisait `ip addr add 192.168.1.200/24 dev lan0`.

    Il posait l'adresse de gestion sur un port mort — ce qui ne retablissait
    rien et pouvait creer un doublon d'adresse sur le reseau."""
    body = "\n".join(l for l in SCRIPT.read_text().splitlines()
                     if not l.lstrip().startswith("#"))
    assert "192.168.1." not in body, "aucune adresse de gestion en dur"
    adds = [l for l in body.splitlines() if "ip addr add" in l]
    for line in adds:
        assert "dev lo" in line, \
            f"seule l'adresse de bouclage peut etre posee : {line.strip()}"


def test_script_always_succeeds():
    """Un assistant d'attente ne doit pas pouvoir emporter le frontal TLS."""
    body = SCRIPT.read_text()
    assert body.rstrip().endswith("exit 0"), "le script doit toujours sortir en succes"
    assert "set -e" not in body.replace("set -euo", "").replace("set -uo", ""), \
        "un `set -e` ferait echouer le script sur la premiere commande en erreur"


def test_haproxy_depends_weakly():
    """`Requires=` fait ABANDONNER le job d'HAProxy si l'attente echoue.

    Sans trace au journal — c'est ce qui a rendu la panne indiagnosticable.
    Un frontal TLS mort n'ecoutera jamais ; demarre sans reseau, il ecoutera
    des que le reseau viendra."""
    conf = HAPROXY_DROPIN.read_text()
    assert "Wants=secubox-network-ready.service" in conf
    assert not re.search(r"^Requires=", conf, re.M), \
        "Requires= reintroduit la panne du 2026-08-06"


def test_wait_online_does_not_wait_for_unplugged_ports():
    """lan0..lan3 sont les ports du switch : sans cable ils ne seront jamais
    configures, et l'unite echouait a chaque demarrage."""
    assert "--any" in WAITONLINE.read_text()


def test_unit_timeout_is_bounded():
    """180 s suspendaient le demarrage trois minutes avant meme d'echouer."""
    m = re.search(r"^TimeoutStartSec=(\d+)", UNIT.read_text(), re.M)
    assert m and int(m.group(1)) <= 120, "l'attente doit rester bornee"
