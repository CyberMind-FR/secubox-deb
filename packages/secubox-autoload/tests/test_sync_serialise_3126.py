# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126, L2 « Agir », tâche 0 : la projection publique des pairs suit TOUJOURS les révocations (elle ouvre bientôt des actions).

  N2  tunnel-sync exporte la projection même si WireGuard échoue (le code de retour dit l'échec du tunnel) ;
  N3  tunnel-sync et exporter-pairs passent un par un (flock) : un passage horaire qui a lu les pairs AVANT une révocation ne repose plus le
      pair révoqué APRÈS la synchronisation de la révocation ;
  N4  la minuterie horaire (`tunnel-sync --horaire`) ne relance pas un wg-autoload dont l'exploitant a DÉSACTIVÉ l'unité : seulement l'export.
"""
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from secubox_core import auth
from api import main as A
from autoload import jetons as J, tunnel as T

ICI = Path(__file__).resolve().parents[1]
CLE_A = "A" * 43 + "="
HUB = "H" * 43 + "="
UNITE = "wg-quick@wg-autoload.service"


def _charger_ctl():
    ldr = importlib.machinery.SourceFileLoader("autoloadctl_3126_l2", str(ICI / "sbin" / "autoloadctl"))
    spec = importlib.util.spec_from_loader("autoloadctl_3126_l2", ldr)
    m = importlib.util.module_from_spec(spec)
    ldr.exec_module(m)
    return m


def _ctl(ctl, *argv):
    """Le code de retour de `autoloadctl argv…`, y compris un refus d'argparse (2)."""
    try:
        return ctl.main(list(argv))
    except SystemExit as e:
        return e.code


class R:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


class FauxSysteme:
    """wg-quick, wg et systemctl factices : wg-autoload n'est pas montée (wg syncconf échoue) ; son unité est activée ou non."""

    def __init__(self, unite_activee: bool):
        self.unite_activee, self.appels = unite_activee, []

    def __call__(self, argv, **kw):
        self.appels.append(list(argv))
        if argv[:2] == ["wg-quick", "strip"]:
            return R(0, "[Interface]\nAddress = 10.64.0.1/16\nListenPort = 51830\n")
        if argv[:2] == ["wg", "syncconf"]:
            return R(1, err="Unable to access interface: No such device")
        if argv[:2] == ["systemctl", "is-enabled"]:
            return R(0 if self.unite_activee else 1, "enabled\n" if self.unite_activee else "disabled\n")
        return R(0)

    def demarrages(self):
        return [a for a in self.appels if a[0] == "systemctl" and {"start", "restart", "enable", "reload-or-restart"} & set(a)]


@pytest.fixture
def base(tmp_path, monkeypatch):
    var = tmp_path / "var"
    var.mkdir(mode=0o750)
    db = var / "jetons.db"
    monkeypatch.setenv("SECUBOX_AUTOLOAD_DB", str(db))
    monkeypatch.setenv("SECUBOX_AUTOLOAD_AUDIT", str(tmp_path / "audit.log"))
    reg = J.Registre(db, tmp_path / "audit.log")
    pairs = T.Pairs(db)
    e = reg.emettre("lgm", "lite", lot="lot-1", serie="SBX-1")
    reg.reclamer(e.valeur, CLE_A)
    assert pairs.attribuer(CLE_A) == "10.64.0.2"
    return {"db": db, "reg": reg, "pairs": pairs, "id": e.id, "sortie": tmp_path / "autoload-public" / "pairs-publics.json",
            "verrou": tmp_path / "autoload-sync.lock"}


def _clients(b):
    return {p["client"]: p["abonnement"] for p in json.loads(b["sortie"].read_text())["pairs"]}


def _brancher(ctl, monkeypatch, tmp_path, unite_activee):
    """Le vrai `synchroniser`, sur de vrais fichiers (clé du hub, configuration), avec un système factice."""
    cle = tmp_path / "hub.key"
    cle.write_text("K" * 43 + "=\n")
    monkeypatch.setenv("SECUBOX_AUTOLOAD_CLE_HUB", str(cle))
    monkeypatch.setenv("SECUBOX_AUTOLOAD_CONF_WG", str(tmp_path / "wg" / "wg-autoload.conf"))
    systeme, vrai = FauxSysteme(unite_activee), ctl.T.synchroniser
    monkeypatch.setattr(ctl.T, "synchroniser", lambda *a, **k: vrai(*a, executeur=systeme, **k))
    return systeme


# ── N2 ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("panne", [T.TunnelErreur("tunnel non monté : wg-quick@wg-autoload absent"), subprocess.TimeoutExpired("wg", 30),
                                   OSError(5, "Input/output error")])
def test_export_meme_si_wireguard_echoue(base, monkeypatch, capsys, panne):
    ctl = _charger_ctl()
    monkeypatch.setattr(ctl.T, "synchroniser", lambda *a, **k: 1)
    assert ctl.main(["tunnel-sync"]) == 0 and _clients(base) == {"lgm": "actif"}
    base["pairs"].retirer(base["reg"].revoquer(base["id"], "box volée"))

    def en_panne(*a, **k):
        raise panne
    monkeypatch.setattr(ctl.T, "synchroniser", en_panne)
    assert ctl.main(["tunnel-sync"]) == 1                    # le tunnel a échoué : le code de retour le dit…
    assert _clients(base) == {}                              # …mais la révocation a atteint la projection
    assert "tunnel" in capsys.readouterr().err


# ── N3 ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("passage", [("tunnel-sync", "--horaire"), ("tunnel-sync",)], ids=["minuterie", "enrolement"])
def test_revocation_et_sync_serialisees(base, monkeypatch, passage):
    """Le passage horaire (ou un enrôlement) lit les pairs (lgm encore actif) puis traîne ; la révocation arrive par l'API, qui relance
    tunnel-sync. Sans verrou, la synchronisation de la révocation passait d'abord, puis le passage lent reposait sa liste périmée : lgm revenait
    pour une heure."""
    ctl = _charger_ctl()
    lu, reprendre = threading.Event(), threading.Event()
    appliques = []

    def synchro(pairs, *a, **k):
        actifs = [p["adresse"] for p in pairs.actifs()]
        if threading.current_thread().name == "horaire":
            lu.set()
            reprendre.wait(5)
        appliques.append((threading.current_thread().name, actifs))
        return len(actifs)
    monkeypatch.setattr(ctl.T, "synchroniser", synchro)

    def appliquer():                                         # ce que fait `sudo -n /usr/sbin/autoloadctl tunnel-sync`
        if ctl.main(["tunnel-sync"]) != 0:
            raise T.TunnelErreur("tunnel-sync en échec")
    app = A.creer_app(base["reg"], base["pairs"], HUB, appliquer)
    app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
    client = TestClient(app)

    horaire = threading.Thread(target=_ctl, args=(ctl, *passage), name="horaire")
    horaire.start()
    assert lu.wait(5)
    reponse = {}
    revocation = threading.Thread(target=lambda: reponse.update(r=client.post(f"/jetons/{base['id']}/revoquer", json={"motif": "box volée"})))
    revocation.start()
    revocation.join(0.5)                                     # sans verrou, la révocation est appliquée ET publiée ici, avant la fin de l'horaire
    reprendre.set()
    horaire.join(10)
    revocation.join(10)
    assert not horaire.is_alive() and not revocation.is_alive()
    assert reponse["r"].status_code == 200 and reponse["r"].json()["tunnel_applique"] is True
    assert appliques[0] == ("horaire", ["10.64.0.2"])
    assert appliques[-1][1] == [], appliques                 # le dernier état posé sur le tunnel n'a plus le pair révoqué
    assert _clients(base) == {}


def test_exporter_pairs_attend_le_verrou(base):
    ctl = _charger_ctl()
    fini = threading.Event()
    with T.verrou_sync(base["verrou"]):
        t = threading.Thread(target=lambda: (ctl.main(["exporter-pairs"]), fini.set()))
        t.start()
        assert not fini.wait(0.4)                            # un tunnel-sync en cours : l'export attend son tour
    assert fini.wait(5) and _clients(base) == {"lgm": "actif"}


@pytest.mark.parametrize("piege", ["lien", "fifo"])
def test_verrou_piege_remplace_jamais_suivi(base, tmp_path, piege):
    """/run/secubox est 1777 : un autre compte peut y poser le nom du verrou avant root. Un lien n'est jamais suivi, une FIFO jamais gardée."""
    victime = tmp_path / "victime"
    victime.write_text("intact")
    if piege == "lien":
        base["verrou"].symlink_to(victime)
    else:
        os.mkfifo(base["verrou"])
    assert _charger_ctl().main(["exporter-pairs"]) == 0
    assert victime.read_text() == "intact"
    assert base["verrou"].is_file() and not base["verrou"].is_symlink()


# ── N4 ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_minuterie_ne_relance_pas_wg_desactive(base, monkeypatch, tmp_path, capsys):
    ctl = _charger_ctl()
    systeme = _brancher(ctl, monkeypatch, tmp_path, unite_activee=False)
    assert _ctl(ctl, "tunnel-sync", "--horaire") == 0
    assert systeme.demarrages() == []                        # ni enable, ni start : l'exploitant l'a arrêtée
    assert (tmp_path / "wg" / "wg-autoload.conf").is_file()  # la configuration est posée pour le jour où il la relance
    assert _clients(base) == {"lgm": "actif"}                # et la projection est publiée
    assert "désactivée" in capsys.readouterr().err


def test_minuterie_relance_un_wg_active_tombe(base, monkeypatch, tmp_path):
    ctl = _charger_ctl()
    systeme = _brancher(ctl, monkeypatch, tmp_path, unite_activee=True)
    assert _ctl(ctl, "tunnel-sync", "--horaire") == 0
    assert systeme.demarrages() == [["systemctl", "enable", "--now", UNITE]]
    assert _clients(base) == {"lgm": "actif"}


def test_enrolement_monte_toujours_le_tunnel(base, monkeypatch, tmp_path):
    """Sans --horaire (enrôlement, révocation, abonnement) : inchangé, l'interface est montée même jamais activée (première box)."""
    ctl = _charger_ctl()
    systeme = _brancher(ctl, monkeypatch, tmp_path, unite_activee=False)
    assert _ctl(ctl, "tunnel-sync") == 0
    assert systeme.demarrages() == [["systemctl", "enable", "--now", UNITE]]


def test_la_minuterie_passe_par_l_argv_horaire():
    vus = []
    T.appliquer_horaire_par_sudo(lambda argv, **kw: (vus.append(argv), R())[1])
    assert vus == [["sudo", "-n", "/usr/sbin/autoloadctl", "tunnel-sync", "--horaire"]]
    lanceur = (ICI / "sbin" / "secubox-autoload-api").read_text()
    assert "T.republier_periodiquement(T.appliquer_horaire_par_sudo)" in lanceur
    sudoers = [x for x in (ICI / "sudoers.d" / "secubox-autoload").read_text().splitlines() if x and not x.startswith("#")]
    assert "secubox-autoload ALL=(root) NOPASSWD: /usr/sbin/autoloadctl " + " ".join(vus[0][3:]) in sudoers


def test_l_export_lance_par_le_service_peut_ecrire():
    """L'assistant root lancé par sudo HÉRITE de l'espace de montage de l'unité (ProtectSystem=strict) : sans le dossier de la projection dans
    ReadWritePaths, l'export de la minuterie et des révocations par l'API échouait en lecture seule (seul `autoloadctl` lancé à la main
    publiait). Le dossier doit exister avant le démarrage du service pour être monté en écriture : le postinst l'exporte d'abord."""
    unite = (ICI / "systemd" / "secubox-autoload.service").read_text().splitlines()
    chemins = [c for x in unite if x.startswith("ReadWritePaths=") for c in x.split("=", 1)[1].split()]
    assert "-/var/lib/secubox/autoload-public" in chemins
    assert {"/run/secubox", "/etc/wireguard"} <= set(chemins)                                 # le verrou et la configuration du tunnel
    post = (ICI / "debian" / "postinst").read_text()
    assert "/usr/sbin/autoloadctl exporter-pairs" in post
    assert post.index("/usr/sbin/autoloadctl exporter-pairs") < post.index("systemctl enable secubox-autoload.service")
