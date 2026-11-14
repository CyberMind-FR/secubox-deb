# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""waf-blocs (#3716), tâche 2 : table nft des blocs, état root, réapplication, wafctl, sudoers, unité.

Aucun appel nft réel hors d'un espace de noms jetable (`unshare -rn`) : nft est simulé partout ailleurs.
"""

import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

COMPOSANT = Path(__file__).resolve().parents[1]
PAQUET = COMPOSANT.parents[1]
CHEMIN = COMPOSANT / "scripts" / "waf-blocs"
WAFCTL = COMPOSANT / "scripts" / "wafctl"
SUDOERS = COMPOSANT / "sudoers" / "secubox-waf"
TABLE = COMPOSANT / "config" / "blocs.nft"
UNITE = PAQUET / "systemd" / "secubox-waf-blocs.service"
TMPFILES = PAQUET / "tmpfiles.d" / "secubox-waf-ng.conf"
RULES = PAQUET / "debian" / "rules"

HOTE = json.dumps([{"addr_info": [{"local": "198.18.0.1"}]}])


@pytest.fixture
def wb():
    chargeur = importlib.machinery.SourceFileLoader("waf_blocs", str(CHEMIN))
    spec = importlib.util.spec_from_loader("waf_blocs", chargeur)
    module = importlib.util.module_from_spec(spec)
    chargeur.exec_module(module)
    return module


@pytest.fixture
def etat(wb, tmp_path, monkeypatch):
    """Dossier d'état « root » (le propriétaire attendu devient l'utilisateur des essais), protégées vides, audit local."""
    dossier = tmp_path / "etat"
    dossier.mkdir(mode=0o700)
    monkeypatch.setattr(wb, "ETAT_DOSSIER", dossier)
    monkeypatch.setattr(wb, "PROPRIETAIRE", os.getuid())
    monkeypatch.setattr(wb, "AUDIT_LOG", tmp_path / "audit.log")
    protegees = tmp_path / "protegees.env"
    protegees.write_text("SECUBOX_WAF_PROTEGEES=\n")
    monkeypatch.setattr(wb, "PROTEGEES_ENV", protegees)
    return dossier


@pytest.fixture
def protegee_203(wb, etat):
    wb.PROTEGEES_ENV.write_text("SECUBOX_WAF_PROTEGEES=203.0.113.0/24\n")


class FauxNft:
    """Exécuteur simulé : `ip`/`wg` rendent une box ordinaire ; les appels nft sont notés dans `appels`."""

    def __init__(self, wb, echecs=(), sortie_set=""):
        self.wb = wb
        self.appels = []
        self.echecs = echecs          # préfixes d'argv nft qui échouent (CalledProcessError)
        self.sortie_set = sortie_set

    def __call__(self, argv):
        if argv[0] == self.wb.IP:
            return HOTE
        if argv[0] == self.wb.WG:
            return ""
        self.appels.append(list(argv))
        if any(argv[:len(e)] == list(e) for e in self.echecs):
            raise subprocess.CalledProcessError(1, argv)
        if argv[:3] == ["nft", "-j", "list"]:
            return self.sortie_set
        return ""


@pytest.fixture
def nft(wb):
    return FauxNft(wb)


@pytest.fixture
def nft_absent(wb):
    return FauxNft(wb, echecs=(["nft", "delete", "element"], ["nft", "get", "element"]))


def audit(wb):
    try:
        return [json.loads(ligne) for ligne in Path(wb.AUDIT_LOG).read_text().splitlines()]
    except FileNotFoundError:
        return []


# --- essais du brief ---------------------------------------------------------

def test_ajouter_pose_l_element_avec_timeout_et_ecrit_l_etat(wb, etat, nft):
    r = wb.ajouter("203.0.113.0/24", 3600, nft, 1_800_000_000)
    assert r["ok"] and ["nft", "add", "element", "inet", "secubox_waf_blocs", "blocs4",
                        "{ 203.0.113.0/24 timeout 3600s }"] in nft.appels
    assert wb.lire_etat(etat) == [{"bloc": "203.0.113.0/24", "debut": 1_800_000_000, "fin": 1_800_003_600}]


def test_ajouter_refuse_avant_nft_si_protegee(wb, etat, nft, protegee_203):
    assert wb.ajouter("203.0.113.0/24", 3600, nft, 0)["motif"] == "protegee" and nft.appels == []


def test_duree_hors_bornes(wb, etat, nft):
    assert wb.ajouter("203.0.113.0/24", 3599, nft, 0)["motif"] == "duree"
    assert wb.ajouter("203.0.113.0/24", 604_801, nft, 0)["motif"] == "duree"


def test_retirer_absent_n_est_pas_une_erreur(wb, etat, nft_absent):
    assert wb.retirer("203.0.113.0/24", nft_absent)["ok"] is True


def test_reappliquer_rejoue_les_blocs_non_echus_avec_le_reste(wb, etat, nft):
    wb.ecrire_etat(etat, [{"bloc": "203.0.113.0/24", "debut": 0, "fin": 1000},
                          {"bloc": "198.51.100.0/24", "debut": 0, "fin": 500}])
    assert wb.reappliquer(nft, 600) == 1
    assert ["nft", "-f", str(wb.FICHIER_TABLE)] in nft.appels
    assert ["nft", "add", "element", "inet", "secubox_waf_blocs", "blocs4", "{ 203.0.113.0/24 timeout 400s }"] in nft.appels


def test_reappliquer_ignore_une_entree_forgee(wb, etat, nft):
    wb.ecrire_etat(etat, [{"bloc": "10.0.0.0/8", "debut": 0, "fin": 10**10}])   # forme valide, contenu hors gardes
    assert wb.reappliquer(nft, 0) == 0
    assert not [a for a in nft.appels if a[:3] == ["nft", "add", "element"]]


def test_etat_refuse_un_lien_ou_un_dossier_non_root(wb, tmp_path, monkeypatch):
    if os.getuid() == 0:
        pytest.skip("essai d'un dossier non root : impossible en root")
    dossier = tmp_path / "vrai"
    dossier.mkdir(mode=0o700)
    # Propriétaire attendu root (valeur livrée) : le dossier de l'utilisateur des essais est refusé.
    with pytest.raises(wb.GardeIllisible):
        wb.lire_etat(dossier)
    with pytest.raises(wb.GardeIllisible):
        wb.ecrire_etat(dossier, [])
    # Lien symbolique : refusé même quand son propriétaire serait le bon.
    monkeypatch.setattr(wb, "PROPRIETAIRE", os.getuid())
    lien = tmp_path / "lien"
    lien.symlink_to(dossier)
    with pytest.raises(wb.GardeIllisible):
        wb.lire_etat(lien)
    with pytest.raises(wb.GardeIllisible):
        wb.ecrire_etat(lien, [])
    # Fichier d'état en lien symbolique dans un bon dossier : refusé aussi.
    (dossier / "ailleurs.json").write_text("[]")
    (dossier / "blocs.json").symlink_to(dossier / "ailleurs.json")
    with pytest.raises(wb.GardeIllisible):
        wb.lire_etat(dossier)


def test_fichier_nft_rejouable_dans_un_espace_de_noms(tmp_path):
    nft_bin = shutil.which("nft") or "/usr/sbin/nft"
    if not Path(nft_bin).exists():
        pytest.skip("nft absent")
    if subprocess.run(["unshare", "-rn", "true"], check=False, timeout=10, capture_output=True).returncode != 0:
        pytest.skip("unshare -rn refusé sur ce poste : essai au banc")
    script = (f'set -e; {nft_bin} -f "$1"; {nft_bin} -f "$1"; '
              f'{nft_bin} add element inet secubox_waf_blocs blocs4 "{{ 203.0.113.0/24 timeout 60s }}"; '
              f'{nft_bin} -j list set inet secubox_waf_blocs blocs4')
    r = subprocess.run(["unshare", "-rn", "sh", "-c", script, "sh", str(TABLE)],
                       check=False, timeout=30, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    ensemble = [o["set"] for o in json.loads(r.stdout)["nftables"] if "set" in o][0]
    assert set(ensemble["flags"]) == {"interval", "timeout"}
    assert ensemble["elem"][0]["elem"]["val"]["prefix"] == {"addr": "203.0.113.0", "len": 24}


def test_wafctl_verbes_et_ban_verifie():
    t = WAFCTL.read_text()
    assert "ban-bloc)" in t and "unban-bloc)" in t and "blocs)" in t
    assert "/usr/sbin/waf-blocs verifier" in t        # cmd_ban passe par la garde
    assert subprocess.run(["bash", "-n", str(WAFCTL)], check=False, timeout=10).returncode == 0


def test_sudoers_bornes_et_visudo():
    t = SUDOERS.read_text()
    assert "/usr/bin/systemd-run --wait --pipe --collect --quiet /usr/sbin/wafctl ban-bloc *" in t
    assert "/usr/bin/systemd-run --wait --pipe --collect --quiet /usr/sbin/wafctl unban-bloc *" in t
    assert "/usr/sbin/wafctl blocs" in t
    assert "cle-ai-ban" not in t                     # la gestion des clés reste à root
    assert "/usr/sbin/waf-blocs" not in t            # secubox n'obtient jamais le script lui-même
    for ligne in ("Defaults!SBX_WAF_BLOCS !requiretty", "Defaults!SBX_WAF_BLOCS log_output",
                  "secubox ALL=(root) NOPASSWD: SBX_WAF_BLOCS"):
        assert ligne in t
    visudo = shutil.which("visudo") or "/usr/sbin/visudo"
    if not Path(visudo).exists():
        pytest.skip("visudo absent")
    r = subprocess.run([visudo, "-c", "-f", str(SUDOERS)], check=False, timeout=10, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_unite_reappliquer_suit_nftables():
    u = UNITE.read_text()
    for attendu in ("PartOf=nftables.service", "ReloadPropagatedFrom=nftables.service",
              "ExecReload=/usr/sbin/waf-blocs reappliquer", "UMask=0027", "NoNewPrivileges=yes"):
        assert attendu in u
    for attendu in ("Type=oneshot", "RemainAfterExit=yes", "ExecStart=/usr/sbin/waf-blocs reappliquer",
              "After=nftables.service", "WantedBy=multi-user.target", "ProtectSystem=strict",
              "ReadWritePaths=/var/lib/secubox-waf-blocs /var/log/secubox", "ProtectHome=yes", "PrivateTmp=yes",
              "CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_OVERRIDE", "RestrictAddressFamilies=AF_NETLINK AF_UNIX"):
        assert attendu in u


def test_tmpfiles_dossier_root_0700():
    assert "d /var/lib/secubox-waf-blocs 0700 root root -" in TMPFILES.read_text()


# --- essais complémentaires --------------------------------------------------

def test_ajouter_audite_et_supprime_avant_d_ajouter(wb, etat, nft):
    wb.ajouter("203.0.113.0/24", 7200, nft, 100)
    sup = ["nft", "delete", "element", "inet", "secubox_waf_blocs", "blocs4", "{ 203.0.113.0/24 }"]
    aj = ["nft", "add", "element", "inet", "secubox_waf_blocs", "blocs4", "{ 203.0.113.0/24 timeout 7200s }"]
    assert nft.appels.index(sup) < nft.appels.index(aj)   # un add ne change pas le timeout d'un élément présent
    lignes = audit(wb)
    assert len(lignes) == 1 and {k: lignes[0][k] for k in ("module", "action", "by")} == {
        "module": "waf", "action": "ban-bloc", "by": "wafctl"}
    assert "203.0.113.0/24" in lignes[0]["detail"] and lignes[0]["ts"].endswith("Z")


def test_ajouter_deux_fois_remplace_l_entree(wb, etat, nft):
    wb.ajouter("203.0.113.0/24", 3600, nft, 100)
    wb.ajouter("203.0.113.0/24", 86400, nft, 200)
    assert wb.lire_etat(etat) == [{"bloc": "203.0.113.0/24", "debut": 200, "fin": 86600}]


def test_ajouter_purge_les_entrees_echues(wb, etat, nft):
    wb.ecrire_etat(etat, [{"bloc": "198.51.100.0/24", "debut": 0, "fin": 50}])
    wb.ajouter("203.0.113.0/24", 3600, nft, 100)
    assert [e["bloc"] for e in wb.lire_etat(etat)] == ["203.0.113.0/24"]


def test_ajouter_charge_la_table_absente(wb, etat):
    faux = FauxNft(wb, echecs=(["nft", "list", "table"],))
    assert wb.ajouter("203.0.113.0/24", 3600, faux, 0)["ok"]
    assert ["nft", "-f", str(wb.FICHIER_TABLE)] in faux.appels


def test_ajouter_nft_refuse_rien_ecrit(wb, etat):
    faux = FauxNft(wb, echecs=(["nft", "add", "element"],))
    r = wb.ajouter("203.0.113.0/24", 3600, faux, 0)
    assert r == {"ok": False, "motif": "nft"}
    assert wb.lire_etat(etat) == [] and audit(wb) == []


def test_ajouter_refuse_la_forme_et_la_garde_illisible(wb, etat, nft):
    for faux in ("203.0.113.7/24", "203.0.113.0/23", "2001:db8::/64", "203.0.113.7"):
        assert wb.ajouter(faux, 3600, nft, 0)["motif"] == "invalide"
    wb.PROTEGEES_ENV.unlink()                          # P2 : fichier absent => aucun bloc
    assert wb.ajouter("203.0.113.0/24", 3600, nft, 0)["motif"] == "garde_illisible"
    assert nft.appels == []


def test_ajouter_refuse_l_adresse_de_la_box(wb, etat):
    class Box(FauxNft):
        def __call__(self, argv):
            if argv[0] == self.wb.IP:
                return json.dumps([{"addr_info": [{"local": "203.0.113.10"}]}])
            return super().__call__(argv)
    faux = Box(wb)
    assert wb.ajouter("203.0.113.0/24", 3600, faux, 0)["motif"] == "box" and faux.appels == []


def test_ajouter_etat_illisible_refuse_avant_nft(wb, etat, nft):
    (etat / "blocs.json").write_text("{pas du json")
    os.chmod(etat / "blocs.json", 0o600)
    assert wb.ajouter("203.0.113.0/24", 3600, nft, 0)["motif"] == "etat" and nft.appels == []


def test_audit_en_echec_retire_le_ban(wb, etat, nft, monkeypatch, tmp_path):
    monkeypatch.setattr(wb, "AUDIT_LOG", tmp_path / "absent" / "audit.log")
    r = wb.ajouter("203.0.113.0/24", 3600, nft, 0)
    assert r == {"ok": False, "motif": "audit"}
    assert nft.appels[-1] == ["nft", "delete", "element", "inet", "secubox_waf_blocs", "blocs4", "{ 203.0.113.0/24 }"]
    assert wb.lire_etat(etat) == []


def test_retirer_enleve_l_etat_et_audite(wb, etat, nft):
    wb.ajouter("203.0.113.0/24", 3600, nft, 0)
    r = wb.retirer("203.0.113.0/24", nft)
    assert r["ok"] is True and wb.lire_etat(etat) == []
    assert [ligne["action"] for ligne in audit(wb)] == ["ban-bloc", "unban-bloc"]


def test_retirer_element_present_mais_suppression_refusee(wb, etat):
    faux = FauxNft(wb, echecs=(["nft", "delete", "element"],))   # `get element` réussit : il est encore là
    assert wb.retirer("203.0.113.0/24", faux) == {"ok": False, "motif": "nft"}


def test_retirer_forme_invalide(wb, etat, nft):
    assert wb.retirer("10.0.0.0/8", nft)["motif"] == "invalide" and nft.appels == []


def test_reappliquer_regarde_les_gardes_et_le_plafond(wb, etat, nft, protegee_203):
    wb.ecrire_etat(etat, [{"bloc": "203.0.113.0/24", "debut": 0, "fin": 1000},        # protégée depuis
                          {"bloc": "192.0.2.0/24", "debut": 0, "fin": 700_000},       # reste > 7 j : forgée
                          {"bloc": "198.51.100.0/24", "debut": 0, "fin": 5000}])
    assert wb.reappliquer(nft, 0) == 1
    ajouts = [a for a in nft.appels if a[:3] == ["nft", "add", "element"]]
    assert ajouts == [["nft", "add", "element", "inet", "secubox_waf_blocs", "blocs4", "{ 198.51.100.0/24 timeout 5000s }"]]


def test_reappliquer_charge_la_table_avant_tout(wb, etat, nft):
    assert wb.reappliquer(nft, 0) == 0
    assert nft.appels[0] == ["nft", "-f", str(wb.FICHIER_TABLE)]


def test_reappliquer_table_refusee(wb, etat):
    faux = FauxNft(wb, echecs=(["nft", "-f"],))
    with pytest.raises(wb.ErreurNft):
        wb.reappliquer(faux, 0)


def test_reappliquer_dossier_illisible_charge_quand_meme_la_table(wb, etat, nft, monkeypatch, tmp_path):
    monkeypatch.setattr(wb, "ETAT_DOSSIER", tmp_path / "absent")
    with pytest.raises(wb.GardeIllisible):
        wb.reappliquer(nft, 0)
    assert nft.appels == [["nft", "-f", str(wb.FICHIER_TABLE)]]


def test_ecrire_etat_refuse_un_schema_faux_sans_trace(wb, etat):
    for faux in ([{"bloc": "203.0.113.0/24", "debut": 0}], [{"bloc": 1, "debut": 0, "fin": 1}],
                 [{"bloc": "203.0.113.0/24", "debut": True, "fin": 1}], {"bloc": "x"},
                 [{"bloc": "203.0.113.0/24", "debut": 5, "fin": 1}]):
        with pytest.raises(ValueError):
            wb.ecrire_etat(etat, faux)
    assert sorted(p.name for p in etat.iterdir()) == []


def test_etat_fichier_0600_et_schema_relu(wb, etat):
    wb.ecrire_etat(etat, [{"bloc": "203.0.113.0/24", "debut": 0, "fin": 10}])
    assert (os.stat(etat / "blocs.json").st_mode & 0o777) == 0o600
    assert sorted(p.name for p in etat.iterdir()) == ["blocs.json"]
    os.chmod(etat / "blocs.json", 0o644)              # lisible par d'autres : refusé
    with pytest.raises(wb.GardeIllisible):
        wb.lire_etat(etat)
    os.chmod(etat / "blocs.json", 0o600)
    (etat / "blocs.json").write_text('[{"bloc": "203.0.113.0/24"}]')
    with pytest.raises(wb.GardeIllisible):
        wb.lire_etat(etat)


def test_lister_marque_les_blocs_presents_dans_nft(wb, etat):
    wb.ecrire_etat(etat, [{"bloc": "203.0.113.0/24", "debut": 0, "fin": 1000},
                          {"bloc": "198.51.100.0/24", "debut": 0, "fin": 2000},
                          {"bloc": "192.0.2.0/24", "debut": 0, "fin": 10}])
    sortie = json.dumps({"nftables": [{"metainfo": {}}, {"set": {"name": "blocs4", "elem": [
        {"elem": {"val": {"prefix": {"addr": "203.0.113.0", "len": 24}}, "timeout": 1000, "expires": 900}}]}}]})
    faux = FauxNft(wb, sortie_set=sortie)
    assert wb.lister(faux, 100) == [
        {"bloc": "203.0.113.0/24", "debut": 0, "fin": 1000, "reste": 900, "actif": True},
        {"bloc": "198.51.100.0/24", "debut": 0, "fin": 2000, "reste": 1900, "actif": False}]


def test_lister_nft_illisible_actif_inconnu(wb, etat):
    wb.ecrire_etat(etat, [{"bloc": "203.0.113.0/24", "debut": 0, "fin": 1000}])
    faux = FauxNft(wb, echecs=(["nft", "-j"],))
    assert wb.lister(faux, 0)[0]["actif"] is None


def _cli(wb, monkeypatch, nft, *argv):
    monkeypatch.setattr(wb, "executer", nft)
    monkeypatch.setattr(wb.time, "time", lambda: 1_000)
    return wb.main(list(argv))


def test_cli_ajouter_retirer_lister_reappliquer(wb, etat, nft, monkeypatch, capsys):
    assert _cli(wb, monkeypatch, nft, "ajouter", "203.0.113.0/24", "3600") == 0
    sortie = capsys.readouterr().out
    assert sortie.count("\n") == 1 and json.loads(sortie) == {
        "ok": True, "motif": None, "bloc": "203.0.113.0/24", "debut": 1000, "fin": 4600}
    assert _cli(wb, monkeypatch, nft, "lister") == 0
    assert json.loads(capsys.readouterr().out)["blocs"][0]["bloc"] == "203.0.113.0/24"
    assert _cli(wb, monkeypatch, nft, "reappliquer") == 0
    assert json.loads(capsys.readouterr().out) == {"ok": True, "motif": None, "rejoues": 1}
    assert _cli(wb, monkeypatch, nft, "retirer", "203.0.113.0/24") == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_cli_codes_des_nouveaux_motifs(wb, etat, monkeypatch, capsys):
    faux = FauxNft(wb, echecs=(["nft", "add", "element"],))
    assert _cli(wb, monkeypatch, faux, "ajouter", "203.0.113.0/24", "3600") == 7
    assert json.loads(capsys.readouterr().out) == {"ok": False, "motif": "nft"}
    assert _cli(wb, monkeypatch, faux, "ajouter", "203.0.113.0/24", "1h") == wb.CODES["duree"]
    assert _cli(wb, monkeypatch, faux, "ajouter", "203.0.113.0/24", "60") == wb.CODES["duree"]
    assert json.loads(capsys.readouterr().out.splitlines()[-1]) == {"ok": False, "motif": "duree"}
    assert _cli(wb, monkeypatch, faux, "ajouter", "203.0.113.0/24") == 64
    assert _cli(wb, monkeypatch, faux, "lister", "x") == 64
    capsys.readouterr()
    assert _cli(wb, monkeypatch, FauxNft(wb, echecs=(["nft", "-f"],)), "reappliquer") == 7
    assert json.loads(capsys.readouterr().out) == {"ok": False, "motif": "nft"}
    assert len({v for k, v in wb.CODES.items()}) == len(wb.CODES)     # un code par motif


def test_executer_chemin_fixe(wb, monkeypatch):
    vus = {}

    def faux_run(argv, **kw):
        vus.update(kw)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
    monkeypatch.setattr(wb.subprocess, "run", faux_run)
    wb.executer(["nft", "list", "ruleset"])
    assert vus["env"]["PATH"] == "/usr/sbin:/usr/bin:/sbin:/bin" and vus["check"] is True and vus["timeout"]


# --- préfixes encapsulés (reliquat de la revue de la tâche 1) ----------------

def test_siit_et_nat64_local_refuses(wb):
    for x in ("::ffff:0:c000:201", "::ffff:0:a00:1", "64:ff9b:1::c000:201", "64:ff9b:1:ffff::1"):
        with pytest.raises(ValueError):
            wb.normaliser_cible(x)
    assert wb.normaliser_cible("64:ff9b:2::1")       # hors /48 local : IPv6 ordinaire


# --- wafctl : verbes de blocs, garde de `ban` ---------------------------------

def _wafctl(*argv):
    return subprocess.run(["bash", str(WAFCTL), *argv], check=False, timeout=10, capture_output=True, text=True)


def test_wafctl_ban_bloc_valide_ses_arguments_avant_waf_blocs():
    r = _wafctl("ban-bloc", "203.0.113.0/24", "4x")
    assert r.returncode == 8 and json.loads(r.stdout) == {"ok": False, "motif": "duree"}
    r = _wafctl("ban-bloc", "203.0.113.0/24", "99999999h")
    assert json.loads(r.stdout)["motif"] == "duree"
    for argv in (("ban-bloc", "203.0.113.0/24"), ("ban-bloc", "203.0.113.0/24", "4h", "x"),
                 ("unban-bloc",), ("unban-bloc", "a", "b"), ("blocs", "x")):
        r = _wafctl(*argv)
        assert r.returncode == 64 and json.loads(r.stdout) == {"ok": False, "motif": "usage"}, argv


def test_wafctl_delegue_a_waf_blocs():
    t = WAFCTL.read_text()
    for attendu in ('exec /usr/sbin/waf-blocs ajouter "$1" "$secondes"', 'exec /usr/sbin/waf-blocs retirer "$1"',
              "exec /usr/sbin/waf-blocs lister"):
        assert attendu in t


def test_wafctl_ban_ferme_sans_garde():
    if Path("/usr/sbin/waf-blocs").exists():
        pytest.skip("waf-blocs installé sur ce poste : la garde répondrait pour de vrai")
    r = _wafctl("ban", "203.0.113.7", "1h")           # garde introuvable => refus, jamais nft
    assert r.returncode == 1 and "refus:garde_illisible" in r.stderr


def test_wafctl_shellcheck():
    if not shutil.which("shellcheck"):
        pytest.skip("shellcheck absent")
    r = subprocess.run(["shellcheck", str(WAFCTL)], check=False, timeout=30, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


def test_rules_installe_script_et_unite():
    r = RULES.read_text()
    assert "composants/waf/scripts/waf-blocs debian/secubox-waf-ng/usr/sbin/waf-blocs" in r
    assert "systemd/secubox-waf-blocs.service" in r and "dh_installsystemd --name=secubox-waf-blocs" in r


def test_retirer_nft_muet_n_est_pas_un_succes(wb, etat):
    class Muet(FauxNft):
        def __call__(self, argv):
            if argv[:3] == ["nft", "delete", "element"]:
                raise subprocess.CalledProcessError(1, argv)
            if argv[:3] == ["nft", "get", "element"]:
                raise subprocess.TimeoutExpired(argv, 10)
            return super().__call__(argv)
    assert wb.retirer("203.0.113.0/24", Muet(wb)) == {"ok": False, "motif": "nft"}
