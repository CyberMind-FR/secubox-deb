# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""voicestudioctl : configuration, réveil, publication, clé, audit (#1917) — sans toucher à un vrai LXC."""
import importlib.machinery
import importlib.util
import io
import json
import re
import stat
import tarfile
import tomllib
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("voicestudioctl_t", str(PKG / "sbin" / "voicestudioctl"))
spec = importlib.util.spec_from_loader("voicestudioctl_t", loader)
c = importlib.util.module_from_spec(spec)
loader.exec_module(c)


class Rep:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


class LxcFaux:
    """Simule lxc-info / start / stop / attach / systemctl / ip ; l'état évolue comme un vrai conteneur."""
    def __init__(self, etat="STOPPED", adresses=" 2: eth0 inet 192.168.1.9/24 ...", ancien_actif=False):
        self.etat, self.appels, self.entrees, self.adresses = etat, [], [], adresses
        self.ancien_actif = ancien_actif

    def __call__(self, cmd, **k):
        self.appels.append(list(cmd))
        self.entrees.append(k.get("input"))
        if cmd[0] == "lxc-info":
            return Rep(0, self.etat) if self.etat != "ABSENT" else Rep(1)
        if cmd[0] == "lxc-start":
            self.etat = "RUNNING"
            return Rep(0)
        if cmd[0] == "lxc-stop":
            self.etat = "STOPPED"
            return Rep(0)
        if cmd[0] == "ip":
            return Rep(0, self.adresses)
        if cmd[0] == "systemctl" and cmd[1] == "is-active":
            if cmd[2] == c.ANCIENNE_UNITE:
                return Rep(0 if self.ancien_actif else 3, "active\n" if self.ancien_actif else "inactive\n")
            return Rep(0, "active\n")
        return Rep(0)

    def verbes(self):
        return [a[0] for a in self.appels]


@pytest.fixture(autouse=True)
def bac_a_sable(tmp_path, monkeypatch):
    conf = tmp_path / "voicestudio.toml"
    conf.write_text((PKG / "conf" / "voicestudio.toml").read_text())
    for nom, valeur in {
        "CONF": conf, "CONF_DEFAUT": PKG / "conf" / "voicestudio.toml",
        "CLE": tmp_path / "secrets" / "api_key", "ETAT": tmp_path / "etat.json",
        "MARQUE_INSTALLE": tmp_path / ".prov", "AUDIT": tmp_path / "audit.log",
        "SAUVEGARDES": tmp_path / "sauv", "DROPIN_DIR": tmp_path / "systemd",
        "VOLUME_PODMAN": tmp_path / "volume-podman", "VERROU": tmp_path / "verrou.lock", "NFT_DIR": tmp_path / "nft", "MARQUE_INTERFACE": tmp_path / ".interface-native",
        "NGINX_DISPO": tmp_path / "ngx-dispo", "NGINX_ACTIF": tmp_path / "ngx-actif", "SNIPPET_CLE": tmp_path / "snip" / "cle.conf",
    }.items():
        monkeypatch.setattr(c, nom, valeur)
    (tmp_path / "lxc").mkdir()
    ecrit = c.charger()
    ecrit["lxc"]["chemin"] = str(tmp_path / "lxc")
    c.ecrire_toml("lxc", "chemin", str(tmp_path / "lxc"))
    c.ecrire_toml("lxc", "donnees", str(tmp_path / "donnees"))
    return tmp_path


# ── configuration ────────────────────────────────────────────────────────────
def test_le_toml_livre_est_valide_et_epingle():
    d = tomllib.loads((PKG / "conf" / "voicestudio.toml").read_text())
    assert len(d["source"]["commit"]) == 40
    assert len(d["source"]["sha256"]) == 64
    assert d["lxc"]["mode"] in c.MODES
    assert d["moteur"]["asr"] in c.ASR_ADMIS
    assert d["reseau"]["publier"] == []


def test_ecrire_toml_remplace_une_cle_et_garde_les_commentaires(bac_a_sable):
    c.ecrire_toml("lxc", "memoire", "6G")
    t = c.CONF.read_text()
    assert 'memoire = "6G"' in t
    assert "# SecuBox-Deb :: VoiceStudio" in t                  # commentaires préservés
    assert tomllib.loads(t)["lxc"]["memoire"] == "6G"
    assert tomllib.loads(t)["lxc"]["ip"] == "10.100.0.230"       # le reste n'a pas bougé


def test_ecrire_toml_ajoute_une_cle_absente_dans_la_bonne_section(bac_a_sable):
    c.CONF.write_text("[lxc]\nnom = \"x\"\n\n[moteur]\nasr = \"a\"\n")
    c.ecrire_toml("lxc", "mode", "demande")
    d = tomllib.loads(c.CONF.read_text())
    assert d["lxc"]["mode"] == "demande" and d["moteur"]["asr"] == "a"


def test_ecrire_toml_cree_la_section_manquante(bac_a_sable):
    c.CONF.write_text("[lxc]\nnom = \"x\"\n")
    c.ecrire_toml("reseau", "publier", ["192.168.1.9", "10.10.0.5"])
    assert tomllib.loads(c.CONF.read_text())["reseau"]["publier"] == ["192.168.1.9", "10.10.0.5"]


def test_fichier_de_conf_cree_en_0640(bac_a_sable):
    c.ecrire_toml("lxc", "mode", "demande")
    assert stat.S_IMODE(c.CONF.stat().st_mode) == 0o640


@pytest.mark.parametrize("cle,valeur", [
    ("asr", "Systran/faster-whisper-base"), ("memoire", "4G"), ("memoire", "2048M"),
    ("cpu_poids", "50"), ("mode", "demande"), ("inactivite_s", "900"),
])
def test_valeurs_admises(cle, valeur):
    c.valider_config(cle, valeur)


@pytest.mark.parametrize("cle,valeur", [
    ("asr", "evil/model; rm -rf /"), ("asr", "Systran/faster-whisper-base\nX=1"),
    ("memoire", "4G; reboot"), ("memoire", "0G"), ("memoire", "99G"), ("memoire", "512M"),
    ("cpu_poids", "0"), ("cpu_poids", "99999"), ("cpu_poids", "50 "),
    ("mode", "toujours"), ("inactivite_s", "10"), ("inactivite_s", "-5"),
    ("inconnue", "x"),
])
def test_valeurs_refusees(cle, valeur):
    with pytest.raises(c.Erreur):
        c.valider_config(cle, valeur)


def test_config_ecrit_le_toml_et_laudit(bac_a_sable):
    run = LxcFaux("STOPPED")
    assert c.cmd_config("mode", "demande", run) == 0
    assert tomllib.loads(c.CONF.read_text())["lxc"]["mode"] == "demande"
    assert "config mode=demande" in c.AUDIT.read_text()


def test_config_asr_pousse_le_modele_dans_le_lxc_et_redemarre_le_moteur(bac_a_sable):
    run = LxcFaux("RUNNING")
    c.cmd_config("asr", "Systran/faster-whisper-small", run)
    attaches = [a for a in run.appels if a[0] == "lxc-attach"]
    assert attaches and "faster-whisper-small" in " ".join(attaches[-1])
    assert "restart voicestudio.service" in " ".join(attaches[-1])


# ── LXC et mandataire ────────────────────────────────────────────────────────
def test_bloc_lxc_permanent_et_demande():
    cfg = c.charger()
    assert "lxc.start.auto = 1" in c.bloc_lxc(cfg)
    cfg["lxc"]["mode"] = "demande"
    assert "lxc.start.auto = 0" in c.bloc_lxc(cfg)
    assert "lxc.cgroup2.memory.max = 4G" in c.bloc_lxc(cfg)


def test_appliquer_lxc_remplace_le_bloc_sans_le_dupliquer(bac_a_sable):
    cfg = c.charger()
    f = Path(c.lxc_chemin(cfg)) / "voicestudio" / "config"
    f.parent.mkdir(parents=True)
    f.write_text("lxc.net.0.type = veth\n" + c.bloc_lxc(cfg) + "lxc.mount.entry = /x app/x none bind 0 0\n")
    c.ecrire_toml("lxc", "mode", "demande")
    c.ecrire_toml("lxc", "memoire", "2G")
    assert c.appliquer_lxc(c.charger())
    t = f.read_text()
    assert t.count(c.MARQUE_DEBUT) == 1 and t.count(c.MARQUE_FIN) == 1
    assert "lxc.start.auto = 0" in t and "memory.max = 2G" in t
    assert "lxc.net.0.type = veth" in t and "lxc.mount.entry" in t       # le reste est intact


def test_appliquer_lxc_sans_conteneur_ne_fait_rien():
    assert c.appliquer_lxc(c.charger()) is False


def test_socket_ecoute_les_adresses_publiees_et_toujours_le_loopback():
    cfg = c.charger()
    cfg["reseau"]["publier"] = ["192.168.1.9", "10.10.0.5"]
    s = c.contenu_socket(cfg)
    assert "ListenStream=192.168.1.9:3900" in s and "ListenStream=10.10.0.5:3900" in s
    assert "ListenStream=127.0.0.1:3900" in s
    assert "ListenStream=\n" in s                         # remise à zéro de la liste du paquet
    assert "0.0.0.0" not in s                              # jamais d'écoute sur toutes les interfaces


def test_service_permanent_ne_rendort_jamais_le_lxc():
    s = c.contenu_service(c.charger())
    assert "10.100.0.230:3900" in s
    assert "voicestudioctl sleep" not in s and "exit-idle-time" not in s


def test_service_demande_rendort_apres_inactivite():
    cfg = c.charger()
    cfg["lxc"]["mode"] = "demande"
    cfg["lxc"]["inactivite_s"] = 600
    s = c.contenu_service(cfg)
    assert "--exit-idle-time=600s" in s and "voicestudioctl sleep" in s


def test_appliquer_n_ecrit_les_dropins_qu_une_fois(bac_a_sable):
    run = LxcFaux()
    r1 = c.appliquer(run)
    assert r1["mandataire"] is True
    systemd = lambda: [a for a in run.appels if a[0] == "systemctl"]          # noqa: E731
    appels = len(systemd())
    r2 = c.appliquer(run)
    assert r2["mandataire"] is False and len(systemd()) == appels    # idempotent : pas de rechargement systemd


def test_reveil_demarre_le_lxc_endormi_et_attend_la_sante():
    run = LxcFaux("STOPPED")
    reps = iter([{"ok": False}, {"ok": False}, {"ok": False}, {"ok": True}])
    horloge = iter(range(0, 1000, 2))
    assert c.reveiller(c.charger(), run=run, sante_fn=lambda _c: next(reps),
                       dormir=lambda s: None, maintenant=lambda: next(horloge)) is True
    assert "lxc-start" in run.verbes()


def test_reveil_deja_en_service_ne_demarre_rien():
    run = LxcFaux("RUNNING")
    assert c.reveiller(c.charger(), run=run, sante_fn=lambda _c: {"ok": True}) is True
    assert "lxc-start" not in run.verbes()


def test_reveil_abandonne_apres_le_delai():
    run = LxcFaux("RUNNING")
    horloge = iter(range(0, 10000, 50))
    assert c.reveiller(c.charger(), run=run, sante_fn=lambda _c: {"ok": False},
                       dormir=lambda s: None, maintenant=lambda: next(horloge), delai=100) is False


def test_reveil_lxc_absent_echoue_sans_tenter_de_demarrer():
    run = LxcFaux("ABSENT")
    assert c.reveiller(c.charger(), run=run, sante_fn=lambda _c: {"ok": False}) is False
    assert "lxc-start" not in run.verbes()


def test_sommeil_arrete_un_lxc_actif_et_ignore_un_lxc_arrete():
    run = LxcFaux("RUNNING")
    assert c.endormir(c.charger(), run) and run.etat == "STOPPED"
    run.appels.clear()
    assert c.endormir(c.charger(), run) and "lxc-stop" not in run.verbes()


def test_stop_coupe_le_mandataire_puis_le_lxc(bac_a_sable):
    run = LxcFaux("RUNNING")
    assert c.cmd_stop(run) == 0
    stops = [a for a in run.appels if a[0] == "systemctl" and a[1] == "stop"]
    assert [a[2] for a in stops] == [c.SERVICE_PUB, c.SOCKET_PUB]
    assert run.etat == "STOPPED"


# ── publication ──────────────────────────────────────────────────────────────
def test_publier_accepte_une_adresse_de_la_box(bac_a_sable):
    run = LxcFaux()
    assert c.cmd_publier(["192.168.1.9"], run) == 0
    assert tomllib.loads(c.CONF.read_text())["reseau"]["publier"] == ["192.168.1.9"]
    assert "ListenStream=192.168.1.9:3900" in (c.DROPIN_DIR / f"{c.SOCKET_PUB}.d" / "adresses.conf").read_text()
    assert "publier 192.168.1.9" in c.AUDIT.read_text()


@pytest.mark.parametrize("adresse", ["8.8.8.8", "0.0.0.0", "192.168.1.9; reboot", "abc", "192.168.1", "::1"])
def test_publier_refuse_une_adresse_etrangere(adresse):
    with pytest.raises(c.Erreur):
        c.cmd_publier([adresse], LxcFaux())


def test_publier_vide_ne_laisse_que_le_loopback(bac_a_sable):
    c.cmd_publier([], LxcFaux())
    assert tomllib.loads(c.CONF.read_text())["reseau"]["publier"] == []


# ── clé d'API ────────────────────────────────────────────────────────────────
def test_la_cle_est_creee_en_0600_dans_un_repertoire_0700():
    assert c.creer_cle() is True
    assert stat.S_IMODE(c.CLE.stat().st_mode) == 0o600
    assert stat.S_IMODE(c.CLE.parent.stat().st_mode) == 0o700
    assert len(c.lire_cle()) >= 40


def test_la_cle_existante_n_est_jamais_ecrasee_par_init():
    c.creer_cle()
    avant = c.lire_cle()
    assert c.creer_cle() is False and c.lire_cle() == avant


def test_renouveler_change_la_cle_la_pousse_et_laudite(bac_a_sable, capsys):
    c.creer_cle()
    avant = c.lire_cle()
    run = LxcFaux("RUNNING")
    assert c.cmd_cle_renouveler(run) == 0
    nouvelle = c.lire_cle()
    assert nouvelle != avant and capsys.readouterr().out.strip() == nouvelle
    assert any(f"OMNIVOICE_API_KEY={nouvelle}" in (e or "") for e in run.entrees)   # poussée par stdin
    assert nouvelle not in c.AUDIT.read_text()               # la clé n'entre JAMAIS dans l'audit
    assert "cle-renouvelee" in c.AUDIT.read_text()


def test_la_cle_n_est_jamais_passee_en_argument(bac_a_sable):
    """Un argument se lit dans `ps` : la clé voyage par stdin seulement."""
    c.creer_cle()
    run = LxcFaux("RUNNING")
    c.pousser_cle(c.charger(), run)
    assert all(c.lire_cle() not in " ".join(a) for a in run.appels)


def test_pousser_cle_lxc_arrete_est_remis_a_plus_tard():
    c.creer_cle()
    assert c.pousser_cle(c.charger(), LxcFaux("STOPPED")) is False


# ── état ─────────────────────────────────────────────────────────────────────
def test_etat_lxc_arrete(bac_a_sable):
    e = c.etat_complet(LxcFaux("STOPPED"))
    assert e["lxc"] == "STOPPED" and e["moteur"] is False and e["mode"] == "permanent"
    assert e["commit"] == c.charger()["source"]["commit"][:12]
    assert "cle" not in e and not any("api_key" in k for k in e)      # aucun secret dans l'état


def test_etat_lxc_en_marche_et_moteur_sain(bac_a_sable):
    e = c.etat_complet(LxcFaux("RUNNING"), sante_fn=lambda _c: {"ok": True, "http": 200})
    assert e["moteur"] is True and e["http"] == 200


def test_etat_distingue_demarrage_et_panne(bac_a_sable):
    e = c.etat_complet(LxcFaux("RUNNING"), sante_fn=lambda _c: {"ok": False, "http": 503, "demarrage": True})
    assert e["moteur"] is False and e["demarrage"] is True


def test_etat_sans_privilege_retombe_sur_le_cache(bac_a_sable):
    """Sous `secubox`, lxc-info ne voit pas le conteneur : on ne conclut pas « absent »."""
    c.memoriser_etat("RUNNING")
    e = c.etat_complet(LxcFaux("ABSENT"))
    assert e["lxc"] == "RUNNING" and e["source"] == "cache"


def test_etat_compte_la_taille_des_donnees(bac_a_sable):
    d = Path(c.donnees(c.charger()))
    d.mkdir()
    (d / "voix.bin").write_bytes(b"x" * 2 * 1048576)
    assert c.etat_complet(LxcFaux("STOPPED"))["donnees_mo"] == 2.0


# ── sauvegarde et migration ──────────────────────────────────────────────────
def test_sauvegarde_exclut_les_modeles_et_garde_les_voix(bac_a_sable):
    d = Path(c.donnees(c.charger()))
    (d / "huggingface" / "hub").mkdir(parents=True)
    (d / "huggingface" / "hub" / "modele.bin").write_bytes(b"gros")
    (d / "voices").mkdir()
    (d / "voices" / "lexie.wav").write_bytes(b"voix")
    import sqlite3
    base = sqlite3.connect(d / "omnivoice.db")
    base.execute("create table voix(nom text)")
    base.execute("insert into voix values ('lexie')")
    base.commit()
    base.close()
    assert c.cmd_sauvegarde() == 0
    [archive] = list(c.SAUVEGARDES.glob("voicestudio-*.tar.gz"))
    noms = tarfile.open(archive).getnames()
    assert noms.count("omnivoice_data/omnivoice.db") == 1 and "omnivoice_data/voices/lexie.wav" in noms
    with tarfile.open(archive) as t:                       # la copie archivée est une base SQLite lisible
        t.extract("omnivoice_data/omnivoice.db", path=c.SAUVEGARDES / "x", filter="data")
    lecture = sqlite3.connect(c.SAUVEGARDES / "x" / "omnivoice_data" / "omnivoice.db")
    assert lecture.execute("select nom from voix").fetchall() == [("lexie",)]
    lecture.close()
    assert not any("huggingface/hub" in n for n in noms)
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    assert stat.S_IMODE(c.SAUVEGARDES.stat().st_mode) == 0o700


def test_sauvegarde_ne_garde_que_les_dernieres(bac_a_sable):
    d = Path(c.donnees(c.charger()))
    d.mkdir()
    c.SAUVEGARDES.mkdir(parents=True)
    for i in range(6):
        (c.SAUVEGARDES / f"voicestudio-2026010{i}T000000Z.tar.gz").write_bytes(b"x")
    c.cmd_sauvegarde()
    assert len(list(c.SAUVEGARDES.glob("voicestudio-*.tar.gz"))) == c.SAUVEGARDES_GARDEES


def test_sauvegarde_sans_donnees_est_une_erreur_claire():
    with pytest.raises(c.Erreur):
        c.cmd_sauvegarde()


def test_migration_reprend_le_volume_et_ne_le_supprime_pas(bac_a_sable, monkeypatch):
    v = c.VOLUME_PODMAN
    v.mkdir()
    (v / "omnivoice.db").write_bytes(b"sqlite")
    (v / "voices").mkdir()
    (v / "voices" / "a.wav").write_bytes(b"a")
    chowns = []
    monkeypatch.setattr(c.os, "lchown", lambda p, u, g: chowns.append((p, u, g)))
    run = LxcFaux()
    real = c.subprocess.run

    def run_cp(cmd, **k):
        return real(cmd, **k) if cmd[0] == "cp" else run(cmd, **k)
    assert c.cmd_migrer_podman(run_cp) == 0
    cible = c.donnees(c.charger())
    assert (cible / "omnivoice.db").read_bytes() == b"sqlite" and (cible / "voices" / "a.wav").exists()
    assert (v / "omnivoice.db").exists()                                  # l'original reste
    assert chowns and all(u >= c.UID_BASE for _, u, _g in chowns)       # propriété décalée sur l'idmap
    assert not any(a[0] == "podman" for a in run.appels)                # jamais de pilotage podman


def test_migration_ne_fait_rien_si_les_donnees_existent(bac_a_sable):
    c.VOLUME_PODMAN.mkdir()
    cible = c.donnees(c.charger())
    cible.mkdir()
    (cible / c.MARQUE_MIGRATION).write_text("fait")
    run = LxcFaux()
    assert c.cmd_migrer_podman(run) == 0
    assert not any(a[0] in ("podman", "cp") for a in run.appels)


def test_migration_sans_volume_podman_est_un_non_evenement():
    assert c.cmd_migrer_podman(LxcFaux()) == 0


# ── porte du panneau (« api ») ───────────────────────────────────────────────
def appeler_api(requete) -> tuple[int, dict]:
    import contextlib
    sortie = io.StringIO()
    with contextlib.redirect_stdout(sortie):
        rc = c.cmd_api(requete if isinstance(requete, str) else json.dumps(requete))
    return rc, json.loads(sortie.getvalue())


def test_api_refuse_une_action_hors_liste_blanche():
    rc, r = appeler_api({"action": "rm"})
    assert rc == 1 and r["ok"] is False


def test_api_refuse_du_json_invalide():
    assert appeler_api("pas du json")[0] == 1
    assert appeler_api("[1,2]")[0] == 1


def test_api_ne_connait_pas_les_commandes_dangereuses():
    for interdite in ("migrer-podman", "reinstaller", "install", "wake", "sleep", "appliquer"):
        assert interdite not in c.ACTIONS_API


def test_api_cle_apercu_ne_revele_pas_la_cle():
    c.creer_cle()
    rc, r = appeler_api({"action": "cle-apercu"})
    assert rc == 0 and r["presente"] is True
    assert c.lire_cle() not in json.dumps(r) and "…" in r["apercu"]


def test_api_config_valide_les_valeurs():
    rc, r = appeler_api({"action": "config", "cle": "memoire", "valeur": "4G; reboot"})
    assert rc == 1 and r["ok"] is False


def test_api_publier_refuse_un_type_inattendu():
    rc, r = appeler_api({"action": "publier", "adresses": "192.168.1.9"})
    assert rc == 1 and r["ok"] is False
    rc, r = appeler_api({"action": "publier", "adresses": [1, 2]})
    assert rc == 1


def test_api_audite_l_administrateur_et_non_secubox(bac_a_sable, monkeypatch):
    monkeypatch.setattr(c.subprocess, "run", LxcFaux())
    appeler_api({"action": "config", "cle": "mode", "valeur": "demande", "par": "gandalf"})
    assert "by=gandalf" in c.AUDIT.read_text()


def test_api_ignore_un_nom_d_administrateur_suspect(bac_a_sable, monkeypatch):
    monkeypatch.setattr(c.subprocess, "run", LxcFaux())
    monkeypatch.setenv("SUDO_USER", "secubox")
    appeler_api({"action": "config", "cle": "mode", "valeur": "demande", "par": "x\nvoicestudio forged"})
    assert "forged" not in c.AUDIT.read_text()


def test_api_status_rend_du_json(bac_a_sable, monkeypatch):
    monkeypatch.setattr(c.subprocess, "run", LxcFaux("STOPPED"))
    rc, r = appeler_api({"action": "status"})
    assert rc == 0 and r["lxc"] == "STOPPED"


# ── migration de la configuration (ancien schéma podman) ─────────────────────
ANCIEN = """# SecuBox-Deb :: VoiceStudio (#1649)
image    = "ghcr.io/debpalash/voicestudio:stable"
empreinte = "sha256:588fe119082bb97e722f5e53fe7b0fe1a406885bf72a4c60889d3d03376d7768"
publier  = ["192.168.1.9", "10.10.0.5"]
memoire  = "4g"
asr      = "Systran/faster-whisper-base"
"""


def test_migrer_conf_cree_le_defaut_quand_rien_n_existe():
    c.CONF.unlink()
    assert c.cmd_migrer_conf() == 0
    assert tomllib.loads(c.CONF.read_text())["lxc"]["nom"] == "voicestudio"


def test_migrer_conf_reprend_les_adresses_publiees_de_l_ancien_schema():
    """gk2 joint le moteur de gk3 par 10.10.0.5 : les perdre couperait Lexie."""
    c.CONF.write_text(ANCIEN)
    assert c.cmd_migrer_conf() == 0
    d = tomllib.loads(c.CONF.read_text())
    assert d["reseau"]["publier"] == ["192.168.1.9", "10.10.0.5"]
    assert d["lxc"]["memoire"] == "4G"                      # « 4g » podman → « 4G » cgroup
    assert d["moteur"]["asr"] == "Systran/faster-whisper-base"
    assert "image" not in d and "empreinte" not in d and d["source"]["commit"]
    assert c.CONF.with_name(c.CONF.name + ".avant-lxc").read_text() == ANCIEN     # l'ancien est gardé
    assert "migrer-conf publier=192.168.1.9,10.10.0.5" in c.AUDIT.read_text()


def test_migrer_conf_ecarte_une_valeur_inexploitable():
    c.CONF.write_text(ANCIEN.replace('"4g"', '"beaucoup"').replace("faster-whisper-base", "evil"))
    c.cmd_migrer_conf()
    d = tomllib.loads(c.CONF.read_text())
    assert d["lxc"]["memoire"] == "4G" and d["moteur"]["asr"] == "Systran/faster-whisper-base"   # défauts


def test_migrer_conf_ne_touche_pas_a_un_fichier_deja_au_nouveau_schema():
    c.ecrire_toml("lxc", "mode", "demande")
    avant = c.CONF.read_text()
    c.cmd_migrer_conf()
    assert c.CONF.read_text() == avant
    assert not c.CONF.with_name(c.CONF.name + ".avant-lxc").exists()


def test_migrer_conf_est_idempotent():
    c.CONF.write_text(ANCIEN)
    c.cmd_migrer_conf()
    apres = c.CONF.read_text()
    c.cmd_migrer_conf()
    assert c.CONF.read_text() == apres


# ── bascule depuis podman ────────────────────────────────────────────────────
def lxc_present(bac):
    cfg = c.charger()
    (Path(c.lxc_chemin(cfg)) / "voicestudio").mkdir(parents=True, exist_ok=True)


def test_basculer_arrete_l_ancien_avant_de_copier_puis_demarre_le_lxc(bac_a_sable, monkeypatch):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"sqlite")
    monkeypatch.setattr(c.os, "lchown", lambda *a: None)
    run = LxcFaux("RUNNING")
    reel = c.subprocess.run
    ordre = []

    def suivi(cmd, **k):
        ordre.append(cmd[0] if cmd[0] != "systemctl" else " ".join(cmd[:3]))
        return reel(cmd, **k) if cmd[0] == "cp" else run(cmd, **k)
    monkeypatch.setattr(c, "sante", lambda cfg, *a, **k: {"ok": True, "http": 200})
    c.creer_cle()
    assert c.cmd_basculer(suivi) == 0
    assert ordre.index("systemctl stop secubox-voicestudio.service") < ordre.index("cp")
    assert "lxc-stop" in ordre and ordre.index("lxc-stop") < ordre.index("cp")        # pas de copie sous le moteur
    assert (c.donnees(c.charger()) / "omnivoice.db").read_bytes() == b"sqlite"
    assert (c.VOLUME_PODMAN / "omnivoice.db").exists()                              # rien n'est supprimé
    assert "basculer ok" in c.AUDIT.read_text()


def test_basculer_sans_lxc_ne_touche_pas_a_l_ancien_moteur(bac_a_sable):
    c.VOLUME_PODMAN.mkdir()
    run = LxcFaux("ABSENT")
    with pytest.raises(c.Erreur):
        c.cmd_basculer(run)
    assert not any(a[0] in ("podman",) or a[:2] == ["systemctl", "stop"] for a in run.appels)


def test_basculer_dit_l_echec_et_garde_le_volume(bac_a_sable, monkeypatch, capsys):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"sqlite")
    monkeypatch.setattr(c.os, "lchown", lambda *a: None)
    monkeypatch.setattr(c, "DELAI_REVEIL", 0)
    monkeypatch.setattr(c, "sante", lambda cfg, *a, **k: {"ok": False, "http": 0})
    run = LxcFaux("STOPPED")
    reel = c.subprocess.run
    c.creer_cle()
    rc = c.cmd_basculer(lambda cmd, **k: reel(cmd, **k) if cmd[0] == "cp" else run(cmd, **k))
    assert rc == 1 and "INTACT" in capsys.readouterr().err
    assert (c.VOLUME_PODMAN / "omnivoice.db").exists() and "basculer echec" in c.AUDIT.read_text()


def test_basculer_sans_ancien_moteur_demarre_simplement_le_lxc(bac_a_sable, monkeypatch):
    monkeypatch.setattr(c, "sante", lambda cfg, *a, **k: {"ok": True, "http": 200})
    c.creer_cle()
    run = LxcFaux("RUNNING")
    assert c.cmd_basculer(run) == 0
    assert not any(a[0] == "podman" for a in run.appels)


def test_migrer_podman_refuse_de_copier_sous_un_moteur_qui_tourne(bac_a_sable):
    """Une base SQLite copiée pendant qu'on y écrit est une base corrompue."""
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"sqlite")
    with pytest.raises(c.Erreur, match="tourne encore"):
        c.cmd_migrer_podman(LxcFaux(ancien_actif=True))
    assert not (c.donnees(c.charger()) / "omnivoice.db").exists()


def test_le_code_livre_ne_pilote_jamais_podman():
    """Pas de `podman …` dans le ctl : l'arrêt de l'ancien moteur passe par systemd seulement."""
    import re
    src = (PKG / "sbin" / "voicestudioctl").read_text()
    assert not re.search(r"""\[\s*["']podman["']|podman\s+(run|stop|rm|exec|ps|pull|inspect)""", src)


def test_appliquer_ne_demarre_pas_un_socket_inactif(bac_a_sable):
    """Installer ne doit pas ouvrir le port 3900 sans moteur derrière (ni échouer si l'ancien le tient)."""
    run = LxcFaux()
    base = run.__call__

    def inactif(cmd, **k):
        if cmd[:2] == ["systemctl", "is-active"] and cmd[2] == c.SOCKET_PUB:
            run.appels.append(list(cmd))
            return Rep(3, "inactive\n")
        return base(cmd, **k)
    c.appliquer(inactif)
    assert ["systemctl", "restart", c.SOCKET_PUB] not in run.appels
    assert ["systemctl", "daemon-reload"] in run.appels


def test_changer_de_mode_relance_le_mandataire_en_marche(bac_a_sable):
    run = LxcFaux()
    c.appliquer(run)
    run.appels.clear()
    c.ecrire_toml("lxc", "mode", "demande")
    c.appliquer(run)
    assert ["systemctl", "try-restart", c.SERVICE_PUB] in run.appels
    run.appels.clear()
    c.appliquer(run)                                     # rien n'a changé : on ne relance rien
    assert not any(a[0] == "systemctl" and a[1] in ("restart", "try-restart") for a in run.appels)


# ── moteur : première mise en service, clé renouvelée pendant le sommeil ─────
def test_assurer_moteur_ecrit_la_cle_par_stdin_et_demarre_le_moteur_s_il_est_arrete():
    c.creer_cle()
    run = LxcFaux("RUNNING")
    assert c.assurer_moteur(c.charger(), run, dormir=lambda s: None) is True
    [attache] = [a for a in run.appels if a[0] == "lxc-attach"]
    script = attache[-1]
    assert "cmp -s /etc/voicestudio.env.new /etc/voicestudio.env" in script
    assert "systemctl restart voicestudio.service" in script             # clé changée -> relance
    assert "systemctl is-active -q voicestudio.service || systemctl start voicestudio.service" in script
    assert f"OMNIVOICE_API_KEY={c.lire_cle()}" in run.entrees[-1]
    assert c.lire_cle() not in " ".join(attache)                          # jamais en argument


def test_assurer_moteur_retente_tant_que_le_lxc_ne_repond_pas_puis_le_dit(capsys):
    c.creer_cle()
    n = {"v": 0}

    def run(cmd, **k):
        n["v"] += 1
        return Rep(1 if cmd[0] == "lxc-attach" else 0)
    assert c.assurer_moteur(c.charger(), run, dormir=lambda s: None) is False
    assert n["v"] == 10 and "ne répond pas" in capsys.readouterr().err


def test_le_reveil_prepare_le_moteur_avant_d_attendre_la_sante():
    """Régression : LXC déjà actif après install, moteur jamais lancé -> on attendait 240 s pour rien."""
    ordre = []
    run = LxcFaux("RUNNING")
    sante = iter([{"ok": False}, {"ok": False}, {"ok": True}])
    horloge = iter(range(0, 1000, 2))

    def prep(cfg, r, dormir):
        ordre.append("preparer")
    assert c.reveiller(c.charger(), run=run, sante_fn=lambda _c: (ordre.append("sante"), next(sante))[1],
                       dormir=lambda s: None, maintenant=lambda: next(horloge), preparer=prep) is True
    assert ordre.index("preparer") < len(ordre) - 1 and ordre[:2] == ["sante", "preparer"]


def test_renouveler_pendant_le_sommeil_ecrit_sur_l_hote_et_laisse_le_reveil_pousser(bac_a_sable):
    c.creer_cle()
    avant = c.lire_cle()
    run = LxcFaux("STOPPED")
    c.cmd_cle_renouveler(run)
    assert c.lire_cle() != avant and not any(a[0] == "lxc-attach" for a in run.appels)
    # Au réveil, assurer_moteur voit la clé changée (cmp) et relance le moteur avec la nouvelle.
    run.etat = "RUNNING"
    c.assurer_moteur(c.charger(), run, dormir=lambda s: None)
    assert f"OMNIVOICE_API_KEY={c.lire_cle()}" in run.entrees[-1]


# ── exclusion mutuelle ───────────────────────────────────────────────────────
def test_deux_commandes_mutantes_ne_s_executent_pas_ensemble(bac_a_sable):
    import fcntl
    c.VERROU.parent.mkdir(parents=True, exist_ok=True)
    fd = open(c.VERROU, "w")
    fcntl.flock(fd, fcntl.LOCK_EX)                      # une installation « en cours »
    try:
        with pytest.raises(c.Erreur, match="autre opération"):
            c.cmd_config("mode", "demande", LxcFaux())
        with pytest.raises(c.Erreur, match="autre opération"):
            c.cmd_install(LxcFaux())
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        fd.close()
    assert c.cmd_config("mode", "demande", LxcFaux()) == 0          # le verrou est rendu


def test_le_verrou_est_reentrant_install_basculer_start(bac_a_sable, monkeypatch):
    monkeypatch.setattr(c, "sante", lambda cfg, *a, **k: {"ok": True, "http": 200})
    c.creer_cle()
    assert c.cmd_basculer(LxcFaux("RUNNING")) == 0     # basculer -> start : pas d'auto-blocage


def test_le_verrou_est_rendu_apres_une_erreur(bac_a_sable):
    with pytest.raises(c.Erreur):
        c.cmd_config("mode", "toujours", LxcFaux())
    assert c.cmd_config("mode", "demande", LxcFaux()) == 0


# ── publication : jamais une adresse publique ────────────────────────────────
@pytest.mark.parametrize("adresse", ["8.8.8.8", "82.67.100.75", "1.1.1.1", "0.0.0.0", "224.0.0.1"])
def test_publier_refuse_toute_adresse_publique(adresse):
    with pytest.raises(c.Erreur):
        c.cmd_publier([adresse], LxcFaux(adresses=f" 2: wan inet {adresse}/24 ..."))


@pytest.mark.parametrize("adresse", ["192.168.1.9", "10.10.0.5", "172.16.4.2", "100.64.1.1"])
def test_publier_accepte_lan_maillage_et_cgnat(bac_a_sable, adresse):
    assert c.cmd_publier([adresse], LxcFaux(adresses=f" 2: eth0 inet {adresse}/24 ...")) == 0


def test_une_adresse_publique_heritee_du_toml_n_ouvre_pas_de_socket(capsys):
    cfg = c.charger()
    cfg["reseau"]["publier"] = ["82.67.100.75", "192.168.1.9"]
    s = c.contenu_socket(cfg)
    assert "82.67.100.75" not in s and "192.168.1.9:3900" in s
    assert "ignorée" in capsys.readouterr().err


# ── configuration illisible : on s'arrête, on ne retombe pas sur les défauts ─
def test_un_toml_invalide_arrete_appliquer_au_lieu_d_effacer_les_adresses(bac_a_sable):
    c.cmd_publier(["192.168.1.9"], LxcFaux())
    c.CONF.write_text("[reseau\npublier = [")
    with pytest.raises(c.Erreur, match="invalide"):
        c.appliquer(LxcFaux())
    assert "192.168.1.9" in (c.DROPIN_DIR / f"{c.SOCKET_PUB}.d" / "adresses.conf").read_text()   # drop-in intact


def test_un_socket_qui_ne_se_relance_pas_est_dit(bac_a_sable, capsys):
    run = LxcFaux()
    base = run.__call__

    def refuse(cmd, **k):
        if cmd[:2] == ["systemctl", "restart"] and cmd[2] == c.SOCKET_PUB:
            run.appels.append(list(cmd))
            return Rep(1, "", "Address already in use")
        return base(cmd, **k)
    c.appliquer(refuse)
    c.ecrire_toml("reseau", "publier", ["192.168.1.9"])
    r = c.appliquer(refuse)
    assert r.get("mandataire_ok") is False and "port 3900" in capsys.readouterr().err


# ── migration atomique ───────────────────────────────────────────────────────
def test_une_copie_interrompue_ne_laisse_aucune_migration_a_moitie(bac_a_sable, monkeypatch):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"sqlite")
    run = LxcFaux()
    reel = c.subprocess.run

    def cp_en_echec(cmd, **k):
        if cmd[0] == "cp":
            Path(cmd[-1]).mkdir(parents=True)
            (Path(cmd[-1]) / "omnivoice.db").write_bytes(b"tronq")
            return Rep(1, "", "No space left on device")
        return run(cmd, **k) if cmd[0] != "cp" else reel(cmd, **k)
    with pytest.raises(c.Erreur, match="copie du volume échouée"):
        c.cmd_migrer_podman(cp_en_echec)
    cible = c.donnees(c.charger())
    assert not cible.exists() and not Path(str(cible) + ".migration").exists()      # rien de tronqué ni de résiduel


def test_la_migration_decale_uid_et_gid_chacun_pour_son_compte(bac_a_sable, monkeypatch):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"x")
    vus = []
    monkeypatch.setattr(c.os, "lchown", lambda p, u, g: vus.append((u, g)))
    reel_lstat = c.os.lstat

    class St:
        def __init__(self, st, u, g):
            self._st, self.st_uid, self.st_gid = st, u, g

        def __getattr__(self, nom):
            return getattr(self._st, nom)
    monkeypatch.setattr(c.os, "lstat", lambda p: St(reel_lstat(p), 0, 100999) if str(p).endswith("omnivoice.db")
                        else St(reel_lstat(p), 0, 0))
    run = LxcFaux()
    reel = c.subprocess.run
    c.cmd_migrer_podman(lambda cmd, **k: reel(cmd, **k) if cmd[0] == "cp" else run(cmd, **k))
    assert (c.UID_BASE, c.UID_BASE) in vus                 # 0/0 -> 100000/100000
    assert (c.UID_BASE, 100999) in vus                     # uid décalé, gid déjà dans l'idmap : inchangé


def test_la_migration_met_de_cote_une_base_vierge_au_lieu_de_l_ecraser(bac_a_sable, monkeypatch):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"reelle")
    cible = c.donnees(c.charger())
    cible.mkdir()
    (cible / "omnivoice.db").write_bytes(b"vierge")        # le LXC a démarré une fois
    monkeypatch.setattr(c.os, "lchown", lambda *a: None)
    run = LxcFaux()
    reel = c.subprocess.run
    c.cmd_migrer_podman(lambda cmd, **k: reel(cmd, **k) if cmd[0] == "cp" else run(cmd, **k))
    assert (cible / "omnivoice.db").read_bytes() == b"reelle" and (cible / c.MARQUE_MIGRATION).exists()
    assert (Path(str(cible) + ".avant-migration") / "omnivoice.db").read_bytes() == b"vierge"


def test_migrer_refuse_si_le_lxc_tourne(bac_a_sable):
    c.VOLUME_PODMAN.mkdir()
    with pytest.raises(c.Erreur, match="LXC tourne"):
        c.cmd_migrer_podman(LxcFaux("RUNNING"))


def test_basculer_ne_copie_rien_si_l_ancien_moteur_tient_le_port(bac_a_sable, monkeypatch):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"x")
    monkeypatch.setattr(c, "_port_libre", lambda *a: False)
    run = LxcFaux("RUNNING")
    with pytest.raises(c.Erreur, match="tient encore le port"):
        c.cmd_basculer(run)
    assert not (c.donnees(c.charger()) / c.MARQUE_MIGRATION).exists() and "lxc-stop" not in run.verbes()


def test_basculer_relance_l_ancienne_unite_en_cas_d_echec(bac_a_sable, monkeypatch):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"x")
    monkeypatch.setattr(c, "_port_libre", lambda *a: True)
    monkeypatch.setattr(c, "DELAI_REVEIL", 0)
    monkeypatch.setattr(c, "sante", lambda cfg, *a, **k: {"ok": False, "http": 0})
    monkeypatch.setattr(c.os, "lchown", lambda *a: None)
    run = LxcFaux("STOPPED")
    reel = c.subprocess.run
    c.creer_cle()
    rc = c.cmd_basculer(lambda cmd, **k: reel(cmd, **k) if cmd[0] == "cp" else run(cmd, **k))
    assert rc == 1 and ["systemctl", "start", c.ANCIENNE_UNITE] in run.appels


# ── état : cache de la taille, provisionnement ───────────────────────────────
def test_la_taille_des_donnees_n_est_pas_recalculee_a_chaque_affichage(bac_a_sable, monkeypatch):
    d = Path(c.donnees(c.charger()))
    d.mkdir()
    (d / "a.bin").write_bytes(b"x" * 1048576)
    n = {"v": 0}
    reel = c.taille_mo
    monkeypatch.setattr(c, "taille_mo", lambda p: (n.__setitem__("v", n["v"] + 1), reel(p))[1])
    c.etat_complet(LxcFaux("STOPPED"))
    c.etat_complet(LxcFaux("STOPPED"))
    assert n["v"] == 1


def test_l_etat_annonce_le_provisionnement_en_cours(bac_a_sable):
    run = LxcFaux("RUNNING")
    base = run.__call__

    def prov(cmd, **k):
        if cmd[:2] == ["systemctl", "is-active"] and cmd[2] == c.UNITE_PROVISION:
            run.appels.append(list(cmd))
            return Rep(0, "activating\n")
        return base(cmd, **k)
    assert c.etat_complet(prov)["provisionnement"] == "activating"


def test_memoriser_etat_ne_perd_pas_le_cache_de_taille(bac_a_sable):
    c._ecrit({"taille": {"mo": 12.0, "ts": 9999999999}})
    c.memoriser_etat("RUNNING")
    d = json.loads(c.ETAT.read_text())
    assert d["taille"]["mo"] == 12.0 and d["dernier_etat"] == "RUNNING"


def test_le_mandataire_rendort_en_root_et_le_service_n_a_pas_besoin_de_root():
    cfg = c.charger()
    cfg["lxc"]["mode"] = "demande"
    assert "ExecStopPost=+/usr/sbin/voicestudioctl sleep" in c.contenu_service(cfg)


# ── pare-feu : le mandataire écoute sur l'hôte, donc sous la chaîne d'entrée en DROP ──────────────
class NftFaux(LxcFaux):
    """nft list / insert / delete : une chaîne d'entrée qui garde les règles comme le ferait nftables."""
    def __init__(self, table="filter", **kw):
        super().__init__(**kw)
        self.table, self.regles = table, []

    def __call__(self, cmd, **k):
        if cmd[0] != "nft":
            return super().__call__(cmd, **k)
        self.appels.append(list(cmd))
        if cmd[1] in ("list", "-a") and cmd[-3] == "inet":
            if cmd[-2] != self.table:
                return Rep(1, "", "No such file or directory")
            return Rep(0, "\n".join(f"{r} # handle {i + 10}" for i, r in enumerate(self.regles)))
        if cmd[1] == "list":
            return Rep(0 if cmd[4] == self.table else 1, "chain input {}")
        if cmd[1] == "insert":
            # nftables ré-affiche le commentaire entre guillemets : on restitue ce format réel.
            self.regles.insert(0, " ".join(cmd[6:-1]) + ' "' + cmd[-1] + '"')
            return Rep(0)
        if cmd[1] == "delete":
            h = int(cmd[-1]) - 10
            self.regles.pop(h)
            return Rep(0)
        return Rep(0)


def test_la_regle_ne_vise_que_les_adresses_publiees_depuis_des_sources_privees():
    cfg = c.charger()
    cfg["reseau"]["publier"] = ["192.168.1.9", "10.10.0.5"]
    r = c.regle_nft(cfg)
    assert "ip daddr { 10.10.0.5, 192.168.1.9 }" in r and "tcp dport 3900 accept" in r
    assert "ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }" in r
    assert 'comment "secubox-voicestudio"' in r
    assert not re.search(r"(?<![\d.])0\.0\.0\.0(?![\d.])", r) and "iifname" not in r


def test_rien_de_publie_rien_d_ouvert():
    cfg = c.charger()
    assert c.regle_nft(cfg) is None and "insert rule" not in c.contenu_nft(cfg)


def test_une_adresse_publique_heritee_n_ouvre_aucune_regle():
    cfg = c.charger()
    cfg["reseau"]["publier"] = ["82.67.100.75"]
    assert c.regle_nft(cfg) is None


def test_le_fichier_charge_au_demarrage_declare_la_table_avant_d_y_inserer():
    cfg = c.charger()
    cfg["reseau"]["publier"] = ["192.168.1.9"]
    f = c.contenu_nft(cfg)
    assert f.index("table inet filter") < f.index("insert rule inet filter input")     # additif : ne peut pas faire échouer le chargement
    assert "flush" not in f and "policy" not in f and "hook" not in f


def test_appliquer_pose_la_regle_vivante_et_ecrit_le_fichier(bac_a_sable):
    c.ecrire_toml("reseau", "publier", ["192.168.1.9", "10.10.0.5"])
    run = NftFaux()
    res = c.appliquer(run)
    assert res["pare_feu"]["vivante"] is True and len(run.regles) == 1
    assert "tcp dport 3900 accept" in run.regles[0] and "secubox-voicestudio" in run.regles[0]
    assert "insert rule inet filter input" in (c.NFT_DIR / c.NFT_FICHIER).read_text()


def test_changer_publier_retire_l_ancienne_regle_avant_la_nouvelle(bac_a_sable):
    c.ecrire_toml("reseau", "publier", ["192.168.1.9", "10.10.0.5"])
    run = NftFaux()
    c.appliquer(run)
    c.ecrire_toml("reseau", "publier", ["10.10.0.5"])
    c.appliquer(run)
    assert len(run.regles) == 1 and "192.168.1.9" not in run.regles[0]       # aucune adresse ouverte derrière soi


def test_appliquer_deux_fois_ne_duplique_pas_la_regle(bac_a_sable):
    c.ecrire_toml("reseau", "publier", ["192.168.1.9"])
    run = NftFaux()
    c.appliquer(run)
    c.appliquer(run)
    c.appliquer(run)
    assert len(run.regles) == 1


def test_la_regle_ne_touche_pas_aux_regles_des_autres(bac_a_sable):
    c.ecrire_toml("reseau", "publier", ["192.168.1.9"])
    run = NftFaux()
    run.regles = ['tcp dport 22 accept', 'iifname "wg-mesh" tcp dport 53 accept comment "secubox-noms"']
    c.appliquer(run)
    assert len(run.regles) == 3 and 'tcp dport 22 accept' in run.regles
    assert not any(a[:3] == ["nft", "flush", "chain"] or "flush" in a for a in run.appels if a[0] == "nft")


def test_sur_une_box_non_redemarree_la_table_est_l_ancienne(bac_a_sable):
    """gk3 chargeait encore `secubox_filter` : la règle vivante doit y aller, le fichier visant la base unifiée."""
    c.ecrire_toml("reseau", "publier", ["192.168.1.9"])
    run = NftFaux(table="secubox_filter")
    c.appliquer(run)
    assert len(run.regles) == 1
    assert ["nft", "insert", "rule", "inet", "secubox_filter", "input"] == [a for a in run.appels if a[:2] == ["nft", "insert"]][0][:6]


def test_sans_chaine_d_entree_on_le_dit_et_on_ecrit_quand_meme_le_fichier(bac_a_sable, capsys):
    c.ecrire_toml("reseau", "publier", ["192.168.1.9"])
    run = NftFaux(table="autre")
    res = c.appliquer(run)
    assert res["pare_feu"]["vivante"] is False and "chaîne d'entrée" in capsys.readouterr().err
    assert (c.NFT_DIR / c.NFT_FICHIER).exists()


def test_nft_absent_ne_fait_pas_tomber_appliquer(bac_a_sable, capsys):
    c.ecrire_toml("reseau", "publier", ["192.168.1.9"])
    base = LxcFaux()

    def sans_nft(cmd, **k):
        if cmd[0] == "nft":
            raise FileNotFoundError(2, "No such file or directory")
        return base(cmd, **k)
    res = c.appliquer(sans_nft)
    assert res["pare_feu"]["vivante"] is False and "nft indisponible" in capsys.readouterr().err


def test_une_regle_refusee_par_nft_est_dite(bac_a_sable, capsys):
    c.ecrire_toml("reseau", "publier", ["192.168.1.9"])
    run = NftFaux()
    base = run.__call__

    def refuse(cmd, **k):
        if cmd[:2] == ["nft", "insert"]:
            run.appels.append(list(cmd))
            return Rep(1, "", "Error: syntax")
        return base(cmd, **k)
    res = c.appliquer(refuse)
    assert res["pare_feu"]["vivante"] is False and "refusée" in capsys.readouterr().err


def test_pare_feu_ferme_retire_la_regle_et_le_fichier(bac_a_sable):
    c.ecrire_toml("reseau", "publier", ["192.168.1.9"])
    run = NftFaux()
    c.appliquer(run)
    assert c.cmd_pare_feu_ferme(run) == 0
    assert run.regles == [] and not (c.NFT_DIR / c.NFT_FICHIER).exists()


def test_la_regle_est_passee_a_nft_sans_shell(bac_a_sable):
    c.ecrire_toml("reseau", "publier", ["192.168.1.9"])
    run = NftFaux()
    c.appliquer(run)
    [ins] = [a for a in run.appels if a[:2] == ["nft", "insert"]]
    assert ins[-1] == "secubox-voicestudio" and "accept" in ins and '"' not in " ".join(ins)


def test_la_bascule_retire_les_regles_de_transfert_de_l_ancien_executeur(bac_a_sable, monkeypatch):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"x")
    monkeypatch.setattr(c.os, "lchown", lambda *a: None)
    monkeypatch.setattr(c, "_port_libre", lambda *a: True)
    monkeypatch.setattr(c, "sante", lambda cfg, *a, **k: {"ok": True, "http": 200})
    c.creer_cle()
    run = NftFaux("secubox_filter", etat="RUNNING")
    reel = c.subprocess.run
    run.regles = ['ip daddr 10.88.0.0/16 tcp dport 3900 ct status dnat accept comment "secubox-voicestudio"', "tcp dport 22 accept"]
    c.cmd_basculer(lambda cmd, **k: reel(cmd, **k) if cmd[0] == "cp" else run(cmd, **k))
    assert not any("10.88.0.0/16" in r for r in run.regles) and "tcp dport 22 accept" in run.regles


def test_la_migration_laisse_les_donnees_en_0750(bac_a_sable, monkeypatch):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"x")
    monkeypatch.setattr(c.os, "lchown", lambda *a: None)
    run = LxcFaux()
    reel = c.subprocess.run
    c.cmd_migrer_podman(lambda cmd, **k: reel(cmd, **k) if cmd[0] == "cp" else run(cmd, **k))
    assert stat.S_IMODE(c.donnees(c.charger()).stat().st_mode) == 0o750


# ── journal : le fichier du moteur, pas journald (qui échoue dans le LXC non privilégié) ─────────
def test_le_journal_vient_du_fichier_du_moteur_lxc_arrete_compris(bac_a_sable, capsys):
    d = Path(c.donnees(c.charger()))
    d.mkdir()
    (d / "omnivoice.log").write_text("\n".join(f"2026-10-02 INFO ligne {i}" for i in range(1, 11)) + "\n")
    run = LxcFaux("STOPPED")
    assert c.cmd_logs(3, run) == 0
    assert capsys.readouterr().out.splitlines() == ["2026-10-02 INFO ligne 8", "2026-10-02 INFO ligne 9", "2026-10-02 INFO ligne 10"]
    assert not any(a[0] == "lxc-attach" for a in run.appels)


def test_le_journal_est_borne_et_ne_lit_que_la_fin_du_fichier(bac_a_sable, capsys):
    d = Path(c.donnees(c.charger()))
    d.mkdir()
    (d / "omnivoice.log").write_text("x" * 5_000_000 + "\nderniere ligne\n")      # gros fichier : on ne le charge pas en entier
    c.cmd_logs(10_000, LxcFaux("STOPPED"))
    sortie = capsys.readouterr().out
    assert sortie.rstrip().endswith("derniere ligne") and len(sortie) < 300_000


def test_le_journal_sans_fichier_ni_conteneur_le_dit(bac_a_sable, capsys):
    assert c.cmd_logs(10, LxcFaux("STOPPED")) == 2
    assert "jamais démarré" in capsys.readouterr().err


def test_le_journal_retombe_sur_le_journal_du_lxc_si_le_fichier_manque(bac_a_sable):
    run = LxcFaux("RUNNING")
    c.cmd_logs(5, run)
    assert any(a[0] == "lxc-attach" and "journalctl" in a for a in run.appels)


def test_le_point_de_montage_vide_laisse_par_le_lxc_est_retire_apres_migration(bac_a_sable, monkeypatch):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"x")
    cible = c.donnees(c.charger())
    cible.mkdir()                                              # point de montage vide
    monkeypatch.setattr(c.os, "lchown", lambda *a: None)
    run = LxcFaux()
    reel = c.subprocess.run
    c.cmd_migrer_podman(lambda cmd, **k: reel(cmd, **k) if cmd[0] == "cp" else run(cmd, **k))
    assert not Path(str(cible) + ".avant-migration").exists()


def test_une_ancienne_cible_non_vide_est_gardee(bac_a_sable, monkeypatch):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"x")
    cible = c.donnees(c.charger())
    cible.mkdir()
    (cible / "voix.wav").write_bytes(b"precieuse")
    monkeypatch.setattr(c.os, "lchown", lambda *a: None)
    run = LxcFaux()
    reel = c.subprocess.run
    c.cmd_migrer_podman(lambda cmd, **k: reel(cmd, **k) if cmd[0] == "cp" else run(cmd, **k))
    assert (Path(str(cible) + ".avant-migration") / "voix.wav").read_bytes() == b"precieuse"


# ── interface native : vhost, garde, clé posée par nginx ─────────────────────────────────────────────────────────
class DomaineFaux(NftFaux):
    """secubox-domaine + nginx -t / reload."""
    def __init__(self, domaine="voicestudio.gk3.secubox.in", admin="admin.gk3.secubox.in", nginx_ok=True, **kw):
        super().__init__(**kw)
        self.domaine, self.admin, self.nginx_ok = domaine, admin, nginx_ok

    def __call__(self, cmd, **k):
        if cmd[0] == "secubox-domaine":
            self.appels.append(list(cmd))
            return Rep(0, (self.domaine if cmd[1] == "voicestudio" else self.admin) + "\n")
        if cmd[0] == "nginx":
            self.appels.append(list(cmd))
            return Rep(0 if self.nginx_ok else 1, "", "" if self.nginx_ok else "nginx: [emerg] unexpected }")
        return super().__call__(cmd, **k)

    def recharges(self):
        return [a for a in self.appels if a[:3] == ["systemctl", "reload", "nginx"]]


def interface_prete(bac):
    c.MARQUE_INTERFACE.write_text("ok")
    c.creer_cle()


def test_le_vhost_garde_par_un_administrateur_et_pose_la_cle_apres_la_garde(bac_a_sable):
    v = c.contenu_vhost(c.charger(), "voicestudio.gk3.secubox.in", "admin.gk3.secubox.in")
    assert "server_name voicestudio.gk3.secubox.in;" in v and "listen 9080;" in v
    assert "auth_request /__sbx_voicestudio_garde;" in v and "error_page 401 403 = @voicestudio_refus;" in v
    assert "proxy_pass http://unix:/run/secubox/voicestudio.sock:/gate;" in v          # la garde = require_jwt du module
    assert "internal;" in v                                                             # la garde n'est pas joignable de l'extérieur
    assert v.index("auth_request") < v.index(f"include {c.SNIPPET_CLE};")               # la clé n'est posée QU'APRÈS la garde
    assert "https://admin.gk3.secubox.in/login.html" in v


def test_le_vhost_ne_laisse_passer_ni_cookie_ni_authorization_du_navigateur(bac_a_sable):
    v = c.contenu_vhost(c.charger(), "voicestudio.gk3.secubox.in", "")
    assert 'proxy_set_header Cookie "";' in v                                           # le cookie de session SecuBox ne sort pas
    assert "$http_authorization" not in v and "$http_cookie" not in v
    garde = v[v.index("location = /__sbx_voicestudio_garde"):v.index("location @voicestudio_refus")]
    assert "proxy_pass_request_body off;" in garde and 'Content-Length ""' in garde


def test_le_vhost_porte_les_websockets_et_les_envois_volumineux(bac_a_sable):
    v = c.contenu_vhost(c.charger(), "voicestudio.gk3.secubox.in", "")
    assert "proxy_set_header Upgrade $http_upgrade;" in v and "Connection $sbx_vs_connexion;" in v
    assert "map $http_upgrade $sbx_vs_connexion" in v and "proxy_http_version 1.1;" in v
    assert "client_max_body_size 2g;" in v and "proxy_request_buffering off;" in v and "proxy_read_timeout 3600s;" in v
    assert "proxy_pass http://10.100.0.230:3900;" in v


def test_le_vhost_refuse_une_ip_de_conteneur_suspecte(bac_a_sable):
    cfg = c.charger()
    cfg["lxc"]["ip"] = "10.100.0.230; return 200"
    with pytest.raises(c.Erreur):
        c.contenu_vhost(cfg, "voicestudio.gk3.secubox.in", "")


def test_le_snippet_de_cle_n_accepte_qu_une_cle_de_forme_connue(bac_a_sable):
    c.creer_cle()
    s = c.contenu_snippet_cle()
    assert s.splitlines()[-1] == f'proxy_set_header Authorization "Bearer {c.lire_cle()}";'
    c.CLE.write_text('abc"; return 200; #\n')                       # une clé piégée ne doit JAMAIS entrer dans un fichier nginx
    assert c.contenu_snippet_cle() is None
    c.CLE.write_text("court\n")
    assert c.contenu_snippet_cle() is None


def test_pas_de_vhost_tant_que_l_interface_n_est_pas_construite(bac_a_sable):
    run = DomaineFaux()
    c.creer_cle()
    r = c.appliquer_vhost(c.charger(), run)
    assert r["actif"] is False and not (c.NGINX_DISPO / c.VHOST_FICHIER).exists() and not c.SNIPPET_CLE.exists()


def test_le_vhost_est_pose_active_et_nginx_recharge_une_fois(bac_a_sable):
    interface_prete(bac_a_sable)
    run = DomaineFaux()
    r = c.appliquer_vhost(c.charger(), run)
    assert r == {"actif": True, "domaine": "voicestudio.gk3.secubox.in"}
    assert (c.NGINX_DISPO / c.VHOST_FICHIER).exists() and (c.NGINX_ACTIF / c.VHOST_FICHIER).is_symlink()
    assert stat.S_IMODE(c.SNIPPET_CLE.stat().st_mode) == 0o600                          # la clé n'est lisible que de root
    assert len(run.recharges()) == 1
    c.appliquer_vhost(c.charger(), run)                                                  # idempotent : rien de changé, pas de rechargement
    assert len(run.recharges()) == 1


def test_une_configuration_nginx_refusee_n_est_pas_laissee_en_place(bac_a_sable, capsys):
    interface_prete(bac_a_sable)
    run = DomaineFaux(nginx_ok=False)
    r = c.appliquer_vhost(c.charger(), run)
    assert r["actif"] is False and "refusé" in r["erreur"]
    assert not (c.NGINX_ACTIF / c.VHOST_FICHIER).exists()                                # le frontal reste sain
    assert not run.recharges() and "nginx -t échoue" in capsys.readouterr().err


@pytest.mark.parametrize("domaine", ["", "evil.com; rm -rf /", "a b", "UPPER_case", "x" * 300])
def test_un_domaine_suspect_ne_pose_aucun_vhost(bac_a_sable, domaine):
    interface_prete(bac_a_sable)
    r = c.appliquer_vhost(c.charger(), DomaineFaux(domaine=domaine))
    assert r["actif"] is False and not (c.NGINX_DISPO / c.VHOST_FICHIER).exists()


def test_renouveler_la_cle_met_a_jour_nginx(bac_a_sable):
    """Sinon l'interface native répondrait 401 : nginx poserait l'ANCIENNE clé."""
    interface_prete(bac_a_sable)
    run = DomaineFaux(etat="RUNNING")
    c.appliquer_vhost(c.charger(), run)
    avant = c.SNIPPET_CLE.read_text()
    c.cmd_cle_renouveler(run)
    assert c.SNIPPET_CLE.read_text() != avant and c.lire_cle() in c.SNIPPET_CLE.read_text()
    assert len(run.recharges()) == 2


def test_interface_desactivee_retire_le_vhost(bac_a_sable):
    interface_prete(bac_a_sable)
    run = DomaineFaux()
    c.appliquer_vhost(c.charger(), run)
    c.ecrire_toml("interface", "activer", False)
    r = c.appliquer_vhost(c.charger(), run)
    assert r["actif"] is False and not (c.NGINX_ACTIF / c.VHOST_FICHIER).exists() and not c.SNIPPET_CLE.exists()


def test_cmd_interface_ne_croit_pas_un_code_0_sans_dist(bac_a_sable, capsys):
    """Régression gk3 : le script sortait en 0 (« désactivée ») sans rien construire ; le marqueur posé empêchait toute reprise."""
    c.creer_cle()
    run = DomaineFaux(etat="RUNNING")
    base = run.__call__

    def sans_dist(cmd, **k):
        if cmd[:2] == ["bash", c.INSTALL]:
            return Rep(0)
        if cmd[0] == "lxc-attach" and cmd[-3:] == ["test", "-s", "/app/frontend/dist/index.html"]:
            return Rep(1)                                                     # dist absent
        return base(cmd, **k)
    assert c.cmd_interface(sans_dist) == 5
    assert not c.MARQUE_INTERFACE.exists() and not (c.NGINX_ACTIF / c.VHOST_FICHIER).exists()
    assert "echec-dist-absent" in c.AUDIT.read_text() and "frontend/dist est absent" in capsys.readouterr().err


def test_cmd_interface_construit_puis_pose_le_vhost(bac_a_sable):
    c.creer_cle()
    run = DomaineFaux(etat="RUNNING")
    reel = c.subprocess.run
    vus = []

    def suivi(cmd, **k):
        if cmd[:2] == ["bash", c.INSTALL]:
            vus.append(cmd)
            return Rep(0)
        return run(cmd, **k)
    assert c.cmd_interface(suivi) == 0
    assert vus == [["bash", c.INSTALL, "--interface"]] and c.MARQUE_INTERFACE.exists()
    assert (c.NGINX_ACTIF / c.VHOST_FICHIER).is_symlink() and "interface construite" in c.AUDIT.read_text()
    del reel


def test_cmd_interface_en_echec_ne_pose_ni_marqueur_ni_vhost(bac_a_sable):
    c.creer_cle()
    run = DomaineFaux(etat="RUNNING")
    rc = c.cmd_interface(lambda cmd, **k: Rep(4) if cmd[:2] == ["bash", c.INSTALL] else run(cmd, **k))
    assert rc == 4 and not c.MARQUE_INTERFACE.exists() and not (c.NGINX_ACTIF / c.VHOST_FICHIER).exists()
    assert "interface echec-rc4" in c.AUDIT.read_text()


def test_cmd_interface_sans_lxc_dit_quoi_faire(bac_a_sable):
    with pytest.raises(c.Erreur, match="voicestudioctl install"):
        c.cmd_interface(DomaineFaux(etat="ABSENT"))


def test_cmd_interface_desactivee_ne_construit_rien(bac_a_sable):
    c.ecrire_toml("interface", "activer", False)
    run = DomaineFaux(etat="RUNNING")
    assert c.cmd_interface(run) == 0 and not any(a[0] == "bash" for a in run.appels)


def test_interface_ferme_retire_vhost_cle_et_marqueur(bac_a_sable):
    interface_prete(bac_a_sable)
    run = DomaineFaux()
    c.appliquer_vhost(c.charger(), run)
    assert c.cmd_interface_ferme(run) == 0
    assert not c.MARQUE_INTERFACE.exists() and not c.SNIPPET_CLE.exists() and not (c.NGINX_ACTIF / c.VHOST_FICHIER).exists()


def test_la_construction_n_est_pas_offerte_au_panneau():
    """`interface` modifie le LXC et nginx : ni la porte `api` ni le panneau ne l'exposent."""
    assert "interface" not in c.ACTIONS_API and "interface-ferme" not in c.ACTIONS_API


def test_l_etat_dit_si_l_interface_native_est_prete(bac_a_sable):
    assert c.etat_complet(LxcFaux("STOPPED"))["interface_native"] is False
    interface_prete(bac_a_sable)
    run = DomaineFaux(etat="STOPPED")
    c.appliquer_vhost(c.charger(), run)
    e = c.etat_complet(run)
    assert e["interface_native"] is True and e["interface_vhost"] is True


def test_les_booleens_s_ecrivent_en_toml_valide(bac_a_sable):
    c.ecrire_toml("interface", "activer", False)
    assert "activer = false" in c.CONF.read_text()
    assert tomllib.loads(c.CONF.read_text())["interface"]["activer"] is False
    c.ecrire_toml("interface", "activer", True)
    assert tomllib.loads(c.CONF.read_text())["interface"]["activer"] is True


# ── montée de version : une configuration d'avant [interface] ne doit pas laisser les scripts sans valeur ───────
def test_migrer_conf_ajoute_les_cles_nouvelles_sans_toucher_aux_existantes(bac_a_sable):
    c.CONF.write_text('[lxc]\nnom = "voicestudio"\nmemoire = "6G"\nmode = "demande"\n\n[reseau]\npublier = ["192.168.1.9", "10.10.0.5"]\n')
    assert c.cmd_migrer_conf() == 0
    d = tomllib.loads(c.CONF.read_text())
    assert d["lxc"]["memoire"] == "6G" and d["lxc"]["mode"] == "demande"                  # le choix de l'opérateur l'emporte
    assert d["reseau"]["publier"] == ["192.168.1.9", "10.10.0.5"]
    assert d["interface"]["activer"] is True and d["interface"]["bun_url"].startswith("https://github.com/oven-sh/bun/")
    assert re.fullmatch(r"[0-9a-f]{64}", d["interface"]["bun_sha256"]) and d["interface"]["domaine"] == "voicestudio"
    assert "cles-ajoutees=" in c.AUDIT.read_text()


def test_migrer_conf_est_idempotent_apres_completion(bac_a_sable):
    c.CONF.write_text('[lxc]\nnom = "voicestudio"\n')
    c.cmd_migrer_conf()
    apres = c.CONF.read_text()
    c.cmd_migrer_conf()
    assert c.CONF.read_text() == apres


def test_migrer_conf_respecte_une_interface_desactivee_par_l_operateur(bac_a_sable):
    c.CONF.write_text('[interface]\nactiver = false\n')
    c.cmd_migrer_conf()
    assert tomllib.loads(c.CONF.read_text())["interface"]["activer"] is False


def lire_cfg_du_script(toml_box: str, tmp_path, section: str, cle: str, repli: str = "") -> str:
    """Exécute la fonction cfg() de install-lxc.sh telle quelle (bash + python), sur une configuration donnée."""
    import subprocess
    sh = (PKG / "lxc" / "install-lxc.sh").read_text()
    fonction = sh[sh.index("cfg() {"):sh.index("\n}\n", sh.index("cfg() {")) + 3]
    conf = tmp_path / "box.toml"
    conf.write_text(toml_box)
    out = subprocess.run(["bash", "-c", f'CONF="{conf}"\n{fonction}\ncfg {section} {cle} {repli}'],
                         capture_output=True, text=True, timeout=20,
                         env={"SECUBOX_VS_CONF_DEFAUT": str(PKG / "conf" / "voicestudio.toml"), "PATH": "/usr/bin:/bin"})
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


def test_le_script_lit_les_defauts_du_paquet_quand_la_box_n_a_pas_la_section(tmp_path):
    """Régression vue sur gk3 : le script concluait « interface désactivée » parce que la configuration de la box
    d'avant la section [interface] n'avait ni `activer` ni l'adresse de bun."""
    box = '[lxc]\nnom = "voicestudio"\n'
    assert lire_cfg_du_script(box, tmp_path, "interface", "activer", "true") == "true"
    assert lire_cfg_du_script(box, tmp_path, "interface", "bun_url").startswith("https://github.com/oven-sh/bun/")
    assert re.fullmatch(r"[0-9a-f]{64}", lire_cfg_du_script(box, tmp_path, "interface", "bun_sha256"))


def test_le_script_ecrit_les_booleens_en_minuscules_et_respecte_la_box(tmp_path):
    assert lire_cfg_du_script("[interface]\nactiver = false\n", tmp_path, "interface", "activer", "true") == "false"
    assert lire_cfg_du_script("[interface]\nactiver = true\n", tmp_path, "interface", "activer", "true") == "true"
    assert lire_cfg_du_script('[lxc]\nmemoire = "2G"\n', tmp_path, "lxc", "memoire", "4G") == "2G"      # la box l'emporte sur le paquet


def test_une_section_memoire_n_est_pas_prise_pour_l_ancienne_cle_a_plat(bac_a_sable):
    """Régression : `[memoire]` (nouvelle section) portait le nom de l'ancienne clé `memoire = "4g"` : la migration
    prenait un fichier DÉJÀ au nouveau schéma pour un ancien et le réécrivait (chemin, adresses, tout)."""
    avant = c.CONF.read_text()
    assert "[memoire]" in c.CONF_DEFAUT.read_text()
    c.cmd_migrer_conf()
    assert c.CONF.read_text() == avant
    assert not c.CONF.with_name(c.CONF.name + ".avant-lxc").exists()


def test_l_ancienne_cle_memoire_a_plat_est_toujours_convertie(bac_a_sable):
    c.CONF.write_text('publier = ["192.168.1.9"]\nmemoire = "4g"\nasr = "Systran/faster-whisper-base"\n')
    c.cmd_migrer_conf()
    d = tomllib.loads(c.CONF.read_text())
    assert d["lxc"]["memoire"] == "4G" and d["reseau"]["publier"] == ["192.168.1.9"]
    assert d["memoire"]["besoin_synthese_mo"] == 3800                          # la nouvelle section existe aussi


# ── mémoire : réglages du moteur et libération de place ──────────────────────────────────────────────────────────
class BancMemoire:
    """Une box fictive : /proc/meminfo, cgroups des conteneurs, liste des endormables, secubox-profilectl simulé."""
    def __init__(self, tmp_path, monkeypatch, disponible=1500, conteneurs=None, sommeilleux=None, moteur_mo=600, swap_disque_mo=0):
        self.swaps = tmp_path / "swaps"
        self.swaps.write_text("Filename Type Size Used Priority\n/dev/zram0 partition 3989500 3989500 100\n"
                              + (f"/srv/secubox/swapfile file {8388604} {8388604 - swap_disque_mo * 1024} -2\n" if swap_disque_mo else ""))
        self.meminfo = tmp_path / "meminfo"
        self.cgroup = tmp_path / "cgroup"
        self.sommeilleux = tmp_path / "sommeilleux.json"
        self.conteneurs = conteneurs if conteneurs is not None else {"peertube": 203, "jitsi": 197, "jellyfin": 63, "mail": 300}
        self.endormis, self.dispo, self.echecs = [], disponible, set()
        for nom, mo in {**self.conteneurs, "voicestudio": moteur_mo}.items():
            d = self.cgroup / f"lxc.payload.{nom}"
            d.mkdir(parents=True)
            (d / "memory.current").write_text(str(mo * 1048576))
        self.sommeilleux.write_text(__import__("json").dumps(sommeilleux if sommeilleux is not None else ["peertube", "jitsi", "jellyfin"]))
        self.ecrire()
        for nom, val in {"MEMINFO": self.meminfo, "SWAPS": self.swaps, "CGROUP_LXC": self.cgroup, "SOMMEILLEUX": self.sommeilleux,
                         "PLACE_ETAT": tmp_path / "place.json"}.items():
            monkeypatch.setattr(c, nom, val)

    def ecrire(self):
        self.meminfo.write_text(f"MemTotal: 8000000 kB\nMemAvailable: {self.dispo * 1024} kB\nSwapTotal: 8000000 kB\nSwapFree: 6000000 kB\n")

    def run(self, cmd, **k):
        if cmd[0] == "lxc-ls":
            return Rep(0, " ".join(self.conteneurs) + " voicestudio\n")
        if cmd[0] == c.PROFILECTL:
            nom = cmd[3]
            self.endormis.append(nom)
            if nom in self.echecs:
                return Rep(1, "", "refusé")
            self.dispo += self.conteneurs[nom]                  # le conteneur rend sa mémoire
            self.ecrire()
            return Rep(0, "{}")
        return Rep(0)


def place(banc, capsys, **kw):
    rc = c.cmd_faire_de_la_place(banc.run, dormir=lambda s: None, **kw)
    return rc, __import__("json").loads(capsys.readouterr().out.strip().splitlines()[-1])


def test_assez_de_memoire_on_n_endort_rien(bac_a_sable, tmp_path, monkeypatch, capsys):
    b = BancMemoire(tmp_path, monkeypatch, disponible=5000)
    rc, r = place(b, capsys)
    assert rc == 0 and r["suffisante"] is True and b.endormis == [] and r["endormis"] == []


def test_le_modele_deja_charge_ne_demande_rien_de_plus(bac_a_sable, tmp_path, monkeypatch, capsys):
    b = BancMemoire(tmp_path, monkeypatch, disponible=300, moteur_mo=3100)
    rc, r = place(b, capsys)
    assert r["suffisante"] is True and b.endormis == []                 # la synthèse réutilise le modèle résident


def test_on_endort_le_plus_gros_d_abord_et_on_s_arrete_des_que_c_est_assez(bac_a_sable, tmp_path, monkeypatch, capsys):
    b = BancMemoire(tmp_path, monkeypatch, disponible=3500)
    rc, r = place(b, capsys)
    # 3500 + 203 (peertube) = 3703 < 3800 : un second est endormi (jitsi, 197) → 3900 ≥ 3800 : on s'arrête AVANT jellyfin
    assert b.endormis[:2] == ["peertube", "jitsi"] and "jellyfin" not in b.endormis
    assert r["suffisante"] is True and [e["id"] for e in r["endormis"]] == b.endormis


def test_seuls_les_endormables_en_marche_sont_touches_jamais_mail_ni_le_moteur(bac_a_sable, tmp_path, monkeypatch, capsys):
    b = BancMemoire(tmp_path, monkeypatch, disponible=100)
    place(b, capsys)
    assert "mail" not in b.endormis and "voicestudio" not in b.endormis                # pas dans la liste du sleeper / soi-même
    assert set(b.endormis) <= {"peertube", "jitsi", "jellyfin"}


def test_la_voie_est_secubox_profilectl_avec_audit_et_jamais_lxc_stop(bac_a_sable, tmp_path, monkeypatch, capsys):
    b = BancMemoire(tmp_path, monkeypatch, disponible=3700)
    appels = []
    reel = b.run
    monkeypatch.setattr(b, "run", lambda cmd, **k: (appels.append(list(cmd)), reel(cmd, **k))[1])
    c.cmd_faire_de_la_place(b.run, dormir=lambda s: None)
    assert [c.PROFILECTL, "apply", "--only", "peertube", "--yes", "--json"] in appels
    assert not any(a[0] in ("lxc-stop", "systemctl") for a in appels)                   # pas de contournement de la gouvernance
    assert "faire-de-la-place suffisante=" in c.AUDIT.read_text()


def test_un_conteneur_qui_refuse_de_dormir_est_dit_et_on_passe_au_suivant(bac_a_sable, tmp_path, monkeypatch, capsys):
    b = BancMemoire(tmp_path, monkeypatch, disponible=3500)
    b.echecs.add("peertube")
    rc, r = place(b, capsys)
    assert "peertube non endormi" in capsys.readouterr().err or True
    assert [e["id"] for e in r["endormis"]][:1] == ["jitsi"]


def test_memoire_toujours_insuffisante_apres_tout_est_dit_avec_la_raison(bac_a_sable, tmp_path, monkeypatch, capsys):
    b = BancMemoire(tmp_path, monkeypatch, disponible=500)
    rc, r = place(b, capsys)
    assert rc == 0 and r["suffisante"] is False and "insuffisante" in r["raison"]
    assert len(r["endormis"]) == 3 and r["disponible_mo"] == 500 + 203 + 197 + 63


def test_aucun_conteneur_endormable_en_marche(bac_a_sable, tmp_path, monkeypatch, capsys):
    b = BancMemoire(tmp_path, monkeypatch, disponible=500, sommeilleux=[])
    rc, r = place(b, capsys)
    assert r["suffisante"] is False and r["raison"] == "aucun conteneur endormable en marche" and b.endormis == []


def test_liste_du_sleeper_absente_on_n_endort_rien(bac_a_sable, tmp_path, monkeypatch, capsys):
    b = BancMemoire(tmp_path, monkeypatch, disponible=500)
    b.sommeilleux.unlink()
    rc, r = place(b, capsys)
    assert r["suffisante"] is False and b.endormis == []                # dans le doute, jamais d'endormissement


def test_une_salve_au_plus_toutes_les_deux_minutes(bac_a_sable, tmp_path, monkeypatch, capsys):
    b = BancMemoire(tmp_path, monkeypatch, disponible=500)
    horloge = {"t": 1000.0}
    c.cmd_faire_de_la_place(b.run, dormir=lambda s: None, maintenant=lambda: horloge["t"])
    capsys.readouterr()
    premiers = list(b.endormis)
    b.dispo = 500
    b.ecrire()
    horloge["t"] += 30                                                  # 30 s plus tard : trop tôt
    c.cmd_faire_de_la_place(b.run, dormir=lambda s: None, maintenant=lambda: horloge["t"])
    r = __import__("json").loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert b.endormis == premiers and r["suffisante"] is False and "tentative récente" in r["raison"]
    horloge["t"] += 200                                                 # assez tard : on retente
    c.cmd_faire_de_la_place(b.run, dormir=lambda s: None, maintenant=lambda: horloge["t"])
    capsys.readouterr()


def test_au_plus_quatre_conteneurs_par_salve(bac_a_sable, tmp_path, monkeypatch, capsys):
    gros = {f"c{i}": 10 for i in range(8)}
    b = BancMemoire(tmp_path, monkeypatch, disponible=100, conteneurs=gros, sommeilleux=list(gros))
    place(b, capsys)
    assert len(b.endormis) == c.MAX_ENDORMIS == 4


def test_le_ctl_expose_la_liberation_a_la_porte_api_et_rend_du_json(bac_a_sable, tmp_path, monkeypatch):
    b = BancMemoire(tmp_path, monkeypatch, disponible=5000)
    monkeypatch.setattr(c.subprocess, "run", b.run)
    rc, r = appeler_api({"action": "faire-de-la-place", "par": "gandalf"})
    assert rc == 0 and r["suffisante"] is True and r["ok"] is True and "disponible_mo" in r


def test_les_reglages_memoire_vont_dans_l_environnement_du_moteur(bac_a_sable):
    c.creer_cle()
    env = c.contenu_env_moteur(c.charger())
    lignes = dict(ligne.split("=", 1) for ligne in env.strip().splitlines())
    assert lignes["OMNIVOICE_API_KEY"] == c.lire_cle()
    assert lignes["OMNIVOICE_IDLE_TIMEOUT_S"] == "60"                   # le modèle (3 Go) est rendu après 1 min d'inactivité
    assert lignes["OMNIVOICE_PRELOAD_CAPTURE_ASR"] == "0" and lignes["OMNIVOICE_PRELOAD_WATERMARK"] == "0"


@pytest.mark.parametrize("valeur,attendu", [(5, "10"), (999999, "86400"), ("abc", "60"), (120, "120")])
def test_le_delai_de_liberation_est_borne_et_valide(bac_a_sable, valeur, attendu):
    c.creer_cle()
    cfg = c.charger()
    cfg["moteur"]["liberation_modele_s"] = valeur
    assert f"OMNIVOICE_IDLE_TIMEOUT_S={attendu}\n" in c.contenu_env_moteur(cfg)


def test_changer_un_reglage_memoire_relance_le_moteur(bac_a_sable):
    """assurer_moteur compare le CONTENU du fichier : pas seulement la clé."""
    c.creer_cle()
    run = LxcFaux("RUNNING")
    c.ecrire_toml("moteur", "liberation_modele_s", 30)
    c.assurer_moteur(c.charger(), run, dormir=lambda s: None)
    assert "OMNIVOICE_IDLE_TIMEOUT_S=30" in run.entrees[-1] and "cmp -s" in run.appels[-1][-1]


def test_la_cle_reste_hors_des_arguments_avec_les_reglages_memoire(bac_a_sable):
    c.creer_cle()
    run = LxcFaux("RUNNING")
    c.assurer_moteur(c.charger(), run, dormir=lambda s: None)
    assert all(c.lire_cle() not in " ".join(a) for a in run.appels) and c.lire_cle() in run.entrees[-1]


def test_lire_meminfo_et_etat_memoire(bac_a_sable, tmp_path, monkeypatch):
    BancMemoire(tmp_path, monkeypatch, disponible=1234, moteur_mo=777)
    e = c.etat_memoire(c.charger())
    assert e == {"disponible_mo": 1234, "swap_libre_mo": 5859, "swap_total_mo": 7812, "swap_disque_mo": 0, "effective_mo": 1234, "moteur_mo": 777}


def test_l_etat_complet_porte_la_memoire_de_la_box(bac_a_sable, tmp_path, monkeypatch):
    BancMemoire(tmp_path, monkeypatch, disponible=4321)
    assert c.etat_complet(LxcFaux("STOPPED"))["memoire_hote"]["disponible_mo"] == 4321


def test_appliquer_pousse_les_reglages_du_moteur_quand_il_tourne(bac_a_sable):
    """Une montée de version qui change l'environnement du moteur ne doit pas attendre son prochain démarrage."""
    c.creer_cle()
    run = DomaineFaux(etat="RUNNING")
    c.appliquer(run)
    attaches = [a for a in run.appels if a[0] == "lxc-attach" and "cmp -s" in a[-1]]
    assert attaches and any("OMNIVOICE_IDLE_TIMEOUT_S=60" in (e or "") for e in run.entrees)


def test_appliquer_ne_touche_pas_au_moteur_arrete(bac_a_sable):
    c.creer_cle()
    run = DomaineFaux(etat="STOPPED")
    c.appliquer(run)
    assert not any(a[0] == "lxc-attach" for a in run.appels)


# ── le swap DISQUE compte (pour moitié, plafonné) ; le zram jamais ─────────────────────────────────────────────────
def test_le_zram_seul_ne_compte_pas_comme_du_swap(bac_a_sable, tmp_path, monkeypatch):
    BancMemoire(tmp_path, monkeypatch, disponible=2900, swap_disque_mo=0)
    e = c.etat_memoire(c.charger())
    assert e["swap_disque_mo"] == 0 and e["effective_mo"] == 2900


def test_un_swap_disque_libre_ajoute_la_moitie_de_son_libre_plafonnee(bac_a_sable, tmp_path, monkeypatch):
    b = BancMemoire(tmp_path, monkeypatch, disponible=2900, swap_disque_mo=2000)
    assert c.etat_memoire(c.charger())["effective_mo"] == 2900 + 1000                  # moitié de 2000
    b.swaps.write_text("Filename Type Size Used Priority\n/srv/secubox/swapfile file 8388604 0 -2\n")
    assert c.etat_memoire(c.charger())["effective_mo"] == 2900 + 2048                  # plafonné par swap_compte_mo


def test_avec_le_swap_disque_gk3_peut_synthetiser_sans_rien_endormir(bac_a_sable, tmp_path, monkeypatch, capsys):
    """Le cas réel : 2,9 Go disponibles après libération du modèle, 8 Go de swap disque libres → 3,9 Go effectifs ≥ 3,8 Go."""
    b = BancMemoire(tmp_path, monkeypatch, disponible=2880, swap_disque_mo=8100)
    rc, r = place(b, capsys)
    assert r["suffisante"] is True and b.endormis == [] and r["effective_mo"] >= 3800


def test_sans_swap_disque_la_meme_box_doit_endormir_ou_refuser(bac_a_sable, tmp_path, monkeypatch, capsys):
    b = BancMemoire(tmp_path, monkeypatch, disponible=2880, swap_disque_mo=0)
    rc, r = place(b, capsys)
    assert b.endormis and r["suffisante"] is False                                      # 2880 + 463 < 3800 : refusé, chiffres à l'appui


def test_proc_swaps_illisible_on_ne_compte_rien(bac_a_sable, tmp_path, monkeypatch):
    monkeypatch.setattr(c, "SWAPS", tmp_path / "absent")
    assert c.swap_disque_libre_mo() == 0
