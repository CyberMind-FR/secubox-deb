# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2702 : le capteur DNS d'ad-guard alimente aussi les alertes de dns-guard (alerts.jsonl), sans jamais journaliser une requête ordinaire."""
import importlib.machinery
import importlib.util
import json
import random
import socket
import sqlite3
import string
import threading
from datetime import datetime
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
SBIN = PKG / "sbin" / "secubox-adguard-dnssensor"
NOW = 1_800_000_000
TV = "192.168.1.60"
CHAMPS_DNSALERT = {"id", "type", "severity", "domain", "client_ip", "description", "details", "timestamp", "blocked"}


@pytest.fixture()
def capteur(tmp_path, monkeypatch):
    (tmp_path / "etat").mkdir()
    (tmp_path / "dnsguard").mkdir()
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_ETAT", str(tmp_path / "etat"))
    monkeypatch.setenv("SECUBOX_ACTORD_SOCKET", str(tmp_path / "a.sock"))
    monkeypatch.setenv("SECUBOX_DNS_MALVEILLANTS", str(tmp_path / "liste.txt"))
    monkeypatch.setenv("SECUBOX_DNSGUARD_ALERTES", str(tmp_path / "dnsguard" / "alerts.jsonl"))
    loader = importlib.machinery.SourceFileLoader("dnssensor_2702", str(SBIN))
    spec = importlib.util.spec_from_loader("dnssensor_2702", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


@pytest.fixture()
def anomalies(capteur):
    return capteur.A


def magasin(tmp_path, recents):
    cx = sqlite3.connect(tmp_path / "etat" / "dnstv.db")
    cx.executescript("""CREATE TABLE dnstv_counts (jour TEXT, client TEXT, domaine TEXT, categorie TEXT DEFAULT '', decision TEXT, hits INTEGER, PRIMARY KEY (jour, client, domaine, decision));
    CREATE TABLE dnstv_recents (ts INTEGER, client TEXT, domaine TEXT, qtype TEXT DEFAULT '', decision TEXT, categorie TEXT DEFAULT '');""")
    cx.executemany("INSERT INTO dnstv_recents(ts,client,domaine,qtype,decision) VALUES (?,?,?,?,?)", recents)
    cx.commit()
    cx.close()


def serveur(chemin):
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(chemin)
    srv.listen(4)

    def boucle():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            while c.recv(4096):
                pass
            c.close()
    threading.Thread(target=boucle, daemon=True).start()
    return srv


def alea(n, graine):
    r = random.Random(graine)
    return "".join(r.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def dga(tmp_path):
    magasin(tmp_path, [(NOW - i * 10, TV, alea(16, i) + ".com", "A", "ALLOWED") for i in range(5)])


def lignes(tmp_path):
    f = tmp_path / "dnsguard" / "alerts.jsonl"
    return [json.loads(ligne) for ligne in f.read_text(encoding="utf-8").splitlines() if ligne] if f.exists() else []


# ---------- fonctions pures ----------

@pytest.mark.parametrize("regle,type_", [
    ("dns.listed", "malicious"), ("dns.dga", "dga"), ("dns.tunnel", "tunneling"), ("dns.drift.spike", "high_rate"),
    ("dns.drift.subdomains", "exfiltration"), ("dns.hijack.new_net", "malicious"), ("dns.hijack.autre", "malicious"),
])
def test_chaque_regle_du_capteur_a_un_type_connu_de_dns_guard(anomalies, regle, type_):
    assert anomalies.type_dnsguard(regle) == type_


def test_une_regle_inconnue_retombe_sur_malicious_plutot_que_de_disparaitre(anomalies):
    assert anomalies.type_dnsguard("dns.nouvelle") == "malicious"


@pytest.mark.parametrize("score,gravite", [(95, "critical"), (80, "critical"), (79, "high"), (60, "high"), (59, "medium"), (40, "medium"), (39, "low"), (0, "low")])
def test_gravite_du_score_du_capteur(anomalies, score, gravite):
    assert anomalies.gravite_dnsguard(score) == gravite


def test_l_alerte_n_a_que_les_champs_de_dns_guard_le_domaine_enregistre_et_pas_le_detail_libre(anomalies):
    c = {"client": TV, "src_ip": TV, "domaine": "exemple.fr", "rule": "dns.tunnel", "severity": 70, "tags": ["dns_tunnel"],
         "detail": "42 sous-noms secret-12345.exemple.fr"}
    a = anomalies.alerte_dnsguard(c, NOW)
    assert set(a) == CHAMPS_DNSALERT
    assert a["domain"] == "exemple.fr" and a["client_ip"] == TV and a["type"] == "tunneling" and a["severity"] == "high" and a["blocked"] is False
    assert "secret-12345" not in json.dumps(a, ensure_ascii=False)
    assert datetime.fromisoformat(a["timestamp"].rstrip("Z")).timestamp() > 0       # même lecture que DnsGuard.get_alerts


def test_deux_constats_distincts_ont_deux_identifiants(anomalies):
    c1 = {"client": TV, "domaine": "a.fr", "rule": "dns.dga", "severity": 50, "tags": []}
    c2 = dict(c1, domaine="b.fr")
    assert anomalies.alerte_dnsguard(c1, NOW)["id"] != anomalies.alerte_dnsguard(c2, NOW)["id"]


def test_rattrapage_depuis_l_etat_ne_prend_que_les_24_dernieres_heures(anomalies):
    emis = {f"{TV}|dns.dga|recent.fr": NOW - 3600, f"{TV}|dns.tunnel|vieux.fr": NOW - 30 * 3600, "cle-cassee": NOW}
    alertes = anomalies.alertes_depuis_etat(emis, NOW)
    assert [a["domain"] for a in alertes] == ["recent.fr"] and alertes[0]["type"] == "dga" and alertes[0]["client_ip"] == TV
    assert set(alertes[0]) == CHAMPS_DNSALERT


# ---------- le passage du capteur, de bout en bout ----------

def test_un_constat_nouveau_est_ecrit_dans_les_alertes_de_dns_guard_une_seule_fois(tmp_path, capteur):
    dga(tmp_path)
    srv = serveur(str(tmp_path / "a.sock"))
    capteur.principal([], now=NOW)
    capteur.principal([], now=NOW + 60)                      # même constat : dédoublonné
    srv.close()
    al = lignes(tmp_path)
    assert len(al) == 1 and al[0]["type"] == "dga" and al[0]["client_ip"] == TV and set(al[0]) == CHAMPS_DNSALERT


def test_le_trafic_ordinaire_n_ecrit_rien_chez_dns_guard(tmp_path, capteur):
    magasin(tmp_path, [(NOW - i, TV, d, "A", "ALLOWED") for i, d in enumerate(["www.netflix.com", "api.france.tv"] * 200)])
    srv = serveur(str(tmp_path / "a.sock"))
    capteur.principal([], now=NOW)
    srv.close()
    assert lignes(tmp_path) == []


def test_sans_actord_rien_n_est_ecrit_et_le_constat_est_retente(tmp_path, capteur):
    dga(tmp_path)
    capteur.principal([], now=NOW)                           # socket absent
    assert lignes(tmp_path) == []
    srv = serveur(str(tmp_path / "a.sock"))
    capteur.principal([], now=NOW + 60)
    srv.close()
    assert len(lignes(tmp_path)) == 1


def test_dry_run_n_ecrit_rien(tmp_path, capteur, capsys):
    dga(tmp_path)
    assert capteur.principal(["--dry-run"], now=NOW) == 0
    capsys.readouterr()
    assert lignes(tmp_path) == []


def test_si_dns_guard_n_est_pas_installe_le_capteur_continue_sans_creer_son_dossier(tmp_path, capteur, monkeypatch):
    monkeypatch.setattr(capteur, "ALERTES_DNSGUARD", tmp_path / "absent" / "alerts.jsonl")
    dga(tmp_path)
    srv = serveur(str(tmp_path / "a.sock"))
    assert capteur.principal([], now=NOW) == 0
    srv.close()
    assert not (tmp_path / "absent").exists() and (tmp_path / "etat" / "dnssensor-etat.json").exists()


def test_premier_passage_rattrape_les_constats_deja_memorises_puis_ne_recommence_pas(tmp_path, capteur):
    (tmp_path / "etat" / "dnssensor-etat.json").write_text(json.dumps({"emis": {f"{TV}|dns.dga|ancien.fr": NOW - 7200}}), encoding="utf-8")
    magasin(tmp_path, [])                                    # magasin présent, rien de neuf
    capteur.principal([], now=NOW)
    assert [a["domain"] for a in lignes(tmp_path)] == ["ancien.fr"]
    capteur.principal([], now=NOW + 60)
    assert len(lignes(tmp_path)) == 1                        # le fichier existe : pas de second rattrapage


def test_l_unite_du_capteur_peut_ecrire_chez_dns_guard_sans_dependre_de_son_dossier():
    unite = (PKG / "debian" / "secubox-ad-guard-dnssensor.service").read_text()
    sans_com = "\n".join(ligne for ligne in unite.splitlines() if not ligne.lstrip().startswith("#"))
    assert "ReadWritePaths=/var/lib/secubox/ad-guard -/var/lib/secubox/dns-guard" in sans_com   # « - » : dossier absent toléré
    assert "NoNewPrivileges=yes" in sans_com and "User=root" not in sans_com


def test_une_adresse_publique_n_est_jamais_un_client_de_dns_guard(anomalies):
    """Un détournement (dns.hijack.*) sans appareil connu porte l'adresse RÉSOLUE dans `client` : ce n'est pas un client du réseau."""
    c = {"client": "185.199.108.133", "domaine": "github.com", "rule": "dns.hijack.new_net", "severity": 60, "tags": ["dns_hijack_suspect"]}
    a = anomalies.alerte_dnsguard(c, NOW)
    assert a["client_ip"] is None and a["details"]["adresse_resolue"] == "185.199.108.133"
    c2 = dict(c, client=TV)
    a2 = anomalies.alerte_dnsguard(c2, NOW)
    assert a2["client_ip"] == TV and "adresse_resolue" not in a2["details"]


def test_le_rattrapage_applique_la_meme_regle_d_adresse(anomalies):
    emis = {"185.199.108.133|dns.hijack.new_net|github.com": NOW - 600, f"{TV}|dns.dga|x.fr": NOW - 600}
    par_domaine = {a["domain"]: a for a in anomalies.alertes_depuis_etat(emis, NOW)}
    assert par_domaine["github.com"]["client_ip"] is None and par_domaine["github.com"]["details"]["adresse_resolue"] == "185.199.108.133"
    assert par_domaine["x.fr"]["client_ip"] == TV


def test_une_adresse_illisible_ne_fait_pas_tomber_le_capteur(anomalies):
    a = anomalies.alerte_dnsguard({"client": "pas-une-ip", "domaine": "x.fr", "rule": "dns.dga", "severity": 50, "tags": []}, NOW)
    assert a["client_ip"] is None
