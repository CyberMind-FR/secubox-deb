# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3794 — moteur de secubox-garde : passage, échéances, suivi des adresses, rapprochement."""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from garde import base, moteur  # noqa: E402
from garde.politique import Signal  # noqa: E402

T = 1_800_000_000
MAC = "aa:bb:cc:dd:ee:01"
REG = {"automatique": True, "quarantaines_max": 3, "rafale_bans": 50, "sms_bans": False, "lan_prefixes": []}


class Effets:
    def __init__(self, echec=()):
        self.appels, self.echec = [], set(echec)

    def _r(self, nom, *a):
        self.appels.append((nom,) + a)
        return {"ok": nom not in self.echec, "motif": "x" if nom in self.echec else ""}

    def bannir(self, ip, duree, motif):
        return self._r("bannir", ip, duree)

    def isoler(self, ip, mac, fin, motif=""):
        return self._r("isoler", ip, mac, fin)

    def liberer(self, ip, mac=None, motif=""):
        return self._r("liberer", ip)

    def fermer_evasion(self, ip, mac, noms, motif=""):
        return self._r("fermer_evasion", ip, tuple(noms))

    def rouvrir(self, ip, mac=None, motif=""):
        return self._r("rouvrir", ip)

    def alerte(self, texte):
        self.appels.append(("alerte", texte))


class Notifs:
    def __init__(self):
        self.file = []

    def mettre_en_file(self, db, canal, cle, texte, maintenant):
        self.file.append((canal, cle, texte))
        return True

    def vider(self, db, reglages, maintenant):
        return {"envoyes": 0, "en_attente": 0}


def sources(signaux=(), voisins=None, noms=None):
    voisins = voisins if voisins is not None else {"192.168.1.20": MAC}
    return SimpleNamespace(
        voisins=lambda: dict(voisins),
        alertes=lambda db, v: list(signaux),
        propositions=lambda t: [],
        doh=lambda depuis, v: [],
        protegees=lambda ip: False,
        nommer=lambda ip, mac: (noms or {}).get(mac, f"Appareil inconnu ({mac or ip})"),
    )


def infection(t=T, ip="192.168.1.20"):
    return [Signal("dns-guard", "dga", ip, None, "x.example", "", t - 10),
            Signal("dns-guard", "malicious", ip, None, "y.example", "", t - 5)]


def test_passage_infection_isole_et_previent(tmp_path):
    db, ef, nt = base.ouvrir(tmp_path / "g.db"), Effets(), Notifs()
    vois = {"192.168.1.20": MAC, "2a01:e0a::20": MAC}
    moteur.passage(db, REG, sources(infection(), vois, {MAC: "TV salon"}), ef, nt, T)
    isoles = sorted(a[1] for a in ef.appels if a[0] == "isoler")
    assert isoles == ["192.168.1.20", "2a01:e0a::20"]
    etat, cible, motif = db.execute("SELECT etat, cible, motif FROM decisions WHERE menace='infection'").fetchone()
    assert (etat, cible) == ("active", MAC) and "TV salon" in motif
    assert {c for c, *_ in nt.file} == {"sms", "courriel"}
    assert all("TV salon" in t for *_, t in nt.file)


def test_passage_intrusion_resume_horaire(tmp_path):
    db, ef, nt = base.ouvrir(tmp_path / "g.db"), Effets(), Notifs()
    src = sources()
    src.propositions = lambda t: [Signal("actord", "intrusion", "8.8.4.4", None, "", "scan", t)]
    moteur.passage(db, REG, src, ef, nt, T)
    assert ("bannir", "8.8.4.4", 14400) in ef.appels
    assert nt.file == []                       # pas de notification immédiate pour un ban
    src.propositions = lambda t: []
    moteur.passage(db, REG, src, ef, nt, T + 3600)
    assert [(c, k) for c, k, _ in nt.file] == [("courriel", "resume_bans")]
    assert "1 adresse" in nt.file[0][2]


def test_rafale_bans_envoie_un_sms(tmp_path):
    db, ef, nt = base.ouvrir(tmp_path / "g.db"), Effets(), Notifs()
    src = sources()
    src.propositions = lambda t: [Signal("actord", "intrusion", f"8.8.{i // 250}.{i % 250 + 1}", None, "", "scan", t)
                                  for i in range(51)]
    moteur.passage(db, REG, src, ef, nt, T)
    assert [k for c, k, _ in nt.file if c == "sms"] == ["rafale"]


def test_reevaluation_24h_leve_ou_prolonge(tmp_path):
    db, ef, nt = base.ouvrir(tmp_path / "g.db"), Effets(), Notifs()
    moteur.passage(db, REG, sources(infection()), ef, nt, T)
    # sans nouveau signal : levée à l'échéance
    ef.appels.clear()
    moteur.passage(db, REG, sources(), ef, nt, T + 86400)
    assert ("liberer", "192.168.1.20") in ef.appels
    assert db.execute("SELECT etat FROM decisions WHERE menace='infection'").fetchone()[0] == "levee"

    db2, ef2 = base.ouvrir(tmp_path / "g2.db"), Effets()
    moteur.passage(db2, REG, sources(infection()), ef2, Notifs(), T)
    moteur.passage(db2, REG, sources([Signal("dns-guard", "dga", "192.168.1.20", None, "z", "", T + 50000)]),
                   ef2, Notifs(), T + 50001)
    ef2.appels.clear()
    moteur.passage(db2, REG, sources(), ef2, Notifs(), T + 86400)
    assert ("isoler", "192.168.1.20", MAC, T + 2 * 86400) in ef2.appels
    assert db2.execute("SELECT etat, fin FROM decisions WHERE menace='infection'").fetchone() == ("active", T + 2 * 86400)


def test_quarantaine_suit_la_mac(tmp_path):
    db, ef, nt = base.ouvrir(tmp_path / "g.db"), Effets(), Notifs()
    moteur.passage(db, REG, sources(infection()), ef, nt, T)
    ef.appels.clear()
    moteur.passage(db, REG, sources(voisins={"192.168.1.42": MAC}), ef, nt, T + 60)
    assert ef.appels.index(("liberer", "192.168.1.20")) < ef.appels.index(("isoler", "192.168.1.42", MAC, T + 86400))
    did = db.execute("SELECT id FROM decisions WHERE menace='infection'").fetchone()[0]
    assert [r[0] for r in db.execute("SELECT ip FROM adresses WHERE decision_id=?", (did,))] == ["192.168.1.42"]
    # appareil absent des voisins : on ne lève rien
    ef.appels.clear()
    moteur.passage(db, REG, sources(voisins={}), ef, nt, T + 120)
    assert not [a for a in ef.appels if a[0] == "liberer"]


def test_rapprochement_demarrage(tmp_path):
    db, ef, nt = base.ouvrir(tmp_path / "g.db"), Effets(), Notifs()
    moteur.passage(db, REG, sources(infection()), ef, nt, T)
    src = sources()
    src.propositions = lambda t: [Signal("actord", "intrusion", "8.8.4.4", None, "", "scan", t)]
    moteur.passage(db, REG, src, ef, nt, T)
    ef.appels.clear()
    assert moteur.rapprocher(db, ef, T + 100) == {"reappliquees": 2, "echues": 0}
    assert ("isoler", "192.168.1.20", MAC, T + 86400) in ef.appels
    assert ("bannir", "8.8.4.4", 14300) in ef.appels
    ef.appels.clear()
    assert moteur.rapprocher(db, ef, T + 86400) == {"reappliquees": 0, "echues": 2}
    assert ("liberer", "192.168.1.20") in ef.appels
    assert db.execute("SELECT COUNT(*) FROM decisions WHERE etat='active'").fetchone()[0] == 0


def test_echec_effet_pas_de_decision_active(tmp_path):
    db, ef, nt = base.ouvrir(tmp_path / "g.db"), Effets(echec={"isoler", "bannir"}), Notifs()
    src = sources(infection())
    src.propositions = lambda t: [Signal("actord", "intrusion", "8.8.4.4", None, "", "scan", t)]
    bilan = moteur.passage(db, REG, src, ef, nt, T)
    assert bilan["echecs"] == 2
    assert db.execute("SELECT COUNT(*) FROM decisions WHERE etat='active'").fetchone()[0] == 0
    assert len([a for a in ef.appels if a[0] == "alerte"]) == 2
    assert nt.file == []


def test_ban_deja_actif_enregistre_sans_reessai(tmp_path):
    db, nt = base.ouvrir(tmp_path / "g.db"), Notifs()
    ef = Effets()
    ef.bannir = lambda ip, d, m: (ef.appels.append(("bannir", ip)), {"ok": True, "deja": True})[1]
    src = sources()
    src.propositions = lambda t: [Signal("actord", "intrusion", "8.8.4.4", None, "", "scan", t)]
    moteur.passage(db, REG, src, ef, nt, T)
    moteur.passage(db, REG, src, ef, nt, T + 60)
    assert ef.appels.count(("bannir", "8.8.4.4")) == 1
    assert "déjà banni ailleurs" in db.execute("SELECT motif FROM decisions").fetchone()[0]


def test_alerte_de_masse_une_seule_fois(tmp_path):
    db, ef, nt = base.ouvrir(tmp_path / "g.db"), Effets(), Notifs()
    reg = dict(REG, quarantaines_max=0)
    moteur.passage(db, reg, sources(infection()), ef, nt, T)
    moteur.passage(db, reg, sources(infection(T + 60)), ef, nt, T + 60)
    assert len([a for a in ef.appels if a[0] == "alerte"]) == 1


def test_mac_apprise_plus_tot_pas_de_doublon(tmp_path):
    db, ef, nt = base.ouvrir(tmp_path / "g.db"), Effets(), Notifs()
    moteur.passage(db, REG, sources(), ef, nt, T - 100)              # registre : 192.168.1.20 -> MAC
    moteur.passage(db, REG, sources(infection(), voisins={}), ef, nt, T)
    moteur.passage(db, REG, sources(infection(T + 60), voisins={}), ef, nt, T + 60)
    assert db.execute("SELECT COUNT(*), cible FROM decisions WHERE menace='infection'").fetchone() == (1, MAC)


class EffetsLevee(Effets):
    """liberer échoue pour les adresses de `refus`."""

    def __init__(self, refus=()):
        super().__init__()
        self.refus = set(refus)

    def liberer(self, ip, mac=None, motif=""):
        self.appels.append(("liberer", ip))
        return {"ok": ip not in self.refus, "motif": ""}


def _etat(db):
    return db.execute("SELECT etat FROM decisions WHERE menace='infection'").fetchone()[0]


def test_levee_echouee_reessayee_jusqua_succes(tmp_path):
    db, nt = base.ouvrir(tmp_path / "g.db"), Notifs()
    ef = EffetsLevee(refus={"192.168.1.20"})
    moteur.passage(db, REG, sources(infection()), ef, nt, T)
    moteur.passage(db, REG, sources(), ef, nt, T + 86400)
    assert _etat(db) == "levee_en_cours"
    moteur.passage(db, REG, sources(), ef, nt, T + 86460)
    assert _etat(db) == "levee_en_cours"
    assert len([a for a in ef.appels if a[0] == "alerte"]) == 1      # une alerte, pas une par passage
    ef.refus.clear()
    moteur.passage(db, REG, sources(), ef, nt, T + 86520)
    assert _etat(db) == "levee"


def test_levee_partielle_ne_ferme_que_les_adresses_levees(tmp_path):
    db, nt = base.ouvrir(tmp_path / "g.db"), Notifs()
    ef = EffetsLevee(refus={"2a01:e0a::20"})
    vois = {"192.168.1.20": MAC, "2a01:e0a::20": MAC}
    moteur.passage(db, REG, sources(infection(), vois), ef, nt, T)
    moteur.passage(db, REG, sources(voisins=vois), ef, nt, T + 86400)
    assert _etat(db) == "levee_en_cours"
    assert [r[0] for r in db.execute("SELECT ip FROM adresses")] == ["2a01:e0a::20"]


def test_rapprochement_levee_echouee_reste_en_cours(tmp_path):
    db, nt = base.ouvrir(tmp_path / "g.db"), Notifs()
    ef = EffetsLevee(refus={"192.168.1.20"})
    moteur.passage(db, REG, sources(infection()), ef, nt, T)
    assert moteur.rapprocher(db, ef, T + 86400)["echues"] == 0
    assert _etat(db) == "levee_en_cours"
    ef.refus.clear()
    moteur.rapprocher(db, ef, T + 86500)
    assert _etat(db) == "echue"


def test_rafale_un_seul_sms_par_rafale(tmp_path):
    db, ef, nt = base.ouvrir(tmp_path / "g.db"), Effets(), Notifs()
    src = sources()
    lot = [0]

    def props(t):
        lot[0] += 1
        return [Signal("actord", "intrusion", f"9.{lot[0]}.{i // 250}.{i % 250 + 1}", None, "", "scan", t)
                for i in range(51)]
    src.propositions = props
    moteur.passage(db, REG, src, ef, nt, T)
    moteur.passage(db, REG, src, ef, nt, T + 60)
    assert [k for c, k, _ in nt.file if c == "sms"] == ["rafale"]
    src.propositions = lambda t: []
    moteur.passage(db, REG, src, ef, nt, T + 1000)                  # fin de rafale : réarmée
    src.propositions = props
    moteur.passage(db, REG, src, ef, nt, T + 1100)
    assert [k for c, k, _ in nt.file if c == "sms"] == ["rafale", "rafale"]


def test_prolongation_echouee_reposee_au_passage_suivant(tmp_path):
    db, nt = base.ouvrir(tmp_path / "g.db"), Notifs()
    vois = {"192.168.1.20": MAC, "2a01:e0a::20": MAC}
    ef = Effets()
    moteur.passage(db, REG, sources(infection(), vois), ef, nt, T)
    moteur.passage(db, REG, sources([Signal("dns-guard", "dga", "192.168.1.20", None, "z", "", T + 50000)], vois),
                   ef, nt, T + 50001)
    reel = ef.isoler
    ef.isoler = lambda ip, mac, fin, motif="": ({"ok": False} if ip == "2a01:e0a::20" else reel(ip, mac, fin, motif))
    moteur.passage(db, REG, sources(voisins=vois), ef, nt, T + 86400)
    ef.isoler = reel
    ef.appels.clear()
    moteur.passage(db, REG, sources(voisins=vois), ef, nt, T + 86460)
    assert ("isoler", "2a01:e0a::20", MAC, T + 2 * 86400) in ef.appels


def test_echec_effet_une_alerte_par_heure_et_signale_dedoublonne(tmp_path):
    db, nt = base.ouvrir(tmp_path / "g.db"), Notifs()
    ef = Effets(echec={"isoler"})
    for k in range(3):
        moteur.passage(db, REG, sources(infection(T + 60 * k)), ef, nt, T + 60 * k)
    assert len([a for a in ef.appels if a[0] == "alerte"]) == 1
    db2 = base.ouvrir(tmp_path / "g2.db")
    reg = dict(REG, automatique=False)
    for k in range(3):
        moteur.passage(db2, reg, sources(infection(T + 60 * k)), Effets(), nt, T + 60 * k)
    n = db2.execute("SELECT COUNT(*) FROM decisions WHERE menace='signale' AND signe='dga+malicious'").fetchone()[0]
    assert n == 1


def test_migration_contrainte_etat(tmp_path):
    import sqlite3
    f = tmp_path / "g.db"
    cx = sqlite3.connect(f)
    cx.executescript(base.SCHEMA.replace(",'levee_en_cours'", "").split("CREATE INDEX")[0])
    cx.execute("INSERT INTO decisions(id, menace, etat) VALUES ('a', 'signale', 'echue')")
    cx.commit()
    cx.close()
    db = base.ouvrir(f)
    db.execute("UPDATE decisions SET etat='levee_en_cours' WHERE id='a'")
    assert db.execute("SELECT etat FROM decisions").fetchall() == [("levee_en_cours",)]


def test_levee_en_cours_bloque_nouvelle_decision(tmp_path):
    db, nt = base.ouvrir(tmp_path / "g.db"), Notifs()
    ef = EffetsLevee(refus={"192.168.1.20"})
    moteur.passage(db, REG, sources(infection()), ef, nt, T)
    moteur.passage(db, REG, sources(), ef, nt, T + 86400)
    moteur.passage(db, REG, sources(infection(T + 86460)), ef, nt, T + 86460)
    assert db.execute("SELECT etat FROM decisions WHERE menace='infection'").fetchall() == [("levee_en_cours",)]


def test_levee_reessayee_ne_retire_pas_la_nouvelle_quarantaine(tmp_path):
    db, nt = base.ouvrir(tmp_path / "g.db"), Notifs()
    ef = EffetsLevee()
    db.execute("INSERT INTO decisions(id, menace, cible, mac, ip, debut, fin, etat, leve_par) VALUES "
               "('A','infection',?,?,'192.168.1.20',?,?,'levee_en_cours','reevaluation')", (MAC, MAC, T - 90000, T - 3600))
    db.execute("INSERT INTO decisions(id, menace, cible, mac, ip, debut, fin, etat) VALUES "
               "('B','infection',?,?,'192.168.1.20',?,?,'active')", (MAC, MAC, T - 60, T + 86000))
    db.executemany("INSERT INTO adresses(decision_id, ip, fin) VALUES (?,?,?)",
                   [("A", "192.168.1.20", T - 3600), ("B", "192.168.1.20", T + 86000)])
    db.commit()
    moteur.passage(db, REG, sources(), ef, nt, T)
    assert ("liberer", "192.168.1.20") not in ef.appels
    assert dict(db.execute("SELECT id, etat FROM decisions")) == {"A": "levee", "B": "active"}
    assert db.execute("SELECT ip FROM adresses WHERE decision_id='B'").fetchall() == [("192.168.1.20",)]


def _doh_tunnel(types):
    return [Signal("ad-guard" if t == "doh" else "dns-guard", t, "192.168.1.20", None, d, t, T - 5) for t, d in types]


def test_evasion_tunnel_refuse_le_domaine_du_tunnel(tmp_path):
    db, ef, nt = base.ouvrir(tmp_path / "g.db"), Effets(), Notifs()
    moteur.passage(db, REG, sources(_doh_tunnel([("tunneling", "abcd1234.t.Tunnel.example.")])), ef, nt, T)
    assert ("fermer_evasion", "192.168.1.20", ("tunnel.example",)) in ef.appels
    assert db.execute("SELECT etat FROM decisions WHERE menace='evasion'").fetchone() == ("active",)


def test_evasion_sans_nom_devient_signale(tmp_path):
    db, ef, nt = base.ouvrir(tmp_path / "g.db"), Effets(), Notifs()
    moteur.passage(db, REG, sources(_doh_tunnel([("tunneling", "")])), ef, nt, T)
    assert not [a for a in ef.appels if a[0] in ("fermer_evasion", "alerte")]
    assert db.execute("SELECT menace, etat FROM decisions").fetchall() == [("signale", "echue")]


def test_migration_fin_des_adresses_remplie(tmp_path):
    import sqlite3
    f = tmp_path / "g.db"
    cx = sqlite3.connect(f)
    cx.executescript(base.SCHEMA.replace(", fin INTEGER, PRIMARY KEY (decision_id, ip)", ", PRIMARY KEY (decision_id, ip)"))
    cx.execute("INSERT INTO decisions(id, menace, fin, etat) VALUES ('a', 'infection', 99, 'active')")
    cx.execute("INSERT INTO adresses(decision_id, ip) VALUES ('a', '192.168.1.20')")
    cx.commit()
    cx.close()
    assert base.ouvrir(f).execute("SELECT fin FROM adresses").fetchall() == [(99,)]
