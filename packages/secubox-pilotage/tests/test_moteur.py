# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3702 — moteur des macros : série box après box, arrêt au premier écart, arrêt demandé après l'étape en cours, refus au
lancement, planificateur, relais des opérations vers le flux d'une exécution. Aucun vrai boîtier, aucune vraie attente : le
temps est injecté (`Horloge`) et l'attente l'avance."""
import asyncio
import logging
from datetime import datetime, timedelta, timezone

import pytest

from pilotage.diffusion import Diffusion
from pilotage.identite import Box
from pilotage.inventaire import box_de_ligne
from pilotage.macros import LIVREES
from pilotage.moteur import Moteur, RefusLancement, cle_flux
from pilotage.stockage import HORS_LIGNE_S, RESUME_REDEMARREE, StockageSqlite
from outils import GK5_AUTOLOAD, Horloge, P, releve_gk5

GK7 = Box("gk7", "10.10.0.7", "maillage", None, None)
GK6 = Box("gk6", "10.10.0.6", "maillage", None, None)
GK8 = Box("gk8", "10.10.0.8", "maillage", None, None)
CLIENTE = GK5_AUTOLOAD
PAS = 5.0                      # une attente du moteur avance l'horloge d'au moins 5 s (sondes à 0,01 s : la boucle reste courte)
MAJ = next(m for m in LIVREES if m["id"] == "livree:mise-a-jour-sure")["etapes"]
R_AVANT = {"type": "releve", "duree_s": 60, "nom": "avant"}
R_APRES = {"type": "releve", "duree_s": 60, "nom": "apres"}
A_MAJ = {"type": "action", "action": "maj-paquets"}
A_REBOOT = {"type": "action", "action": "reboot"}
A_HUB = {"type": "action", "action": "service-redemarrer", "args": {"unite": "secubox-hub.service"}}
CHAMPS_MACRO = {"execution", "evenement", "box", "cle", "rang", "type", "etat", "resultat", "raison"}
CHAMPS_AUDIT = {"evenement", "execution", "macro", "nom", "cibles", "acteur", "etat", "raison"}
NUIT = datetime(2026, 11, 15, 3, 0, 10, tzinfo=timezone.utc)


def corps(echecs=(), ancien=False):
    """Un inventaire complet : secubox-hub actif, plus les services `echecs` en échec. `ancien` : agent sans liste de services,
    sans compteur d'échecs ni mesure du processeur."""
    c = releve_gk5(failed=len(echecs))
    p = c["results"][0]["params"]
    for i, n in enumerate(["secubox-hub.service", *echecs], 1):
        p[f"{P}X_SECUBOX_Services.{i}.Name"] = n
        p[f"{P}X_SECUBOX_Services.{i}.ActiveState"] = "failed" if n in echecs else "active"
    if ancien:
        for k in [k for k in p if k.startswith(P + "X_SECUBOX_Services.") or k.endswith("CPUUsage")]:
            del p[k]
    return c


class FauxExecutant:
    """Range l'opération comme executer_action, puis la termine selon `fins[action]` (rc) ; `None` = jamais de fin."""

    def __init__(self, s, fins=None, etats=None):
        self.s, self.fins, self.etats = s, fins or {}, etats or {}
        self.appels = []
        self.confirmations = []
        self.echecs = {}           # nom de box -> services en échec au prochain relevé
        self.casse = {}            # (box, action) -> services qui tombent en échec après l'action
        self.anciens = set()       # box à l'agent ancien (mesures absentes)
        self.frais = True          # le relevé range un inventaire frais
        self.statut_releve = "ok"
        self.pendant = None        # appelé pendant chaque action : (b, action)
        self.diffusion = None

    async def action(self, b, action, args, *, confirmation, support, acteur):
        self.appels.append((b["nom"], action))
        self.confirmations.append((b["nom"], confirmation, support, acteur))
        etat = self.etats.get(action, "accepte")
        op = self.s.operation_demander(b["cle"], action, args, acteur, support)
        job = f"job-{op}" if etat == "accepte" else None
        self.s.operation_reponse(op, etat, job, None)
        if self.diffusion is not None:
            self.diffusion.publier(b["cle"], "operation", {"cle": b["cle"], "operation": op, "action": action})
            self.diffusion.publier(b["cle"], "notify", {"cle": b["cle"], "type": "X_SECUBOX_OperationProgress"})
        if self.pendant is not None:
            self.pendant(b, action)
        self.echecs.setdefault(b["nom"], []).extend(self.casse.get((b["nom"], action), ()))
        rc = self.fins.get(action, 0)
        if etat == "accepte" and rc is not None:
            self.s.operation_fin(b["cle"], job, rc, "fait")
        return {"operation": op, "etat": etat, "job": job or "", "raison": ""}

    async def releve(self, b, duree_s, acteur):
        self.appels.append((b["nom"], "releve"))
        if self.frais:
            self.s.inventaire_enregistrer(box_de_ligne(b), corps(self.echecs.get(b["nom"], []), b["nom"] in self.anciens))
        return self.statut_releve


class Monde:
    def __init__(self, tmp_path, t=1_000_000.0, fins=None, etats=None, boites=(GK7, GK6)):
        self.h = Horloge(t)
        self.s = StockageSqlite(tmp_path / "pilotage", horloge=self.h)
        self.d = Diffusion()
        self.audits = []
        self.audit_en_panne = False
        self.vivantes = {}         # Box -> boot_id : vues à chaque attente
        self.crochets = []         # appelés à chaque attente
        self.x = FauxExecutant(self.s, fins, etats)
        self.resoudre = self.s.boite
        for b in boites:
            self.allumer(b)
        self.m = Moteur(self.s, self.x, self.d, self.audit, horloge=self.h, attente=self.attente, sonde_s=0.01,
                        resoudre=lambda cle: self.resoudre(cle))

    def audit(self, evenement, champs):
        if self.audit_en_panne:
            raise OSError("audit indisponible")
        self.audits.append((evenement, dict(champs)))

    def allumer(self, b, boot="b1"):
        self.vivantes[b] = boot
        self.s.vu(b, {"boot_id": boot})

    def eteindre(self, b):
        self.vivantes.pop(b, None)

    async def attente(self, s):
        self.h.avance(max(s, PAS))
        for b, boot in list(self.vivantes.items()):
            self.s.vu(b, {"boot_id": boot})
        for f in list(self.crochets):
            f()
        await asyncio.sleep(0)

    def macro_audits(self, evenement=None):
        return [c for e, c in self.audits if e == "pilotage_macro" and evenement in (None, c["evenement"])]

    async def lancer(self, etapes, boites=(GK7, GK6), confirmations=None, support=None, programme=False):
        return await self.m.lancer({"id": "m-essai", "nom": "Essai", "etapes": etapes}, [self.s.boite(b.cle) for b in boites],
                                   confirmations or {}, support or {}, "alice", programme=programme)

    async def derouler(self, etapes, **k):
        ident = await self.lancer(etapes, **k)
        await self.m.taches[ident]
        return self.s.execution(ident)


def etats(ex, nom):
    return [e["etat"] for e in ex["etapes"] if e["box"] == f"maillage:{nom}"]


def evenements(ab):
    out = []
    while ab._file:
        out.append(ab._file.popleft())
    return out


@pytest.fixture
def w(tmp_path):
    return Monde(tmp_path)


# --- série ---

@pytest.mark.asyncio
async def test_serie_une_box_apres_l_autre(w):
    ex = await w.derouler(MAJ)
    assert w.x.appels == [("gk7", "releve"), ("gk7", "maj-paquets"), ("gk7", "releve"),
                          ("gk6", "releve"), ("gk6", "maj-paquets"), ("gk6", "releve")]
    assert ex["etat"] == "terminee" and ex["raison"] is None
    assert etats(ex, "gk7") == etats(ex, "gk6") == ["ok"] * 5
    action = next(e for e in ex["etapes"] if e["type"] == "action")
    assert set(action["resultat"]) == {"operation", "rc", "resume"} and action["resultat"]["rc"] == 0
    assert set(w.s.releves_execution(ex["id"], "maillage:gk7")) == {"avant", "apres"}
    assert [c["evenement"] for c in w.macro_audits()] == ["lancement", "fin"]
    lancement, fin = w.macro_audits()
    assert set(lancement) == CHAMPS_AUDIT and lancement["cibles"] == "gk7, gk6" and lancement["acteur"] == "alice"
    assert lancement["macro"] == "m-essai" and lancement["nom"] == "Essai"
    assert fin["execution"] == ex["id"] and fin["etat"] == "terminee"
    assert w.m.occupees() == set()


@pytest.mark.asyncio
async def test_ecart_arrete_la_serie_box_suivante_non_lancee(w):
    w.x.casse[("gk7", "maj-paquets")] = ["secubox-dns.service"]
    ex = await w.derouler(MAJ)
    assert ex["etat"] == "ecart" and "gk7" in ex["raison"] and "secubox-dns.service" in ex["raison"]
    assert not [a for a in w.x.appels if a[0] == "gk6"]
    assert etats(ex, "gk7") == ["ok", "ok", "ok", "ok", "ecart"]
    assert etats(ex, "gk6") == ["non_lancee"] * 5
    comp = [e for e in ex["etapes"] if e["box"] == "maillage:gk7"][4]["resultat"]
    assert comp["nouveaux"] == ["secubox-dns.service"]
    assert comp["propositions"] == [{"action": "service-redemarrer", "args": {"unite": "secubox-dns.service"}}]
    (ecart,) = w.macro_audits("ecart")
    assert ecart["nouveaux"] == "secubox-dns.service" and ecart["execution"] == ex["id"]
    assert w.macro_audits("fin")[0]["etat"] == "ecart"


@pytest.mark.asyncio
async def test_ecart_n_audite_pas_un_nom_de_service_hors_motif(w):
    """Le journal d'audit ne porte jamais de valeur lue sur une box hors motif : seuls les noms d'unités secubox-* y vont."""
    w.x.casse[("gk7", "maj-paquets")] = ["x‮ evil", "secubox-dns.service"]
    ex = await w.derouler(MAJ)
    assert ex["etat"] == "ecart"
    assert w.macro_audits("ecart")[0]["nouveaux"] == "secubox-dns.service (+1 hors motif)"


@pytest.mark.asyncio
async def test_echec_action_consentement(tmp_path):
    w = Monde(tmp_path, etats={"maj-paquets": "consentement"})
    ex = await w.derouler([A_MAJ, R_AVANT])
    assert ex["etat"] == "echec" and "une macro n'attend pas l'accord du détenteur" in ex["raison"]
    assert w.x.appels == [("gk7", "maj-paquets")]
    assert etats(ex, "gk7") == ["echec", "non_lancee"] and etats(ex, "gk6") == ["non_lancee", "non_lancee"]
    assert "une macro n'attend pas l'accord du détenteur" in ex["etapes"][0]["resultat"]["raison"]
    assert w.macro_audits("fin")[0]["etat"] == "echec"


@pytest.mark.asyncio
async def test_action_en_echec_sur_la_box(tmp_path):
    w = Monde(tmp_path, fins={"maj-paquets": 3})
    ex = await w.derouler([A_MAJ])
    assert ex["etat"] == "echec" and "maj-paquets : echec" in ex["raison"]
    assert ex["etapes"][0]["resultat"]["rc"] == 3 and etats(ex, "gk6") == ["non_lancee"]


@pytest.mark.asyncio
async def test_delai_action_depasse(tmp_path):
    w = Monde(tmp_path, fins={"maj-paquets": None})
    t0 = w.h()
    ex = await w.derouler([{**A_MAJ, "delai_s": 60}])
    assert ex["etat"] == "echec" and "délai dépassé" in ex["raison"]
    assert 60 <= w.h() - t0 <= 60 + PAS
    assert etats(ex, "gk7") == ["echec"] and etats(ex, "gk6") == ["non_lancee"]
    assert w.x.appels == [("gk7", "maj-paquets")]


# --- conditions et comparaisons ---

@pytest.mark.asyncio
async def test_condition_arreter_saute_le_reste_de_la_box_et_continue(w):
    w.x.echecs["gk7"] = ["secubox-dns.service"]
    cond = {"type": "condition", "mesure": "services_en_echec", "releve": "avant", "op": ">", "seuil": 0, "alors": "arreter"}
    ex = await w.derouler([R_AVANT, cond, A_MAJ, R_APRES])
    assert w.x.appels == [("gk7", "releve"), ("gk6", "releve"), ("gk6", "maj-paquets"), ("gk6", "releve")]
    assert etats(ex, "gk7") == ["ok", "ok", "passee", "passee"]
    assert etats(ex, "gk6") == ["ok", "ok", "ok", "ok"]
    assert ex["etat"] == "terminee"
    assert ex["etapes"][1]["resultat"]["vrai"] is True


@pytest.mark.asyncio
async def test_condition_passer_saute_l_etape_suivante(w):
    w.x.echecs["gk7"] = ["secubox-dns.service"]
    cond = {"type": "condition", "mesure": "services_en_echec", "releve": "avant", "op": ">", "seuil": 0, "alors": "passer"}
    ex = await w.derouler([R_AVANT, cond, A_MAJ, A_HUB], boites=(GK7,))
    assert w.x.appels == [("gk7", "releve"), ("gk7", "service-redemarrer")]
    assert etats(ex, "gk7") == ["ok", "ok", "passee", "ok"] and ex["etat"] == "terminee"


@pytest.mark.asyncio
async def test_condition_mesure_absente_notee(w):
    """Agent ancien : la condition est fausse ET le dit (résultat de l'étape, événement du journal) ; la comparaison sans mesure
    n'est jamais un « sans écart » muet."""
    w.x.anciens.add("gk7")
    cond = {"type": "condition", "mesure": "cpu_pct", "releve": "avant", "op": ">", "seuil": 50, "alors": "arreter"}
    comp = {"type": "comparer", "avant": "avant", "apres": "apres", "regle": "nouveau_service_en_echec", "seuil": 0}
    ident = await w.lancer([R_AVANT, cond, A_MAJ, R_APRES, comp], boites=(GK7,))
    ab = w.d.abonner("alice", cle_flux(ident))
    await w.m.taches[ident]
    ex = w.s.execution(ident)
    assert ex["etat"] == "terminee" and ("gk7", "maj-paquets") in w.x.appels       # condition fausse : l'action a eu lieu
    r_cond, r_comp = ex["etapes"][1]["resultat"], ex["etapes"][4]["resultat"]
    assert r_cond["vrai"] is False and r_cond["mesure_absente"] is True and "mesure absente" in r_cond["note"]
    assert r_comp["ecart"] is False and r_comp["mesure_absente"] is True and "mesure absente" in r_comp["note"]
    notes = [d for n, d in evenements(ab) if n == "macro" and d["evenement"] == "etape" and d["etat"] == "ok"
             and d["raison"] and "mesure absente" in d["raison"]]
    assert [d["rang"] for d in notes] == [1, 4]


# --- attendre ---

@pytest.mark.asyncio
async def test_attendre_apres_reboot(tmp_path):
    w = Monde(tmp_path, fins={"reboot": None})
    w.x.pendant = lambda b, a: w.allumer({"gk7": GK7, "gk6": GK6}[b["nom"]], boot="b2")   # revient avec un autre boot_id
    ex = await w.derouler([A_REBOOT, {"type": "attendre", "delai_s": 60}], confirmations={"maillage:gk7": "gk7", "maillage:gk6": "gk6"})
    assert ex["etat"] == "terminee"
    assert w.x.appels == [("gk7", "reboot"), ("gk6", "reboot")]
    assert ex["etapes"][0]["resultat"]["resume"] == RESUME_REDEMARREE
    assert etats(ex, "gk7") == etats(ex, "gk6") == ["ok", "ok"]
    assert [c[1] for c in w.x.confirmations] == ["gk7", "gk6"]


@pytest.mark.asyncio
async def test_box_qui_ne_revient_pas_arrete_la_serie(w):
    def coupure(b, action):      # l'action coupe la box et dure : elle n'est plus vue depuis plus de HORS_LIGNE_S
        w.eteindre(GK7)
        w.h.avance(HORS_LIGNE_S + 1)
    w.x.pendant = coupure
    ex = await w.derouler([A_HUB, {"type": "attendre", "delai_s": 30}, R_APRES])
    assert ex["etat"] == "echec" and "la box n'est pas revenue" in ex["raison"]
    assert etats(ex, "gk7") == ["ok", "echec", "non_lancee"] and etats(ex, "gk6") == ["non_lancee"] * 3
    assert not [a for a in w.x.appels if a[0] == "gk6"]


# --- arrêt ---

@pytest.mark.asyncio
async def test_arreter_apres_l_etape_en_cours(w):
    arrets = []
    w.x.pendant = lambda b, a: arrets.append(w.m.arreter(ident))
    ident = await w.lancer([A_MAJ, R_AVANT])
    await w.m.taches[ident]
    ex = w.s.execution(ident)
    assert arrets == [True] and w.x.appels == [("gk7", "maj-paquets")]
    assert etats(ex, "gk7") == ["ok", "non_lancee"] and etats(ex, "gk6") == ["non_lancee", "non_lancee"]
    assert ex["etat"] == "arretee"
    assert [c["evenement"] for c in w.macro_audits()] == ["lancement", "arret", "fin"]
    assert w.macro_audits("fin")[0]["etat"] == "arretee"
    assert w.m.arreter(ident) is False and w.m.arreter(99999) is False


# --- refus au lancement ---

@pytest.mark.asyncio
async def test_refus_au_lancement(tmp_path):
    w = Monde(tmp_path, fins={"maj-paquets": None}, boites=(GK7, GK6, CLIENTE))

    async def refus(statut, *a, **k):
        with pytest.raises(RefusLancement) as e:
            await w.lancer(*a, **k)
        assert e.value.statut == statut and e.value.message
        assert w.m.occupees() == occupees
        return e.value.message

    occupees = set()
    await refus(400, [A_REBOOT])                                                  # forte sans nom
    await refus(400, [A_REBOOT], confirmations={"maillage:gk7": "GK7", "maillage:gk6": "gk6"})
    await refus(400, [A_REBOOT], confirmations={"maillage:gk7": "gk7 ", "maillage:gk6": "gk6"})
    await refus(400, [{"type": "shell", "cmd": "id"}])                            # liste fermée
    await refus(400, [R_AVANT], boites=())
    await refus(400, [R_AVANT], boites=(GK7, GK7))
    assert "support" in await refus(409, [R_AVANT], boites=(GK7, CLIENTE))        # cliente sans session de support
    w.audit_en_panne = True
    await refus(503, [R_AVANT])                                                   # pas d'audit, pas de lancement
    w.audit_en_panne = False
    w.eteindre(GK6)
    await w.attente(HORS_LIGNE_S)
    assert "gk6" in await refus(409, [R_AVANT])                                   # hors ligne
    assert w.x.appels == [] and w.s.executions() == []
    assert not [c for c in w.macro_audits() if c["evenement"] == "lancement"]

    ident = await w.lancer([A_MAJ], boites=(GK7,))                                # gk7 occupée par une action sans fin
    occupees = {"maillage:gk7"}
    while not w.x.appels:
        await asyncio.sleep(0)
    assert w.m.occupees() == occupees
    assert "gk7" in await refus(409, [R_AVANT], boites=(GK7,))
    assert w.x.appels == [("gk7", "maj-paquets")] and [e["id"] for e in w.s.executions()] == [ident]
    await w.m.fermer()


# --- programmation : box hors ligne sautée ---

@pytest.mark.asyncio
async def test_programme_box_hors_ligne_sautee_la_serie_continue(tmp_path):
    w = Monde(tmp_path, boites=(GK7, GK6, GK8))
    w.eteindre(GK6)
    await w.attente(HORS_LIGNE_S)
    ex = await w.derouler([R_AVANT], boites=(GK7, GK6, GK8), programme=True)
    assert ex["etat"] == "terminee" and "gk6" in ex["raison"]
    assert w.x.appels == [("gk7", "releve"), ("gk8", "releve")]
    assert etats(ex, "gk6") == ["sautee"] and etats(ex, "gk7") == etats(ex, "gk8") == ["ok"]
    assert "gk6" in w.macro_audits("lancement")[0]["raison"]


@pytest.mark.asyncio
async def test_manuel_box_hors_ligne_a_son_tour_echec(w):
    def coupure(b, action):
        w.eteindre(GK6)
        w.h.avance(HORS_LIGNE_S + 1)
    w.x.pendant = coupure
    ex = await w.derouler([A_HUB])
    assert ex["etat"] == "echec" and "gk6" in ex["raison"] and "hors ligne" in ex["raison"]
    assert w.x.appels == [("gk7", "service-redemarrer")] and etats(ex, "gk6") == ["echec"]


# --- cycle de vie ---

@pytest.mark.asyncio
async def test_interrompre_au_demarrage_audite(w):
    i = w.s.execution_creer("m-x", "Nuit", [{"cle": "maillage:gk7", "nom": "gk7"}, {"cle": "maillage:gk6", "nom": "gk6"}], [R_AVANT], "bob")
    assert await w.m.interrompre_au_demarrage() == [i]
    assert w.s.execution(i)["etat"] == "interrompue"
    (fin,) = w.macro_audits("fin")
    assert fin["etat"] == "interrompue" and fin["execution"] == i and fin["cibles"] == "gk7, gk6" and fin["acteur"] == "bob"
    assert set(fin) == CHAMPS_AUDIT
    assert await w.m.interrompre_au_demarrage() == []


@pytest.mark.asyncio
async def test_fermer_laisse_l_execution_en_cours_puis_interrompue(tmp_path):
    w = Monde(tmp_path, fins={"maj-paquets": None})
    ident = await w.lancer([A_MAJ])
    for _ in range(20):
        await asyncio.sleep(0)
    await w.m.fermer()
    assert w.s.execution(ident)["etat"] == "en_cours" and w.m.occupees() == set()
    assert w.d._relais == {}
    assert await w.m.interrompre_au_demarrage() == [ident]


# --- planificateur ---

def programmer(w, etapes=(R_AVANT,), cibles=(GK7,), heure="03:00"):
    return w.s.macro_creer("Nuit", list(etapes), [{"cle": b.cle, "nom": b.nom} for b in cibles], {"quotidien": heure}, "alice")


@pytest.mark.asyncio
async def test_planificateur_une_fois_par_nuit_sans_rattrapage(tmp_path):
    w = Monde(tmp_path, t=NUIT.timestamp())
    mid = programmer(w)
    (ident,) = await w.m.tic(NUIT)
    await w.m.taches[ident]
    ex = w.s.execution(ident)
    assert ex["acteur"] == "planificateur" and ex["macro_id"] == mid and ex["etat"] == "terminee"
    w.h.avance(60)
    assert await w.m.tic(NUIT + timedelta(minutes=1)) == []
    w.h.avance(7140)
    assert await w.m.tic(NUIT.replace(hour=5, second=0)) == []                 # heure manquée : jamais rattrapée
    assert len(w.s.executions()) == 1
    assert await w.m.tic(NUIT.replace(hour=2, minute=59)) == []                # avant l'heure
    assert w.macro_audits("lancement")[0]["acteur"] == "planificateur"


@pytest.mark.asyncio
async def test_planificateur_refuse_forte_ou_cliente(tmp_path):
    w = Monde(tmp_path, t=NUIT.timestamp(), boites=(GK7, CLIENTE))
    programmer(w, etapes=(A_REBOOT,))                    # devenue forte depuis l'enregistrement
    programmer(w, cibles=(GK7, CLIENTE))                 # une cible devenue cliente
    assert await w.m.tic(NUIT) == []
    assert w.x.appels == [] and w.s.executions() == []
    refus = w.macro_audits("refus_programme")
    assert len(refus) == 2 and all(c["acteur"] == "planificateur" for c in refus)
    assert await w.m.tic(NUIT + timedelta(minutes=1)) == []
    assert len(w.macro_audits("refus_programme")) == 2   # une tentative par macro et par heure


@pytest.mark.asyncio
async def test_planificateur_cible_disparue_sautee_et_boucle_vivante(tmp_path, caplog):
    w = Monde(tmp_path, t=NUIT.timestamp())
    programmer(w, cibles=(GK7, GK6))
    resolutions = iter(["gk6 oubliée", "panne", "normal"])
    nuit = {"n": None}

    def resoudre(cle):
        if nuit["n"] == "gk6 oubliée" and cle == "maillage:gk6":
            return None                               # renommée ou oubliée depuis l'enregistrement
        if nuit["n"] == "panne":
            raise RuntimeError("stockage indisponible")
        return w.s.boite(cle)
    w.resoudre = resoudre

    tics = []
    origine = w.m.tic

    async def tic(maintenant):
        nuit["n"] = next(resolutions, "fin")
        if nuit["n"] == "fin":
            raise asyncio.CancelledError
        tics.append(await origine(maintenant))
        for t in list(w.m.taches.values()):
            await t
        return tics[-1]
    w.m.tic = tic

    async def une_nuit(s):
        w.h.avance(s)
        for b, boot in list(w.vivantes.items()):
            w.s.vu(b, {"boot_id": boot})
    w.m.attente = une_nuit
    with caplog.at_level(logging.ERROR, logger="pilotage.moteur"), pytest.raises(asyncio.CancelledError):
        await w.m.planifier(lambda: datetime.fromtimestamp(w.h(), timezone.utc), periode_s=86400)
    assert [len(t) for t in tics] == [1, 0, 1]                    # la nuit de la panne n'a rien lancé, la boucle a survécu
    premiere, troisieme = w.s.execution(tics[0][0]), w.s.execution(tics[2][0])
    assert [c["nom"] for c in premiere["cibles"]] == ["gk7"] and premiere["etat"] == "terminee"
    assert "gk6" in w.macro_audits("lancement")[0]["raison"]
    assert [c["nom"] for c in troisieme["cibles"]] == ["gk7", "gk6"]
    assert "stockage indisponible" in caplog.text


@pytest.mark.asyncio
async def test_planifier_survit_a_un_tic_qui_leve(tmp_path, caplog):
    w = Monde(tmp_path)
    n = {"tics": 0}

    async def tic(maintenant):
        n["tics"] += 1
        if n["tics"] == 1:
            raise RuntimeError("tic cassé")
        raise asyncio.CancelledError
    w.m.tic = tic
    with caplog.at_level(logging.ERROR, logger="pilotage.moteur"), pytest.raises(asyncio.CancelledError):
        await w.m.planifier(lambda: NUIT, periode_s=60)
    assert n["tics"] == 2 and "tic cassé" in caplog.text


# --- diffusion ---

def test_relais_unitaire():
    d = Diffusion()
    box, flux = d.abonner("a", "maillage:gk7"), d.abonner("a", "exec:1")
    d.relayer("maillage:gk7", "exec:1")
    d.publier("maillage:gk7", "operation", {"i": 1})
    d.publier("maillage:gk7", "notify", {"i": 2})
    d.publier("maillage:gk7", "etat", {"i": 3})
    d.cesser("maillage:gk7", "exec:1")
    d.publier("maillage:gk7", "operation", {"i": 4})
    assert [(n, x["i"]) for n, x in evenements(flux)] == [("operation", 1)]
    assert [x["i"] for _, x in evenements(box)] == [1, 2, 3, 4]
    d.cesser("maillage:gk7", "exec:1")                       # idempotent
    assert d._relais == {}


@pytest.mark.asyncio
async def test_relais_operation_vers_le_flux_d_execution(w):
    w.x.diffusion = w.d
    w.x.pendant = lambda b, a: b["nom"] == "gk6" and w.d.publier("maillage:gk7", "operation", {"cle": "maillage:gk7", "tard": True})
    ident = await w.lancer([A_MAJ])
    ab = w.d.abonner("alice", cle_flux(ident))
    await w.m.taches[ident]
    w.d.publier("maillage:gk7", "operation", {"cle": "maillage:gk7", "apres": True})
    evs = evenements(ab)
    ops = [d for n, d in evs if n == "operation"]
    assert [d["cle"] for d in ops] == ["maillage:gk7", "maillage:gk6"] and not any(d.get("tard") or d.get("apres") for d in ops)
    assert not [n for n, _ in evs if n == "notify"]
    macros = [d for n, d in evs if n == "macro"]
    assert all(set(d) == CHAMPS_MACRO for d in macros) and all(d["execution"] == ident for d in macros)
    assert [d["evenement"] for d in macros][0] == "lancement" and macros[-1]["evenement"] == "fin"
    assert macros[-1]["etat"] == "terminee"
    assert w.d._relais == {}


# --- points de relecture du plan ---

@pytest.mark.asyncio
async def test_releve_attend_un_inventaire_posterieur_au_debut(w):
    w.s.inventaire_enregistrer(GK7, corps())          # inventaire d'AVANT l'étape : sans échec
    w.h.avance(30)
    w.x.frais = False                                  # le relevé ne rafraîchit pas l'inventaire lui-même
    n = {"attentes": 0}

    def tardif():
        n["attentes"] += 1
        if n["attentes"] == 3:                         # le relevé périodique arrive 15 s plus tard, avec un service en échec
            w.s.inventaire_enregistrer(GK7, corps(["secubox-dns.service"]))
    w.crochets.append(tardif)
    ex = await w.derouler([R_AVANT], boites=(GK7,))
    assert ex["etat"] == "terminee"
    inst = w.s.releves_execution(ex["id"], "maillage:gk7")["avant"]
    assert inst["services"] == ["secubox-dns.service"] and inst["inventaire_le"] >= ex["etapes"][0]["debut"]

    w.crochets.clear()
    w.h.avance(30)
    t0 = w.h()
    ex = await w.derouler([R_AVANT], boites=(GK7, GK6))   # aucun inventaire neuf : échec, jamais l'ancien
    assert ex["etat"] == "echec" and "inventaire non rafraîchi" in ex["raison"]
    assert 90 <= w.h() - t0 <= 90 + PAS
    assert w.s.releves_execution(ex["id"], "maillage:gk7") == {} and etats(ex, "gk6") == ["non_lancee"]


@pytest.mark.asyncio
async def test_releve_en_echec_sur_la_box(w):
    w.x.statut_releve = "expire"
    ex = await w.derouler([R_AVANT])
    assert ex["etat"] == "echec" and "expire" in ex["raison"] and etats(ex, "gk6") == ["non_lancee"]


@pytest.mark.asyncio
async def test_deux_lancements_concurrents_une_seule_execution(w):
    r = await asyncio.gather(w.lancer([R_AVANT], boites=(GK7,)), w.lancer([R_AVANT], boites=(GK6, GK7)), return_exceptions=True)
    ids = [x for x in r if isinstance(x, int)]
    refus = [x for x in r if isinstance(x, RefusLancement)]
    assert len(ids) == 1 and len(refus) == 1 and refus[0].statut == 409
    assert [e["id"] for e in w.s.executions()] == ids
    await w.m.taches[ids[0]]
    assert w.x.appels == [("gk7", "releve")]


@pytest.mark.asyncio
async def test_support_echu_en_cours_echec_et_serie_arretee(tmp_path):
    w = Monde(tmp_path, boites=(CLIENTE, GK6))
    w.s.support_demander(CLIENTE.cle, "sid-1", 30, "alice")
    w.s.support_noter(CLIENTE.cle, "sid-1", "ouvert", None)
    w.x.pendant = lambda b, a: w.s.support_fermer_local(CLIENTE.cle, "sid-1")   # le détenteur ferme la session
    ex = await w.derouler([A_HUB, R_AVANT], boites=(CLIENTE, GK6), support={CLIENTE.cle: "sid-1"})
    assert ex["etat"] == "echec" and "session de support échue" in ex["raison"]
    assert w.x.appels == [("gk5", "service-redemarrer")]
    assert w.x.confirmations[0][2] == "sid-1"                         # la session est passée à executer_action
    lignes = [e for e in ex["etapes"] if e["box"] == CLIENTE.cle]
    assert [e["etat"] for e in lignes] == ["ok", "echec"] and etats(ex, "gk6") == ["non_lancee", "non_lancee"]
