# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L2 tâche 7 — temps réel vers la page : GET /boxes/{x}/flux (text/event-stream), un abonnement par flux, 4 au plus par
administrateur, libéré à la déconnexion, files bornées, vue en direct d'une box cliente réservée à une session de support ouverte."""
import asyncio
import json

import httpx
import pytest

from secubox_core import auth

from api.canal import creer_app_canal
from api.main import creer_app_admin
from pilotage.diffusion import Diffusion, LimiteAtteinte, formater
from pilotage.files import Files
from pilotage.inventaire import Inventaire
from pilotage.stockage import StockageSqlite
from outils import GK5_AUTOLOAD, Horloge
from test_canal import CONNUES, GK5 as GK5_CANAL, client as client_canal

MARQUEUR_TUNNEL = "x-secubox-pilotage-tunnel"


def analyser(brut: bytes):
    """Événements SSE d'un flux : liste de (event, data analysé) ; les commentaires (« : … ») sont rendus sous ('#', texte)."""
    out = []
    for bloc in brut.decode().split("\n\n"):
        if not bloc:
            continue
        nom, data = None, []
        for ligne in bloc.split("\n"):
            if ligne.startswith(":"):
                out.append(("#", ligne[1:].strip()))
            elif ligne.startswith("event: "):
                nom = ligne[7:]
            elif ligne.startswith("data: "):
                data.append(ligne[6:])
            else:
                raise AssertionError(f"ligne SSE inattendue : {ligne!r}")
        if nom is not None:
            out.append((nom, json.loads("\n".join(data))))
    return out


class Flux:
    """Un client SSE sur l'application ASGI (httpx ne rend pas un flux sans fin : on parle ASGI directement)."""

    def __init__(self, app, chemin, headers=()):
        self.app, self.corps, self.entete, self.statut = app, b"", {}, None
        self.fin = asyncio.Event()
        self.q = asyncio.Queue()
        self.demarre = asyncio.Event()
        self.scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET", "path": chemin, "raw_path": chemin.encode(),
                      "query_string": b"", "headers": [(k.encode(), v.encode()) for k, v in headers], "server": ("t", 80), "client": ("c", 1),
                      "scheme": "http", "root_path": ""}
        self.t = asyncio.create_task(self._run())

    async def fin_msg(self):
        await self.fin.wait()
        return {"type": "http.disconnect"}

    async def _send(self, m):
        if m["type"] == "http.response.start":
            self.statut, self.entete = m["status"], {k.decode().lower(): v.decode() for k, v in m["headers"]}
            self.demarre.set()
        elif m["type"] == "http.response.body":
            self.corps += m.get("body", b"")
            self.q.put_nowait(True)

    async def _run(self):
        async def recevoir():
            if not hasattr(self, "_requete"):
                self._requete = True
                return {"type": "http.request", "body": b"", "more_body": False}
            return await self.fin_msg()
        await self.app(self.scope, recevoir, self._send)

    async def evenements(self, n, delai=3.0):
        """Attend au moins n blocs complets (événements ou commentaires)."""
        async def attendre():
            while len(analyser(self.corps.rsplit(b"\n\n", 1)[0] + b"\n\n" if b"\n\n" in self.corps else b"")) < n:
                await asyncio.sleep(0.01)
        await asyncio.wait_for(attendre(), delai)
        return analyser(self.corps.rsplit(b"\n\n", 1)[0] + b"\n\n")

    async def fermer(self):
        self.fin.set()
        await asyncio.wait_for(self.t, 3)


class Monde:
    def __init__(self, tmp_path, battement_s=15.0, **diff):
        self.h = Horloge()
        self.s = StockageSqlite(tmp_path / "p", horloge=self.h)
        self.f = Files()
        self.lignes = []
        self.diffusion = Diffusion(**diff)
        self.sub = "alice"
        inv = Inventaire(self.f, self.s, horloge=self.h)
        self.app = creer_app_admin(self.s, self.f, inv, lambda e, c: self.lignes.append((e, c)), horloge=self.h, diffusion=self.diffusion,
                                   battement_s=battement_s)
        self.app.dependency_overrides[auth.require_jwt] = lambda: {"sub": self.sub}
        self.canal = creer_app_canal(self.f, CONNUES.get, self.s, lambda e, c: None, vu_intervalle_s=0, audit_intervalle_s=0,
                                     diffuser=self.diffusion.diffuser_notification)

    def ouvrir(self, ident="gk5", sub="alice", **kw):
        self.sub = sub
        return Flux(self.app, f"/boxes/{ident}/flux", **kw)

    async def notifier(self, *evs):
        async with client_canal(self.canal) as c:
            r = await c.post("/canal/v1/notifs", json=[{"type": "NOTIFY", "body": {"event": {"ts": 1, **e}}} for e in evs])
        assert r.status_code == 200, r.text
        return r.json()


@pytest.fixture
def m(tmp_path):
    w = Monde(tmp_path)
    w.s.vu(GK5_CANAL, {})
    return w


@pytest.mark.asyncio
async def test_flux_recoit_les_notifications(m):
    f = m.ouvrir()
    (etat,) = await f.evenements(1)
    assert f.statut == 200 and f.entete["content-type"].startswith("text/event-stream")
    assert f.entete["x-accel-buffering"] == "no" and "no-cache" in f.entete["cache-control"]
    assert etat[0] == "etat" and etat[1]["box"] == "gk5" and etat[1]["connecte"] is True

    await m.notifier({"type": "X_SECUBOX_ServiceLoop", "unit": "secubox-hub.service", "value": 3},
                     {"type": "X_SECUBOX_OperationProgress", "job": "j1", "etape": "en_cours", "pct": 40},
                     {"type": "X_SECUBOX_OperationDone", "job": "j1", "rc": 0, "resume": "maj-paquets : succès"},
                     {"type": "X_SECUBOX_Support", "id": "s1", "etat": "ouvert", "fin": "2026-10-29T12:30:00Z"},
                     {"type": "X_SECUBOX_HandsTied", "etat": "actif"},
                     {"type": "X_SECUBOX_Consent", "id": "c1", "decision": "accepte"})
    ev = await f.evenements(1 + 6 + 4)
    suite = ev[1:]
    assert [n for n, _ in suite] == ["notify", "notify", "operation", "notify", "operation", "notify", "etat", "notify", "etat", "notify", "etat"]
    notif = suite[0][1]
    assert notif["box"] == "gk5" and notif["cle"] == "maillage:gk5" and notif["type"] == "X_SECUBOX_ServiceLoop" and notif["value"] == 3
    prog, fin = suite[2][1], suite[4][1]
    assert prog == {"box": "gk5", "cle": "maillage:gk5", "type": "X_SECUBOX_OperationProgress", "job": "j1", "etape": "en_cours", "pct": 40, "ts": 1}
    assert fin["job"] == "j1" and fin["rc"] == 0 and fin["resume"] == "maj-paquets : succès"
    assert suite[6][1]["etat"] == "ouvert" and suite[6][1]["id"] == "s1"
    await f.fermer()


@pytest.mark.asyncio
async def test_flux_ne_recoit_que_sa_box(m):
    m.s.vu(GK5_AUTOLOAD, {})
    f = m.ouvrir("maillage:gk5")
    await f.evenements(1)
    m.diffusion.publier("autoload:gk5", "notify", {"type": "X"})
    m.diffusion.publier("maillage:gk5", "notify", {"type": "Y"})
    ev = await f.evenements(2)
    assert [e[1]["type"] for e in ev[1:]] == ["Y"]
    await f.fermer()


@pytest.mark.asyncio
async def test_flux_garde_jwt_et_box_inconnue(tmp_path):
    w = Monde(tmp_path)
    w.s.vu(GK5_CANAL, {})
    sans = dict(w.app.dependency_overrides)
    w.app.dependency_overrides.clear()
    f = Flux(w.app, "/boxes/gk5/flux")
    await asyncio.wait_for(f.demarre.wait(), 3)
    assert f.statut == 401
    await f.fermer()
    assert w.diffusion.total() == 0
    w.app.dependency_overrides.update(sans)
    f = w.ouvrir("nexiste-pas")
    await asyncio.wait_for(f.demarre.wait(), 3)
    assert f.statut == 404
    await f.fermer()


@pytest.mark.asyncio
async def test_flux_libere_a_la_deconnexion(m):
    f = m.ouvrir()
    await f.evenements(1)
    assert m.diffusion.compte("alice") == 1 and m.diffusion.total() == 1
    await f.fermer()
    assert m.diffusion.compte("alice") == 0 and m.diffusion.total() == 0
    # abonnement jamais lu (déconnexion avant le premier envoi) : libéré aussi
    ab = m.diffusion.abonner("alice", "maillage:gk5")
    assert m.diffusion.compte("alice") == 1
    m.diffusion.liberer(ab)
    m.diffusion.liberer(ab)   # idempotent
    assert m.diffusion.compte("alice") == 0


@pytest.mark.asyncio
async def test_flux_battement_puis_liberation_si_l_ecriture_echoue(tmp_path):
    w = Monde(tmp_path, battement_s=0.02)
    w.s.vu(GK5_CANAL, {})
    f = w.ouvrir()
    ev = await f.evenements(3)
    assert [n for n, _ in ev[1:]] == ["#", "#"] and ev[1][1] == "battement"
    await f.fermer()

    # le client est parti sans que la réception le signale : l'écriture du battement échoue
    w.sub = "bob"
    envoyes = []

    corps_lu = []

    async def recevoir():
        if not corps_lu:
            corps_lu.append(1)
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(3600)

    async def envoyer(m_):
        if m_["type"] == "http.response.body" and m_.get("body"):
            envoyes.append(m_)
            if len(envoyes) >= 2:
                raise OSError("connexion rompue")

    t = asyncio.create_task(w.app(f.scope, recevoir, envoyer))
    await asyncio.wait({t}, timeout=3)
    assert t.done() and w.diffusion.total() == 0 and w.diffusion.compte("bob") == 0


@pytest.mark.asyncio
async def test_flux_limite_par_admin(m):
    flux = []
    for _ in range(4):
        flux.append(m.ouvrir(sub="alice"))
        await flux[-1].evenements(1)
    assert m.diffusion.compte("alice") == 4
    cinq = m.ouvrir(sub="alice")
    await asyncio.wait_for(cinq.demarre.wait(), 3)
    assert cinq.statut == 429
    await cinq.fermer()
    assert m.diffusion.compte("alice") == 4
    # la limite se compte par login
    autre = m.ouvrir(sub="bob")
    await autre.evenements(1)
    assert autre.statut == 200 and m.diffusion.compte("bob") == 1
    # un flux fermé libère une place
    await flux.pop().fermer()
    de_nouveau = m.ouvrir(sub="alice")
    await de_nouveau.evenements(1)
    assert de_nouveau.statut == 200 and m.diffusion.compte("alice") == 4
    for x in flux + [autre, de_nouveau]:
        await x.fermer()
    assert m.diffusion.total() == 0


def test_limite_diffusion_unitaire():
    d = Diffusion()
    abonnes = [d.abonner("a", "k") for _ in range(4)]
    with pytest.raises(LimiteAtteinte):
        d.abonner("a", "k")
    d.liberer(abonnes[0])
    d.abonner("a", "k")


@pytest.mark.asyncio
async def test_file_bornee_abandonne_les_plus_vieux_sans_bloquer():
    d = Diffusion(file_max=3)
    ab = d.abonner("a", "k")
    for i in range(10):
        d.publier("k", "notify", {"i": i})        # synchrone, ne bloque jamais
    lus = []
    while (e := await ab.suivant(0.01)) is not None:
        lus.append(e)
    assert [e[0] for e in lus][0] == "etat" and lus[0][1]["perte"] == 7     # la page est prévenue qu'elle doit se resynchroniser
    assert [e[1]["i"] for e in lus[1:]] == [7, 8, 9]


@pytest.mark.asyncio
async def test_abonne_lent_ne_bloque_pas_les_autres():
    d = Diffusion(file_max=2)
    _lent, vif = d.abonner("a", "k"), d.abonner("b", "k")
    for i in range(1000):
        d.publier("k", "notify", {"i": i})
    assert (await vif.suivant(0.01))[0] == "etat"
    assert d.total() == 2


def test_format_sse_une_seule_ligne_data():
    brut = formater("operation", {"resume": "a\nb\r\nc d\x00", "raison": "event: x\n\ndata: y", "args": {"nom": "e\nf"}})
    assert brut.endswith("\n\n") and brut.count("\n\n") == 1
    lignes = brut.rstrip("\n").split("\n")
    assert len(lignes) == 2 and lignes[0] == "event: operation" and lignes[1].startswith("data: ")
    assert "\r" not in brut and " " not in brut
    assert json.loads(lignes[1][6:])["resume"] == "a\nb\r\nc d\x00"
    with pytest.raises(ValueError):
        formater("evil\nevent: x", {})


@pytest.mark.asyncio
async def test_aucun_secret_dans_le_flux(m):
    f = m.ouvrir()
    await f.evenements(1)
    await m.notifier({"type": "X_SECUBOX_OperationDone", "job": "j1", "rc": 0, "resume": "ok", "code": "SECRET-CODE", "token": "tok"})
    await f.evenements(3)
    assert b"SECRET" not in f.corps and b"tok" not in f.corps.replace(b"token", b"")
    await f.fermer()


@pytest.mark.asyncio
async def test_action_publie_l_operation(m):
    f = m.ouvrir()
    await f.evenements(1)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=m.app), base_url="http://t") as c:
        t = asyncio.create_task(c.post("/boxes/gk5/actions/service-redemarrer", json={"args": {"unite": "secubox-hub.service"}}))
        (rq,) = await m.f.attendre_requetes("maillage:gk5", 1)
        m.f.livrer_reponse("maillage:gk5", {"msg_id": rq["msg_id"], "type": "OPERATE_RESP", "body": {"etat": "accepte", "job": "a1b2c3d4e5f60718", "raison": ""}})
        r = await t
    assert r.status_code == 200
    ev = await f.evenements(2)
    nom, d = ev[1]
    assert nom == "operation" and d["action"] == "service-redemarrer" and d["etat"] == "accepte" and d["job"] == "a1b2c3d4e5f60718"
    assert d["acteur"] == "alice" and d["args"] == {"unite": "secubox-hub.service", "action": "redemarrer"} and d["box"] == "gk5"
    await f.fermer()


# --- R-L2-31 : vue en direct d'une box cliente = session de support ouverte et non échue ---

@pytest.mark.asyncio
async def test_box_cliente_flux_exige_une_session_de_support(tmp_path):
    w = Monde(tmp_path)
    w.s.vu(GK5_AUTOLOAD, {})
    f = w.ouvrir("autoload:gk5")
    await asyncio.wait_for(f.demarre.wait(), 3)
    assert f.statut == 403 and w.diffusion.total() == 0
    await f.fermer()

    w.s.support_demander(GK5_AUTOLOAD.cle, "s1", 30, "alice")                    # demandée, pas encore acceptée
    f = w.ouvrir("autoload:gk5")
    await asyncio.wait_for(f.demarre.wait(), 3)
    assert f.statut == 403
    await f.fermer()

    w.s.support_noter(GK5_AUTOLOAD.cle, "s1", "ouvert", None)
    f = w.ouvrir("autoload:gk5")
    (etat,) = await f.evenements(1)
    assert f.statut == 200 and etat[1]["support"] == "s1"
    await f.fermer()


@pytest.mark.asyncio
async def test_box_cliente_flux_se_ferme_a_la_fin_du_support(tmp_path):
    w = Monde(tmp_path, battement_s=0.02)
    w.s.vu(GK5_AUTOLOAD, {})
    w.s.support_demander(GK5_AUTOLOAD.cle, "s1", 1, "alice")
    w.s.support_noter(GK5_AUTOLOAD.cle, "s1", "ouvert", None)
    f = w.ouvrir("autoload:gk5")
    await f.evenements(1)
    w.h.avance(61)                                                                # la minute est passée : session échue
    await asyncio.wait_for(f.t, 3)                                                # le flux se termine de lui-même
    ev = analyser(f.corps)
    assert ev[-1][0] == "etat" and ev[-1][1]["support"] == "termine"
    assert w.diffusion.total() == 0
    await f.fermer()


@pytest.mark.asyncio
async def test_fermeture_du_service_termine_les_flux(m):
    f = m.ouvrir()
    await f.evenements(1)
    m.diffusion.fermer()
    await asyncio.wait_for(f.t, 3)
    assert m.diffusion.total() == 0
    await f.fermer()


def test_nginx_laisse_passer_le_flux_sans_tampon_ni_coupure():
    """Le battement (15 s) reste sous proxy_read_timeout et le proxy ne met rien en tampon ; l'application ajoute X-Accel-Buffering: no."""
    import re
    from pathlib import Path
    import inspect
    assert inspect.signature(creer_app_admin).parameters["battement_s"].default == 15.0
    snippet = (Path(__file__).resolve().parents[3] / "common" / "nginx" / "secubox-proxy.conf").read_text()
    delai = int(re.search(r"^proxy_read_timeout\s+(\d+)s;", snippet, re.M).group(1))
    assert delai > 2 * 15 and re.search(r"^proxy_buffering\s+off;", snippet, re.M)
