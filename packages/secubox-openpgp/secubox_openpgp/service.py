# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: openpgp — échange signé et chiffré entre box (#1736)
CyberMind — https://cybermind.fr

Le démon et la CLI partagent ce module. Trois règles le traversent :

1. UN PAIR, C'EST UNE LIAISON. Son empreinte vient de l'annuaire (entrée
   openpgp_bind signée par SON node.key, lue par annuaire.openpgp), jamais
   d'un serveur de clés, jamais d'une toile de confiance.
2. ON NE SIGNE QU'UNE ENVELOPPE. {v, de, a, emis, nonce, objet, contenu} :
   pas de « signe-moi ces octets » (#1417, S8).
3. À LA RÉCEPTION, TOUT SE VÉRIFIE : signataire = empreinte liée à `de`,
   `a` = cette box, fraîcheur ±15 min, nonce inédit. Un message qui échoue
   n'est pas conservé — et la réponse ne dit pas pourquoi au déposant.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import enveloppe as env
from .gpg import ErreurGpg, Trousseau

USAGE_INTERBOX = "interbox"
PORT_MAILLAGE = 8799
CHEMIN_DEPOT = "/api/v1/openpgp/boite/depot"
_ID = re.compile(r"^[0-9]{10}-[0-9a-f]{16}$")


class Refus(ValueError):
    """Refus métier ; le message est sûr à montrer à l'administrateur."""


# ── lecture de l'annuaire ────────────────────────────────────────────────

def export_par_socket(chemin: str = "/run/secubox/annuaire.sock") -> List[dict]:
    """Les entrées signées de l'annuaire local (même route que les pairs)."""
    class _Unix(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect(chemin)
    c = _Unix("localhost", timeout=10)
    try:
        c.request("GET", "/log/export", headers={"X-SecuBox-Maillage": "1",
                                                  "Accept": "application/json"})
        r = c.getresponse()
        corps = r.read()
        if r.status != 200:
            raise Refus(f"annuaire injoignable ({r.status})")
    finally:
        c.close()
    d = json.loads(corps)
    return d.get("entries", d) if isinstance(d, dict) else d


def _noeuds(entrees: List[dict]) -> Dict[str, dict]:
    """{did: {boxname, mesh_ip}} — dernière fiche AUTO-signée et vérifiée."""
    from annuaire.openpgp import authentique  # noqa: PLC0415
    out: Dict[str, dict] = {}
    for e in entrees:
        if str(e.get("op")) != "node_publish" or not authentique(e):
            continue
        p = e.get("payload") or {}
        if p.get("did") == e.get("author") and p.get("mesh_ip"):
            out[p["did"]] = {"boxname": str(p.get("boxname") or ""), "mesh_ip": str(p["mesh_ip"])}
    return out


# ── la box ───────────────────────────────────────────────────────────────

@dataclass
class Box:
    trousseau: Trousseau
    did: str
    racine: Path
    lire_annuaire: Callable[[], List[dict]] = export_par_socket

    @property
    def boite(self) -> Path:
        return self.racine / "boite"

    def journal(self, evenement: str, **champs: Any) -> None:
        """Trace ajoutée — jamais le contenu d'un message, jamais un secret."""
        ligne = {"t": int(time.time()), "evenement": evenement, **champs}
        try:
            with open(self.racine / "journal.jsonl", "a") as f:
                f.write(json.dumps(ligne, ensure_ascii=False, sort_keys=True) + "\n")
        except OSError:
            pass

    # ── état ─────────────────────────────────────────────────────────────
    def ma_cle(self) -> Optional[dict]:
        return self.trousseau.cle_de_box()

    def pairs(self, maintenant: Optional[float] = None) -> Dict[str, dict]:
        """Les box dont l'annuaire porte une liaison OpenPGP active."""
        from annuaire.openpgp import liaisons  # noqa: PLC0415
        entrees = self.lire_annuaire()
        noeuds = _noeuds(entrees)
        out = {}
        for did, l in liaisons(entrees, maintenant, verifier=True).items():
            n = noeuds.get(did, {})
            out[did] = {"did": did, "boxname": n.get("boxname", ""), "mesh_ip": n.get("mesh_ip", ""),
                        "empreinte": l["empreinte"], "expire": l["expire"],
                        "cle_publique": l["cle_publique"], "soi": did == self.did}
        return out

    def resoudre(self, qui: str, pairs: Optional[Dict[str, dict]] = None) -> dict:
        """Un pair par did ou par nom de box ; jamais soi."""
        pairs = self.pairs() if pairs is None else pairs
        trouves = [p for p in pairs.values() if qui in (p["did"], p["boxname"]) and not p["soi"]]
        if len(trouves) != 1:
            raise Refus(f"aucun pair lié (ou plusieurs) pour « {qui} »")
        return trouves[0]

    # ── envoyer ──────────────────────────────────────────────────────────
    def preparer(self, pair: dict, objet: str, contenu: str,
                 maintenant: Optional[float] = None) -> str:
        """L'enveloppe, signée par notre clé et chiffrée pour la clé LIÉE du pair."""
        moi = self.ma_cle()
        if not moi:
            raise Refus("cette box n'a pas encore de clé OpenPGP (sbx-openpgp init)")
        self.trousseau.importer(pair["cle_publique"], pair["empreinte"])
        clair = env.construire(self.did, pair["did"], objet, contenu, maintenant)
        return self.trousseau.chiffrer_signer(clair, pour=pair["empreinte"],
                                              par=moi["empreinte"], usage=USAGE_INTERBOX)

    def envoyer(self, qui: str, objet: str, contenu: str,
                poster: Optional[Callable[[str, bytes], int]] = None) -> dict:
        pair = self.resoudre(qui)
        if not pair["mesh_ip"]:
            raise Refus(f"adresse maillée de {pair['boxname'] or pair['did']} inconnue")
        armure = self.preparer(pair, objet, contenu)
        code = (poster or _poster_maillage)(pair["mesh_ip"], armure.encode())
        self.journal("envoi", a=pair["did"], boxname=pair["boxname"], code=code,
                     taille=len(armure), empreinte=hashlib.sha256(armure.encode()).hexdigest()[:16])
        if code != 201:
            raise Refus(f"{pair['boxname'] or pair['did']} a refusé le dépôt ({code})")
        return {"ok": True, "a": pair["did"], "boxname": pair["boxname"]}

    # ── recevoir ─────────────────────────────────────────────────────────
    def deposer(self, armure: str, maintenant: Optional[float] = None) -> dict:
        """Vérifie TOUT, puis conserve le message chiffré (jamais en clair)."""
        t = time.time() if maintenant is None else maintenant
        # Les clés publiques LIÉES des pairs d'abord : sans elles, gpg ne peut
        # pas vérifier la signature. Chacune n'entre que si le bloc contient
        # exactement l'empreinte liée.
        pairs = self.pairs(t)
        self._importer_pairs(pairs)
        try:
            d = self.trousseau.dechiffrer_verifier(armure)
            e = env.lire(d.texte, t)
        except (ErreurGpg, env.EnveloppeInvalide) as ex:
            self.journal("depot_refuse", motif=str(ex)[:120])
            raise Refus("message refusé")
        emetteur = pairs.get(e["de"])
        motif = None
        if e["a"] != self.did:
            motif = "destiné à une autre box"
        elif not emetteur or emetteur["soi"]:
            motif = "expéditeur sans liaison OpenPGP active"
        elif d.signataire != emetteur["empreinte"]:
            motif = "signé par une autre clé que celle liée à l'expéditeur"
        elif d.notations.get("usage@secubox.in") != USAGE_INTERBOX:
            motif = "usage de signature inattendu"
        elif not self._nonce_inedit(e["nonce"], t):
            motif = "déjà reçu (rejeu)"
        if motif:
            self.journal("depot_refuse", de=e.get("de"), motif=motif)
            raise Refus("message refusé")
        ident = f"{int(t):010d}-{hashlib.sha256(armure.encode()).hexdigest()[:16]}"
        self.boite.mkdir(mode=0o700, parents=True, exist_ok=True)
        fiche = {"id": ident, "recu": int(t), "de": e["de"], "boxname": emetteur["boxname"],
                 "empreinte": d.signataire, "emis": e["emis"], "taille": len(armure),
                 "armure": armure}
        chemin = self.boite / f"{ident}.json"
        tmp = chemin.with_suffix(".tmp")
        tmp.write_text(json.dumps(fiche))
        os.chmod(tmp, 0o600)
        tmp.replace(chemin)
        self.journal("depot", de=e["de"], boxname=emetteur["boxname"], id=ident)
        return {"ok": True, "id": ident}

    def _importer_pairs(self, pairs: Dict[str, dict]) -> None:
        for p in pairs.values():
            if p["soi"]:
                continue
            try:
                self.trousseau.importer(p["cle_publique"], p["empreinte"])
            except ErreurGpg:
                self.journal("cle_pair_refusee", de=p["did"])

    def _nonce_inedit(self, nonce: str, t: float) -> bool:
        """Nonces vus dans la fenêtre de fraîcheur (au-delà, `emis` refuse déjà)."""
        f = self.racine / "nonces.json"
        try:
            vus = {n: v for n, v in json.loads(f.read_text()).items()
                   if v > t - 2 * env.DERIVE_S}
        except (OSError, ValueError):
            vus = {}
        if nonce in vus:
            return False
        vus[nonce] = int(t)
        tmp = f.with_suffix(".tmp")
        tmp.write_text(json.dumps(vus))
        os.chmod(tmp, 0o600)
        tmp.replace(f)
        return True

    def lister(self) -> List[dict]:
        if not self.boite.is_dir():
            return []
        out = []
        for p in sorted(self.boite.glob("*.json"), reverse=True):
            try:
                d = json.loads(p.read_text())
            except (OSError, ValueError):
                continue
            out.append({k: d[k] for k in ("id", "recu", "de", "boxname", "empreinte", "emis", "taille")})
        return out

    def lire(self, ident: str) -> dict:
        """Déchiffre un message CONSERVÉ — l'administrateur seulement (l'API
        le garde) ; chaque lecture est tracée."""
        if not _ID.match(ident or ""):
            raise Refus("identifiant invalide")
        try:
            d = json.loads((self.boite / f"{ident}.json").read_text())
        except (OSError, ValueError):
            raise Refus("message inconnu")
        clair = self.trousseau.dechiffrer_verifier(d["armure"])
        e = json.loads(clair.texte.decode())
        self.journal("lecture", id=ident, de=d["de"])
        return {"id": ident, "de": d["de"], "boxname": d["boxname"], "empreinte": d["empreinte"],
                "emis": e["emis"], "objet": e["objet"], "contenu": e["contenu"]}


def _poster_maillage(mesh_ip: str, corps: bytes) -> int:
    """POST du message armuré vers l'écoute maillée du pair (:8799)."""
    c = http.client.HTTPConnection(mesh_ip, PORT_MAILLAGE, timeout=10)
    try:
        c.request("POST", CHEMIN_DEPOT, body=corps,
                  headers={"Content-Type": "application/pgp-encrypted"})
        r = c.getresponse()
        r.read()
        return r.status
    except OSError:
        return 0
    finally:
        c.close()


def did_local(chemin: str = "/etc/secubox/annuaire/node.did") -> str:
    """Le did de CETTE box, publié en clair par le postinst (jamais node.key ici)."""
    try:
        d = Path(chemin).read_text().strip()
    except OSError:
        return ""
    return d if re.fullmatch(r"did:plc:[0-9a-f]{32}", d) else ""
