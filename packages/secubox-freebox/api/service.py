# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: freebox :: service
CyberMind — https://cybermind.fr

États en langage clair (non configuré, en attente de validation sur la Freebox, autorisé, injoignable…), droits obtenus et manquants,
lectures avec un cache court (la Freebox n'est pas faite pour être interrogée en boucle). Aucune réponse ne contient le jeton.
"""
import json
import os
import socket
import time

from . import client as C
from . import normalise as N

TTL_LECTURE_S = 30

AIDE_DROITS = {
    "settings": "Modification des réglages de la Freebox : nécessaire pour créer ou supprimer des redirections de ports.",
}

# Où la Freebox publie les ouvertures IPv6 selon sa version : on essaie dans l'ordre, la première qui répond fait foi.
CHEMINS_EXCEPTIONS_IPV6 = ("fw/ipv6/", "fw/ipv6/redir/", "fw/pinhole/")


class Freebox:
    def __init__(self, client, magasin, horloge=time.time, nom_appareil=None, ttl=TTL_LECTURE_S):
        self.client = client
        self.magasin = magasin
        self.horloge = horloge
        self.nom_appareil = nom_appareil or socket.gethostname()
        self.ttl = ttl
        self._cache = {}
        self.journal = self._journal_fichier      # remplaçable (tests) ; jamais de jeton dans une entrée

    # ── état ─────────────────────────────────────────────────────────────────
    def statut(self):
        base = {"freebox": {}, "droits": {}, "droits_manquants": [], "aide_droits": AIDE_DROITS}
        try:
            base["freebox"] = self.client.decouvrir()
        except C.Injoignable as e:
            return {**base, "etat": "injoignable", "message": str(e)}
        mem = self.magasin.lire()
        if not mem.get("app_token"):
            return {**base, "etat": "non_configure", "message": "SecuBox n'est pas encore connecté à la Freebox."}
        if not mem.get("autorise"):
            try:
                etat = self.client.etat_autorisation()["etat"]
            except C.ErreurFreebox as e:
                return {**base, "etat": "erreur", "message": str(e)}
            if etat == "attente":
                return {**base, "etat": "attente_validation",
                        "message": "Validez la demande sur la Freebox : appuyez sur ✓ sur son afficheur, puis revenez ici."}
            if etat == "refusee":
                return {**base, "etat": "refusee", "message": "La demande a été refusée sur la Freebox. Relancez la connexion."}
            if etat == "expiree":
                return {**base, "etat": "expiree", "message": "La demande a expiré faute de validation. Relancez la connexion."}
            if etat != "accordee":
                return {**base, "etat": "erreur", "message": "L'état de la demande est inconnu : relancez la connexion."}
        try:
            droits = self.client.ouvrir_session()
        except C.Injoignable as e:
            return {**base, "etat": "injoignable", "message": str(e)}
        except C.ErreurFreebox as e:
            return {**base, "etat": "retiree", "message": str(e)}
        manquants = [k for k in AIDE_DROITS if not droits.get(k)]
        return {**base, "etat": "autorise", "droits": droits, "droits_manquants": manquants,
                "message": "Connecté à la Freebox." + (" Certains droits manquent : voir plus bas." if manquants else "")}

    def autoriser(self):
        r = self.client.demander_autorisation(self.nom_appareil)
        self._cache.clear()
        return {**r, "message": "Demande envoyée. Validez-la sur la Freebox : appuyez sur ✓ sur son afficheur."}

    def etat_autorisation(self):
        return self.client.etat_autorisation()

    def revoquer(self):
        self.magasin.oublier()
        self.client.session = None
        self._cache.clear()
        return {"message": ("Autorisation oubliée par SecuBox. Pour la retirer aussi de la Freebox : "
                            "Paramètres → Gestion des accès → Applications.")}

    # ── lectures (cache court) ───────────────────────────────────────────────
    def _lu(self, cle, produire):
        t, v = self._cache.get(cle, (0.0, None))
        if v is not None and self.horloge() - t < self.ttl:
            return v
        v = produire()
        self._cache[cle] = (self.horloge(), v)
        return v

    def appareils(self):
        return self._lu("appareils", lambda: N.appareils(self.client.lire("lan/browser/pub/")))

    def connexion(self):
        def produire():
            conn = self.client.lire("connection/")
            try:
                cfg6 = self.client.lire("connection/ipv6/config/")
            except C.ErreurFreebox:
                cfg6 = {}
            return N.connexion(conn, cfg6)
        return self._lu("connexion", produire)

    def pare_feu(self):
        def produire():
            try:
                cfg6 = self.client.lire("connection/ipv6/config/") or {}
            except C.DroitManquant:
                raise
            actif = cfg6.get("ipv6_firewall") if "ipv6_firewall" in cfg6 else None
            exceptions, lues = [], False
            for chemin in CHEMINS_EXCEPTIONS_IPV6:
                try:
                    brut = self.client.lire(chemin)
                except C.DroitManquant:
                    raise
                except C.ErreurFreebox:
                    continue
                if isinstance(brut, list):
                    exceptions, lues = N.exceptions_ipv6(brut), True
                    break
            return {"pare_feu_actif": actif, "exceptions": exceptions, "exceptions_lues": lues}
        return self._lu("pare_feu", produire)

    # ── écriture : pare-feu IPv6 ─────────────────────────────────────────────
    def _journal_fichier(self, entree):
        ligne = json.dumps({"ts": int(self.horloge()), "module": "freebox", **entree}, ensure_ascii=False)
        for chemin in ("/var/log/secubox/audit.log", os.path.join(os.path.dirname(self.magasin.chemin), "audit.log")):
            try:
                with open(chemin, "a") as f:
                    f.write(ligne + "\n")
                return
            except OSError:
                continue

    def _regler(self, chemin, cle, actif, action):
        """Écriture d'un réglage booléen : droit « settings » exigé, relu avant ET après, journalisé, rien d'écrit si déjà dans l'état voulu."""
        if not self.client.session:
            self.client.ouvrir_session()
        if not self.client.droits.get("settings"):
            raise C.DroitManquant("Cette action demande le droit « Modification des réglages de la Freebox » : réglez-le dans "
                                  "Paramètres → Gestion des accès → Applications.")
        actif = bool(actif)
        avant = (self.client.lire(chemin) or {}).get(cle)
        if avant is actif:
            return actif, False
        self.client.ecrire("PUT", chemin, {cle: actif})
        apres = (self.client.lire(chemin) or {}).get(cle)
        self._cache.clear()
        self.journal({"action": action, "avant": avant, "apres": apres, "voulu": actif})
        if apres is not actif:
            raise C.ErreurFreebox("La Freebox n'a pas pris en compte le changement : le réglage n'a pas changé d'état.")
        return apres, True

    def regler_pare_feu_ipv6(self, actif):
        etat, change = self._regler("connection/ipv6/config/", "ipv6_firewall", actif, "pare_feu_ipv6")
        return {"pare_feu_actif": etat, "change": change}

    def upnp(self):
        def produire():
            cfg = self.client.lire("upnpigd/config/")
            try:
                red = self.client.lire("upnpigd/redir/")
            except C.ErreurFreebox:
                red = None
            return N.upnp(cfg, red)
        return self._lu("upnp", produire)

    def regler_upnp(self, actif):
        etat, change = self._regler("upnpigd/config/", "enabled", actif, "upnp")
        return {"actif": etat, "change": change}

    # ── autoconfiguration : état → cible recommandée, écart par écart ─────────────
    ITEMS_AUTOCONFIG = ("pare_feu_ipv6", "dns", "ip_fixe", "dmz")

    def _lire_autoconfig(self):
        fw = (self.client.lire("connection/ipv6/config/") or {}).get("ipv6_firewall")
        dns = [x for x in ((self.client.lire("dhcp/config/") or {}).get("dns") or []) if x]
        dmz = self._lire_dmz()
        return {"pare_feu_ipv6": fw, "dns": dns, "dmz": dmz}

    def _etat_ip_fixe(self, ip_box):
        """{"mac", "ip"} : l'adresse MAC de la box (celle que la Freebox lui connaît pour cette adresse IPv4) et l'IP de son bail statique ("" si aucun)."""
        mac = ""
        for h in self.client.lire("lan/browser/pub/") or []:
            if any(x.get("addr") == ip_box and x.get("af", "ipv4") == "ipv4" for x in h.get("l3connectivities") or []):
                mac = ((h.get("l2ident") or {}).get("id") or "").upper()
                break
        ip = ""
        for b in self.client.lire("dhcp/static_lease/") or []:
            if mac and (b.get("mac") or "").upper() == mac:
                ip = b.get("ip") or ""
        return {"mac": mac, "ip": ip}

    def _lire_dmz(self):
        d = self.client.lire("fw/dmz/") or {}
        return {"enabled": bool(d.get("enabled")), "ip": d.get("ip") or ""}

    def autoconfig(self, ip_box):
        """Ce que SecuBox recommande pour la Freebox, comparé à l'état réel. Lecture seule. La DMZ est marquée sensible : elle expose TOUTE la
        machine visée à Internet, elle ne s'applique jamais avec le reste."""
        cur = self._lire_autoconfig()
        fixe = self._etat_ip_fixe(ip_box)
        items = [
            {"id": "pare_feu_ipv6", "titre": "Pare-feu IPv6", "actuel": cur["pare_feu_ipv6"], "cible": True, "sensible": False,
             "pourquoi": "Bloque les connexions entrantes IPv6 vers les appareils du réseau."},
            {"id": "dns", "titre": "DNS distribué par la Freebox (DHCP)", "actuel": cur["dns"], "cible": [ip_box], "sensible": False,
             "pourquoi": "Les appareils du réseau interrogent la box (filtrage, journal) au lieu d'un résolveur extérieur."},
            {"id": "ip_fixe", "titre": "Adresse IP fixe de la box (bail DHCP statique)", "actuel": fixe, "cible": {"mac": fixe["mac"], "ip": ip_box}, "sensible": False,
             "pourquoi": "La Freebox réserve toujours cette adresse à la box : DNS, DMZ et redirections continuent de la viser après un redémarrage."},
            {"id": "dmz", "titre": "DMZ", "actuel": cur["dmz"], "cible": {"enabled": True, "ip": ip_box}, "sensible": True,
             "pourquoi": "Envoie à la box tout le trafic IPv4 entrant qui n'a pas de redirection. Nécessaire si la box publie des services ; expose toute la machine."},
        ]
        for i in items:
            i["conforme"] = i["actuel"] == i["cible"]
        return {"items": items, "ecarts": sum(1 for i in items if not i["conforme"]), "ip_box": ip_box}

    def appliquer_autoconfig(self, ids, ip_box, confirme_dmz=False):
        """Applique les éléments demandés (pas plus), relit avant ET après, journalise. La DMZ exige `confirme_dmz`."""
        ids = list(dict.fromkeys(ids or []))
        if not ids or any(i not in self.ITEMS_AUTOCONFIG for i in ids):
            raise ValueError("éléments inconnus ou absents")
        if "dmz" in ids and not confirme_dmz:
            raise ValueError("la DMZ demande une confirmation dédiée")
        if not self.client.session:
            self.client.ouvrir_session()
        if not self.client.droits.get("settings"):
            raise C.DroitManquant("Cette action demande le droit « Modification des réglages de la Freebox » : réglez-le dans "
                                  "Paramètres → Gestion des accès → Applications.")
        appliques = []
        for ident in ids:
            chemin, corps, lire, voulu = {
                "pare_feu_ipv6": ("connection/ipv6/config/", {"ipv6_firewall": True}, lambda: (self.client.lire("connection/ipv6/config/") or {}).get("ipv6_firewall"), True),
                "dns": ("dhcp/config/", {"dns": [ip_box, "", "", "", "", ""]},
                        lambda: [x for x in ((self.client.lire("dhcp/config/") or {}).get("dns") or []) if x], [ip_box]),
                "dmz": ("fw/dmz/", {"enabled": True, "ip": ip_box}, lambda: self._lire_dmz(), {"enabled": True, "ip": ip_box}),
            }.get(ident) or (None, None, None, None)
            methode = "PUT"
            if ident == "ip_fixe":
                avant = self._etat_ip_fixe(ip_box)
                if not avant["mac"]:
                    raise C.ErreurFreebox("La Freebox ne connaît pas l'adresse MAC de la box : impossible de réserver son adresse.")
                voulu = {"mac": avant["mac"], "ip": ip_box}
                if avant == voulu:
                    continue
                chemin = "dhcp/static_lease/" + (avant["mac"] if avant["ip"] else "")
                corps = {"mac": avant["mac"], "ip": ip_box, "comment": "SecuBox"}
                methode = "PUT" if avant["ip"] else "POST"
                lire = lambda: self._etat_ip_fixe(ip_box)
            else:
                avant = lire()
                if avant == voulu:
                    continue
            self.client.ecrire(methode, chemin, corps)
            apres = lire()
            self._cache.clear()
            self.journal({"action": "autoconfig_" + ident, "avant": avant, "apres": apres, "voulu": voulu})
            if apres != voulu:
                raise C.ErreurFreebox("La Freebox n'a pas pris en compte le changement de « %s »." % ident)
            appliques.append(ident)
        return {"appliques": appliques}

    def redirections(self):
        return self._lu("redirections", lambda: N.redirections(self.client.lire("fw/redir/")))

    def explorer(self, chemin):
        """Lecture brute d'un chemin de l'API (administrateur), pour découvrir ce qu'une version de Freebox propose."""
        return self.client.lire(chemin)
