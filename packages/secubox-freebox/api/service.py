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

# Maillage distant (#3742) : la règle que SecuBox pose et reconnaît comme sienne.
COMMENTAIRE_MAILLAGE = "SecuBox maillage distant (wg-mesh)"


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

    def appareils_non_classes(self, macs_connues):
        """Suggestions de classement (#2940) : appareils vus par la Freebox dont la MAC n'est
        pas deja connue du NAC. Jamais applique seul — une liste pour decision du proprietaire."""
        hotes = self.client.lire("lan/browser/pub/") or []
        resultat = []
        for h in hotes:
            mac = (h.get("l2ident") or {}).get("id")
            if not mac:
                continue
            mac = mac.lower()
            if mac in macs_connues:
                continue
            noms = h.get("names") or []
            resultat.append({"mac": mac, "nom": noms[0].get("name", "") if noms else "", "host_type": h.get("host_type")})
        return resultat

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
            actif = N.pare_feu_ipv6(cfg6)
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
        lu = self.client.lire(chemin) or {}
        if isinstance(cle, tuple):       # plusieurs noms selon le firmware (#2930) : le premier present dans la lecture fait foi
            cle = next((k for k in cle if k in lu), cle[0])
        avant = lu.get(cle)
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
        etat, change = self._regler("connection/ipv6/config/", N.CLES_PARE_FEU_IPV6, actif, "pare_feu_ipv6")
        return {"pare_feu_actif": etat, "change": change}

    def regler_passerelle_dhcp(self, ip):
        """Bascule la passerelle DHCP (#2940) : même charpente que _regler, mais une valeur chaîne
        (pas un booléen) — on ne touche QUE la clé « gateway », jamais dns/ip_range_start/end etc.
        que lire() rend aussi."""
        if not self.client.session:
            self.client.ouvrir_session()
        if not self.client.droits.get("settings"):
            raise C.DroitManquant("Cette action demande le droit « Modification des réglages de la Freebox » : réglez-le dans "
                                  "Paramètres → Gestion des accès → Applications.")
        chemin = "dhcp/config/"
        avant = (self.client.lire(chemin) or {}).get("gateway")
        if avant == ip:
            return {"passerelle": avant, "change": False}
        self.client.ecrire("PUT", chemin, {"gateway": ip})
        apres = (self.client.lire(chemin) or {}).get("gateway")
        self._cache.clear()
        self.journal({"action": "passerelle_dhcp", "avant": avant, "apres": apres, "voulu": ip})
        if apres != ip:
            raise C.ErreurFreebox("La Freebox n'a pas pris en compte le changement de passerelle DHCP.")
        return {"passerelle": apres, "change": True}

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
    ITEMS_AUTOCONFIG = ("pare_feu_ipv6", "dns", "ip_fixe", "dmz", "maillage_distant")

    def _lire_autoconfig(self):
        fw = N.pare_feu_ipv6(self.client.lire("connection/ipv6/config/") or {})
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

    def autoconfig(self, ip_box, maillage=None):
        """Ce que SecuBox recommande pour la Freebox, comparé à l'état réel. Lecture seule. La DMZ est marquée sensible : elle expose TOUTE la
        machine visée à Internet, elle ne s'applique jamais avec le reste."""
        cur = self._lire_autoconfig()
        fixe = self._etat_ip_fixe(ip_box)
        items = [
            {"id": "pare_feu_ipv6", "titre": "Pare-feu IPv6", "actuel": cur["pare_feu_ipv6"], "cible": True, "sensible": False,
             "pourquoi": "Bloque les connexions entrantes IPv6 vers les appareils du réseau. La Freebox n'a qu'un interrupteur global, pas de règle par port : pour publier un site de la box en IPv6 il faut le désactiver, et TOUTES les machines du réseau deviennent alors joignables en IPv6 (seul leur propre pare-feu les protège)."},
            {"id": "dns", "titre": "DNS distribué par la Freebox (DHCP)", "actuel": cur["dns"], "cible": [ip_box], "sensible": False,
             "pourquoi": "Les appareils du réseau interrogent la box (filtrage, journal) au lieu d'un résolveur extérieur."},
            {"id": "ip_fixe", "titre": "Adresse IP fixe de la box (bail DHCP statique)", "actuel": fixe, "cible": {"mac": fixe["mac"], "ip": ip_box}, "sensible": False,
             "pourquoi": "La Freebox réserve toujours cette adresse à la box : DNS, DMZ et redirections continuent de la viser après un redémarrage."},
            {"id": "dmz", "titre": "DMZ", "actuel": cur["dmz"], "cible": {"enabled": True, "ip": ip_box}, "sensible": True,
             "pourquoi": "Envoie à la box tout le trafic IPv4 entrant qui n'a pas de redirection. Nécessaire si la box publie des services ; expose toute la machine."},
        ]
        if maillage:          # seulement sur un rendez-vous qui déclare une annonce publique (p2p.toml)
            m = self.etat_maillage_distant(ip_box, maillage.get("ipv6", ""), maillage["port"], maillage.get("port_local"))
            items.append({"id": "maillage_distant", "titre": "Maillage distant (UDP %d)" % maillage["port"], "sensible": False,
                          "actuel": {"redirection": m["redirection"]["conforme"], "exception_ipv6": m["ipv6"]["etat"],
                                     "etat_redirection": m["redirection"]["etat"]},
                          "cible": {"redirection": True, "exception_ipv6": m["ipv6"]["cible"],
                                    "etat_redirection": m["redirection"]["etat"] if m["redirection"]["conforme"] else "conforme"},
                          "pourquoi": "Les nœuds du maillage placés hors du réseau local (autre maison) joignent la box par Internet : redirection "
                                      "IPv4 UDP vers la box et, si la Freebox le permet, exception IPv6 ciblée vers son IPv6 fixe. "
                                      "Le pare-feu IPv6 global n'est jamais désactivé pour cela." + (" " + m["ipv6"]["message"] if m["ipv6"]["message"] else "")})
        for i in items:
            i["conforme"] = i["actuel"] == i["cible"]
        return {"items": items, "ecarts": sum(1 for i in items if not i["conforme"]), "ip_box": ip_box}

    def lire_dns(self):
        """Réponse anormale = erreur, jamais « aucun DNS » : la clé relève ici ce qu'elle rendra."""
        dns = (self.client.lire("dhcp/config/") or {}).get("dns")
        if not isinstance(dns, list):
            raise C.ErreurFreebox("Réponse DHCP inattendue de la Freebox.")
        return [x for x in dns if x]

    def lire_dns6(self):
        c = self.client.lire("dhcpv6/config/") or {}
        if not isinstance(c.get("dns"), list):
            raise C.ErreurFreebox("Réponse DHCPv6 inattendue de la Freebox.")
        return {"use_custom_dns": bool(c.get("use_custom_dns")), "dns": [x for x in c["dns"] if x]}

    def regler_dns6(self, personnalise, serveurs):
        """DNS IPv6 annoncé (#3467) : sans lui, les appareils en double pile contournent le blocage."""
        if not self.client.session:
            self.client.ouvrir_session()
        if not self.client.droits.get("settings"):
            raise C.DroitManquant("Cette action demande le droit « Modification des réglages de la Freebox ».")
        avant = self.lire_dns6()
        self.client.ecrire("PUT", "dhcpv6/config/", {"use_custom_dns": bool(personnalise), "dns": list(serveurs)})
        apres = self.lire_dns6()
        self._cache.clear()
        self.journal({"action": "dns6", "avant": avant, "apres": apres})
        if apres["dns"] != list(serveurs) or apres["use_custom_dns"] != bool(personnalise):
            raise C.ErreurFreebox("La Freebox n'a pas pris en compte le changement de DNS IPv6.")
        return apres

    def regler_dns(self, serveurs):
        """DNS distribué par le DHCP (#3467) : uniquement la clé « dns ». Liste vide = la Freebox se donne elle-même."""
        if not self.client.session:
            self.client.ouvrir_session()
        if not self.client.droits.get("settings"):
            raise C.DroitManquant("Cette action demande le droit « Modification des réglages de la Freebox ».")
        avant = self.lire_dns()
        self.client.ecrire("PUT", "dhcp/config/", {"dns": (list(serveurs) + [""] * 6)[:6]})
        apres = self.lire_dns()
        self._cache.clear()
        self.journal({"action": "dns_dhcp", "avant": avant, "apres": apres, "voulu": list(serveurs)})
        if apres != list(serveurs):
            raise C.ErreurFreebox("La Freebox n'a pas pris en compte le changement de DNS.")
        return {"dns": apres}

    def poser_bail(self, mac, ip):
        """Restaure le bail d'origine de cette MAC (#3467), sans chercher l'hôte par son adresse."""
        if not self.client.session:
            self.client.ouvrir_session()
        self.client.ecrire("PUT", "dhcp/static_lease/" + mac, {"mac": mac, "ip": ip})
        self._cache.clear()
        self.journal({"action": "bail_restaure", "mac": mac, "ip": ip})
        return {"mac": mac, "ip": ip}

    def retirer_ip_fixe(self, mac):
        """Retire le bail statique posé pour cette MAC (#3467)."""
        if not self.client.session:
            self.client.ouvrir_session()
        self.client.ecrire("DELETE", "dhcp/static_lease/" + mac)
        self._cache.clear()
        self.journal({"action": "ip_fixe_retiree", "mac": mac})
        return {"retire": mac}

    def appliquer_autoconfig(self, ids, ip_box, confirme_dmz=False, maillage=None):
        """Applique les éléments demandés (pas plus), relit avant ET après, journalise. La DMZ exige `confirme_dmz`."""
        ids = list(dict.fromkeys(ids or []))
        if not ids or any(i not in self.ITEMS_AUTOCONFIG for i in ids):
            raise ValueError("éléments inconnus ou absents")
        if "maillage_distant" in ids and not maillage:
            raise ValueError("aucune annonce publique du maillage (p2p.toml : public_endpoint)")
        if "dmz" in ids and not confirme_dmz:
            raise ValueError("la DMZ demande une confirmation dédiée")
        if not self.client.session:
            self.client.ouvrir_session()
        if not self.client.droits.get("settings"):
            raise C.DroitManquant("Cette action demande le droit « Modification des réglages de la Freebox » : réglez-le dans "
                                  "Paramètres → Gestion des accès → Applications.")
        appliques = []
        cle6 = [N.CLES_PARE_FEU_IPV6[0]]      # nom du reglage IPv6 selon le firmware, fixe par la lecture (#2930)

        def lire6():
            cfg = self.client.lire("connection/ipv6/config/") or {}
            cle6[0] = N.cle_pare_feu_ipv6(cfg)
            return N.pare_feu_ipv6(cfg)
        for ident in ids:
            if ident == "maillage_distant":
                r = self.appliquer_maillage_distant(ip_box, maillage.get("ipv6", ""), maillage["port"], maillage.get("port_local"))
                if r["change"]:
                    appliques.append(ident)
                continue
            chemin, corps, lire, voulu = {
                "pare_feu_ipv6": ("connection/ipv6/config/", None, lire6, True),
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
                if ident == "pare_feu_ipv6":
                    corps = {cle6[0]: True}
            self.client.ecrire(methode, chemin, corps)
            apres = lire()
            self._cache.clear()
            self.journal({"action": "autoconfig_" + ident, "avant": avant, "apres": apres, "voulu": voulu})
            if apres != voulu:
                raise C.ErreurFreebox("La Freebox n'a pas pris en compte le changement de « %s »." % ident)
            appliques.append(ident)
        return {"appliques": appliques}

    # ── maillage distant (#3742) : redirection IPv4 + exception IPv6 ciblée ─────────
    # Seule la règle portant COMMENTAIRE_MAILLAGE est à SecuBox : c'est la seule jamais réécrite. Une autre règle qui prend déjà le
    # port vers un autre appareil (plage, tcp_udp compris) n'est jamais touchée : refus « port_pris », journalisé.
    @staticmethod
    def redir_voulue(ip_box, port, port_local=None):
        return {"enabled": True, "comment": COMMENTAIRE_MAILLAGE, "lan_port": int(port_local or port), "wan_port_start": int(port),
                "wan_port_end": int(port), "lan_ip": ip_box, "ip_proto": "udp", "src_ip": "0.0.0.0"}

    @staticmethod
    def _redir_conforme(r, voulu, commentaire=True):
        vu = dict(r)
        vu.setdefault("wan_port_end", vu.get("wan_port_start"))
        if vu.get("src_ip") in (None, ""):
            vu["src_ip"] = "0.0.0.0"
        return all(vu.get(k) == v for k, v in voulu.items() if commentaire or k != "comment")

    @staticmethod
    def _couvre(r, port, cle_debut="wan_port_start", cle_fin="wan_port_end"):
        try:
            debut = int(r.get(cle_debut))
            fin = int(r.get(cle_fin) or debut)
        except (TypeError, ValueError):
            return False
        return debut <= port <= fin

    @staticmethod
    def _par_id(liste):
        def cle(r):
            try:
                return int(r.get("id"))
            except (TypeError, ValueError):
                return 1 << 30
        return sorted(liste, key=cle)

    def _analyse_redir(self, regles, dmz, ip_box, port, port_local=None):
        """Verdict sur la redirection : couvert_par_dmz | conforme | port_pris | a_corriger | absente, la règle SecuBox retenue,
        les doublons SecuBox (signalés, jamais supprimés) et l'occupant éventuel."""
        voulu = self.redir_voulue(ip_box, port, port_local)
        regles = [r for r in regles or [] if isinstance(r, dict)]
        a_nous = self._par_id([r for r in regles if r.get("comment") == COMMENTAIRE_MAILLAGE])
        autres = [r for r in regles if r.get("comment") != COMMENTAIRE_MAILLAGE and r.get("enabled", True)
                  and (r.get("ip_proto") or "tcp") in ("udp", "tcp_udp") and self._couvre(r, port)]
        base = {"voulue": voulu, "regle": a_nous[0] if a_nous else None, "doublons": [r.get("id") for r in a_nous[1:]],
                "occupant": None, "actuelles": N.redirections(a_nous + autres)}
        if dmz.get("enabled") and dmz.get("ip") == ip_box:
            return {**base, "etat": "couvert_par_dmz", "conforme": True}
        if any(self._redir_conforme(r, voulu, commentaire=False) for r in autres):
            return {**base, "etat": "conforme", "conforme": True}
        if autres:
            return {**base, "etat": "port_pris", "conforme": False, "occupant": autres[0].get("lan_ip") or "",
                    "occupant_id": autres[0].get("id")}
        if not a_nous:
            return {**base, "etat": "absente", "conforme": False}
        ok = self._redir_conforme(a_nous[0], voulu)
        return {**base, "etat": "conforme" if ok else "a_corriger", "conforme": ok}

    def _lire_redir(self, ip_box, port, port_local=None):
        return self._analyse_redir(self.client.lire("fw/redir/") or [], self._lire_dmz(), ip_box, port, port_local)

    def _exceptions6(self):
        """(chemin, liste) de la première voie d'exceptions IPv6 que la Freebox expose, sinon (None, None). Sur la Freebox de gk2
        les trois chemins sont refusés : aucune exception ciblée n'existe, rien n'est alors écrit côté IPv6."""
        for chemin in CHEMINS_EXCEPTIONS_IPV6:
            try:
                brut = self.client.lire(chemin)
            except C.DroitManquant:
                raise
            except C.ErreurFreebox:
                continue
            if isinstance(brut, list):
                return chemin, brut
        return None, None

    @staticmethod
    def _style6(liste):
        """Noms des champs selon le firmware : les entrées existantes font foi (style des redirections IPv4 ou style « pinhole »)."""
        if any("lan_ip" in e or "wan_port_start" in e for e in liste):
            return "ip_proto", "lan_ip", "wan_port_start", "wan_port_end"
        return "ip_proto", "ip", "port_start", "port_end"

    def _exception6_voulue(self, liste, ipv6, port):
        proto, cle_ip, debut, fin = self._style6(liste)
        return {"enabled": True, "comment": COMMENTAIRE_MAILLAGE, proto: "udp", cle_ip: ipv6, debut: int(port), fin: int(port)}

    def _analyse6(self, liste, ipv6, port):
        """(etat, règle SecuBox retenue, doublons). Conformité jugée sur la seule règle SecuBox (ou une règle tierce identique)."""
        liste = [e for e in liste if isinstance(e, dict)]
        voulue = self._exception6_voulue(liste, ipv6, port)
        a_nous = self._par_id([e for e in liste if e.get("comment") == COMMENTAIRE_MAILLAGE])
        tierce = any(all(e.get(k) == v for k, v in voulue.items() if k != "comment") for e in liste if e not in a_nous)
        retenue = a_nous[0] if a_nous else None
        if retenue is not None and all(retenue.get(k) == v for k, v in voulue.items()) or tierce:
            etat = "conforme"
        else:
            etat = "a_corriger" if retenue is not None else "absente"
        return etat, retenue, [e.get("id") for e in a_nous[1:]], voulue

    def etat_maillage_distant(self, ip_box, ipv6, port, port_local=None):
        """Lecture seule : la redirection IPv4 et l'exception IPv6 sont-elles en place ?"""
        redir = self._lire_redir(ip_box, port, port_local)
        if not ipv6:
            v6 = {"etat": "sans_ipv6", "cible": "sans_ipv6", "chemin": None,
                  "message": "Aucune IPv6 fixe connue pour la box : seule l'IPv4 est traitée."}
        else:
            chemin6, liste6 = self._exceptions6()
            if chemin6 is None:
                fw = N.pare_feu_ipv6(self.client.lire("connection/ipv6/config/") or {})
                v6 = {"etat": "indisponible", "cible": "indisponible", "chemin": None, "pare_feu_actif": fw,
                      "message": ("Cette Freebox n'expose pas d'exception IPv6 par port : le pare-feu IPv6 global n'est PAS désactivé "
                                  "d'office. Les nœuds distants passent par l'IPv4." if fw else
                                  "Le pare-feu IPv6 de la Freebox est déjà désactivé : l'IPv6 fixe de la box est joignable sans exception.")}
            else:
                etat, retenue, doublons, voulue = self._analyse6(liste6, ipv6, port)
                v6 = {"etat": etat, "cible": "conforme", "chemin": chemin6, "voulue": voulue, "doublons": doublons, "message": ""}
        return {"port": int(port), "ip_box": ip_box, "ipv6_fixe": ipv6 or "", "redirection": redir, "ipv6": v6}

    def appliquer_maillage_distant(self, ip_box, ipv6, port, port_local=None):
        """Idempotent : lit d'abord, crée seulement si absente, ne corrige QUE la règle SecuBox, jamais de doublon ; relit et journalise.
        DMZ vers la box : l'IPv4 est déjà ouverte, rien n'est écrit. Port pris par un autre appareil : refus. Sans voie d'exception
        IPv6, rien n'est écrit côté IPv6 (le pare-feu global n'est jamais désactivé ici)."""
        if not ip_box:
            raise ValueError("adresse de la box inconnue")
        if not self.client.session:
            self.client.ouvrir_session()
        if not self.client.droits.get("settings"):
            raise C.DroitManquant("Cette action demande le droit « Modification des réglages de la Freebox » : réglez-le dans "
                                  "Paramètres → Gestion des accès → Applications.")
        change = False
        voulu = self.redir_voulue(ip_box, port, port_local)
        a = self._lire_redir(ip_box, port, port_local)
        if a["etat"] == "port_pris":
            self.journal({"action": "maillage_redirection", "geste": "port_pris", "occupant": a["occupant"], "port": int(port)})
            raise C.ErreurFreebox("Le port UDP %d de la Freebox est déjà redirigé vers %s : SecuBox ne réécrit pas cette règle. "
                                  "Libérez-le dans Freebox OS, puis relancez." % (int(port), a["occupant"] or "un autre appareil"))
        geste = "couvert_par_dmz" if a["etat"] == "couvert_par_dmz" else "inchangee"
        if a["etat"] == "absente":
            self.client.ecrire("POST", "fw/redir/", voulu)
            change, geste = True, "creee"
        elif a["etat"] == "a_corriger":
            self.client.ecrire("PUT", "fw/redir/%d" % int(a["regle"]["id"]), voulu)
            change, geste = True, "corrigee"
        if change:
            apres = self._lire_redir(ip_box, port, port_local)
            self._cache.clear()
            self.journal({"action": "maillage_redirection", "geste": geste, "avant": a["actuelles"], "apres": apres["actuelles"],
                          "voulu": voulu, "doublons": a["doublons"]})
            if not apres["conforme"]:
                raise C.ErreurFreebox("La Freebox n'a pas pris en compte la redirection du maillage.")
        r6 = "sans_ipv6"
        if ipv6:
            chemin6, liste6 = self._exceptions6()
            if chemin6 is None:
                r6 = "indisponible"
                self.journal({"action": "maillage_exception_ipv6", "geste": "indisponible", "ipv6": ipv6})
            else:
                etat, retenue, doublons, voulue6 = self._analyse6(liste6, ipv6, port)
                if etat == "conforme":
                    r6 = "inchangee"
                else:
                    if retenue is not None:
                        self.client.ecrire("PUT", "%s%d" % (chemin6, int(retenue["id"])), voulue6)
                        r6 = "corrigee"
                    else:
                        self.client.ecrire("POST", chemin6, voulue6)
                        r6 = "creee"
                    apres6 = self.client.lire(chemin6) or []
                    self._cache.clear()
                    self.journal({"action": "maillage_exception_ipv6", "geste": r6, "avant": retenue, "voulu": voulue6, "doublons": doublons})
                    change = True
                    if self._analyse6(apres6 if isinstance(apres6, list) else [], ipv6, port)[0] != "conforme":
                        raise C.ErreurFreebox("La Freebox n'a pas pris en compte l'exception IPv6 du maillage.")
        return {"change": change, "redirection": geste, "exception_ipv6": r6, "doublons": a["doublons"]}

    def redirections(self):
        return self._lu("redirections", lambda: N.redirections(self.client.lire("fw/redir/")))

    def explorer(self, chemin):
        """Lecture brute d'un chemin de l'API (administrateur), pour découvrir ce qu'une version de Freebox propose."""
        return self.client.lire(chemin)
