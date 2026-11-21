# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SADE ACTIVE : exécuteur automatique du cas sûr (#3839).

Lancé toutes les 2 min (`python3 -m api.sade_auto`, utilisateur `secubox`). En mode `active` seulement, il bannit
lui-même les propositions d'actord qui forment le « cas sûr » ; tout le reste demeure dans la file d'approbation
manuelle (`/defense/approve`). Même ordre et même sémantique que `defense._traiter` :

mode lu (valeur, depuis) → propositions relues (illisibles ⇒ sortie) → première vue de chaque proposition notée
(`propositions_vues`, dans TOUS les modes : c'est ce qui sépare l'arriéré du neuf) → hors `active`, sortie → protégés :
liste blanche + passerelles + pairs du maillage (liste blanche illisible ⇒ sortie ; pairs locaux `wg_mesh.json`
illisibles ⇒ sortie, absents ⇒ on continue ; threatmesh `/peers` fusionné s'il répond, non lu ⇒ on continue et l'audit
porte `pairs_maillage=non_verifies`) → filtre `cas_sur` → exclusions : décision déjà tranchée, empreinte ou ADRESSE
refusée un jour par un humain, proposition vue avant le passage en ACTIVE (arriéré : à la main) → pour chaque retenue,
dans un budget de 3 min : plafond horaire (dépassé ⇒ retour en OBSERVE, audit `sade-auto-plafond`, arrêt) →
réclamation `en_cours` (mode relu, audit `sade-auto-demande` fsync, dans UNE transaction) → `wafctl ban` par adresse,
arrêt au premier échec → conclusion → audit `sade-auto-resultat`.

Conclusion : tout banni ⇒ `applique` ; `wafctl` a rendu un VERDICT DE GARDE (`refus:privee|protegee|box|pair|invalide`,
adresse privée ou invalide) ⇒ `refuse`, ré-armable après 24 h, jamais retenté à chaque passage ; tout autre échec
(garde illisible, nft, délai, sudo, message inconnu) est temporaire ⇒ `en_attente` et arrêt du passage (nouvel essai
au passage suivant, le ban est idempotent). Un ban partiel nomme dans le résultat les adresses déjà bannies.

Limite v1 : l'adresse publique de sortie de la box et celle du poste d'administration ne sont pas détectées ; elles
doivent être en liste blanche avant de passer en ACTIVE (README, § Modes).
"""
import json
import os
import re
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from secubox_core.auth import ENTETE_LAN, mode_tableau_de_bord_actif

from . import defense, defense_etat

PLAFOND_HEURE = 20            # adresses bannies automatiquement par heure glissante, au plus
TTL_AUTO_MAX_S = 86400        # un ban automatique ne dure jamais plus de 24 h
# bande contenir seulement : la spec n'admet 80-94 qu'avec une récidive confirmée par le code (non livrée en v1) ⇒ proposé
SCORE_MIN, SCORE_MAX = 60, 79
ADRESSES_AUTO_MAX = 8         # au plus 8 adresses par proposition
OPERATEUR = "sade-auto"
DELAI_WAFCTL_S = 30           # wafctl et sudo ; au-delà, l'issue est incertaine (« delai »)
FENETRE_PLAFOND_S = 3600
BUDGET_PASSAGE_S = 180        # au-delà, aucune nouvelle proposition n'est entamée dans ce passage
WG_MESH_DEFAUT = "/var/lib/secubox/p2p/wg_mesh.json"  # surcharge : SECUBOX_SOC_WG_MESH

_horloge: Callable[[], float] = time.monotonic  # remplaçable par les tests
_sain = defense_etat.champ_sain

# Verdicts de garde de wafctl, seuls refus DÉFINITIFS (relevés dans secubox-waf-ng wafctl `_garde`/`cmd_ban` et
# waf-blocs `verifier`) : « refus:<motif> » sur stderr, ou le message de `_valide_ip` (« ERROR: Adresse privée
# refusée : … », « ERROR: Adresse invalide : … »). `refus:garde_illisible`, un refus de nft, une durée refusée ou tout
# message inconnu sont TEMPORAIRES.
_VERDICT_GARDE = re.compile(r"^refus:(invalide|privee|protegee|box|pair|lan)$")  # lan : préfixe on-link (#3723 I3)
_VERDICT_VALIDATION = re.compile(r"ERROR: Adresse (privée refusée|invalide) : ")


# ── point d'exécution unique ─────────────────────────────────────────────────────────────────────

def _sudo(argv: List[str]) -> subprocess.CompletedProcess:
    """SEUL appel de sous-processus du module (et de la file d'approbation, qui passe par ici) : `sudo -n` + argv exact
    du sudoers. Lève TimeoutExpired, OSError, SubprocessError."""
    return subprocess.run(["sudo", "-n", *argv], capture_output=True, text=True, timeout=DELAI_WAFCTL_S)


# Verbes de wafctl exécutables depuis SADE, et leurs argv (`wafctl <verbe> <ip> <n>s`) : ceux du compte ai-ban
# (gestes_ia de secubox-waf-ng), accordés à `secubox` par les sudoers SBX_WAF_BANMANUEL, _LIMITER, _LEURRE, _PROLONGER.
VERBES_WAFCTL = ("ban", "limiter", "leurre", "prolonger")


def _wafctl(verbe: str, ip: str, duree: str) -> Tuple[bool, str]:
    """SEUL point d'exécution d'un geste. Rend (succès, raison) :
    - `(True, "ok")` ;
    - `(False, "refus:<motif>")` : verdict de garde de `wafctl` (privee, protegee, box, pair, invalide) : DÉFINITIF ;
    - `(False, "echec: <message>")` : autre sortie non nulle (garde illisible, nft, durée, absent, inconnu) : transitoire ;
    - `(False, "delai")` : délai dépassé, le geste a peut-être été posé : transitoire ;
    - `(False, "injoignable: <message>")` : sudo absent ou refusé (`sudo: …`), exécutable introuvable : transitoire.
    `refus_definitif(raison)` tranche entre les deux familles."""
    if verbe not in VERBES_WAFCTL:
        raise ValueError(f"verbe wafctl non admis : {verbe}")
    try:
        r = _sudo(["/usr/sbin/wafctl", verbe, ip, duree])
    except subprocess.TimeoutExpired:
        return False, "delai"
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"injoignable: {e.__class__.__name__}"
    if r.returncode == 0:
        return True, "ok"
    message = (r.stderr or r.stdout or "").strip()
    # dépend du préfixe « sudo: » que sudo met à ses propres messages (mot de passe exigé, règle absente, introuvable)
    if message.startswith("sudo:"):
        return False, f"injoignable: {message[:200]}"
    for ligne in message.splitlines():
        m = _VERDICT_GARDE.match(ligne.strip())
        if m:
            return False, f"refus:{m.group(1)}"
        m = _VERDICT_VALIDATION.search(ligne)
        if m:
            return False, "refus:privee" if m.group(1).startswith("privée") else "refus:invalide"
    return False, f"echec: {message[:200] or f'code {r.returncode}'}"


def _wafctl_ban(ip: str, duree: str) -> Tuple[bool, str]:
    """`wafctl ban <ip> <durée>` (exécuteur automatique) ; voir `_wafctl`."""
    return _wafctl("ban", ip, duree)


class EnsembleIllisible(Exception):
    """L'ensemble nft des bans du WAF n'a pas pu être lu."""


def expiration_ban(ip: str) -> Optional[float]:
    """Secondes restantes du ban IPv4 `ip` dans `inet secubox waf_ban` (`sudo nft -j list set`, argv exact du sudoers
    SBX_WAF_NFTLIST) ; None si l'adresse n'y est pas ; `float('inf')` pour un élément sans délai. Lève
    `EnsembleIllisible`."""
    try:
        r = _sudo(["/usr/sbin/nft", "-j", "list", "set", "inet", "secubox", "waf_ban"])
        if r.returncode != 0:
            raise EnsembleIllisible((r.stderr or "")[:200])
        doc = json.loads(r.stdout)
    except (subprocess.SubprocessError, OSError, ValueError, RecursionError) as e:
        raise EnsembleIllisible(e.__class__.__name__) from e
    items = doc.get("nftables") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        raise EnsembleIllisible("forme")
    for it in items:
        ens = it.get("set") if isinstance(it, dict) else None
        if not isinstance(ens, dict):
            continue
        for el in ens.get("elem") or []:
            if el == ip:
                return float("inf")
            e = el.get("elem") if isinstance(el, dict) else None
            if isinstance(e, dict) and e.get("val") == ip:
                exp = e.get("expires", e.get("timeout"))
                return float(exp) if isinstance(exp, (int, float)) and not isinstance(exp, bool) else float("inf")
        return None
    raise EnsembleIllisible("ensemble absent")


def refus_definitif(raison: str) -> bool:
    """Vrai si l'échec de `_wafctl_ban` est un verdict de garde de `wafctl` (jamais retenté), faux s'il est
    transitoire."""
    return raison.startswith("refus:")


# ── pairs du maillage (source locale) ────────────────────────────────────────────────────────────

def _pairs_wg_mesh() -> Optional[List[Any]]:
    """Réseaux des pairs WireGuard lus dans `wg_mesh.json` (champs `mesh_ip`, `endpoint`), sans jeton ni réseau.
    Fichier absent (box sans maillage) : []. Illisible, JSON invalide ou forme inattendue (ni liste, ni objet à liste
    `peers`) : None — l'appelant ne bannit alors rien (un pair ne doit jamais être banni)."""
    chemin = os.environ.get("SECUBOX_SOC_WG_MESH", WG_MESH_DEFAUT)
    try:
        with open(chemin, encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError:
        return []
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    pairs = doc.get("peers") if isinstance(doc, dict) else doc
    if not isinstance(pairs, list):
        return None
    out = []
    for p in pairs:
        if isinstance(p, dict):
            for champ in ("mesh_ip", "endpoint"):
                n = defense._reseau(p.get(champ))
                if n is not None:
                    out.append(n)
    return out


# ── cas sûr ──────────────────────────────────────────────────────────────────────────────────────

def cas_sur(p: Dict[str, Any], proteges: List[Any]) -> Tuple[bool, str]:
    """Le cas sûr : geste `ban`, score entier dans [60, 79], 1 à 8 adresses, toutes publiques et hors réseaux protégés.
    Rend (retenue, motif) ; motif ∈ ok, geste, score, sans_adresse, trop_d_adresses, adresse_protegee."""
    if p.get("geste") != "ban":
        return False, "geste"
    s = p.get("score")
    if isinstance(s, bool) or not isinstance(s, int) or not SCORE_MIN <= s <= SCORE_MAX:
        return False, "score"
    ips = p.get("ips") or []
    if not ips:
        return False, "sans_adresse"
    if len(ips) > ADRESSES_AUTO_MAX:
        return False, "trop_d_adresses"
    if any(defense._adresse_interdite(ip, proteges) for ip in ips):
        return False, "adresse_protegee"
    return True, "ok"


# ── un passage ───────────────────────────────────────────────────────────────────────────────────

def _plafond(p: Dict[str, Any], out: Dict[str, Any]) -> bool:
    """Vrai si le lot ferait dépasser le plafond horaire : le mode repasse alors en OBSERVE (audité)."""
    n = defense_etat.bans_auto_depuis(FENETRE_PLAFOND_S)
    if n + len(p["ips"]) <= PLAFOND_HEURE:
        return False
    out["plafond"] = True
    try:
        defense_etat.ecrire_audit(f"sade-auto-plafond adresses_heure={n} lot={len(p['ips'])} plafond={PLAFOND_HEURE} "
                                  f"empreinte={p['empreinte']} operateur={OPERATEUR}")
    except defense_etat.AuditIndisponible:
        out["erreur"] = "audit_indisponible"
    try:
        # Retour forcé en OBSERVE, même si un administrateur vient de passer en REACTIVE entre-temps : le plafond ne
        # peut que rendre la défense plus stricte (OBSERVE n'autorise aucun geste), jamais l'ouvrir davantage.
        # le resserrement ne dépend jamais de l'audit : OBSERVE est validé même si audit.log n'est pas inscriptible
        if not defense_etat.changer_mode("observe", OPERATEUR):
            out["erreur"] = "audit_indisponible"
        out["mode"] = "observe"
    except defense_etat.EtatIndisponible:
        out["erreur"] = "base_indisponible"
    return True


def _bannir(p: Dict[str, Any], note: str, out: Dict[str, Any]) -> bool:
    """Réclame puis exécute une proposition retenue. Rend True si le passage doit s'arrêter."""
    duree_s = min(p["ttl_s"] or defense_etat.TTL_DEFAUT_WAF_S, TTL_AUTO_MAX_S)
    duree = f"{duree_s}s"
    champs = defense._champs(p, OPERATEUR, duree)
    try:
        # la durée enregistrée est celle réellement posée : le ré-armement suit l'expiration réelle du ban
        gen = defense_etat.reclamer(p["empreinte"], p["menace_id"], p["geste"], ",".join(p["ips"]), p["score"], duree_s,
                                    OPERATEUR, "en_cours", f"sade-auto-demande {champs}{note}", modes=("active",))
    except defense_etat.DejaTraitee:
        return False
    except defense_etat.ModeRefuse as e:
        out["mode"] = str(e)
        return True
    except defense_etat.AuditIndisponible:
        out["erreur"] = "audit_indisponible"
        return True
    except defense_etat.EtatIndisponible:
        out["erreur"] = "base_indisponible"
        return True

    bannies: List[str] = []
    echec: Optional[Tuple[str, str]] = None
    for ip in p["ips"]:
        ok, raison = _wafctl_ban(ip, duree)
        if ok:
            bannies.append(ip)
            continue
        echec = (ip, raison)
        break
    out["bannies"].extend(bannies)
    if echec is None:
        etat = issue = "applique"
        resultat = f"{len(bannies)} adresse(s) bannie(s) pour {duree} par l'exécuteur automatique"
    else:
        if refus_definitif(echec[1]):
            etat = issue = "refuse"
        else:
            etat = "en_attente"
            issue = "incertain" if echec[1] == "delai" else ("partiel" if bannies else "echec")
        resultat = f"échec de wafctl sur {echec[0]} : {echec[1]} ; déjà bannies : {', '.join(bannies) or 'aucune'}"
    arret = echec is not None and etat == "en_attente"  # sudo ou wafctl en panne : les suivantes échoueraient aussi
    conclusion = ""
    try:
        defense_etat.conclure(p["empreinte"], gen, etat, resultat, getattr(gen, "demande_ts", None))
    except defense_etat.EtatIndisponible:
        # la ligne reste `en_cours` : plus aucun geste sans reprise explicite (et elle compte dans le plafond)
        out["erreur"] = "base_indisponible"
        conclusion = "conclusion=echec "
        arret = True
    try:
        defense_etat.ecrire_audit(f"sade-auto-resultat issue={issue} generation={gen} {conclusion}"
                                  f"bannies={_sain(','.join(bannies) or 'aucune', 1024)} "
                                  + (f"echec={_sain(echec[0], 64)} erreur={_sain(echec[1], 200)} " if echec else "")
                                  + champs + note)
    except defense_etat.AuditIndisponible:
        out["erreur"] = "audit_indisponible"
        arret = True
    return arret


# ── file des gestes gradués approuvés par un administrateur (#3839, 1.12.0) ──────────────────────────

APPROUVEES_PAR_PASSAGE = 8          # approbations entamées par passage, au plus (dans le même budget de 3 min)
APPROBATION_MAX_S = 3600            # une approbation non exécutée après 1 h revient à la file humaine (jamais d'office)
# plafonds horaires (glissants) des gestes approuvés par un humain, en ADRESSES : ceux de gk2 (plan V2 4-7)
PLAFONDS_APPROUVES_HEURE = {"limiter": 60, "leurre": 30, "prolonger": 30}


def _champs_decision(d: Dict[str, Any], ips: List[str], duree: str) -> str:
    return (f"empreinte={d['empreinte']} acteur={_sain(d['menace_id'], 16)} adresses={_sain(','.join(ips), 1024)} "
            f"geste={_sain(d['geste'], 32)} duree={duree} "
            f"score={d['score'] if d['score'] is not None else 'inconnu'} "
            f"operateur={defense_etat._operateur_sain(d['par'] or 'inconnu')}")


def _controle_execution(d: Dict[str, Any], ips: List[str], secondes: Optional[int],
                        proteges: List[Any]) -> Optional[Tuple[str, str]]:
    """Recontrôle d'une approbation au moment de l'exécuter. Rend None (on exécute), ("abandon", motif) (rendue à la
    file humaine) ou ("attente", motif) (laissée `approuve`, essai au passage suivant)."""
    if d["geste"] not in defense.DUREES_GRADUEES:
        return "abandon", "geste_non_admis"
    _defaut, bas, haut = defense.DUREES_GRADUEES[d["geste"]]
    if not ips or len(ips) > defense.ADRESSES_MAX:
        return "abandon", "adresses"
    if secondes is None or not bas <= secondes <= haut:
        return "abandon", "duree_invalide"
    if d["geste"] == "prolonger" and any(":" in ip for ip in ips):
        return "abandon", "ipv4_seulement"
    if any(defense._adresse_interdite(ip, proteges) for ip in ips):
        return "abandon", "cible_protegee"
    if d["geste"] == "prolonger":
        try:
            restes = [expiration_ban(ip) for ip in ips]
        except EnsembleIllisible:
            return "attente", "waf_illisible"
        if any(r is None for r in restes):
            return "abandon", "absent"
        if any(r > secondes for r in restes):
            return "abandon", "raccourcit"
    return None


def _executer_approuvees(out: Dict[str, Any], t0: float) -> bool:
    """Exécute les gestes gradués approuvés (`approuve`), en REACTIVE comme en ACTIVE. `par` reste l'administrateur
    (jamais 'sade-auto' : ni le plafond de 20/h ni le retour en OBSERVE de l'automatique). Rend True si le passage doit
    s'arrêter (base, audit, sudo en panne)."""
    try:
        file = defense_etat.approuvees()
    except defense_etat.EtatIndisponible:
        out["erreur"] = "base_indisponible"
        return True
    if not file:
        return False
    entetes = {ENTETE_LAN: "1"} if mode_tableau_de_bord_actif() else {}
    try:
        proteges, illisibles, pairs_lus = defense._proteges(entetes, [])
    except defense_etat.EtatIndisponible:
        out["erreur"] = "base_indisponible"
        return True
    if illisibles:
        out["erreur"] = "liste_blanche_illisible"
        return True
    locaux = _pairs_wg_mesh()
    if locaux is None:
        out["erreur"] = "pairs_illisibles"
        return True
    proteges = proteges + locaux
    note = f" pairs_maillage={'verifies' if pairs_lus else 'non_verifies'} file=approuvee"
    maintenant = time.time()
    for n, d in enumerate(file):
        if n >= APPROUVEES_PAR_PASSAGE or _horloge() - t0 >= BUDGET_PASSAGE_S:
            out["budget"] = True
            break
        ips = [a for a in (d["cible"] or "").split(",") if a]
        secondes = d["ttl_s"] if isinstance(d["ttl_s"], int) and not isinstance(d["ttl_s"], bool) else None
        duree = f"{secondes}s" if secondes else "inconnue"
        champs = _champs_decision(d, ips, duree)
        demande = defense_etat._epoch(d["demande_ts"])
        verdict = (("abandon", "expiree") if demande is None or maintenant - demande > APPROBATION_MAX_S
                   else _controle_execution(d, ips, secondes, proteges))
        if verdict is not None:
            if verdict[0] == "attente":
                out["approuvees_en_attente"] += 1
                continue
            try:
                defense_etat.abandonner_approuvee(d["empreinte"], d["generation"], d["demande_ts"],
                                                  f"approbation non exécutée : {verdict[1]}",
                                                  f"sade-approuve-abandon motif={verdict[1]} {champs}{note}")
            except defense_etat.DejaTraitee:
                pass
            except defense_etat.AuditIndisponible:
                out["erreur"] = "audit_indisponible"
                return True
            except defense_etat.EtatIndisponible:
                out["erreur"] = "base_indisponible"
                return True
            out["approuvees_abandonnees"] += 1
            continue
        try:
            deja = defense_etat.gestes_humains_depuis(d["geste"], FENETRE_PLAFOND_S)
        except defense_etat.EtatIndisponible:
            out["erreur"] = "base_indisponible"
            return True
        plafond = PLAFONDS_APPROUVES_HEURE[d["geste"]]
        if len(ips) > plafond:
            # plus grande que le plafond lui-même : n'aboutirait jamais, rendue tout de suite (visible, auditée)
            try:
                defense_etat.abandonner_approuvee(d["empreinte"], d["generation"], d["demande_ts"],
                                                  f"approbation non exécutée : plafond ({len(ips)} adresses, "
                                                  f"{plafond} par heure au plus)",
                                                  f"sade-approuve-abandon motif=plafond {champs}{note}")
            except defense_etat.DejaTraitee:
                pass
            except defense_etat.AuditIndisponible:
                out["erreur"] = "audit_indisponible"
                return True
            except defense_etat.EtatIndisponible:
                out["erreur"] = "base_indisponible"
                return True
            out["approuvees_abandonnees"] += 1
            continue
        if deja + len(ips) > plafond:
            out["approuvees_en_attente"] += 1  # plafond horaire : essai au passage suivant (expire après 1 h)
            continue
        try:
            gen = defense_etat.prendre_approuvee(d["empreinte"], d["generation"], d["demande_ts"],
                                                 f"sade-approuve-execution {champs}{note}")
        except defense_etat.DejaTraitee:
            continue  # un autre passage l'a prise : jamais deux fois
        except defense_etat.ModeRefuse as e:
            out["mode"] = str(e)
            return True
        except defense_etat.AuditIndisponible:
            out["erreur"] = "audit_indisponible"
            return True
        except defense_etat.EtatIndisponible:
            out["erreur"] = "base_indisponible"
            return True
        faites: List[str] = []
        echec: Optional[Tuple[str, str]] = None
        for ip in ips:
            ok, raison = _wafctl(d["geste"], ip, duree)
            if ok:
                faites.append(ip)
                continue
            echec = (ip, raison)
            break
        out["approuvees_executees"].extend(faites)
        if echec is None:
            etat = issue = "applique"
            resultat = f"{len(faites)} adresse(s) traitée(s) ({d['geste']}, {duree}) par sade-auto"
        else:
            etat = "en_attente"  # rendue à l'administrateur, jamais retentée seule
            issue = "incertain" if echec[1] == "delai" else ("partiel" if faites else "echec")
            resultat = f"échec de wafctl sur {echec[0]} : {echec[1]} ; déjà traitées : {', '.join(faites) or 'aucune'}"
        arret = echec is not None and not refus_definitif(echec[1])
        try:
            defense_etat.conclure(d["empreinte"], gen, etat, resultat, getattr(gen, "demande_ts", None))
        except defense_etat.EtatIndisponible:
            out["erreur"] = "base_indisponible"
            arret = True
        try:
            defense_etat.ecrire_audit(f"sade-approuve-resultat issue={issue} generation={gen} "
                                      f"traitees={_sain(','.join(faites) or 'aucune', 1024)} "
                                      + (f"echec={_sain(echec[0], 64)} erreur={_sain(echec[1], 200)} " if echec else "")
                                      + champs + note)
        except defense_etat.AuditIndisponible:
            out["erreur"] = "audit_indisponible"
            arret = True
        if arret:
            return True
    return False


def executer() -> Dict[str, Any]:
    """Un passage. Ne lève jamais pour une condition attendue : l'issue est dans `erreur`."""
    out: Dict[str, Any] = {"mode": None, "bannies": [], "ecartees": 0, "arriere": 0, "plafond": False, "budget": False,
                           "erreur": None, "approuvees_executees": [], "approuvees_abandonnees": 0,
                           "approuvees_en_attente": 0}
    t0 = _horloge()
    try:
        out["mode"], depuis, _par = defense_etat.mode_detail()
    except defense_etat.EtatIndisponible:
        out["erreur"] = "base_indisponible"
        return out
    # Gestes approuvés par un administrateur d'abord, en REACTIVE comme en ACTIVE (sans actord : la décision suffit)
    if out["mode"] in ("reactive", "active") and _executer_approuvees(out, t0):
        return out
    r = defense._lire_propositions()
    if not r.get("ok"):
        if out["mode"] == "active":
            out["erreur"] = "actord_indisponible"
        return out
    try:
        propositions = defense._propositions(r)
        # première vue, dans TOUS les modes : une proposition déjà là avant le passage en ACTIVE reste à la main
        vues = defense_etat.noter_propositions_vues([p["empreinte"] for p in propositions])
    except defense_etat.EtatIndisponible:
        if out["mode"] == "active":
            out["erreur"] = "base_indisponible"
        return out
    if out["mode"] != "active":
        return out
    entetes = {ENTETE_LAN: "1"} if mode_tableau_de_bord_actif() else {}
    try:
        proteges, illisibles, pairs_lus = defense._proteges(entetes, [])
        etats = defense_etat.etats_decisions()
        refusees = {defense._normaliser(a) for a in defense_etat.adresses_refusees_par_humain()}
    except defense_etat.EtatIndisponible:
        out["erreur"] = "base_indisponible"
        return out
    if illisibles:
        out["erreur"] = "liste_blanche_illisible"  # échec fermé, comme l'approbation manuelle
        return out
    pairs_locaux = _pairs_wg_mesh()
    if pairs_locaux is None:
        out["erreur"] = "pairs_illisibles"  # un pair ne doit jamais être banni : on ne sait pas qui l'est
        return out
    proteges = proteges + pairs_locaux
    note = f" pairs_maillage={'verifies' if pairs_lus else 'non_verifies'}"
    retenues = []
    try:
        for p in propositions:
            if not cas_sur(p, proteges)[0]:
                out["ecartees"] += 1
            elif etats.get(p["empreinte"], "en_attente") != "en_attente":
                continue  # déjà tranchée : ni plafond ni réclamation
            elif defense_etat.refuse_par_humain(p["empreinte"]) or any(defense._normaliser(a) in refusees
                                                                        for a in p["ips"]):
                continue  # un « non » humain (empreinte ou adresse) lie l'automate ; reste approuvable à la main
            elif depuis is None or vues.get(p["empreinte"], "") < depuis:
                out["arriere"] += 1  # vue avant le passage en ACTIVE (ou date inconnue) : arriéré, à la main
            else:
                retenues.append(p)
    except defense_etat.EtatIndisponible:
        out["erreur"] = "base_indisponible"
        return out
    for p in retenues:
        if _horloge() - t0 >= BUDGET_PASSAGE_S:
            out["budget"] = True  # le reste attend le passage suivant (2 min), jamais un passage sans fin
            break
        try:
            if _plafond(p, out):
                break
        except defense_etat.EtatIndisponible:
            out["erreur"] = "base_indisponible"
            break
        if _bannir(p, note, out):
            break
    return out


def main() -> int:
    r = executer()
    print(f"sade-auto mode={r['mode']} bannies={len(r['bannies'])} ecartees={r['ecartees']} arriere={r['arriere']} "
          f"approuvees={len(r['approuvees_executees'])}/{r['approuvees_abandonnees']}/{r['approuvees_en_attente']} "
          f"plafond={'oui' if r['plafond'] else 'non'} budget={'depasse' if r['budget'] else 'ok'} "
          f"erreur={r['erreur'] or 'aucune'}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
