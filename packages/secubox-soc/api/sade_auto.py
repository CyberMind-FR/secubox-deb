# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SADE ACTIVE : exécuteur automatique du cas sûr (#3839).

Lancé toutes les 2 min (`python3 -m api.sade_auto`, utilisateur `secubox`). En mode `active` seulement, il bannit
lui-même les propositions d'actord qui forment le « cas sûr » ; tout le reste demeure dans la file d'approbation
manuelle (`/defense/approve`). Même ordre et même sémantique que `defense._traiter` :

mode (`active`, sinon sortie) → propositions relues (illisibles ⇒ sortie) → protégés : liste blanche + passerelles +
pairs du maillage (illisibles ⇒ sortie ; pairs non lus ⇒ on continue, `wafctl` garde lui-même les pairs WireGuard en
root, et l'audit porte `pairs_maillage=non_verifies`) → filtre `cas_sur` → pour chaque retenue encore en attente :
plafond horaire (dépassé ⇒ retour en OBSERVE, audit `sade-auto-plafond`, arrêt) → réclamation `en_cours` (mode relu,
audit `sade-auto-demande` fsync, dans UNE transaction) → `wafctl ban` par adresse, arrêt au premier échec →
conclusion → audit `sade-auto-resultat`. Une empreinte refusée un jour par un humain (toute génération) n'est jamais
traitée ici, même ré-armée : elle reste approuvable à la main.

Conclusion : tout banni ⇒ `applique` ; `wafctl` a REFUSÉ une adresse (code de sortie non nul) ⇒ `refuse`, ré-armable
après 24 h, jamais retenté à chaque passage ; délai dépassé ou sudo injoignable ⇒ `en_attente` (nouvel essai au
passage suivant, le ban est idempotent). Un ban partiel nomme dans le résultat les adresses déjà bannies.
"""
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

from secubox_core.auth import ENTETE_LAN, mode_tableau_de_bord_actif

from . import defense, defense_etat

PLAFOND_HEURE = 20            # adresses bannies automatiquement par heure glissante, au plus
TTL_AUTO_MAX_S = 86400        # un ban automatique ne dure jamais plus de 24 h
SCORE_MIN, SCORE_MAX = 60, 94  # bandes contenir et usager ; 95 et plus (incident) exige un humain
ADRESSES_AUTO_MAX = 8         # au plus 8 adresses par proposition
OPERATEUR = "sade-auto"
DELAI_WAFCTL_S = 30           # wafctl et sudo ; au-delà, l'issue est incertaine (« delai »)
FENETRE_PLAFOND_S = 3600

_sain = defense_etat.champ_sain


# ── point d'exécution unique ─────────────────────────────────────────────────────────────────────

def _wafctl_ban(ip: str, duree: str) -> Tuple[bool, str]:
    """SEUL point d'exécution d'un geste. Rend (succès, raison) :
    - `(True, "ok")` ;
    - `(False, "refus: <message>")` : `wafctl` a refusé l'adresse (code non nul) : échec DÉFINITIF ;
    - `(False, "delai")` : délai dépassé, le ban a peut-être été posé : échec transitoire ;
    - `(False, "injoignable: <message>")` : sudo absent ou refusé (`sudo: …`), exécutable introuvable : transitoire.
    `refus_definitif(raison)` tranche entre les deux familles."""
    try:
        r = subprocess.run(["sudo", "-n", "/usr/sbin/wafctl", "ban", ip, duree],
                           capture_output=True, text=True, timeout=DELAI_WAFCTL_S)
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
    return False, f"refus: {message[:200] or f'code {r.returncode}'}"


def refus_definitif(raison: str) -> bool:
    """Vrai si l'échec de `_wafctl_ban` est un refus de `wafctl` (jamais retenté), faux s'il est transitoire."""
    return raison.startswith("refus:")


# ── cas sûr ──────────────────────────────────────────────────────────────────────────────────────

def cas_sur(p: Dict[str, Any], proteges: List[Any]) -> Tuple[bool, str]:
    """Le cas sûr : geste `ban`, score entier dans [60, 94], 1 à 8 adresses, toutes publiques et hors réseaux protégés.
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
        defense_etat.changer_mode("observe", OPERATEUR)
        out["mode"] = "observe"
    except defense_etat.AuditIndisponible:
        out["erreur"] = "audit_indisponible"  # le mode reste ACTIVE : le plafond rejoue au prochain passage
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
    try:
        defense_etat.conclure(p["empreinte"], gen, etat, resultat, getattr(gen, "demande_ts", None))
    except defense_etat.EtatIndisponible:
        # la ligne reste `en_cours` : plus aucun geste sans reprise explicite (et elle compte dans le plafond)
        out["erreur"] = "base_indisponible"
        arret = True
    try:
        defense_etat.ecrire_audit(f"sade-auto-resultat issue={issue} generation={gen} "
                                  f"bannies={_sain(','.join(bannies) or 'aucune', 1024)} "
                                  + (f"echec={_sain(echec[0], 64)} erreur={_sain(echec[1], 200)} " if echec else "")
                                  + champs + note)
    except defense_etat.AuditIndisponible:
        out["erreur"] = "audit_indisponible"
        arret = True
    return arret


def executer() -> Dict[str, Any]:
    """Un passage. Ne lève jamais pour une condition attendue : l'issue est dans `erreur`."""
    out: Dict[str, Any] = {"mode": None, "bannies": [], "ecartees": 0, "plafond": False, "erreur": None}
    try:
        out["mode"] = defense_etat.mode_courant()
    except defense_etat.EtatIndisponible:
        out["erreur"] = "base_indisponible"
        return out
    if out["mode"] != "active":
        return out
    r = defense._lire_propositions()
    if not r.get("ok"):
        out["erreur"] = "actord_indisponible"
        return out
    entetes = {ENTETE_LAN: "1"} if mode_tableau_de_bord_actif() else {}
    try:
        proteges, illisibles, pairs_lus = defense._proteges(entetes, [])
        etats = defense_etat.etats_decisions()
    except defense_etat.EtatIndisponible:
        out["erreur"] = "base_indisponible"
        return out
    if illisibles:
        out["erreur"] = "liste_blanche_illisible"  # échec fermé, comme l'approbation manuelle
        return out
    note = f" pairs_maillage={'verifies' if pairs_lus else 'non_verifies'}"
    retenues = []
    try:
        for p in defense._propositions(r):
            if not cas_sur(p, proteges)[0]:
                out["ecartees"] += 1
            elif (etats.get(p["empreinte"], "en_attente") == "en_attente"  # déjà tranchée : ni plafond ni réclamation
                  and not defense_etat.refuse_par_humain(p["empreinte"])):  # un « non » humain lie l'automate
                retenues.append(p)
    except defense_etat.EtatIndisponible:
        out["erreur"] = "base_indisponible"
        return out
    for p in retenues:
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
    print(f"sade-auto mode={r['mode']} bannies={len(r['bannies'])} ecartees={r['ecartees']} "
          f"plafond={'oui' if r['plafond'] else 'non'} erreur={r['erreur'] or 'aucune'}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
