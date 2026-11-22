# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Apprentissage (#3723, carte 4 de SADE ; complément § 3-4) : filtres WAF d'office et suggestions d'empreintes.

FILTRES (boucle `apprentissage`, 300 s, compte `ai-filtres`, clé remise par LoadCredential=) :

- construits par le CODE, jamais du texte du modèle : un outil NOMMÉ par `veille/outils.py` (≥ 2 traits indépendants,
  attribution gardée dans `dossiers.outils_json`) dont l'entrée de catalogue porte des `[[outil.filtre]]` SOURCÉS au
  contrat de gk2 (#3732 : CVE, produit, famille, motif littéral). Aucune entrée livrée n'en porte aujourd'hui : la
  boucle n'envoie donc rien en production (voir README § Suite) ;
- envoi par `POST /ai/filtres` (ligne `filtres` en `envoi` créée AVANT l'envoi) ; le vérificateur de gk2 a le
  dernier mot : appliqué ou inchangé → `essai`, rejeté → `rejete` (jamais renvoyé) ;
- plafonds de gk3 = ceux de gk2 (10/h, 50/j, fenêtres glissantes, sur les envois) ; mode `observation` de la
  politique ou automatique suspendu (veille.db ou politique) : aucun NOUVEL envoi ;
- essai de 24 h : une touche d'une adresse PROTÉGÉE (non publique, `local`, plages `[veille.analyste] protegees`),
  lue dans les lignes `ia_filtres_*` du journal des menaces déjà collectées (colonne `rule_id` = id du filtre, jamais
  `message`, revue finale F1),
  fait RETIRER le filtre (`DELETE /ai/filtres/{id}`) avec alerte — d'office, à tout moment, y compris pour un filtre
  confirmé et même en observation ou suspendu (retirer protège). Sans touche protégée après 24 h : `a_confirmer`,
  confirmation en UN CLIC d'un administrateur (`POST /filtres/{id}/confirmer`), JAMAIS d'office : le second critère
  (« vhost routé ayant donné une réponse 2xx/3xx ») n'est pas mesurable depuis gk3 (le journal des menaces n'a pas de
  statut, la vue de gk2 n'est pas ouverte au compte de lecture) ;
- réponse perdue, 5xx autre que 503 : le filtre reste `envoi`, rapproché par `GET /ai/filtres` après 120 s, jamais
  renvoyé à l'aveugle ; 503, 401, 403 : `echec` et fin de passe.

TOUR NUCLEI (#3862, porté du POC gk0) : seconde source de la même boucle, `veille/nuclei.py`. Le collecteur sans clé
(`secubox-ai-nuclei.service`) écrit `nuclei/candidats.json` ; la veille le RELIT comme une donnée (forme, taille, id
recalculé : un écart et rien ne part), seulement si `[filtres] nuclei = true` (ai.toml, éteint par défaut). Mêmes
règles que les filtres d'outils : mode `observation`, automatique suspendu ou SADE `observe` → aucun envoi ; ligne
`filtres` (origine `nuclei`, version) créée AVANT l'envoi ; lots `decouper` signés ai-filtres ; rapprochement,
surveillance et retrait d'office communs. Éligibilité et quota du POC (`eligibles`, `quota`, `ordonner`) : 10 par
passage, 10/h et 50/24 h. Un filtre déjà en vigueur sur gk2 (posé par gk0) dans la MÊME version (`GET /ai/filtres`) est
ADOPTÉ sans envoi (`adopte`, hors plafonds) : surveillé, jamais doublé ni retiré sans touche protégée. Un filtre
retiré ne repart jamais, même dans une nouvelle version.

SUGGESTIONS : `suggestions-empreintes.json` (dossier d'état du module, 0640, 200 entrées au plus) = valeurs de traits
(agent HTTP, `tool` de sbxwaf, empreinte HTTP, JA4) vues sur au moins 30 adresses en 7 jours, adresses SANS outil
nommé. Données non fiables de gk2, tronquées ; lisibles dans la console, JAMAIS appliquées (aucun code ne les lit pour
agir).
"""
import asyncio
import ipaddress
import json
import logging
import os
import re
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from veille import decisions, nuclei, outils
from veille.client import ErreurGk2
from veille.decisions import ACTEUR_VEILLE, ajouter_audit, iso
from veille.executeur import _journaliser, _poser_si_change, _sade_releve, ecrire_audit
from veille.riposte import _protegee

log = logging.getLogger("secubox-ai-veille")

ESSAI_S = 86400
PLAFOND_HEURE, PLAFOND_JOUR = 10, 50
DELAI_RAPPROCHEMENT_S = 120          # délai du client 75 s + marge
LOT = 5
SEUIL_SUGGESTION = 30
SUGGESTIONS_MAX = 200
FENETRE_SUGGESTIONS_J = 7
VALEUR_MAX = 128
NOM_SUGGESTIONS = "suggestions-empreintes.json"
SUIVIS = ("essai", "a_confirmer", "confirme")
_RE_ID = re.compile(r"[^a-z0-9._-]+")
#: Trait → clé de l'événement (attributs_json) d'où vient sa valeur.
TRAITS_SUGGERES = {"agent": "user_agent", "outil_waf": "tool", "empreinte_http": "http_fingerprint", "ja4": "ja4"}
_ARRET = frozenset({401, 403, 503})


def chemin_suggestions() -> Path:
    return Path(os.environ.get("SECUBOX_AI_ETAT", "/var/lib/secubox/ai")) / NOM_SUGGESTIONS


def identifiant(outil: str, cve: str) -> str:
    """Id du filtre chez gk2 : `ia-outil-<outil>-<cve>`, forme `ia-[a-z0-9._-]{1,93}`."""
    corps = _RE_ID.sub("-", f"outil-{outil}-{cve}".lower()).strip("-.")
    return ("ia-" + corps)[:96].rstrip("-.")


def _attributions(brut):
    try:
        v = json.loads(brut or "[]")
    except ValueError:
        return []
    return [a for a in v if isinstance(a, dict)] if isinstance(v, list) else []


def candidats(db, cat) -> list:
    """(id, outil, cve, dossier, corps) des filtres à proposer : outils NOMMÉS (≥ 2 traits) d'un dossier, filtres
    sourcés de leur entrée de catalogue. Corps au contrat EXACT de gk2 (`lire_filtre`)."""
    par_nom = {o.nom: o for o in cat}
    out, vus = [], set()
    for did, brut in db.execute("SELECT id, outils_json FROM dossiers ORDER BY derniere_vue DESC").fetchall():
        for a in _attributions(brut):
            nom = a.get("outil")
            if not isinstance(nom, str) or nom == "inconnu" or len(a.get("traits_concordants") or []) < 2:
                continue
            o = par_nom.get(nom)
            for f in (o.filtres if o else []):
                fid = identifiant(o.nom, f["cve"])
                if fid in vus:
                    continue
                vus.add(fid)
                corps = {"id": fid, "version": 1, "cve": f["cve"], "produit": f["produit"], "famille": f["famille"],
                         "motif_type": f["motif_type"], "motif": f["motif"],
                         "sources": [{"outil": o.nom, "source": f["source"][:256]}]}
                if f["parametre"] is not None:
                    corps["parametre"] = f["parametre"]
                out.append((fid, o.nom, f["cve"], did, corps))
    return out


def _protegee_ip(ip, attributs, protegees) -> bool:
    if not ip:
        return True                       # « local » : sbxwaf n'écrit pas l'adresse d'un poste du LAN
    try:
        if json.loads(attributs or "{}").get("local"):
            return True
    except (ValueError, AttributeError):
        pass
    try:
        return _protegee(ipaddress.ip_network(ip), protegees)
    except ValueError:
        return True                       # illisible : doute = protégée (on retire)


def touches_protegees(db, fid, depuis, protegees=()) -> int:
    """Touches du filtre `fid` sur une adresse protégée depuis `depuis` (lignes `ia_filtres_*` collectées)."""
    n = 0
    for ip, attributs in db.execute("SELECT ip_src, attributs_json FROM evenements WHERE famille LIKE "
                                    "'ia\\_filtres\\_%' ESCAPE '\\' AND rule_id = ? AND horodatage >= ?",
                                    (fid, depuis)).fetchall():
        n += _protegee_ip(ip, attributs, protegees)
    return n


def _transaction(db, fonction):
    db.execute("BEGIN IMMEDIATE")
    try:
        res = fonction()
        db.execute("COMMIT")
        return res
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise


def _changer(db, fid, etat, maintenant, operation, details, **champs):
    """Nouvel état du filtre + ligne audit_chaine ; rend la ligne d'audit.log."""
    def faire():
        cols = ", ".join(f"{k} = ?" for k in champs)
        db.execute(f"UPDATE filtres SET etat = ?, maj_le = ?{', ' + cols if cols else ''} WHERE id = ?",
                   (etat, iso(maintenant), *champs.values(), fid))
        d = {"filtre": fid, "etat": etat, **details}
        ajouter_audit(db, maintenant, ACTEUR_VEILLE, operation, fid, etat, d)
        return d
    return _transaction(db, faire)


# ── suggestions ──

def calculer_suggestions(db, maintenant, cat=None) -> list:
    """Traits vus sur ≥ SEUIL_SUGGESTION adresses en 7 j, adresses sans outil nommé ; 200 au plus."""
    debut = iso(maintenant - timedelta(days=FENETRE_SUGGESTIONS_J))
    nommees = ("SELECT DISTINCT e2.ip_src FROM dossiers d JOIN json_each(CASE WHEN json_valid(d.outils_json) "
               "THEN d.outils_json ELSE '[]' END) j JOIN dossier_evenements de ON de.dossier_id = d.id "
               "JOIN evenements e2 ON e2.id = de.evenement_id WHERE json_extract(j.value, '$.outil') IS NOT NULL "
               "AND json_extract(j.value, '$.outil') != 'inconnu' AND e2.ip_src IS NOT NULL")
    cat = outils.catalogue() if cat is None else cat
    out = []
    for type_, cle in TRAITS_SUGGERES.items():
        sql = (f"SELECT substr(json_extract(attributs_json, '$.{cle}'), 1, {VALEUR_MAX}) AS v, "
               "COUNT(DISTINCT ip_src), MIN(horodatage), MAX(horodatage) FROM evenements "
               "WHERE horodatage >= ? AND ip_src IS NOT NULL AND json_valid(attributs_json) "
               f"AND json_type(attributs_json, '$.{cle}') = 'text' "
               "AND json_extract(attributs_json, '$.autotest') IS NULL "
               f"AND ip_src NOT IN ({nommees}) GROUP BY v HAVING COUNT(DISTINCT ip_src) >= ?")
        for v, n, premiere, derniere in db.execute(sql, (debut, SEUIL_SUGGESTION)).fetchall():
            if not isinstance(v, str) or not v.strip():
                continue
            connu = next((o.nom for o in cat for t in o.traits if t.type == type_ and t.motif is not None
                          and t.motif.search(v)), None)
            out.append({"type": type_, "valeur": v, "adresses": n, "premiere_vue": premiere,
                        "derniere_vue": derniere, "outil_catalogue": connu})
    out.sort(key=lambda s: (-s["adresses"], s["type"], s["valeur"]))
    return out[:SUGGESTIONS_MAX]


def ecrire_suggestions(suggestions, maintenant, chemin=None) -> None:
    """Écriture atomique (temporaire, fsync, renommage), 0640. Jamais lue pour agir."""
    chemin = Path(chemin or chemin_suggestions())
    donnees = {"genere_le": iso(maintenant), "seuil_adresses": SEUIL_SUGGESTION, "fenetre_j": FENETRE_SUGGESTIONS_J,
               "jamais_appliquees": True, "suggestions": suggestions}
    fd, tmp = tempfile.mkstemp(dir=chemin.parent, prefix=f".{chemin.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(donnees, f, ensure_ascii=False, sort_keys=True)
            f.flush()
            os.fchmod(f.fileno(), 0o640)
            os.fsync(f.fileno())
        os.replace(tmp, chemin)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def etat_apprentissage(db=None, chemin=None) -> dict:
    """{"filtres_essai", "filtres_a_confirmer", "filtres_confirmes", "filtres_retires", "suggestions"} : nombres, ou
    None quand la source est inconnue (base absente ou non migrée, fichier absent ou illisible) — jamais un zéro
    inventé. `filtres_essai` compte aussi ceux à confirmer (toujours en essai chez gk2)."""
    etat = {"filtres_essai": None, "filtres_a_confirmer": None, "filtres_confirmes": None, "filtres_retires": None,
            "suggestions": None}
    if db is not None:
        try:
            n = dict(db.execute("SELECT etat, COUNT(*) FROM filtres GROUP BY etat").fetchall())
            etat.update(filtres_essai=n.get("essai", 0) + n.get("a_confirmer", 0),
                        filtres_a_confirmer=n.get("a_confirmer", 0), filtres_confirmes=n.get("confirme", 0),
                        filtres_retires=n.get("retire", 0))
        except sqlite3.Error:
            pass
    try:
        s = json.loads(Path(chemin or chemin_suggestions()).read_text(encoding="utf-8")).get("suggestions")
        etat["suggestions"] = len(s) if isinstance(s, list) else None
    except (OSError, ValueError, AttributeError):
        pass
    return etat


# ── filtres ──

async def _rapprocher(veille, client, maintenant, journal) -> bool:
    en_cours = await veille.sql(lambda db: db.execute(
        "SELECT id, envoye_le FROM filtres WHERE etat = 'envoi'").fetchall())
    if not en_cours:
        return True
    murs = [fid for fid, le in en_cours if le <= iso(maintenant - timedelta(seconds=DELAI_RAPPROCHEMENT_S))]
    if not murs:
        return False
    try:
        liste = await client.lister_filtres()
    except ErreurGk2 as e:
        log.warning("apprentissage : GET /ai/filtres illisible (%s %s) : aucun nouvel envoi", e.code, e.motif)
        return False
    presents = {f.get("id") if isinstance(f, dict) else f for f in (liste.get("filtres") or [])}
    lignes = []
    for fid in murs:
        if fid in presents:
            lignes.append(("ai-filtre-rapproche", await veille.sql(
                lambda db, f=fid: _changer(db, f, "essai", maintenant, "filtre_rapproche", {"resultat": "essai"},
                                           essai_depuis=db.execute("SELECT envoye_le FROM filtres WHERE id = ?",
                                                                   (f,)).fetchone()[0]))))
        else:
            lignes.append(("ai-filtre-rapproche", await veille.sql(
                lambda db, f=fid: _changer(db, f, "echec", maintenant, "filtre_rapproche", {"resultat": "echec"},
                                           motif="absent_apres_envoi"))))
    await _journaliser(journal, lignes)
    return len(murs) == len(en_cours)


async def _surveiller(veille, client, maintenant, journal, protegees):
    """Retrait d'office sur touche protégée (alerte) ; essai de 24 h sans touche → `a_confirmer` (un clic)."""
    suivis = await veille.sql(lambda db: db.execute(
        f"SELECT id, etat, COALESCE(essai_depuis, envoye_le) FROM filtres WHERE etat IN ({', '.join('?' * len(SUIVIS))})",
        SUIVIS).fetchall())
    for fid, etat, depuis in suivis:
        n = await veille.sql(touches_protegees, fid, depuis, protegees)
        if n:
            try:
                await client.retirer_filtre(fid)
                issue = "retire"
            except ErreurGk2 as e:
                issue = "retire" if e.code == 404 else None
                if issue is None:
                    log.error("apprentissage : retrait de %s impossible (%s %s), nouvel essai", fid, e.code, e.motif)
                    await veille.sql(lambda db, f=fid, m=f"retrait_{e.code or 'reseau'}": db.execute(
                        "UPDATE filtres SET motif = ?, touches_protegees = ? WHERE id = ?", (m, n, f)))
                    continue
            log.error("apprentissage : filtre %s RETIRÉ, %d touche(s) d'adresse protégée", fid, n)
            d = await veille.sql(lambda db, f=fid: _changer(
                db, f, "retire", maintenant, "filtre_retire", {"motif": "touche_protegee", "touches": n},
                motif="touche_protegee", touches_protegees=n))
            await _journaliser(journal, [("ai-filtre-retire", d), ("ai-filtre-alerte", d)])
        elif etat == "essai" and depuis <= iso(maintenant - timedelta(seconds=ESSAI_S)):
            d = await veille.sql(lambda db, f=fid: _changer(
                db, f, "a_confirmer", maintenant, "filtre_a_confirmer",
                {"critere_legitime": "non_mesurable_depuis_gk3"}, touches_protegees=0))
            await _journaliser(journal, [("ai-filtre-a-confirmer", d)])


def _plafond(db, maintenant) -> bool:
    for recul, plafond in ((3600, PLAFOND_HEURE), (86400, PLAFOND_JOUR)):
        # #3862 : un filtre adopté (déjà en vigueur sur gk2, rien envoyé) ne compte pas.
        if db.execute("SELECT COUNT(*) FROM filtres WHERE envoye_le > ? AND adopte = 0",
                      (iso(maintenant - timedelta(seconds=recul)),)).fetchone()[0] >= plafond:
            return True
    return False


class _Ecarte(Exception):
    pass


def _inscrire(db, c, jti, kid, maintenant, pol):
    fid, outil, cve, did, corps = c

    def faire():
        if pol.mode != "hybride" or pol.automatique_suspendu or decisions.suspension(db)["suspendu"]:
            raise _Ecarte("suspendu")
        if db.execute("SELECT 1 FROM filtres WHERE id = ?", (fid,)).fetchone():
            raise _Ecarte("deja")
        if _plafond(db, maintenant):
            raise _Ecarte("plafond")
        h = iso(maintenant)
        db.execute("INSERT INTO filtres(id, outil, cve, dossier_id, corps_json, etat, jti, cle, envoye_le, maj_le) "
                   "VALUES (?, ?, ?, ?, ?, 'envoi', ?, ?, ?, ?)",
                   (fid, outil, cve, did, json.dumps(corps, sort_keys=True), jti, kid, h, h))
        d = {"filtre": fid, "outil": outil, "cve": cve, "dossier": did, "jti": jti, "cle": kid}
        ajouter_audit(db, maintenant, ACTEUR_VEILLE, "filtre_envoi", fid, "envoi", d)
        return d
    return _transaction(db, faire)


async def _envoyer(veille, client, c, maintenant, pol, journal) -> str:
    fid = c[0]

    async def avant_envoi(jti, kid):
        d = await veille.sql(_inscrire, c, jti, kid, maintenant, pol)
        await _journaliser(journal, [("ai-filtre-envoi", d)])

    try:
        bilan = await client.post_filtres({"filtres": [c[4]]}, avant_envoi=avant_envoi)
    except _Ecarte as e:
        return "arret" if str(e) in ("plafond", "suspendu") else "suite"
    except ErreurGk2 as e:
        if e.code is None or (e.code >= 500 and e.code != 503):
            log.warning("apprentissage : issue inconnue (%s %s) pour %s : rapprochement plus tard", e.code, e.motif,
                        fid)
            return "arret"
        detail = e.reponse.get("detail") if isinstance(e.reponse, dict) else None
        rejets = detail.get("rejets") if isinstance(detail, dict) else None
        motif = next((r.get("motif") for r in rejets or [] if isinstance(r, dict) and r.get("id") == fid), e.motif)
        etat, code, motif = ("rejete" if e.code == 409 else "echec"), e.code, str(motif)[:32]
        d = await veille.sql(lambda db: _changer(db, fid, etat, maintenant, "filtre_reponse",
                                                 {"code": code, "motif": motif}, code_http=code, motif=motif))
        await _journaliser(journal, [("ai-filtre-reponse", d)])
        return "arret" if code in _ARRET else "suite"
    ids = lambda cle: {x.get("id") if isinstance(x, dict) else x for x in (bilan.get(cle) or [])}  # noqa: E731
    if fid in ids("appliques") | ids("inchanges"):
        d = await veille.sql(lambda db: _changer(db, fid, "essai", maintenant, "filtre_reponse",
                                                 {"code": 200, "motif": "applique"}, code_http=200,
                                                 essai_depuis=iso(maintenant)))
    else:
        motif = next((r.get("motif") for r in bilan.get("rejets") or [] if isinstance(r, dict)
                      and r.get("id") == fid), "rejete")
        d = await veille.sql(lambda db: _changer(db, fid, "rejete", maintenant, "filtre_reponse",
                                                 {"code": 200, "motif": str(motif)[:32]}, code_http=200,
                                                 motif=str(motif)[:32]))
    await _journaliser(journal, [("ai-filtre-reponse", d)])
    return "suite"


async def apprendre(veille, client, maintenant: datetime, politiques=None, journal=None, protegees=(), cat=None,
                    chemin=None, nuclei_allume=None, dossier_nuclei=None) -> None:
    """Une passe (cf. docstring du module). `nuclei_allume` : interrupteur `[filtres] nuclei` relu par l'appelant à
    chaque passe (None : tour Nuclei ignoré, état non publié)."""
    if maintenant.tzinfo is None:
        raise ValueError("horodatage sans fuseau")
    journal = journal or ecrire_audit
    cat = await asyncio.to_thread(outils.catalogue) if cat is None else cat
    suggestions = await veille.sql(calculer_suggestions, maintenant, cat)
    await asyncio.to_thread(ecrire_suggestions, suggestions, maintenant, chemin)
    cands_nuclei = None
    if nuclei_allume is not None:
        cands_nuclei = await lire_nuclei(veille, maintenant, nuclei_allume, dossier_nuclei)
    if client is None or not client.peut_filtrer:
        await veille.sql(lambda db: _poser_si_change(db, "cle_ai_filtres", {"etat": "absente"}, maintenant))
        return
    await veille.sql(lambda db: _poser_si_change(db, "cle_ai_filtres", {"etat": "presente"}, maintenant))
    pret = await _rapprocher(veille, client, maintenant, journal)
    await _surveiller(veille, client, maintenant, journal, protegees)
    if not pret:
        return
    if politiques is None:
        from veille.politiques import charger_politiques
        politiques = await asyncio.to_thread(charger_politiques)
    if politiques.mode != "hybride":
        return
    connus = await veille.sql(lambda db: {r[0] for r in db.execute("SELECT id FROM filtres").fetchall()})
    nouveaux = [c for c in await veille.sql(candidats, cat) if c[0] not in connus][:LOT]
    for c in nouveaux:
        if await _envoyer(veille, client, c, maintenant, politiques, journal) == "arret":
            return
    if cands_nuclei:
        await passe_nuclei(veille, client, cands_nuclei, maintenant, politiques, journal)


# ── tour Nuclei (#3862) ──

CLE_NUCLEI = "tour_nuclei"
#: État d'une ligne `filtres` → statut du POC lu par `nuclei.eligibles`.
_STATUTS_NUCLEI = {"essai": "appliqué", "a_confirmer": "appliqué", "confirme": "appliqué", "rejete": "rejeté",
                   "retire": "retiré", "envoi": "envoi"}


def _epoch(texte):
    try:
        return datetime.strptime(texte, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


def etats_filtres(db) -> dict:
    """{id: {"version", "statut", "ts"}} de TOUTES les lignes `filtres` ; une ligne d'une autre origine est tenue
    pour `envoi` (jamais réécrite par le tour Nuclei)."""
    out = {}
    for fid, etat, version, motif, maj, origine in db.execute(
            "SELECT id, etat, version, motif, maj_le, origine FROM filtres").fetchall():
        if origine != "nuclei":
            statut = "envoi"
        elif etat == "echec":
            statut = "en_attente" if motif == "plafond" else "erreur"
        else:
            statut = _STATUTS_NUCLEI.get(etat, "envoi")
        out[fid] = {"version": version, "statut": statut, "ts": _epoch(maj)}
    return out


def _envoyes(db, maintenant, recul) -> int:
    """Nouveaux filtres envoyés (toutes origines, adoptés exclus) et non refusés dans la fenêtre glissante."""
    return db.execute("SELECT COUNT(*) FROM filtres WHERE adopte = 0 AND envoye_le > ? AND etat NOT IN "
                      "('rejete', 'echec')", (iso(maintenant - timedelta(seconds=recul)),)).fetchone()[0]


def quota_nuclei(db, maintenant) -> int:
    return nuclei.quota(_envoyes(db, maintenant, 3600), _envoyes(db, maintenant, 86400), PLAFOND_HEURE)


def bloque_nuclei(db, pol) -> bool:
    """Aucun envoi : mode `observation`, automatique suspendu (politique ou veille.db), SADE de gk2 en `observe`."""
    return (pol.mode != "hybride" or pol.automatique_suspendu or decisions.suspension(db)["suspendu"]
            or _sade_releve(db) == "observe")


async def lire_nuclei(veille, maintenant, allume: bool, dossier=None):
    """Lit etat.json et candidats.json (données du collecteur, revalidées), publie `tour_nuclei` pour /veille/etat ;
    rend les candidats si le tour est allumé et le fichier valide, sinon None."""
    dossier = Path(dossier or nuclei.DOSSIER)
    collecteur = await asyncio.to_thread(nuclei.lire_etat_collecteur, dossier / "etat.json")
    cands, erreur, genere = None, None, None
    try:
        lus = await asyncio.to_thread(nuclei.lire_candidats, dossier / "candidats.json")
        cands, genere = lus["filtres"], lus["genere_le"]
    except nuclei.CandidatsInvalides as e:
        erreur = str(e)[:64]
    etat = {"allume": bool(allume), "collecteur": collecteur, "candidats": None if cands is None else len(cands),
            "candidats_genere_le": genere, "erreur_candidats": erreur}
    await veille.sql(lambda db: _poser_si_change(db, CLE_NUCLEI, etat, maintenant))
    if not allume:
        return None
    if erreur is not None:
        log.warning("tour nuclei : candidats.json refusé (%s) : aucun envoi", erreur)
    return cands


def _adopter(db, f, maintenant):
    """Filtre déjà en vigueur sur gk2 dans la même version : inscrit `essai` SANS envoi (surveillé), hors plafonds."""
    def faire():
        if db.execute("SELECT 1 FROM filtres WHERE id = ?", (f["id"],)).fetchone():
            return None
        h = iso(maintenant)
        db.execute("INSERT INTO filtres(id, outil, cve, dossier_id, corps_json, etat, motif, envoye_le, essai_depuis, "
                   "maj_le, origine, version, adopte) VALUES (?, 'nuclei', ?, NULL, ?, 'essai', 'adopte', ?, ?, ?, "
                   "'nuclei', ?, 1)", (f["id"], f["cve"], json.dumps(f, sort_keys=True), h, h, h, f["version"]))
        d = {"filtre": f["id"], "origine": "nuclei", "cve": f["cve"], "version": f["version"], "adopte": True}
        ajouter_audit(db, maintenant, ACTEUR_VEILLE, "filtre_adopte", f["id"], "essai", d)
        return d
    return _transaction(db, faire)


def _inscrire_lot(db, lot, jti, kid, maintenant, pol):
    """Lignes `envoi` du lot, AVANT le premier octet envoyé, après revérification (politique, éligibilité, quota)."""
    def faire():
        if bloque_nuclei(db, pol):
            raise _Ecarte("suspendu")
        if len(nuclei.eligibles(lot, etats_filtres(db), maintenant.timestamp())) != len(lot):
            raise _Ecarte("deja")
        if quota_nuclei(db, maintenant) < len(lot):
            raise _Ecarte("plafond")
        h = iso(maintenant)
        lignes = []
        for f in lot:
            db.execute(
                "INSERT INTO filtres(id, outil, cve, dossier_id, corps_json, etat, jti, cle, envoye_le, maj_le, "
                "origine, version, adopte) VALUES (?, 'nuclei', ?, NULL, ?, 'envoi', ?, ?, ?, ?, 'nuclei', ?, 0) "
                "ON CONFLICT(id) DO UPDATE SET corps_json = excluded.corps_json, etat = 'envoi', jti = excluded.jti, "
                "cle = excluded.cle, envoye_le = excluded.envoye_le, maj_le = excluded.maj_le, "
                "version = excluded.version, adopte = 0, code_http = NULL, motif = NULL, touches_protegees = NULL, "
                "essai_depuis = NULL, confirme_par = NULL WHERE filtres.origine = 'nuclei'",
                (f["id"], f["cve"], json.dumps(f, sort_keys=True), jti, kid, h, h, f["version"]))
            d = {"filtre": f["id"], "origine": "nuclei", "cve": f["cve"], "version": f["version"], "jti": jti,
                 "cle": kid}
            ajouter_audit(db, maintenant, ACTEUR_VEILLE, "filtre_envoi", f["id"], "envoi", d)
            lignes.append(d)
        return lignes
    return _transaction(db, faire)


def _rejets_de(rep) -> dict:
    """{id: motif} des rejets d'une réponse de gk2 (à la racine ou sous `detail`), donnée non fiable bornée."""
    if not isinstance(rep, dict):
        return {}
    for d in (rep, rep.get("detail") if isinstance(rep.get("detail"), dict) else {}):
        r = d.get("rejets")
        if isinstance(r, list):
            return {str(x.get("id")): str(x.get("motif", ""))[:32] for x in r if isinstance(x, dict)}
    return {}


async def _noter_issues(veille, issues, maintenant, journal):
    lignes = []
    for fid, (etat, code, motif) in issues.items():
        champs = {"code_http": code, "motif": motif}
        if etat == "essai":
            champs["essai_depuis"] = iso(maintenant)
        lignes.append(("ai-filtre-reponse", await veille.sql(
            lambda db, f=fid, e=etat, c=code, m=motif, ch=champs: _changer(
                db, f, e, maintenant, "filtre_reponse", {"code": c, "motif": m}, **ch))))
    await _journaliser(journal, lignes)


async def _envoyer_lot(veille, client, lot, maintenant, pol, journal) -> str:
    async def avant_envoi(jti, kid):
        lignes = await veille.sql(_inscrire_lot, lot, jti, kid, maintenant, pol)
        await _journaliser(journal, [("ai-filtre-envoi", d) for d in lignes])

    try:
        bilan = await client.post_filtres({"filtres": lot}, avant_envoi=avant_envoi)
    except _Ecarte:
        return "arret"
    except ErreurGk2 as e:
        if e.code is None or (e.code >= 500 and e.code != 503):
            log.warning("tour nuclei : issue inconnue (%s %s) pour %d filtre(s) : rapprochement plus tard", e.code,
                        e.motif, len(lot))
            return "arret"
        rejets = _rejets_de(e.reponse)
        issues = {}
        for f in lot:
            m = rejets.get(f["id"])
            if e.code == 409 and m == "plafond":
                issues[f["id"]] = ("echec", 409, "plafond")
            elif e.code == 409:
                issues[f["id"]] = ("rejete", 409, m or "http_409")
            else:
                issues[f["id"]] = ("echec", e.code, str(e.motif)[:32])
        await _noter_issues(veille, issues, maintenant, journal)
        plafond = any(m == "plafond" for _, _, m in issues.values())
        return "arret" if e.code in _ARRET or plafond else "suite"
    ids = lambda cle: {x.get("id") if isinstance(x, dict) else x for x in (bilan.get(cle) or [])}  # noqa: E731
    appliques, inchanges, rejets = ids("appliques"), ids("inchanges"), _rejets_de(bilan)
    issues = {}
    for f in lot:
        fid = f["id"]
        if fid in appliques:
            issues[fid] = ("essai", 200, "applique")
        elif fid in inchanges:
            issues[fid] = ("essai", 200, "inchange")
        elif rejets.get(fid) == "plafond":
            issues[fid] = ("echec", 200, "plafond")         # plafond de gk2 : pas définitif, renvoyé plus tard
        elif fid in rejets:
            issues[fid] = ("rejete", 200, rejets[fid] or "rejete")
        else:
            issues[fid] = ("echec", 200, "sans_bilan")      # ni appliqué ni rejeté : réessai après 24 h
    await _noter_issues(veille, issues, maintenant, journal)
    return "arret" if any(m == "plafond" for _, _, m in issues.values()) else "suite"


async def passe_nuclei(veille, client, cands, maintenant, pol, journal) -> str:
    """Envoi des candidats Nuclei éligibles (cf. docstring du module) ; rend l'issue (journal du service, tests)."""
    if await veille.sql(bloque_nuclei, pol):
        return "bloque"
    restant = await veille.sql(quota_nuclei, maintenant)
    if restant <= 0:
        return "plafond"
    elig = nuclei.eligibles(cands, await veille.sql(etats_filtres), maintenant.timestamp())
    if not elig:
        return "rien"
    connus = await veille.sql(lambda db: {r[0] for r in db.execute("SELECT id FROM filtres").fetchall()})
    inconnus = [f for f in elig if f["id"] not in connus]
    if inconnus:
        try:
            liste = await client.lister_filtres()
        except ErreurGk2 as e:
            log.warning("tour nuclei : GET /ai/filtres illisible (%s %s) : aucun envoi", e.code, e.motif)
            return "lister"
        en_vigueur = {x.get("id"): x.get("version") for x in (liste.get("filtres") or []) if isinstance(x, dict)}
        adoptes, lignes = set(), []
        for f in inconnus:
            v = en_vigueur.get(f["id"])
            if type(v) is int and v == f["version"]:
                d = await veille.sql(_adopter, f, maintenant)
                if d:
                    adoptes.add(f["id"])
                    lignes.append(("ai-filtre-adopte", d))
        await _journaliser(journal, lignes)
        if adoptes:
            log.info("tour nuclei : %d filtre(s) déjà en vigueur sur gk2 adopté(s) sans envoi", len(adoptes))
        elig = [f for f in elig if f["id"] not in adoptes]
    for lot in nuclei.decouper(nuclei.ordonner(elig)[:restant]):
        if await _envoyer_lot(veille, client, lot, maintenant, pol, journal) == "arret":
            return "arret"
    return "fait"
