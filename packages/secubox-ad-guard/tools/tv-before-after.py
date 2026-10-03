#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: tv-before-after — la procédure de comparaison sur un VRAI appareil (Freebox TV), POC « DNS AdBlock TV » (#1943).

Chaque phase est mesurée par la DIFFÉRENCE de deux relevés des compteurs de la box (aucun chiffre n'est saisi à la main) :

  A  référence : la TV utilise son DNS habituel (celui de la Freebox). La box ne la voit pas : on ne note QUE le fonctionnement
     (--note). C'est la seule phase sans mesure côté box, et c'est voulu.
  B  OBSERVE   : la TV utilise la box ; rien n'est bloqué ; la box compte ce qui AURAIT été bloqué.
  C  BLOCK     : mêmes usages, les domaines des listes reçoivent NXDOMAIN ; on note ce qui ne marche plus (--note).

Déroulement (jeton administrateur dans SBX_TOKEN, adresse de la box dans SBX_URL, défaut http://127.0.0.1) :
  MODE LOCAL (sur la box, sans jeton) : SBX_LOCAL=1 — l'outil lit la base de compteurs et écrit l'état directement (comme l'API, même validation) ;
  --ip accepte PLUSIEURS adresses séparées par des virgules : une TV a souvent une adresse IPv4 ET des adresses IPv6 (de confidentialité, qui changent).
  tv-before-after.py debut B --ip 192.168.1.50      pose le mode, prend le relevé de départ
  ... on utilise la TV : zapper, lancer l'application, regarder, 5 à 10 minutes par phase ...
  tv-before-after.py fin B --note "tout fonctionne"  relevé d'arrivée, calcule la phase
  tv-before-after.py rapport                         écrit reports/tv-before-after.md à partir des phases mesurées
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ETAT = Path(os.environ.get("SBX_TV_PHASES", "reports/.tv-phases.json"))
MODES = {"B": "observe", "C": "block", "E": "observe", "P": "observe"}


def api_local(chemin: str, methode: str = "GET", corps=None) -> dict:
    """Même opérations que l'API, appelées directement sur la box (bibliothèque dnstv) : utile sans jeton administrateur."""
    for p in ("/usr/lib/secubox/ad-guard", str(Path(__file__).resolve().parents[1])):
        if p not in sys.path:
            sys.path.append(p)
    from api import dnstv
    if chemin.startswith("/adblock-tv/export"):
        ip = chemin.split("client=", 1)[1]
        return {"lignes": dnstv.Magasin(dnstv.DOSSIER_ETAT / "dnstv.db").lignes(ip)}
    if chemin == "/adblock-tv/clients" and methode == "POST":
        etat, _ = dnstv.lire_etat()
        etat["clients"] = [c for c in etat["clients"] if c["ip"] != dnstv._ip(corps["ip"])] + [
            {"ip": dnstv._ip(corps["ip"]), "nom": corps.get("nom") or corps["ip"], "mode": corps["mode"]}]
        dnstv.ecrire_etat(etat)
        return {}
    if chemin == "/adblock-tv/etat" and methode == "POST":
        etat, _ = dnstv.lire_etat()
        etat["actif"] = bool(corps["actif"])
        dnstv.ecrire_etat(etat)
        return {}
    if chemin == "/adblock-tv/custom" and methode == "POST":
        dom = dnstv.valider_domaine(corps["domaine"])
        if not dom:
            raise SystemExit("domaine invalide : " + str(corps["domaine"])[:60])
        f = dnstv.DOSSIER_ETAT / "custom.txt"
        courants = set(dnstv.lire_liste(f)[0]) if f.is_file() else set()
        courants.add(dom)
        f.write_text("# liste personnalisée (POC DNS AdBlock TV)\n" + "".join(x + "\n" for x in sorted(courants)), encoding="utf-8")
        return {}
    raise SystemExit("opération locale inconnue : " + chemin)


def appliquer_local() -> None:
    subprocess.run(["sudo", "-n", "/usr/sbin/secubox-adguard-tv", "apply"] if os.geteuid() != 0 else ["/usr/sbin/secubox-adguard-tv", "apply"], check=True)


def api(chemin: str, methode: str = "GET", corps=None) -> dict:
    if os.environ.get("SBX_LOCAL"):
        return api_local(chemin, methode, corps)
    url = os.environ.get("SBX_URL", "http://127.0.0.1").rstrip("/") + "/api/v1/ad-guard" + chemin
    req = urllib.request.Request(url, method=methode, data=json.dumps(corps).encode() if corps is not None else None,
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer " + os.environ.get("SBX_TOKEN", "")})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read() or b"{}")


def releve_vers_dict(lignes) -> dict:
    """Relevé -> {(domaine, décision): (catégorie, hits)}. Les compteurs de plusieurs adresses d'un MÊME appareil (IPv4 + IPv6) s'additionnent."""
    out: dict = {}
    for x in lignes:
        cle = (x["domaine"], x["decision"])
        out[cle] = (x["categorie"] or out.get(cle, ("", 0))[0], out.get(cle, ("", 0))[1] + x["hits"])
    return out


def difference(avant: dict, apres: dict) -> list:
    """Compteurs gagnés pendant la phase : (domaine, catégorie, décision, hits)."""
    out = []
    for (dom, dec), (cat, h) in apres.items():
        gain = h - avant.get((dom, dec), (cat, 0))[1]
        if gain > 0:
            out.append({"domaine": dom, "categorie": cat, "decision": dec, "hits": gain})
    return sorted(out, key=lambda x: (-x["hits"], x["domaine"]))


def resumer(lignes) -> dict:
    cats = ("advertising", "tracking", "telemetry", "social", "custom")
    r = {"requetes": sum(x["hits"] for x in lignes), "domaines_uniques": len({x["domaine"] for x in lignes}),
         "bloques": sum(x["hits"] for x in lignes if x["decision"] == "BLOCKED"),
         "domaines_bloques": len({x["domaine"] for x in lignes if x["decision"] == "BLOCKED"}),
         "erreurs_amont": sum(x["hits"] for x in lignes if x["decision"] == "UPSTREAM_ERROR")}
    for c in cats:
        r["domaines_" + c] = len({x["domaine"] for x in lignes if x["categorie"] == c})
        r["resolus_" + c] = sum(x["hits"] for x in lignes if x["categorie"] == c and x["decision"] == "ALLOWED")
    return r


def candidats(base: list, avec: list, connus: dict = None) -> list:
    """Domaines vus pendant la phase « avec pubs » et JAMAIS pendant la phase « essentiel » (différence d'ensembles de NOMS).

    `connus` : domaine -> catégorie des listes du POC (un candidat déjà classé est marqué, jamais écarté)."""
    vus_base = {x["domaine"] for x in base}
    out: dict = {}
    for x in avec:
        if x["domaine"] in vus_base:
            continue
        c = out.setdefault(x["domaine"], {"domaine": x["domaine"], "hits": 0, "categorie": x.get("categorie") or ""})
        c["hits"] += x["hits"]
    res = sorted(out.values(), key=lambda c: (-c["hits"], c["domaine"]))
    for c in res:
        c["connu_des_listes"] = (connus or {}).get(c["domaine"], "") or c["categorie"]
    return res


def charger() -> dict:
    return json.loads(ETAT.read_text()) if ETAT.is_file() else {"phases": {}}


def sauver(d: dict) -> None:
    ETAT.parent.mkdir(parents=True, exist_ok=True)
    ETAT.write_text(json.dumps(d, ensure_ascii=False, indent=2))


def rapport_markdown(d: dict) -> str:
    L = ["# Comparaison TV — avant / après filtrage DNS", "",
         "> Mesures réelles tirées des compteurs de la box (différence de deux relevés par phase). "
         "Formulation : **réduction des domaines publicitaires/tracking résolus par DNS** — ce n'est pas une suppression de publicités.", ""]
    ph = d.get("phases", {})
    if not ph:
        return "\n".join(L + ["**Aucune phase mesurée : POC non validé sur flux Freebox réel.**", ""])
    appareil = next((p.get("ip") for p in ph.values() if p.get("ip")), "?")
    L += [f"Appareil : `{appareil}`", "", "| Phase | Mode | Requêtes DNS | Domaines uniques | Advertising (résolus) | Tracking (résolus) | Bloqués (requêtes) | Domaines bloqués | Erreurs amont |",
          "|---|---|---|---|---|---|---|---|---|"]
    for k in sorted(ph):
        p = ph[k]
        r = p.get("resume")
        L.append(f"| {k} | {p.get('mode', 'DNS habituel')} | " + (" | ".join(str(x) for x in (
            r["requetes"], r["domaines_uniques"], r["resolus_advertising"], r["resolus_tracking"], r["bloques"], r["domaines_bloques"], r["erreurs_amont"]))
            if r else "non mesurable côté box | – | – | – | – | – | –") + " |")
    L.append("")
    for k in sorted(ph):
        p = ph[k]
        L += [f"## Phase {k}", f"Durée : {p.get('duree_s', '?')} s. Note de l'opérateur : {p.get('note') or '(aucune)'}", ""]
        classes = [x for x in p.get("lignes", []) if x["categorie"]]
        if classes:
            L += ["| Domaine classé | Catégorie | Décision | Requêtes |", "|---|---|---|---|"]
            L += [f"| `{x['domaine']}` | {x['categorie']} | {x['decision']} | {x['hits']} |" for x in classes[:40]]
            L.append("")
    L += ["## À renseigner par l'opérateur", "- Domaines **nécessaires** au fonctionnement du service (ceux dont le blocage casse quelque chose) : …",
          "- Faux positifs constatés : …", "- Fonctions cassées en phase C : …", ""]
    return "\n".join(L)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("action", choices=["debut", "fin", "rapport", "apprendre"])
    ap.add_argument("phase", nargs="?", choices=["A", "B", "C", "E", "P"])
    ap.add_argument("phase_pubs", nargs="?", choices=["B", "C", "E", "P"], help="(apprendre) la phase « avec pubs »")
    ap.add_argument("--appliquer", action="store_true", help="(apprendre) ajoute les candidats à la liste personnalisée")
    ap.add_argument("--ip")
    ap.add_argument("--note", default="")
    ap.add_argument("--sortie", default="reports/tv-before-after.md")
    a = ap.parse_args(argv)
    d = charger()
    if a.action == "rapport":
        Path(a.sortie).parent.mkdir(parents=True, exist_ok=True)
        Path(a.sortie).write_text(rapport_markdown(d), encoding="utf-8")
        print("rapport :", a.sortie)
        return 0
    if a.action == "apprendre":
        if not (a.phase and a.phase_pubs):
            ap.error("apprendre <phase essentiel> <phase avec pubs>, ex. : apprendre E P")
        base, avec = d["phases"].get(a.phase, {}), d["phases"].get(a.phase_pubs, {})
        if "lignes" not in base or "lignes" not in avec:
            sys.exit("les deux phases doivent être terminées et mesurées (debut puis fin)")
        cands = candidats(base["lignes"], avec["lignes"])
        print(f"{len(cands)} domaine(s) vus en {a.phase_pubs} et jamais en {a.phase} :")
        for c in cands:
            print(f"  {c['domaine']:45} {c['hits']:5} requêtes  {c['connu_des_listes'] or '(inconnu des listes)'}")
        if a.appliquer:
            for c in cands:
                api("/adblock-tv/custom", "POST", {"domaine": c["domaine"]})
            print(f"{len(cands)} domaine(s) ajouté(s) à la liste personnalisée. Passez la TV en BLOCK et vérifiez ce qui ne marche plus.")
        return 0
    if not a.phase:
        ap.error("phase A, B, C, E ou P requise")
    ph = d["phases"].setdefault(a.phase, {})
    if a.action == "debut":
        if a.phase == "A":
            ph.update(ip=a.ip, debut=int(time.time()), mode="DNS habituel de la Freebox (non mesuré par la box)")
        else:
            if not a.ip:
                ap.error("--ip requis")
            ips = [x.strip() for x in a.ip.split(",") if x.strip()]
            if os.environ.get("SBX_LOCAL"):
                from api import dnstv                                   # noqa: PLC0415 — chemin posé par api_local
                api_local("/adblock-tv/export?client=" + ips[0])          # (charge la bibliothèque et son chemin)
                avant_etat, _ = dnstv.lire_etat()
            for ip in ips:
                api("/adblock-tv/clients", "POST", {"ip": ip, "nom": "TV banc", "mode": MODES[a.phase]})
            api("/adblock-tv/etat", "POST", {"actif": True})
            if os.environ.get("SBX_LOCAL"):
                apres_etat, _ = dnstv.lire_etat()
                if apres_etat != avant_etat:                              # un changement de mode recharge Unbound (≈ 10 s) : seulement s'il a lieu
                    appliquer_local()
            avant = [x for ip in ips for x in api(f"/adblock-tv/export?client={ip}")["lignes"]]
            ph.update(ip=a.ip, debut=int(time.time()), mode=MODES[a.phase].upper(), avant=avant)
        sauver(d)
        print(f"phase {a.phase} commencée ({ph['mode']})")
        return 0
    if "debut" not in ph:
        sys.exit(f"phase {a.phase} non commencée")
    ph.update(fin=int(time.time()), duree_s=int(time.time()) - ph["debut"], note=a.note)
    if a.phase != "A":
        apres = [x for ip in ph["ip"].split(",") for x in api(f"/adblock-tv/export?client={ip.strip()}")["lignes"]]
        ph["lignes"] = difference(releve_vers_dict(ph.pop("avant")), releve_vers_dict(apres))
        ph["resume"] = resumer(ph["lignes"])
    sauver(d)
    print(f"phase {a.phase} terminée : " + (json.dumps(ph["resume"], ensure_ascii=False) if ph.get("resume") else "pas de mesure côté box"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
