# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3921 tâche 5 — vue « Paysage » : vérifications statiques et disposition (node), sans navigateur."""
import ipaddress
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

DS = Path(__file__).resolve().parent.parent
PAGE = DS / "www" / "datascope" / "index.html"
REPERES = DS / "www" / "datascope" / "reperes.js"
REPERES_REF = DS.parent / "secubox-waf-ng" / "www" / "actor" / "reperes.js"
ID = re.compile(r"^[a-z_]+:[A-Za-z0-9:._-]{1,160}$")


def _page():
    return PAGE.read_text(encoding="utf-8")


def _script():
    blocs = re.findall(r"<script>(.*?)</script>", _page(), flags=re.S)
    assert len(blocs) == 1, "un seul script en ligne attendu"
    return blocs[0]


def _entre(debut, fin):
    s = _script()
    i = s.index(debut)
    return s[i:s.index(fin, i)]


def _fonction(nom):
    return _entre(f"function {nom}(", "\n  }")


def _vue():
    return _entre("// <paysage>", "// </paysage>")


def _node(programme):
    node = shutil.which("node")
    if not node:
        pytest.skip("node absent")
    r = subprocess.run([node, "-e", programme], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_reperes_identiques():
    if not REPERES_REF.exists():
        pytest.skip("reperes.js de #3919 (secubox-waf-ng, www/actor) pas encore sur la branche")
    assert REPERES.read_bytes() == REPERES_REF.read_bytes()
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in REPERES.read_text(encoding="utf-8")[:200]


def test_vue_paysage_presente():
    p, s = _page(), _script()
    assert '<button type="button" class="bt" id="vuePaysage" aria-pressed="false">Paysage</button>' in p
    for attendu in ("function rendrePaysage(box,instantane,difference)", "SbxReperes.", "choisirVue('paysage')",
                    "jget('paysage')"):
        assert attendu in s, attendu
    # reperes.js chargé comme le menu commun : createElement, jamais une balise <script src>
    assert re.search(r"createElement\('script'\).{0,160}src='reperes\.js'", s, flags=re.S)
    assert not re.search(r"<script[^>]*\bsrc\s*=", p, flags=re.I)
    assert "v==='paysage'?'paysage':" in s  # vue retenue en sessionStorage


def test_textes_du_reseau_en_textcontent():
    """Noms de population et d'opérateur : influencés par l'attaquant. Aucune chaîne HTML dans toute la vue."""
    v = _vue()
    for interdit in ("innerHTML", "props(", "outerHTML", "insertAdjacentHTML", "xlink", "foreignObject"):
        assert interdit not in v, interdit
    assert "textContent" in v
    # clés venues des données : jamais lues sur la chaîne de prototypes (« constructor » est une classe permise)
    assert "hasOwnProperty.call" in v
    assert not re.search(r"SbxReperes\.(CLASSES|FAMILLES|ETATS)\[(?!k\])", v)  # [k] : Object.keys de la légende
    r = _node(_entre("function texteSur(", "\n") + _entre("function tronquer(", "\n") + r"""
      process.stdout.write(JSON.stringify([texteSur('a‮b​c\u0007d'),texteSur(null),texteSur(12),
        tronquer('🔁🔁🔁🔁',3),tronquer('abc',3)]));""")
    assert r[0] == "abcd" and r[1] == "" and r[2] == "12"
    assert r[3] == "\U0001f501\U0001f501…" and r[4] == "abc"


def test_noeuds_au_clavier_et_texte_complet():
    v = _vue()
    c = _fonction("noeudPaysage")
    assert "tabindex:'0'" in c and "role:'button'" in c and "'aria-label'" in c and "activer(" in c
    for ev in ("'focus'", "'blur'", "'mouseenter'", "'mouseleave'"):
        assert ev in c, ev
    assert "function infoPaysage(" in v and "tronquer(" in v
    assert "@media (prefers-reduced-motion:reduce)" in _page()


def test_formes_par_type():
    c = _fonction("formePaysage")
    for t in ("population", "campagne", "reseau_source", "classe_reseau", "cible", "cve", "pays", "infra", "autres"):
        assert t in c, t
    v = _vue()
    assert "ETATS.rotation" in v and "halo" in v
    assert re.search(r"P_MASQUES_DEFAUT=\['pays'\]", v)  # pays repliés par défaut


def test_legende_filtrante():
    c = _fonction("rendreLegendePaysage")
    assert "type:'checkbox'" in c
    assert "SbxReperes.puce(" in _fonction("rendreAidePaysage")
    assert "CLE_PTYPES" in _script()
    assert 'id="pLegende"' in _page()


def test_releve_date_partiel_et_perime_en_clair():
    s = _script()
    assert "P_PERIME_S=7200" in s
    c = _fonction("rendreEtatPaysage")
    for t in ("relevé de ", "partiel", "périmé", "plus de 2 h", "cumul par population"):
        assert t in c, t
    assert "relevé des populations indisponible" in s
    assert "'—'" in c or "nombre(" in c  # mesure absente : tiret, jamais 0


def test_fiche_et_liens_d_action_en_lecture():
    v = _vue()
    c = _fonction("inspecterPaysage")
    for lien in ("'/actor/'", "'/waf/'", "'/garde/'", "'/nac/'"):
        assert lien in v, lien
    assert "evolutionPaysage(" in c
    e = _fonction("evolutionPaysage")
    assert "motif_difference_24h" in e and "reference_partiel" in e
    assert "fetch(" not in v and "method" not in v


def test_panneaux_et_largeur():
    p = _page()
    assert re.search(r"\.corps\.vuePaysage #panSources\{display:none", p)
    assert re.search(r"\.topoPan h3\{[^}]*flex-wrap:wrap", p)
    assert "overflow:auto" in p[p.index("  .topo{"):p.index("}", p.index("  .topo{"))]


def _disposition():
    return _entre("// <disposition-paysage>", "// </disposition-paysage>")


MAX_JS = r"""
  function graphe(nbPop,nbRes,nbCib,nbCve,nbClasses){
    var n=[],a=[],i,j;
    for(i=0;i<nbPop;i++){var p='pop:famille:p'+i;n.push({id:p,type:'population',libelle:'cible-'+i,famille:'collecte',metriques:{adresses:1000-i,rotation:i%4===0}});
      n.push({id:'camp:sig'+i,type:'campagne',libelle:'sig'+i,metriques:{}});a.push({de:'camp:sig'+i,vers:p,type:'MEMBRE_DE',poids:1});
      for(j=0;j<nbRes;j++){var r='asn:'+(64496+i*nbRes+j);n.push({id:r,type:'reseau_source',libelle:'Opérateur '+r,classe:'hebergeur',metriques:{}});a.push({de:r,vers:p,type:'SOURCE_DE',poids:1+j*7});}
      for(j=0;j<nbClasses;j++){var k='classe:p'+i+':c'+j;n.push({id:k,type:'classe_reseau',libelle:'c'+j,classe:'acces',metriques:{}});a.push({de:k,vers:p,type:'SOURCE_DE',poids:3});}
      n.push({id:'pays:A'+String.fromCharCode(65+i),type:'pays',libelle:'A'+String.fromCharCode(65+i),metriques:{}});a.push({de:p,vers:'pays:A'+String.fromCharCode(65+i),type:'ORIGINE',poids:50});}
    for(i=0;i<nbCib;i++){n.push({id:'cible:c'+i,type:'cible',libelle:'c'+i,metriques:{}});a.push({de:'pop:famille:p'+(i%nbPop),vers:'cible:c'+i,type:'VISE',poids:1});a.push({de:'cible:c'+i,vers:'infra:box',type:'HEBERGE',poids:1});}
    for(i=0;i<nbCve;i++){n.push({id:'cve:CVE-2099-'+(1000+i),type:'cve',libelle:'CVE-2099-'+(1000+i),metriques:{}});a.push({de:'pop:famille:p'+(i%nbPop),vers:'cve:CVE-2099-'+(1000+i),type:'EXPLOITE',poids:1});}
    n.push({id:'infra:box',type:'infra',libelle:'box',metriques:{}},{id:'autres:populations',type:'autres',libelle:'+ 3 autres',metriques:{repliees:3}},{id:'autres:noeuds',type:'autres',libelle:'+ 9 autres',metriques:{repliees:9}});
    return {noeuds:n,aretes:a};
  }
"""


def test_disposition_taille_reelle_lisible():
    r = _node(_disposition() + MAX_JS + r"""
      var g=graphe(12,8,60,20,3),L=disposerPaysage(g.noeuds,g.aretes,['pays']),M=disposerPaysage(g.noeuds.slice().reverse(),g.aretes.slice().reverse(),['pays']);
      var ids=Object.keys(L.pos),min=1e9,trop=0;
      ids.forEach(function(a,i){ids.slice(i+1).forEach(function(b){var p=L.pos[a],q=L.pos[b],dx=Math.abs(p.x-q.x),dy=Math.abs(p.y-q.y);
        if(dx<110&&dy<48)trop++;});});
      process.stdout.write(JSON.stringify({egal:JSON.stringify(L)===JSON.stringify(M),n:ids.length,total:g.noeuds.length,trop:trop,W:L.W,H:L.H,
        dehors:ids.filter(function(i){var p=L.pos[i];return p.x<30||p.x>L.W-30||p.y<30||p.y>L.H-30;}),
        col:ids.reduce(function(o,i){var t=i.split(':')[0];o[t]=o[t]||[1e9,-1e9];o[t][0]=Math.min(o[t][0],L.pos[i].x);o[t][1]=Math.max(o[t][1],L.pos[i].x);return o;},{}),
        ep:L.liens.map(function(l){return l.e;}),vise:L.liens.filter(function(l){return l.type==='VISE';}).map(function(l){return l.e;}),
        src:L.liens.filter(function(l){return l.type==='SOURCE_DE';}).map(function(l){return [l.poids,l.e];}),
        nan:/NaN|Infinity|undefined/.test(JSON.stringify(L)),colonnes:L.colonnes.map(function(c){return c.t;}),pays:ids.filter(function(i){return i.indexOf('pays:')===0;}).length}));""")
    assert r["egal"], "mêmes entrées dans un autre ordre : même disposition"
    assert r["n"] == r["total"] - 12 and r["pays"] == 0  # tout est placé sauf les pays, repliés
    assert r["trop"] == 0, "deux libellés se chevauchent"
    assert r["dehors"] == [] and not r["nan"]
    assert r["W"] <= 1200 and r["H"] <= 2900
    c = r["col"]
    assert max(c["asn"][1], c["classe"][1]) < c["pop"][0] <= c["camp"][1] < c["cible"][0]
    assert max(c["cible"][1], c["cve"][1]) < c["infra"][0]
    assert min(r["ep"]) >= 1 and max(r["ep"]) <= 6
    assert set(r["vise"]) == {1}  # poids uniformes : trait fin, pas 6 px partout
    assert [1, 1] in r["src"] and [50, 6] in r["src"]
    assert r["colonnes"] == ["RÉSEAUX SOURCES", "POPULATIONS ET CAMPAGNES", "CIBLES ET CVE", "INFRASTRUCTURE"]


def test_disposition_cas_limites():
    r = _node(_disposition() + MAX_JS + r"""
      var v=disposerPaysage([],[],[]),g=graphe(1,1,1,0,0),u=disposerPaysage(g.noeuds,g.aretes,[]),
        t=disposerPaysage(g.noeuds,g.aretes,['population','cible']),
        x=disposerPaysage([{id:'pop:a',type:'population'},{id:'zzz:b',type:'inconnu'},null,{id:'asn:1',type:'reseau_source',metriques:null}],
          [{de:'asn:1',vers:'pop:a',type:'SOURCE_DE',poids:'x'},{de:'asn:1',vers:'pop:absent',type:'SOURCE_DE',poids:1},null],[]);
      process.stdout.write(JSON.stringify({v:Object.keys(v.pos).length,u:Object.keys(u.pos).length,n:g.noeuds.length,
        t:Object.keys(t.pos),tl:t.liens.length,x:Object.keys(x.pos).sort(),xl:x.liens.map(function(l){return l.e;}),nan:/NaN|Infinity/.test(JSON.stringify([v,u,t,x]))}));""")
    assert r["v"] == 0 and r["u"] == r["n"] and not r["nan"]
    assert not any(i.startswith(("pop:", "cible:")) for i in r["t"]) and r["tl"] == 0
    assert r["x"] == ["asn:1", "pop:a"] and r["xl"] == [1]


def _demo():
    s = _script()
    i = s.index("var DEMO_DONNEES=(function(){")
    j = s.index("\n  })();", i) + len("\n  })();")
    return _node(s[i:j] + "process.stdout.write(JSON.stringify(DEMO_DONNEES.paysage));")


def test_demo_paysage():
    d = _demo()
    assert d["disponible"] is True and isinstance(d["age_s"], (int, float)) and d["epoch"] == d["instantane"]["epoch"]
    i = d["instantane"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", i["ts"]) and i["partiel"] in (True, False)
    assert set(i["compteurs"]) == {"populations", "rotation", "reseaux", "adresses", "cibles", "bans", "cves"}
    noeuds = {n["id"]: n for n in i["graphe"]["noeuds"]}
    types = {n["type"] for n in noeuds.values()}
    assert types == {"population", "campagne", "reseau_source", "classe_reseau", "cible", "cve", "pays", "infra",
                     "autres"}
    assert all(ID.match(k) for k in noeuds)
    assert all(a["de"] in noeuds and a["vers"] in noeuds for a in i["graphe"]["aretes"])
    assert {a["type"] for a in i["graphe"]["aretes"]} == {"SOURCE_DE", "VISE", "MEMBRE_DE", "EXPLOITE", "HEBERGE",
                                                          "ORIGINE"}
    assert any(n["metriques"].get("rotation") for n in noeuds.values() if n["type"] == "population")
    j = d["difference_24h"]
    for k in ("apparus", "disparus", "hausses", "baisses", "rotation_levee", "rotation_tombee", "tronque",
              "reference_ts", "reference_epoch", "reference_partiel", "ecart_s"):
        assert k in j, k
    # aucune adresse ; ASN de documentation (RFC 5398) ; cibles en .test ou .example ; CVE fictives
    texte = json.dumps(d)
    assert not re.search(r"\d{1,3}(\.\d{1,3}){3}", texte)
    for mot in re.findall(r"[0-9A-Fa-f:]{3,}", texte):
        if mot.count(":") >= 2:
            with pytest.raises(ValueError):
                ipaddress.ip_address(mot)
    for k, n in noeuds.items():
        if n["type"] == "reseau_source":
            assert 64496 <= int(k.split(":")[1]) <= 64511, k
        if n["type"] == "cible":
            assert k.endswith((".test", ".example")), k
        if n["type"] == "cve":
            assert k.startswith("cve:CVE-2099-"), k


def test_couper_les_lignes_d_infobulle():
    r = _node(_fonction_js("couper") + "process.stdout.write(JSON.stringify([couper('aa bb cc',5),couper('abcdefgh ij',3),"
              "couper('',5)]));")
    assert r == [["aa bb", "cc"], ["abc", "def", "gh", "ij"], []]


def _fonction_js(nom):
    return _entre(f"  function {nom}(", "\n  function ")


def test_densite_aurora_12bis():
    """Place au graphe : tuiles de topologie et sources masquées, une ligne d'en-tête, légende sur une ligne, secondaire
    replié avec son chiffre clé ; emplacements de la tâche 6 (barre basse, tendance de la fiche)."""
    p, s = _page(), _script()
    for attendu in ('id="pBarre"', '<details class="pAide" id="pAide"', "id:'pTendance'", "el('tuiles').hidden=pg"):
        assert attendu in p, attendu
    assert p.index('id="pEtat"') < p.index("</h3><div class=\"topoCorps\">")  # l'état tient dans la ligne de titre
    assert re.search(r"\.pLegende fieldset\{[^}]*flex-wrap:nowrap[^}]*overflow-x:auto", p)
    assert "classesEmpilees(" in s and "replie(" in _fonction("inspecterPaysage")
    css = p[p.index("/* vue Paysage (#3921)"):p.index("dl.props{display:grid")]
    tailles = [float(t) for t in re.findall(r"font-size:([0-9.]+)rem", css)]
    assert tailles and min(tailles) >= .85
    assert re.search(r"svg\.paysage text\{font-size:13\.6px", css) and "8.5px" not in css and "font-size:10px" not in css
