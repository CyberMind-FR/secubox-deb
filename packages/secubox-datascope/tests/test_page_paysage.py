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
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secubox_datascope.difference import difference  # noqa: E402

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
      process.stdout.write(JSON.stringify([texteSur('a\u202eb\u200bc\u0007\u061c\u00add'),texteSur(null),texteSur(12),
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
    for t in ("relevé de ", "partiel", "périmé", "plus de 2 h"):
        assert t in c, t
    assert "cumul par population" in _fonction("rendreCompteurs")  # une adresse vue dans deux populations compte deux fois
    assert "relevé des populations indisponible" in s
    assert "'—'" in c or "nombre(" in c  # mesure absente : tiret, jamais 0


def test_fiche_et_liens_d_action_en_lecture():
    v = _vue()
    c = _fonction("inspecterPaysage")
    for lien in ("'/actor/'", "'/waf/'", "'/garde/'", "'/nac/'"):
        assert lien in v, lien
    assert "evolutionPaysage(" in c
    e = _fonction("evolutionPaysage")
    assert "a.motif" in e and "reference_partiel" in e and "motif_difference_24h" in _fonction("affichePaysage")
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
    return _node(_difference_js() + s[i:j] + "process.stdout.write(JSON.stringify(DEMO_DONNEES.paysage));")


def _difference_js():
    return _entre("// <difference-paysage>", "// </difference-paysage>")


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


def test_mots_de_rotation_et_dictionnaires_sans_prototype():
    e = _fonction("evolutionPaysage")
    assert "apparue depuis la référence" in e and "terminée depuis la référence" in e
    assert "levée" not in e and "retombée" not in e
    assert "paysage.noeuds=Object.create(null)" in _fonction("indexerPaysage")
    assert "var N=Object.create(null)" in _fonction("disposerPaysage")
    assert "noeuds:{}" not in _vue()


def test_cle_identifie_l_instantane_dessine():
    c = _fonction("rendrePaysage")
    assert "paysage.cle=clePaysage(" in c  # posée par le dessin lui-même, pas par l'appelant
    assert "instantane.ts" in _fonction("clePaysage")
    assert "indexerPaysage(" not in _fonction("prendrePaysage") or "rejoue" in _fonction("prendrePaysage")
    assert "paysage.lu" not in _fonction("inspecter")


# --- tâche 6 : compteurs à histogrammes, tendance, synthèse et fil ------------------------------------------------

def test_tache6_fonctions_et_bascule():
    p, s = _page(), _script()
    for f in ("function rendreCompteurs(chronologie,maintenantTs)", "function rendreTendance(noeud,points)",
              "function rendreSynthese(instantane,difference)"):
        assert f in s, f
    assert "['24h','24 h']" in s and "['7j','7 j']" in s and "'aria-pressed'" in _fonction("rendreCompteurs")
    assert "'paysage/chronologie?de='" in s and "'paysage/tendance/'" in s and "differences=12" in s
    # barre basse : sous le graphe ET l'inspecteur, pleine largeur du cadre
    assert p.index('id="panInsp"') < p.index('id="pBarre"') < p.index('Lecture seule · chaque relation')
    assert re.search(r"\.pBarre\{[^}]*grid-column:1/-1", p)
    for k in ("populations", "rotation", "reseaux", "adresses", "cibles", "bans", "cves"):
        assert re.search(r"P_COMPTEURS=\[.*\['" + k + "'", s), k


def test_tache6_histogrammes_et_fleches():
    h = _fonction("histoPaysage")
    assert "s('title'" in h and "texteCase(" in h and "tabindex:'0'" in h and "ArrowLeft" in _fonction("lectureHisto")
    t = _entre("// <series-paysage>", "// </series-paysage>")
    assert "▲" in t and "▼" in t and "non mesuré" in t and "innerHTML" not in t


def test_tache6_synthese_deterministe():
    """Aucun texte libre du serveur : ni motif, ni détail d'erreur ; seulement des identifiants, des nombres et des gabarits."""
    for f in ("rendreSynthese", "rendreFil", "evenementsFil"):
        c = _fonction(f)
        for interdit in ("motif", "detail", "message", "innerHTML"):
            assert interdit not in c, (f, interdit)
    c = _fonction("rendreSynthese")
    for k in ("apparus", "disparus", "hausses", "baisses", "rotation_levee", "rotation_tombee"):
        assert k in c, k
    assert "sans_precedent" in _fonction("rendreFil")


def _series(programme):
    return _node(_entre("function nombre(", "\n") + _entre("// <series-paysage>", "// </series-paysage>")
                 + "var H=3600,T0=Math.floor(1795000000/3600)*3600;" + programme)


def test_series_24h_par_epoques_sans_pas_suppose():
    r = _series(r"""
      var m=T0+1500,P=[],i;
      // relevés irréguliers : toutes les 47 min sur 20 h, trou de 3 h, un partiel, une valeur absente, un relevé futur
      for(i=0;i<26;i++){var e=m-100-i*47*60;if(e>m-9*H&&e<m-6*H)continue;P.push({epoch:e,partiel:i===0,v:{adresses:100+i,bans:i===2?null:0}});}
      P.push({epoch:m+50,partiel:false,v:{adresses:9999}});
      var C=casesPaysage('24h',m),S=seriePaysage(P,'adresses',C,T0-8*86400,m),B=seriePaysage(P,'bans',C,T0-8*86400,m);
      process.stdout.write(JSON.stringify({n:C.length,heures:C.every(function(c){return c.a-c.de===H&&c.de%H===0;}),
        fin:[C[23].de<=m&&m<C[23].a,C[23].courant,C[0].courant],S:S,B:B.map(function(x){return x.etat+':'+x.v;}),
        textes:S.map(function(c){return texteCase(c,'24h','adresses');})}));""")
    assert r["n"] == 24 and r["heures"] and r["fin"] == [True, True, False]
    etats = [c["etat"] for c in r["S"]]
    assert etats[-1] == "ok" and r["S"][-1]["v"] == 100 and r["S"][-1]["partiel"] is True  # ni le futur, ni un 0
    assert "relevé partiel" in r["textes"][-1] and "en cours" in r["textes"][-1]
    trou = [c for c in r["S"] if c["etat"] == "non_mesure"]
    assert len(trou) >= 2 + 3 and all(c["v"] is None for c in trou)
    assert all(("non mesuré" in t) == (e == "non_mesure") for t, e in zip(r["textes"], etats))
    assert not any(": 0 " in t for t in r["textes"])
    assert "ok:0" in r["B"]  # un zéro mesuré reste un zéro


def test_series_valeur_absente_non_chargee_et_noeud_absent():
    r = _series(r"""
      var m=T0+1500,C=casesPaysage('24h',m),P=[{epoch:T0+10,partiel:false,v:{adresses:null}},{epoch:T0-H+10,partiel:false,v:{}},
        {epoch:T0-2*H+10,partiel:false,v:{adresses:4}},{epoch:T0-2*H+900,partiel:false,v:{adresses:'12'}},{epoch:T0-3*H+5,partiel:false,v:null}];
      var S=seriePaysage(P,'adresses',C,T0-10*H,m,[T0-4*H+20]);
      process.stdout.write(JSON.stringify([S.map(function(x){return x.etat;}).reverse(),S[21].v,texteCase(S[19],'24h','adresses'),texteCase(S[23],'24h','adresses'),texteCase(S[0],'24h','adresses')]));""")
    assert r[0][:5] == ["vide", "vide", "ok", "vide", "absent"] and r[1] == 4
    assert r[0][5:10] == ["non_mesure"] * 5 and set(r[0][11:]) == {"non_charge"}
    assert "absent du relevé" in r[2] and "mesure absente" in r[3] and "non chargé" in r[4]


def test_series_7j_jours_locaux_et_dernier_releve_du_jour():
    r = _series(r"""
      process.env.TZ='Europe/Paris';
      var m=new Date(2026,9,27,15,0,0).getTime()/1000,C=casesPaysage('7j',m),P=[];   // passage à l'heure d'hiver le 25/10/2026
      for(var i=0;i<60;i++)P.push({epoch:m-i*H,partiel:false,v:{adresses:1000-i}});
      var S=seriePaysage(P,'adresses',C,m-8*86400,m);
      process.stdout.write(JSON.stringify({n:C.length,duree:C.map(function(c){return (c.a-c.de)/H;}),suite:C.every(function(c,i){return !i||C[i-1].a===c.de;}),
        v:S.map(function(x){return x.v;}),e:S.map(function(x){return x.etat;}),t:texteCase(S[6],'7j','adresses')}));""")
    assert r["n"] == 7 and r["duree"] == [24, 24, 24, 24, 25, 24, 24] and r["suite"]
    assert r["e"][:4] == ["non_mesure"] * 4 and r["e"][4:] == ["ok"] * 3 and r["v"][6] == 1000
    assert r["v"][5] == 1000 - 16 and "en cours" in r["t"]  # dernier relevé de la veille : 23 h


def test_ecart_seulement_si_les_deux_points_existent():
    r = _series(r"""
      var m=T0+100,e=T0,p=function(dt,v,part){return {epoch:e+dt,partiel:!!part,v:{adresses:v}};},L=[
        ecartPaysage([p(0,50),p(-86400+1700,40),p(-86400-900,30),p(-3600,9)],'adresses','24h',m),
        ecartPaysage([p(0,50),p(-86400+7300,40)],'adresses','24h',m),ecartPaysage([p(0,50),p(-86400,null)],'adresses','24h',m),
        ecartPaysage([p(0,null),p(-86400,3)],'adresses','24h',m),ecartPaysage([],'adresses','24h',m),
        ecartPaysage([p(0,20),p(-7*86400+3000,80,true)],'adresses','7j',m),ecartPaysage([p(0,5),p(-86400,5)],'adresses','24h',m)];
      process.stdout.write(JSON.stringify([L,L.map(function(x){return texteEcart(x).t;}),texteEcart(L[0]).titre,texteEcart(L[1]).titre,texteEcart(L[5]).titre]));""")
    e = r[0]
    assert (e[0]["de"], e[0]["a"], e[0]["partiel"]) == (30, 50, False)  # le plus proche de la même heure la veille
    assert r[1] == ["▲ +20", "—", "—", "—", "—", "▼ ≈ −60", "= 0"]
    assert "relevé de " in r[2] and "30 → 50" in r[2] and "24 h plus tôt" in r[2]
    assert "aucun relevé" in r[3] and "± 2 h" in r[3] and "partiel" in r[4] and "7 j plus tôt" in r[4]


def test_anneau_de_part_bannie_sur_les_populations():
    c = _fonction("formePaysage")
    assert "'anneauBan'" in c and "partBannie(" in c and "pathLength:100" in c
    r = _node(_entre("function metr(", "\n") + _entre("function partBannie(", "\n") + r"""
      process.stdout.write(JSON.stringify([{adresses:200,bans:50},{adresses:0,bans:0},{adresses:10},{bans:3},{adresses:10000,bans:1},
        {adresses:10000,bans:9999},{adresses:5,bans:9},{adresses:'5',bans:1}].map(function(m){return partBannie({metriques:m});})));""")
    assert r == [25, None, None, None, 1, 99, 100, None]
    assert "part bannie" in _fonction("descPaysage") and "part bannie" in _fonction("inspecterPaysage")


def test_echap_limite_au_graphe_et_a_l_inspecteur():
    s = _script()
    assert not re.search(r"document\.addEventListener\('keydown'", s)
    assert "['topo','panInsp'].forEach(function(i){el(i).addEventListener('keydown',sortieEchap);})" in s
    assert "defaultPrevented" in _fonction("sortieEchap")


def test_requetes_bornees():
    c = _fonction("chargeChronologie")
    assert "document.hidden" in c and "vue!=='paysage'" in c and "P_RELECTURE_MS" in c
    t = _fonction("chargeTendance")
    assert "ficheVisible()" in t and "P_RELECTURE_MS" in t and "P_TENDANCES_MAX" in t


def test_demo_chronologie_et_tendances():
    s = _script()
    i = s.index("var DEMO_DONNEES=(function(){")
    j = s.index("\n  })();", i) + len("\n  })();")
    d = _node(_difference_js() + s[i:j] + "process.stdout.write(JSON.stringify(DEMO_DONNEES));")
    ch, pay = d["chronologie"], d["paysage"]
    assert ch["instantanes"][-1] == {"ts": pay["instantane"]["ts"], "epoch": pay["epoch"], "partiel": False,
                                     "compteurs": pay["instantane"]["compteurs"]}
    e = [x["epoch"] for x in ch["instantanes"]]
    assert e == sorted(e) and max(b - a for a, b in zip(e, e[1:])) > 2 * 3600 and any(x["partiel"] for x in ch["instantanes"])
    assert len(ch["differences"]) == 12 and [x["epoch"] for x in ch["differences"]] == sorted(
        (x["epoch"] for x in ch["differences"]), reverse=True)
    noeuds = {n["id"]: n for n in pay["instantane"]["graphe"]["noeuds"]}
    for k, t in d["tendances"].items():
        assert noeuds[k]["type"] == "population" and t["points"][-1]["adresses"] == noeuds[k]["metriques"]["adresses"]
    assert "Math.random" not in s


# --- tâche 7 : mode évolution et enregistreur ---------------------------------------------------------------------

def test_tache7_transport_fenetre_comparaison_et_bandeau():
    p, s = _page(), _script()
    for ident, signe, nom in (("eDebut", "⏮", "Rembobiner au début de la fenêtre"), ("ePrec", "◀◀", "Relevé précédent"),
                              ("eLire", "▶", "Lire l’enregistrement"), ("eSuiv", "▶▶", "Relevé suivant"),
                              ("eDirect", "⏭", "Revenir au direct")):
        assert re.search(rf'<button type="button" class="bt" id="{ident}" aria-label="{nom}"[^>]*>{signe}', p), ident
    assert "⏸" in s and "Mettre en pause" in s
    for texte in ("48 h (pas fin)", "30 j (1 h)", ">24 h<", ">7 j<", ">date<", "relevé précédent", "×1", "×4", "×16"):
        assert texte in p, texte
    assert "10 min" not in p  # arbitrage R1 : aucun pas supposé
    for badge in ("✚ apparu", "✖ disparu", "▲ en hausse", "▼ en baisse"):
        assert badge in _fonction("badgesPaysage") + _fonction("noeudPaysage"), badge
    assert "lecture du " in s and 'id="eBandeau"' in p and "prefers-reduced-motion" in s
    assert "var Enregistreur=" in s and "E_CACHE_MAX=60" in s and "E_LOT=12" in s and "AbortController" in s
    for m in ("aller:", "lecture:", "pause:", "pas:", "rembobiner:", "direct:", "vitesse:"):
        assert m in s[s.index("var Enregistreur="):], m
    assert "fetch(" not in _vue() and "'paysage/instantane/'" in s and "'paysage/difference?de='" in s
    # barre de l'enregistreur : au-dessus des compteurs, commandes fixes (jamais refaites : le focus ne bouge pas)
    assert p.index('id="panInsp"') < p.index('id="pEnreg"') < p.index('id="pBarre"')
    assert 'id="eAnnonce" class="horsVue" aria-live="polite"' in p
    assert " disabled" not in p[p.index('id="pEnreg"'):p.index('id="pBarre"')]
    assert "vider(el('pEnreg'))" not in s


def _enreg(programme):
    return _node(_entre("function pNombre(", "\n") + _entre("// <enregistreur-purs>", "// </enregistreur-purs>") + programme)


def test_liste_de_l_enregistreur_sans_pas_suppose():
    r = _enreg(r"""
      var E=1795000000-1795000000%3600,H=3600,L=[],i;
      // relevés irréguliers sur 3 jours (pas de 47 min), un trou de 5 h, des entrées invalides, un doublon, en désordre
      for(i=0;i<92;i++){var e=E-i*47*60;if(e<E-10*H&&e>E-15*H)continue;L.push({ts:'t'+i,epoch:e,partiel:false});}
      var n=L.length,M=L.concat([null,{ts:'x'},{ts:'y',epoch:NaN},{ts:3,epoch:E},{ts:'t0',epoch:E}]);
      var F=listeEnregistreur(M,'48h'),J=listeEnregistreur(M,'30j'),T=trousEnregistreur(F);
      process.stdout.write(JSON.stringify({n:n,f:F.map(function(x){return x.epoch;}),j:J.map(function(x){return x.epoch;}),fin:E,
        dern:[F[F.length-1].ts,J[J.length-1].ts],t:T.filter(Boolean),tl:T.length,ti:T.findIndex(Boolean),
        vide:[listeEnregistreur([],'48h'),trousEnregistreur([]),trousEnregistreur(F.slice(0,2)),listeEnregistreur(L.slice(0,1),'30j').length],
        proche:[indexProche(F,0),indexProche(F,E+9),indexProche(F,F[3].epoch+60),indexProche([],5)]}));""")
    assert r["f"] == sorted(r["f"]) and len(set(r["f"])) == len(r["f"])
    assert r["f"][0] >= r["fin"] - 48 * 3600 and r["f"][-1] == r["fin"]
    assert len({int(e // 3600) for e in r["j"][:-1]}) == len(r["j"]) - 1  # 30 j : un relevé par heure, plus le dernier
    assert r["j"][0] < r["fin"] - 48 * 3600 and r["dern"] == ["t0", "t0"]
    assert len(r["t"]) == 1 and r["t"][0] > 5 * 3600 and r["tl"] == len(r["f"])
    assert r["f"][r["ti"]] - r["f"][r["ti"] - 1] == r["t"][0]
    assert r["vide"] == [[], [], [0, 0], 1]  # un seul intervalle : rien ne permet d'appeler cela un trou
    assert r["proche"] == [0, len(r["f"]) - 1, 3, -1]


def test_reference_de_comparaison_et_duree():
    r = _enreg(r"""
      var E=1795000000,H=3600,D=86400,L=[];for(var i=0;i<20;i++)L.push({ts:'t'+i,epoch:E-i*7*H});
      var f=function(m,d,l,e){var x=referenceComparaison(l||L,e||E,m,d);return x?x.ts:null;};
      process.stdout.write(JSON.stringify([f('24h'),f('7j'),f('date',E-20*H),f('date',E+9*D),f('date',null),f('24h',null,L.slice(0,2)),
        f('24h',null,L.slice(0,3)),f('7j',null,L.slice(0,12)),f('24h',null,[]),f('date',E-99*D),f('24h',null,L,E-6*7*H),
        [60,1800,5400,7200,3.5*H,86400,71*H,7*D].map(dureeTexte)]));""")
    # 24 h : au moins 12 h plus ancien (même règle que l'API) ; 7 j : au moins 3,5 j ; date : le plus proche, strictement antérieur
    assert r[:11] == ["t3", "t19", "t3", "t1", None, None, "t2", None, None, "t19", "t9"]
    assert r[11] == ["1 min", "30 min", "90 min", "2 h", "3 h 30", "24 h", "71 h", "7 j"]


def test_difference_de_la_page_identique_a_celle_du_serveur():
    """Le pas de lecture compare les deux graphes affichés (les demi-heures éclaircies n'ont plus leur différence) : même règle."""
    def g(graine):
        n = [{"id": f"pop:p{i}", "type": "population", "metriques": {
            "adresses": (i * 37 * graine) % 211, "bans": None if i % 5 == graine % 5 else (i * 13 * graine) % 97,
            "reseaux": [3, 3.5, True, "9", 40][(i + graine) % 5], "rotation": [True, False, None, 1][(i * graine) % 4]}}
            for i in range(24) if (i + graine) % 7]
        n += [{"id": f"asn:{i}", "type": "reseau_source"} for i in range(30) if (i * graine) % 3]
        return {"noeuds": n + [None, 4, {"type": "cible"}, {"id": "autres:x" + str(graine), "type": "autres"},
                               {"id": "pop:z", "type": "population", "metriques": "x"}], "aretes": []}
    graphes = [g(i) for i in range(1, 7)] + [{"noeuds": "x"}, {}, None]
    r = _node(_difference_js() + "var G=" + json.dumps(graphes) + """;process.stdout.write(JSON.stringify(G.map(function(a){
      return G.map(function(b){return differencePaysage(a,b);});})));""")
    for i, a in enumerate(graphes):
        for j, b in enumerate(graphes):
            assert r[i][j] == difference(a, b), (i, j)


def test_badges_de_l_evolution():
    r = _node("var RE_PID=/^(pop|camp|asn|classe|cible|cve|pays|infra|autres):[A-Za-z0-9:._-]{1,160}$/;"
              + _entre("function listeDiff(", "\n") + _fonction("badgesPaysage") + "\n  }" + r"""
      var d={apparus:['pop:a','pop:<b>'],disparus:['cve:c',3],hausses:[{id:'pop:h',metrique:'adresses',de:1,a:9},{id:'pop:h',metrique:'bans',de:1,a:9},null],
        baisses:[{id:'pop:h',metrique:'reseaux',de:9,a:1},{id:'pop:b',metrique:'bans',de:9,a:1}]},b=badgesPaysage(d);
      process.stdout.write(JSON.stringify([Object.keys(b).sort(),Object.keys(b).map(function(k){return b[k].map(function(x){return x.t;}).join('+');}),
        Object.keys(badgesPaysage(null)).length,Object.keys(badgesPaysage({apparus:['pop:a'],sans_precedent:'premier'})).length,Object.keys(badgesPaysage({})).length]));""")
    assert r[0] == ["cve:c", "pop:a", "pop:b", "pop:h"]
    assert sorted(r[1]) == ["▲ en hausse+▼ en baisse", "▼ en baisse", "✖ disparu", "✚ apparu"]
    assert r[2:] == [0, 0, 0]


def test_demo_instantanes_de_l_enregistreur():
    s = _script()
    i = s.index("var DEMO_DONNEES=(function(){")
    j = s.index("\n  })();", i) + len("\n  })();")
    d = _node(_difference_js() + s[i:j] + """
      var C=DEMO_DONNEES.chronologie.instantanes;
      process.stdout.write(JSON.stringify({p:DEMO_DONNEES.paysage,d:DEMO_DONNEES.chronologie.differences,c:C,
        i:C.map(function(x){return DEMO_DONNEES.lire(x.ts);}),absent:DEMO_DONNEES.lire('2000-01-01T00:00:00.000000Z')}));""")
    assert d["absent"] is None
    for c, x in zip(d["c"], d["i"]):
        assert (x["ts"], x["epoch"], x["partiel"], x["compteurs"]) == (c["ts"], c["epoch"], c["partiel"], c["compteurs"])
        ids = {n["id"] for n in x["graphe"]["noeuds"]}
        assert all(ID.match(k) for k in ids) and all(a["de"] in ids and a["vers"] in ids for a in x["graphe"]["aretes"])
    assert d["i"][-1]["graphe"] == d["p"]["instantane"]["graphe"]
    par_ts = {x["ts"]: x for x in d["i"]}
    for k, x in enumerate(d["d"]):  # fil, pas de lecture et « 24 h » disent la même chose que les graphes
        av = d["i"][len(d["i"]) - 2 - k]
        attendu = difference(av["graphe"], par_ts[x["ts"]]["graphe"])
        assert {c: x["difference"][c] for c in attendu} == attendu, k
    ref = par_ts[d["p"]["difference_24h"]["reference_ts"]]
    attendu = difference(ref["graphe"], d["i"][-1]["graphe"])
    assert {c: d["p"]["difference_24h"][c] for c in attendu} == attendu
    assert attendu["apparus"] and attendu["disparus"] and attendu["hausses"] and attendu["baisses"] and attendu["rotation_levee"]
