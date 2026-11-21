# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3853 — page Network Cockpit (Aurora) : vérifications statiques, sans navigateur."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parent.parent / "www" / "datascope" / "index.html"


def _page():
    return PAGE.read_text(encoding="utf-8")


def _script():
    blocs = re.findall(r"<script>(.*?)</script>", _page(), flags=re.S)
    assert len(blocs) == 1, "un seul script en ligne attendu"
    return blocs[0]


def test_entete_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in _page()[:400]


def test_marqueurs_aurora():
    p = _page()
    for attendu in ("sbxVue", "onglet:'datascope'", "?demo=1", "?embed=1", "selectionner(",
                    "container-type:inline-size", "/api/v1/datascope/"):
        assert attendu in p, attendu
    assert "min-height:100vh" not in p.replace(" ", "")
    assert "scrollHeight" not in p


def test_routes_de_lecture_citees():
    s = _script()
    for route in ("overview", "sources", "graph", "/context"):
        assert route in s, route
    assert "sbx_token" in s and "Bearer" in s


def test_aucune_dependance_ni_dialogue_ni_ecriture():
    p = _page()
    assert not re.search(r"<script[^>]*\bsrc\s*=", p, flags=re.I), "aucun <script src>"
    for interdit in ("confirm(", "alert(", "prompt("):
        assert interdit not in p, interdit
    assert "lorem" not in p.lower()
    assert not re.search(r"method\s*:\s*['\"](POST|PUT|PATCH|DELETE)", p, flags=re.I)


def test_menu_lateral_hors_embed_et_demo():
    s = _script()
    # le menu commun est chargé par le script lui-même, jamais par une balise <script src>
    assert "/shared/sidebar.js" in s
    assert re.search(r"if\(!EMB&&!DEMO\)", s)


def test_echappement_des_valeurs_api():
    s = _script()
    assert "function esc(" in s
    # toute écriture HTML porte esc( sur la même ligne ; aucune autre voie d'injection
    for ligne in s.splitlines():
        if "innerHTML" in ligne:
            assert "esc(" in ligne, ligne.strip()
    for interdit in ("outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert interdit not in s, interdit


def test_selection_unique():
    s = _script()
    assert re.search(r"var selection\s*=\s*\{id:\s*null,\s*type:\s*null,\s*source:\s*null\}", s)
    # seule selectionner() écrit l'objet de sélection
    ecritures = [m.start() for m in re.finditer(r"\bselection\s*=(?!=)|\bselection\.\w+\s*=(?!=)", s)]
    debut = s.index("function selectionner(")
    fin = s.index("\n  }", debut)
    declaration = s.index("var selection") + 4
    for pos in ecritures:
        assert pos == declaration or debut < pos < fin, s[pos - 40:pos + 40]
    assert "sessionStorage" in s and "try{" in s.replace(" ", "")


def test_topologie_deterministe_et_bornee():
    s = _script()
    assert "MAX_PAR_IF=60" in s
    assert "+ " in s and "last_seen" in s
    assert "Math.random" not in s


def test_actualisation_si_visible():
    s = _script()
    assert "30000" in s and "document.hidden" in s


def test_demo_rfc5737_et_bandeau_orange():
    p, s = _page(), _script()
    assert "DONNÉES DE DÉMONSTRATION" in p
    assert re.search(r"\.demo\{[^}]*var\(--orange\)", p)
    ips = set(re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", s))
    assert ips, "la démonstration montre des adresses"
    for ip in ips:
        assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")), ip


def test_sans_session_bandeau_et_tiret():
    p = _page()
    assert "session requise" in p.lower()
    assert "/login.html" in p
    assert "'—'" in _script()


def test_etat_inconnu_si_source_non_ok():
    s = _script()
    assert "etat_source" in s and "inconnu" in s


def test_pas_de_frise_en_v01():
    p = _page().lower()
    assert "timeline" not in p and "frise" not in p.replace("pas de frise", "")


def test_deux_vues_bulles_par_defaut_et_arbre():
    p, s = _page(), _script()
    for fn in ("function rendreBulles(", "function rendreArbre(", "function disposerBulles(", "function dispositionArbre(",
               "function choisirVue("):
        assert fn in s, fn
    assert re.search(r'<button type="button" class="bt" id="vueBulles" aria-pressed="true">Bulles</button>', p)
    assert re.search(r'<button type="button" class="bt" id="vueArbre" aria-pressed="false">Arbre</button>', p)
    assert "CLE_VUE" in s and "==='arbre'?'arbre':'bulles'" in s  # vue retenue en sessionStorage, bulles par défaut
    # les bulles sont des <circle> ; anneau cyan sur la sélection ; gris si la source n'est pas à jour
    assert "s('circle',{'class':'b'" in s
    assert re.search(r"\.bulles \.nd\.sel circle\.anneau\{stroke:var\(--cyan\)", p)
    assert "inc?'#6f84a8'" in s
    # choisirVue ne touche ni la sélection ni l'inspecteur
    debut = s.index("function choisirVue(")
    corps = s[debut:s.index("\n  }", debut)]
    assert "selection" not in corps and "inspecter" not in corps


def _disposition_js():
    s = _script()
    debut, fin = s.index("// <disposition-bulles>"), s.index("// </disposition-bulles>")
    return s[debut:fin]


def _noeud_js(programme):
    node = shutil.which("node")
    if not node:
        pytest.skip("node absent")
    r = subprocess.run([node, "-e", programme], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_disposition_bulles_deterministe_et_bornee():
    prog = _disposition_js() + r"""
    var n=[{id:'node:box',type:'node',label:'box'},{id:'interface:br-lan',type:'interface',label:'br-lan'},
           {id:'interface:eth2',type:'interface',label:'eth2'},{id:'network:lan',type:'network',label:'lan'},
           {id:'service:waf',type:'service',label:'waf'}],a=[];
    a.push({src:'interface:br-lan',dst:'node:box',type:'BELONGS_TO'},{src:'interface:eth2',dst:'node:box',type:'BELONGS_TO'},
           {src:'service:waf',dst:'node:box',type:'HOSTED_ON'});
    for(var i=0;i<65;i++){var id='device:00:00:5e:00:53:'+(100+i);n.push({id:id,type:'device',label:'d'+i,last_seen:'2026-11-21T10:'+(10+i%50)+':00Z'});
      a.push({src:id,dst:'interface:br-lan',type:'CONNECTS_TO',last_seen:'2026-11-21T10:00:00Z'});}
    n.push({id:'device:00:00:5e:00:53:01',type:'device',label:'zone',last_seen:'2026-11-21T09:00:00Z'});
    a.push({src:'device:00:00:5e:00:53:01',dst:'interface:eth2',type:'CONNECTS_TO'},{src:'device:00:00:5e:00:53:01',dst:'network:lan',type:'BELONGS_TO'});
    n.push({id:'device:00:00:5e:00:53:02',type:'device',label:'sanszone',last_seen:'2026-11-21T09:00:00Z'});
    a.push({src:'device:00:00:5e:00:53:02',dst:'interface:eth2',type:'CONNECTS_TO'});
    var L1=disposerBulles(n,a),L2=disposerBulles(n.slice().reverse(),a.slice().reverse());
    var cles=function(L){return L.liens.map(function(x){return x.src+'|'+x.type+'|'+x.dst;});};
    process.stdout.write(JSON.stringify({egal:JSON.stringify(L1.pos)===JSON.stringify(L2.pos)&&JSON.stringify(cles(L1))===JSON.stringify(cles(L2)),
      box:L1.pos['node:box'],plus:L1.plus.map(function(p){return [p.interface,p.n];}),
      nbDev:Object.keys(L1.pos).filter(function(k){return k.indexOf('device:')===0;}).length,liens:cles(L1),
      rIf:L1.pos['interface:br-lan'].r,rDev:L1.pos['device:00:00:5e:00:53:02'].r,rBox:L1.pos['node:box'].r,
      // libellé du côté opposé au parent : produit scalaire (libellé - bulle) · (bulle - parent) > 0
      sens:Object.keys(L1.pos).filter(function(k){var q=L1.pos[k];return k!=='node:box'&&q.px!==undefined;}).every(function(k){var q=L1.pos[k],
        v=(q.lx-q.x)*(q.x-q.px)+(q.ly-q.y)*(q.y-q.py);return k.indexOf('interface:')===0?v<0:v>0;}),
      libre:Object.keys(L1.pos).every(function(k){return L1.pos[k].libre>0;}),
      gene:Object.keys(L1.pos).filter(function(k){return L1.pos[k].gene;}).length===Object.keys(L2.pos).filter(function(k){return L2.pos[k].gene;}).length}));
    """
    r = _noeud_js(prog)
    assert r["egal"], "mêmes entrées dans un autre ordre : mêmes positions"
    assert r["box"]["x"] == 0 and r["box"]["y"] == 0
    assert r["plus"] == [["interface:br-lan", 5]]          # 65 appareils : 60 dessinés + une bulle « +5 »
    assert r["nbDev"] == 60 + 2
    # appareil sans zone : relié directement à son interface, aucune zone fantôme ; toutes les relations dessinées
    assert "device:00:00:5e:00:53:02|CONNECTS_TO|interface:eth2" in r["liens"]
    assert "device:00:00:5e:00:53:01|BELONGS_TO|network:lan" in r["liens"]
    assert "device:00:00:5e:00:53:01|CONNECTS_TO|interface:eth2" in r["liens"]
    assert "service:waf|HOSTED_ON|node:box" in r["liens"]
    assert r["rBox"] > r["rIf"] > r["rDev"]
    assert r["sens"], "libellé à l'opposé du parent (interface : vers la box, côté libre de sa grappe)"
    assert r["libre"] and r["gene"]


def test_liste_d_appareils_au_doigt():
    p, s = _page(), _script()
    assert 'id="liste"' in p and "function rendreListe(" in s
    debut = s.index("function rendreListe(")
    corps = s[debut:s.index("\n  }", debut)]
    assert "h('button'" in corps and "selectionner(" in corps and "parLastSeen" in corps
    assert re.search(r"\.ligneApp\{[^}]*min-height:44px", p)
    assert "@media (pointer:coarse)" in p  # sous le graphe sur écran tactile
    # rayon de prise minimal à l'écran (22 px) là où la place le permet
    assert re.search(r"22/k", s) and "libre" in s


def test_liens_bulles_hors_tabulation_et_libelle_inconnu():
    s = _script()
    debut = s.index("function rendreBulles(")
    corps = s[debut:s.index("\n  }", debut)]
    assert "tabindex:'-1'" in corps and "tabindex:'0'" not in corps
    assert "' ?'" not in s and "' · inconnu'" in s


def test_ip_de_la_liste_et_ordre_par_date_du_nac():
    """IP d'un appareil : attribut ip, sinon relations BELONGS_TO d'une ip, sinon « IP dans l'inspecteur » si le
    graphe en a écarté, sinon « — ». Ordre : vu_nac décroissant, puis last_seen, puis id."""
    prog = _disposition_js() + r"""
    var N={'device:a':{id:'device:a',type:'device',attributes:{ip:'192.0.2.7<b>'}},'device:b':{id:'device:b',type:'device'},
           'device:c':{id:'device:c',type:'device',attributes:{ip:12}},'ip:192.0.2.9':{id:'ip:192.0.2.9',type:'ip',label:'192.0.2.9'}};
    var A=[{src:'ip:192.0.2.9',dst:'device:b',type:'BELONGS_TO'}];
    var t=[{id:'device:x',attributes:{vu_nac:'2026-11-20'},last_seen:'2026-11-21T10:00:00Z'},
           {id:'device:y',attributes:{vu_nac:'2026-11-21'},last_seen:'2026-11-21T10:00:00Z'},
           {id:'device:z',last_seen:'2026-11-21T10:00:00Z'},{id:'device:w',attributes:{vu_nac:'2026-11-21'},last_seen:'2026-11-21T10:00:00Z'}];
    process.stdout.write(JSON.stringify({a:ipAffichee(N['device:a'],A,N,0),b:ipAffichee(N['device:b'],A,N,5),
      c5:ipAffichee(N['device:c'],A,N,5),c0:ipAffichee(N['device:c'],A,N,0),cu:ipAffichee(N['device:c'],A,N,undefined),
      ordre:t.sort(parLastSeen).map(function(d){return d.id;})}));
    """
    r = _noeud_js(prog)
    assert r["a"] == "192.0.2.7<b>"  # brut : la liste l'écrit en textContent
    assert r["b"] == "192.0.2.9"
    assert r["c5"] == "IP dans l’inspecteur" and r["c0"] == "IP —" and r["cu"] == "IP —"
    assert r["ordre"] == ["device:w", "device:y", "device:x", "device:z"]
    s = _script()
    debut = s.index("function rendreListe(")
    corps = s[debut:s.index("\n  }", debut)]
    assert "ipAffichee(d,A,N," in corps and "ip_hors_vue" in corps and "'IP —'" not in corps
    assert "au jour près" in s
