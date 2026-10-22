/* SPDX-License-Identifier: LicenseRef-CMSD-1.0
   Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
   Source-Disclosed License — All rights reserved except as expressly granted.
   See LICENCE-CMSD-1.0.md for terms.

   Hall — composants de la vue maître (#2996, phase 2) : window.SbxUI. Fabriques de nœuds DOM, vanilla,
   icônes SVG stroke inline, aucun emoji. Tout texte passe par textContent ; aucun innerHTML de donnée.
   Statut d'un module : active | idle | offline | stale | nosource → pastille et opacité par CSS. */
(function(){
  'use strict';
  var STATUTS={active:['actif','ok'],idle:['en veille','info'],offline:['hors ligne','off'],stale:['données périmées','warn'],nosource:['aucune source','neutre']};
  var ICONES={
    chevron:'<path d="M9 6l6 6-6 6"/>', cpu:'<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
    memoire:'<rect x="3" y="7" width="18" height="10" rx="2"/><path d="M7 7v10M11 7v10M15 7v10"/>', disque:'<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
    reseau:'<path d="M5 12a10 10 0 0 1 14 0M8 15a6 6 0 0 1 8 0"/><circle cx="12" cy="18" r="1.5"/>', radio:'<rect x="3" y="8" width="18" height="12" rx="2"/><circle cx="8" cy="14" r="2.5"/><path d="M14 12h4M14 16h4M7 8l10-5"/>',
    appareil:'<rect x="4" y="4" width="16" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>', telephone:'<rect x="7" y="2" width="10" height="20" rx="2"/><path d="M11 18h2"/>',
    module:'<rect x="4" y="4" width="7" height="7" rx="1.5"/><rect x="13" y="4" width="7" height="7" rx="1.5"/><rect x="4" y="13" width="7" height="7" rx="1.5"/><rect x="13" y="13" width="7" height="7" rx="1.5"/>',
    bouclier:'<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>', globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
    info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>', actualite:'<path d="M4 5h13v14H4zM17 8h3v9a2 2 0 0 1-2 2"/><path d="M7 9h7M7 12h7M7 15h4"/>'
  };
  function ico(nom){ var s=document.createElementNS('http://www.w3.org/2000/svg','svg'); s.setAttribute('class','sbx-ico'); s.setAttribute('viewBox','0 0 24 24'); s.setAttribute('aria-hidden','true'); s.innerHTML=ICONES[nom]||ICONES.module; return s; }
  function el(tag,cls,texte){ var e=document.createElement(tag); if(cls) e.className=cls; if(texte!=null) e.textContent=texte; return e; }
  function statut(s){ return STATUTS[s]||STATUTS.nosource; }
  function hhmmss(d){ return (d||new Date()).toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit',second:'2-digit'}); }
  function ton(pct){ return pct>=90?'off':pct>=75?'warn':'ok'; }
  function octets(o){ var u=['o','Ko','Mo','Go','To'],i=0; while(o>=1024&&i<u.length-1){ o/=1024; i++; } return (i?o.toFixed(o<10?1:0):o)+' '+u[i]; }
  function anciennete(date){
    var s=Math.max(0,(Date.now()-new Date(date).getTime())/1000);
    if(s<60) return 'à l’instant'; if(s<3600) return 'il y a '+Math.floor(s/60)+' min'; if(s<86400) return 'il y a '+Math.floor(s/3600)+' h'; return 'il y a '+Math.floor(s/86400)+' j';
  }

  function Pill(o){ var p=el('span','sbx-pill',o.texte); p.setAttribute('data-ton',o.ton||'neutre'); return p; }

  // `o.hote` (phase 4) : un article existant est HABILLÉ sur place — ses enfants passent dans le corps, sauf les
  // commandes de carte du Hall (poignée, étoile, aide) qui restent à l'article ; rien n'est remplacé.
  function Card(o){
    var c=o.hote||el('article'); c.classList.add('sbx-card'); if(o.id) c.setAttribute('data-module',o.id);
    var tete=el('header','sbx-card-tete'); tete.appendChild(ico(o.icone));
    var h=el('h3','sbx-card-titre',o.titre); tete.appendChild(h);
    var pill=Pill({texte:'',ton:'neutre'}); pill.classList.add('sbx-card-statut'); tete.appendChild(pill);
    if(o.action){
      var a=el(o.action.href?'a':'button','sbx-card-action'); a.setAttribute('aria-label',o.action.label||'Ouvrir '+o.titre); a.title=o.action.label||'Ouvrir';
      if(o.action.href){ a.href=o.action.href; if(o.action.cible) a.target=o.action.cible; if(a.target==='_blank') a.rel='noopener'; } else { a.type='button'; if(o.action.onClick) a.addEventListener('click',o.action.onClick); }
      if(o.action.attrs) Object.keys(o.action.attrs).forEach(function(k){ a.setAttribute(k,o.action.attrs[k]); });
      a.appendChild(ico('chevron')); tete.appendChild(a);
    }
    var corps=el('div','sbx-card-corps'); if(o.corps) corps.appendChild(o.corps);
    if(o.hote){
      Array.prototype.slice.call(c.childNodes).forEach(function(n){
        if(n.nodeType===1&&/(^|\s)(cl-grip|cl-vedette|cl-aide)(\s|$)/.test(n.className||'')) return;
        corps.appendChild(n);
      });
      c.insertBefore(tete,c.firstChild);
    } else c.appendChild(tete);
    c.appendChild(corps);
    var pied=el('footer','sbx-card-pied'); var src=el('span','sbx-source',o.source||''); pied.appendChild(src); var rel=el('span','sbx-releve'); pied.appendChild(rel); c.appendChild(pied);
    c.sbxStatut=function(s){ var d=statut(s); c.setAttribute('data-status',STATUTS[s]?s:'nosource'); pill.textContent=d[0]; pill.setAttribute('data-ton',d[1]); return c; };
    c.sbxReleve=function(date,perime){ rel.textContent=perime?'données périmées · relevé '+hhmmss(date):'Relevé '+hhmmss(date); if(perime) c.sbxStatut('stale'); return c; };
    c.sbxStatut(o.status||'nosource'); if(o.releve) c.sbxReleve(o.releve);
    c.corps=corps;
    return c;
  }

  function StatRing(o){
    var r=el('div','sbx-ring'); r.setAttribute('role','img'); var v=el('span'); r.appendChild(v);
    r.sbxMaj=function(pct,texte){ var p=pct==null?0:Math.max(0,Math.min(100,pct)); r.style.setProperty('--v',p); r.setAttribute('data-ton',pct==null?'neutre':ton(p)); v.textContent=texte!=null?texte:(pct==null?'—':Math.round(p)+'%'); r.setAttribute('aria-label',(o.libelle||'')+' '+v.textContent); return r; };
    return r.sbxMaj(o.valeur,o.texte);
  }

  // Deux séries côte à côte par pas : `a` (entrant / lu, accent) et `b` (sortant / écrit, vert), même échelle.
  function Sparkline(o){
    var n=o.points||24, ul=el('ul','sbx-spark'); ul.setAttribute('role','img'); ul.setAttribute('aria-label',o.libelle||'');
    for(var i=0;i<n;i++){ var li=el('li'); li.appendChild(el('i','a')); li.appendChild(el('i','b')); ul.appendChild(li); }
    ul.sbxMaj=function(a,b){
      a=a||[]; b=b||[]; var max=o.max||Math.max.apply(null,a.concat(b,[1])), lis=ul.children;
      for(var i=0;i<n;i++){ var va=a[a.length-n+i], vb=b[b.length-n+i];
        lis[i].firstChild.style.setProperty('--h',va==null?0:Math.round(100*va/max)); lis[i].lastChild.style.setProperty('--h',vb==null?0:Math.round(100*vb/max));
        lis[i].lastChild.hidden=!b.length; }
      if(o.libelle) ul.setAttribute('aria-label',o.libelle+(a.length?' '+octets(a[a.length-1])+'/s':'')+(b.length?' / '+octets(b[b.length-1])+'/s':''));
      return ul;
    };
    return ul.sbxMaj(o.valeurs||[],o.valeurs2||[]);
  }
  function debit(cls,prefixe,v){ var s=el('span',cls); s.appendChild(el('b',null,prefixe)); s.appendChild(document.createTextNode(' '+octets(v)+'/s')); return s; }

  function Tabs(o){
    var t=el('div','sbx-tabs'); t.setAttribute('role','tablist'); var boutons=[];
    function choisit(id,focus){ boutons.forEach(function(b){ var on=b.getAttribute('data-id')===id; b.setAttribute('aria-selected',on?'true':'false'); b.tabIndex=on?0:-1; if(on&&focus) b.focus(); }); if(o.onChange) o.onChange(id); }
    (o.onglets||[]).forEach(function(g,i){ var b=el('button',null,g.label); b.type='button'; b.setAttribute('role','tab'); b.setAttribute('data-id',g.id); b.id='sbx-tab-'+g.id; b.addEventListener('click',function(){ choisit(g.id); }); boutons.push(b); t.appendChild(b); });
    t.addEventListener('keydown',function(e){ var i=boutons.findIndex(function(b){ return b.getAttribute('aria-selected')==='true'; }); if(e.key==='ArrowRight'||e.key==='ArrowLeft'){ e.preventDefault(); i=(i+(e.key==='ArrowRight'?1:-1)+boutons.length)%boutons.length; choisit(boutons[i].getAttribute('data-id'),true); } else if(e.key==='Home'||e.key==='End'){ e.preventDefault(); choisit(boutons[e.key==='Home'?0:boutons.length-1].getAttribute('data-id'),true); } });
    boutons.forEach(function(b){ b.setAttribute('aria-selected','false'); b.tabIndex=-1; });
    var act=o.actif||(o.onglets&&o.onglets[0]&&o.onglets[0].id); if(act){ boutons.forEach(function(b){ var on=b.getAttribute('data-id')===act; b.setAttribute('aria-selected',on?'true':'false'); b.tabIndex=on?0:-1; }); }
    t.sbxChoisit=choisit; return t;
  }

  function Tile(o){
    var t=el(o.href?'a':'button','sbx-tile'); if(o.href){ t.href=o.href; } else { t.type='button'; if(o.onClick) t.addEventListener('click',o.onClick); }
    t.appendChild(ico(o.icone)); t.appendChild(el('span',null,o.label));
    if(o.status){ var led=el('i','sbx-led'); led.setAttribute('data-ton',statut(o.status)[1]); led.setAttribute('aria-label',statut(o.status)[0]); t.appendChild(led); }
    return t;
  }

  function ModuleTile(o){
    var t=el('button','sbx-mtile'); t.type='button'; if(o.id) t.setAttribute('data-module',o.id); if(o.onClick) t.addEventListener('click',o.onClick);
    t.appendChild(ico(o.icone)); var tx=el('span','tx'); tx.appendChild(el('b',null,o.nom)); tx.appendChild(el('small',null,o.sousTitre||'')); t.appendChild(tx);
    var led=el('i','sbx-led'); led.setAttribute('data-ton',statut(o.status)[1]); led.setAttribute('aria-label',statut(o.status)[0]); t.appendChild(led);
    return t;
  }

  function NewsItem(o){
    var a=el('a','sbx-news'); a.href=o.href||'#'; if(o.cible){ a.target=o.cible; if(o.cible==='_blank') a.rel='noopener'; }
    var vig=el('span','sbx-news-vignette'); vig.setAttribute('aria-hidden','true'); if(o.vignette) vig.style.backgroundImage='url("'+encodeURI(o.vignette).replace(/"/g,'%22')+'")'; a.appendChild(vig);
    var tx=el('span'); tx.appendChild(el('b',null,o.titre)); tx.appendChild(el('span','sbx-news-meta',[o.source,o.date?anciennete(o.date):null].filter(Boolean).join(' · '))); a.appendChild(tx);
    return a;
  }

  function DeviceRow(o){
    var r=el('div','sbx-device'); r.appendChild(ico(o.icone||'appareil'));
    var tx=el('span'); tx.appendChild(el('b',null,o.nom||o.ip));
    var ip=el(o.lien?'a':'span','ip',o.ip||''); if(o.lien){ ip.href=o.lien; ip.target='_blank'; ip.rel='noopener'; } tx.appendChild(ip); r.appendChild(tx);
    r.appendChild(el('span','vu',o.vu?anciennete(o.vu):'')); return r;
  }

  function Hero(o){
    var h=el('section','sbx-hero'); h.setAttribute('aria-label','Tableau de bord');
    var salut=el('div','sbx-hero-salut'); var titre=el('h2'); var date=el('p','sbx-hero-date'); var heure=el('time','sbx-hero-heure'); var radio=el('p','sbx-hero-radio');
    salut.appendChild(titre); salut.appendChild(date); salut.appendChild(heure); salut.appendChild(radio); h.appendChild(salut);
    function stat(lib,ic){ var s=el('div','sbx-hero-stat'); s.appendChild(el('span','sbx-libelle',lib)); return s; }
    var cpu=StatRing({libelle:'Processeur'}), ram=StatRing({libelle:'Mémoire'}), dsk=StatRing({libelle:'Stockage'}), net=Sparkline({libelle:'Réseau',points:24}), es=Sparkline({libelle:'Entrées-sorties disque',points:24});
    var sc=stat('Processeur'), sm=stat('Mémoire'), sd=stat('Stockage'), sn=stat('Réseau'), se=stat('E/S disque');
    var dc=el('span','sbx-detail','—'), dm=el('span','sbx-detail','—'), dd=el('span','sbx-detail','—'), dn=el('span','sbx-detail','—'), de=el('span','sbx-detail','—');
    sc.appendChild(cpu); sc.appendChild(dc); sm.appendChild(ram); sm.appendChild(dm); sd.appendChild(dsk); sd.appendChild(dd); sn.appendChild(net); sn.appendChild(dn); se.appendChild(es); se.appendChild(de);
    h.appendChild(sc); h.appendChild(sm); h.appendChild(sd); h.appendChild(sn); h.appendChild(se);
    var hRx=[], hTx=[], prec=null, hLu=[], hEc=[], precEs=null;
    function pousse(h,v){ h.push(v); if(h.length>24) h.shift(); }
    function deuxDebits(cible,c1,p1,v1,c2,p2,v2){ cible.textContent=''; cible.appendChild(debit(c1,p1,v1)); cible.appendChild(document.createTextNode(' · ')); cible.appendChild(debit(c2,p2,v2)); }
    h.sbxHorloge=function(d){ d=d||new Date(); var hh=d.getHours(); titre.textContent=(hh<5||hh>=18?'Bonsoir':'Bonjour')+(o.nom&&o.nom!=='Invité'?' '+o.nom:''); date.textContent=d.toLocaleDateString('fr-FR',{weekday:'long',day:'numeric',month:'long'}); heure.textContent=d.toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit',second:'2-digit'}); heure.setAttribute('datetime',d.toISOString()); return h; };
    h.sbxNom=function(n){ o.nom=n; return h.sbxHorloge(); };
    h.sbxSysteme=function(d){
      cpu.sbxMaj(d.cpu_pct); dc.textContent=d.charge?'charge '+d.charge[0].toFixed(2)+' · '+d.coeurs+' cœur'+(d.coeurs>1?'s':''):'—';
      if(d.mem){ ram.sbxMaj(d.mem.pct); dm.textContent=octets(d.mem.used_mb*1048576)+' / '+octets(d.mem.total_mb*1048576); }
      if(d.disque){ dsk.sbxMaj(d.disque.pct); dd.textContent=octets(d.disque.used_mb*1048576)+' / '+octets(d.disque.total_mb*1048576); }
      if(d.reseau){ if(prec&&d.reseau.t>prec.t){ var dt=d.reseau.t-prec.t, rx=Math.max(0,(d.reseau.rx_o-prec.rx_o)/dt), tx=Math.max(0,(d.reseau.tx_o-prec.tx_o)/dt);
          pousse(hRx,rx); pousse(hTx,tx); net.sbxMaj(hRx,hTx); deuxDebits(dn,'sbx-in','↓',rx,'sbx-out','↑',tx); } prec=d.reseau; }
      if(d.es){ if(precEs&&d.es.t>precEs.t){ var dte=d.es.t-precEs.t, lu=Math.max(0,(d.es.lu_o-precEs.lu_o)/dte), ec=Math.max(0,(d.es.ecrit_o-precEs.ecrit_o)/dte);
          pousse(hLu,lu); pousse(hEc,ec); es.sbxMaj(hLu,hEc); deuxDebits(de,'sbx-in','lu',lu,'sbx-out','écrit',ec); } precEs=d.es; }
      return h;
    };
    h.sbxRadio=function(titre2,sousTitre){ radio.textContent=''; if(!titre2) return h; radio.appendChild(ico('radio')); var b=el('b',null,titre2); radio.appendChild(b); if(sousTitre) radio.appendChild(el('span',null,' — '+sousTitre)); return h; };
    return h.sbxHorloge();
  }

  window.SbxUI={ico:ico,Pill:Pill,Card:Card,StatRing:StatRing,Sparkline:Sparkline,Tabs:Tabs,Tile:Tile,ModuleTile:ModuleTile,NewsItem:NewsItem,DeviceRow:DeviceRow,Hero:Hero,STATUTS:STATUTS,anciennete:anciennete,octets:octets};
})();
