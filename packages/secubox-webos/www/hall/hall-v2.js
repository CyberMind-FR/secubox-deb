/* SPDX-License-Identifier: LicenseRef-CMSD-1.0
   Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
   Source-Disclosed License — All rights reserved except as expressly granted.
   See LICENCE-CMSD-1.0.md for terms.

   Hall — coque de la vue maître (#2996). Construit sidebar, compléments de topbar et barre
   d'onglets autour du Hall existant, sans toucher à ses cartes ni à sa navigation : les
   rubriques appellent showView() et filtrent la vue du parc. S'active par le flag hall.v2
   de la box (GET /api/v1/webos/public/etat) ou par ?hall=v2 pour ce navigateur. */
(function(){
  'use strict';
  var root=document.documentElement;
  var CLE_CHOIX='sbx.hall.v2', CLE_BOX='sbx.hall.v2.box';
  function lit(k){ try{ return localStorage.getItem(k); }catch(e){ return null; } }
  function ecrit(k,v){ try{ localStorage.setItem(k,v); }catch(e){} }
  function $(s,r){ return (r||document).querySelector(s); }
  function el(tag,attrs,html){
    var e=document.createElement(tag);
    Object.keys(attrs||{}).forEach(function(k){ e.setAttribute(k,attrs[k]); });
    if(html) e.innerHTML=html;
    return e;
  }

  var ICONES={
    menu:'<path d="M4 7h16M4 12h16M4 17h16"/>',
    chevron:'<path d="M9 6l6 6-6 6"/>',
    externe:'<path d="M14 4h6v6M20 4l-9 9"/><path d="M19 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h5"/>',
    globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
    horloge:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    couches:'<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5M3 17l9 5 9-5"/>',
    maison:'<path d="M3 11.5 12 4l9 7.5"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',
    jauge:'<path d="M4 14a8 8 0 0 1 16 0"/><path d="M12 14l4-4"/><circle cx="12" cy="14" r="1.5"/>',
    reseau:'<circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M12 7.5v4M12 11.5 6.5 17M12 11.5l5.5 5.5"/>',
    bouclier:'<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
    grille:'<rect x="4" y="4" width="7" height="7" rx="1.5"/><rect x="13" y="4" width="7" height="7" rx="1.5"/><rect x="4" y="13" width="7" height="7" rx="1.5"/><rect x="13" y="13" width="7" height="7" rx="1.5"/>',
    disque:'<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
    media:'<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M10 9.5v5l4.5-2.5z"/>',
    bulle:'<path d="M21 12a8 8 0 0 1-11.6 7.1L4 20l1-5A8 8 0 1 1 21 12z"/>',
    ia:'<path d="M12 3v3M12 18v3M3 12h3M18 12h3"/><rect x="7" y="7" width="10" height="10" rx="2"/><circle cx="12" cy="12" r="2"/>',
    outils:'<path d="M14.5 6.5a4 4 0 0 0 5 5L9 22l-3-3z"/><path d="M14 4l6 6"/>',
    systeme:'<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
    etoile:'<path d="M12 3.5l2.6 5.4 5.9.8-4.3 4.1 1.1 5.9L12 16.9l-5.3 2.8 1.1-5.9-4.3-4.1 5.9-.8z"/>',
    cloche:'<path d="M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15z"/><path d="M10 20a2 2 0 0 0 4 0"/>',
    dispo:'<rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="8" height="6" rx="1.5"/><rect x="13" y="14" width="8" height="6" rx="1.5"/>',
    theme:'<circle cx="12" cy="12" r="8"/><path d="M12 4a8 8 0 0 1 0 16z" fill="currentColor" stroke="none"/>',
    usager:'<circle cx="12" cy="8.5" r="3.5"/><path d="M4.5 20a7.5 7.5 0 0 1 15 0"/>'
  };
  function ico(n){ return '<svg class="sbx-ico" viewBox="0 0 24 24" aria-hidden="true">'+ICONES[n]+'</svg>'; }

  // Rubriques : vue cible + filtre de la vue du parc. Les motifs lisent le texte des cartes
  // (nom, description, catégorie) ; « Mes modules » (phase 4) remplacera cette heuristique.
  // Les rubriques ouvrent la MOSAÏQUE (tuiles cliquables) filtrée par leur motif ; « Modules » = tout.
  var RUBRIQUES=[
    {id:'accueil',nom:'Accueil',ic:'maison',nav:'accueil'},
    {id:'tableau',nom:'Tableau de bord',ic:'jauge',nav:'accueil',cible:'.sbx-hero'},
    {id:'favoris',nom:'Favoris',ic:'etoile',nav:'mosaique'},
    {id:'services',nom:'Services',ic:'couches',nav:'mosaique'},
    {id:'reseau',nom:'Réseau',ic:'reseau',nav:'mosaique',motif:/maillage|réseau|reseau|dns|wireguard|vpn|ipv6|mesh|tor\b|exposition|proxy|hôtes|hotes|lan\b|wan\b/i},
    {id:'securite',nom:'Sécurité',ic:'bouclier',nav:'mosaique',motif:/muraille|sécurité|securite|waf|pare-feu|firewall|ban|guardian|coffre|vault|leurre|honeypot|acteur|actor|radar|renseignement|intrusion/i},
    {id:'modules',nom:'Modules',ic:'grille',nav:'mosaique'},
    {id:'recents',nom:'Récents',ic:'horloge',nav:'mosaique'},
    {id:'stockage',nom:'Stockage',ic:'disque',nav:'mosaique',motif:/stockage|fichier|cloud|photo|dépôt|depot|torrent|disque|sauvegarde|partage|droplet/i},
    {id:'media',nom:'Média',ic:'media',nav:'mosaique',motif:/radio|vidéo|video|peertube|\btv\b|lyrion|musique|podcast|audio|mood|écoute|ecoute|youtube|flux|cinéma|cinema/i},
    {id:'communication',nom:'Communication',ic:'bulle',nav:'mosaique',motif:/mail|messag|forum|bbs|chat|voix|voice|social|diffusion|mur\b|gazette|billets|publication|site/i},
    {id:'ia',nom:'IA',ic:'ia',nav:'mosaique',motif:/\bia\b|intelligence|zia|lexie|assistant|modèle|modele|llm|vision|oracle/i},
    {id:'outils',nom:'Outils',ic:'outils',nav:'mosaique',motif:/outil|toolbox|boîte|boite|surf|viewer|dpi|sonde|ytsas|convert|éphéméride|ephemeride|zigbee|domot|devwatch|compteur/i},
    {id:'systeme',nom:'Système',ic:'systeme',nav:'mosaique',motif:/racine|amorce|système|systeme|métrique|metrique|metrics|courbe|journal|paquet|apt\b|noyau|mémoire|memoire|disque|processeur|hub|agrégateur|agregateur|profil|boot|eye/i},
    {id:'sites',nom:'Mes sites',ic:'globe',nav:'mosaique'}
  ];
  var ICO_CAT={wall:'bouclier',mind:'ia',mesh:'reseau',auth:'usager',root:'systeme',boot:'jauge'};
  var ONGLETS=['accueil','modules','securite','reseau','systeme'];

  var construit=false, filtreActif=null;

  function showView(v){ if(typeof window.showView==='function') window.showView(v); }

  function filtreParc(rub){
    filtreActif=rub&&rub.motif?rub:null;
    var sb=$('#sysboard'); if(!sb) return;
    var grilles=sb.querySelectorAll('.grid'), total=0;
    Array.prototype.forEach.call(grilles,function(g){
      var visibles=0;
      Array.prototype.forEach.call(g.querySelectorAll('.card'),function(c){
        var ok=!filtreActif||filtreActif.motif.test(c.textContent||'');
        c.hidden=!ok; if(ok) visibles++;
      });
      var tete=g.previousElementSibling;
      if(tete&&tete.classList.contains('sec')) tete.hidden=!visibles;
      g.hidden=!visibles; total+=visibles;
    });
    var n=$('#n-sys'); if(n&&filtreActif) n.textContent=total+' module'+(total>1?'s':'')+' · '+filtreActif.nom;
  }

  function va(rub){
    var q=$('#q'); if(q&&q.value){ q.value=''; }
    Array.prototype.forEach.call(document.querySelectorAll('#sysboard .card'),function(c){ c.style.display=''; });
    if(rub.nav==='mosaique'){ montreMosaique(rub); marque(rub.id); fermeTiroir(); return; }
    showView(rub.nav);
    if(rub.nav==='systeme') filtreParc(rub); else filtreActif=null;
    if(rub.cible){ var c=$(rub.cible); if(c) c.scrollIntoView({block:'start',behavior:'smooth'}); }
    marque(rub.id);
    fermeTiroir();
  }

  function marque(id){
    Array.prototype.forEach.call(document.querySelectorAll('.sbx-rub[data-rub], .sbx-tabbar button[data-rub]'),function(b){
      b.classList.toggle('on',b.getAttribute('data-rub')===id);
    });
  }
  // La navigation existante (logo, mégamenu, recherche) reste maître : on suit l'état des vues.
  function suitLesVues(){
    var vues={accueil:'accueil',systeme:'modules',aide:null,embed:null};
    var obs=new MutationObserver(function(){
      Object.keys(vues).forEach(function(v){
        var e=document.getElementById('view-'+v);
        if(e&&!e.classList.contains('hidden')){
          var mo=document.getElementById('view-mosaique'); if(mo&&!mo.classList.contains('hidden')&&!mosaiqueEnCours) mo.classList.add('hidden');
          if(v==='embed') marqueService();
          var actuel=document.querySelector('.sbx-rub.on');
          var deja=actuel&&RUBRIQUES.some(function(r){ return r.id===actuel.getAttribute('data-rub')&&r.nav===v; });
          if(!deja) marque(vues[v]);
          if(v!=='systeme') filtreActif=null;
        }
      });
    });
    Object.keys(vues).forEach(function(v){ var e=document.getElementById('view-'+v); if(e) obs.observe(e,{attributes:true,attributeFilter:['class']}); });
    // Changement de service ou de rubrique dans le cadre : le Hall redessine #ctx — on resynchronise la sidebar.
    var ctx=document.getElementById('ctx'); if(ctx) new MutationObserver(function(){ var e=document.getElementById('view-embed'); if(e&&!e.classList.contains('hidden')) marqueService(); }).observe(ctx,{childList:true});
    // Le parc se redessine (registre, sonde) : on réapplique le filtre courant.
    var sb=$('#sysboard'); if(sb) new MutationObserver(function(){ if(filtreActif) filtreParc(filtreActif); }).observe(sb,{childList:true});
  }

  // ── Mosaïque : tuiles cliquables des modules (registre) et des sites (metablogizer) ──
  var CLE_RECENTS='sbx.hall.recents', mosaique=null, ongletMosaique='tous', sites=null, sitesT=0, mosaiqueEnCours=false;
  function recents(){ try{ return JSON.parse(localStorage.getItem(CLE_RECENTS)||'[]'); }catch(e){ return []; } }
  function noteRecent(id){ var r=recents().filter(function(x){ return x!==id; }); r.unshift(id); ecrit(CLE_RECENTS,JSON.stringify(r.slice(0,12))); }
  document.addEventListener('click',function(e){ var o=e.target.closest&&e.target.closest('[data-open]'); if(o&&o.getAttribute('data-open')){ noteRecent(o.getAttribute('data-open')); if(acces) accesRapide(); } },true);
  function modules(){
    var reg=window._reg||{}, parStatut={}; ((regDernier&&regDernier.services)||[]).forEach(function(s){ parStatut[s.id]=s; });
    var ids=Object.keys(reg).length?Object.keys(reg):Object.keys(parStatut);
    return ids.map(function(id){ var s=reg[id]||parStatut[id]||{id:id}; var p=parStatut[id]; return {id:id,name:s.name||id,description:s.description||'',category:s.category||'',status:(p&&p.status)||(s.status)||'nosource',vignette:!!((p&&p.vignette)||s.vignette),hote:(typeof window.host==='function'?window.host(s):'')||''}; })
      .sort(function(a,b){ return String(a.name).localeCompare(String(b.name),'fr',{sensitivity:'base'}); });
  }
  // La curation du Hall (FEATURED, ce que listait le menu Services ▾), en ordre alphabétique des libellés (#3007),
  // avec le statut du registre.
  function services(){
    var F=(typeof FEATURED!=='undefined'&&FEATURED)||[], parStatut={}; ((regDernier&&regDernier.services)||[]).forEach(function(s){ parStatut[s.id]=s; });
    var reg=window._reg||{};
    return F.map(function(f){ var p=parStatut[f.id]||reg[f.id]; return {id:f.id,name:f.label||f.id,description:'',category:'',status:(p&&p.status)||'nosource',vignette:!!(p&&p.vignette),hote:f.url||''}; })
      .sort(function(a,b){ return String(a.name).localeCompare(String(b.name),'fr',{sensitivity:'base'}); });
  }
  function filtreModules(liste,onglet){
    if(onglet==='services') return services();
    if(onglet==='recents'){ var r=recents(); return r.map(function(id){ return liste.filter(function(m){ return m.id===id; })[0]; }).filter(Boolean); }
    if(onglet==='favoris'){ var f={}; Array.prototype.forEach.call(document.querySelectorAll('#favbande .fcard[data-embed]'),function(c){ f[c.getAttribute('data-embed')]=1; }); return liste.filter(function(m){ return f[m.id]; }); }
    var rub=RUBRIQUES.filter(function(x){ return x.id===onglet&&x.motif; })[0];
    if(!rub) return liste;
    return liste.filter(function(m){ return rub.motif.test(m.name+' '+m.description+' '+m.category); });
  }
  // Accès rapides d'un service, comme dans les menus Services / Système : ⚙ console admin, ⧉ onglet réel.
  function actions(m){
    var a=el('span',{'class':'sbx-actions'});
    var adm=el('button',{type:'button','data-admin':m.id,title:'Console d’administration de '+m.name,'aria-label':'Administrer '+m.name},ico('systeme'));
    var tab=el('button',{type:'button','data-open':m.id,'data-mode':'tab',title:'Ouvrir '+m.name+' dans un onglet','aria-label':'Ouvrir '+m.name+' dans un onglet'},ico('externe'));
    a.appendChild(adm); a.appendChild(tab); return a;
  }
  function tuileModule(m){
    var w=el('div',{'class':'sbx-mtuile','data-module':m.id,'data-status':m.status});
    var b=el('button',{type:'button','class':'ouvre','data-open':m.id,'data-mode':'embed',title:m.description||m.name});
    if(m.vignette){ var v=el('span',{'class':'vig'}); var im=new Image(); im.alt=''; im.loading='lazy'; im.decoding='async'; im.src='/api/v1/webos/public/vignette/'+encodeURIComponent(m.id); im.addEventListener('error',function(){ v.remove(); }); v.appendChild(im); b.appendChild(v); w.classList.add('avec-vignette'); }
    b.appendChild(svgIco(ICO_CAT[m.category]||'grille'));
    var tx=el('span',{'class':'tx'}); tx.appendChild(el('b',null,m.name)); tx.appendChild(el('small',{'class':'mono'},m.hote||m.id)); b.appendChild(tx);
    w.appendChild(b);
    var led=el('i',{'class':'sbx-led','data-ton':{active:'ok',idle:'info',offline:'off',stale:'warn'}[m.status]||'neutre','aria-label':{active:'actif',idle:'en veille',offline:'hors ligne',stale:'données périmées'}[m.status]||'aucune source'});
    w.appendChild(led); w.appendChild(actions(m)); return w;
  }
  function svgIco(n){ var w=el('span'); w.innerHTML=ico(n); return w.firstChild; }
  function tuileSite(s){
    var a=el('a',{'class':'sbx-stuile',href:'https://'+s.domain+'/',target:'_blank',rel:'noopener',title:s.title||s.name});
    var v=el('span',{'class':'vig'});
    if(s.vignette){ var im=new Image(); im.alt=''; im.loading='lazy'; im.decoding='async'; im.src='/api/v1/metablogizer/site/'+encodeURIComponent(s.name)+'/screenshot'; im.addEventListener('error',function(){ this.remove(); }); v.appendChild(im); }
    else v.appendChild(el('span',{'class':'sans'},(s.title||s.name).slice(0,1).toUpperCase()));
    a.appendChild(v); var tx=el('span',{'class':'tx'}); tx.appendChild(el('b',null,s.title||s.name)); tx.appendChild(el('small',{'class':'mono'},s.domain||'')); a.appendChild(tx); return a;
  }
  function chargeSites(cb){
    if(sites&&Date.now()-sitesT<900000) return cb(sites);
    fetch('/api/v1/metablogizer/public/mosaique',{credentials:'same-origin'}).then(function(r){ return r.ok?r.json():{sites:[]}; })
      .then(function(d){ sites=(d.sites||[]).filter(function(s){ return s.domain; }); sitesT=Date.now(); cb(sites); }).catch(function(){ cb([]); });
  }
  function rendMosaique(){
    if(!mosaique) return; var grille=mosaique.querySelector('.sbx-mosaique'), vide=mosaique.querySelector('.sbx-mosaique-vide'); grille.textContent=''; vide.hidden=true;
    if(ongletMosaique==='sites'){ grille.setAttribute('data-vue','sites'); return chargeSites(function(l){ if(ongletMosaique!=='sites') return; grille.textContent=''; l.forEach(function(s){ grille.appendChild(tuileSite(s)); }); vide.hidden=!!l.length; vide.textContent='Aucun site publié pour l’instant.'; }); }
    grille.setAttribute('data-vue','modules');
    var l=filtreModules(modules(),ongletMosaique); l.forEach(function(m){ grille.appendChild(tuileModule(m)); });
    var compte=mosaique.querySelector('.sbx-mosaique-compte'); if(compte) compte.textContent=l.length?l.length+' module'+(l.length>1?'s':''):'';
    vide.hidden=!!l.length; vide.textContent=ongletMosaique==='favoris'?'Aucun favori — ★ sur une carte de l’accueil.':ongletMosaique==='recents'?'Rien d’ouvert récemment.':'Aucun module dans cette rubrique.';
  }
  function construisMosaique(){
    if(mosaique) return mosaique;
    var main=$('.main'); if(!main||!window.SbxUI) return null;
    mosaique=el('section',{id:'view-mosaique','class':'hidden','aria-label':'Mosaïque des modules'});
    // La sélection vit dans la sidebar (et la barre basse sur téléphone) : pas d'onglets en double ici.
    var tete=el('div',{'class':'sbx-mosaique-tete'}); tete.appendChild(el('h2',{'class':'sbx-mosaique-titre'},'Modules'));
    tete.appendChild(el('span',{'class':'sbx-mosaique-compte mono'},'')); mosaique.appendChild(tete);
    mosaique.appendChild(el('div',{'class':'sbx-mosaique'})); mosaique.appendChild(el('p',{'class':'sbx-mosaique-vide',hidden:''}));
    main.appendChild(mosaique); return mosaique;
  }
  function montreMosaique(rub){
    if(!construisMosaique()) return;
    mosaiqueEnCours=true;
    ['accueil','embed','systeme','aide'].forEach(function(k){ var e=document.getElementById('view-'+k); if(e) e.classList.add('hidden'); });
    if(typeof window.fermeSurf==='function') window.fermeSurf();
    mosaiqueEnCours=false;
    ongletMosaique=(rub&&rub.id!=='modules')?rub.id:'tous';
    mosaique.classList.remove('hidden'); mosaique.querySelector('.sbx-mosaique-titre').textContent=rub&&rub.id!=='modules'?rub.nom:'Modules';
    rendMosaique(); window.scrollTo({top:0});
  }

  // ── Menus liés : rubriques dépliables, module embarqué marqué, sa sous-navigation sous lui ──
  function plie(grp){ grp.querySelector('.sbx-sous').hidden=true; grp.querySelector('.sbx-plier').setAttribute('aria-expanded','false'); }
  function deplie(grp,rub){
    var sous=grp.querySelector('.sbx-sous'); sous.textContent='';
    var l=filtreModules(modules(),rub.id==='modules'?'tous':rub.id);
    // La curation se déplie en entier (c'était le menu Services ▾) ; les rubriques par motif, 14 puis « Tout voir ».
    var plafond=(rub.id==='services'||rub.id==='favoris')?l.length:14;
    l.slice(0,plafond).forEach(function(m){
      var b=el('button',{type:'button','class':'sbx-rub sbx-sous-item','data-open':m.id,'data-mode':'embed','data-status':m.status},'<span></span>');
      b.firstChild.textContent=m.name; var led=el('i',{'class':'sbx-led','data-ton':{active:'ok',idle:'info',offline:'off',stale:'warn'}[m.status]||'neutre'}); b.insertBefore(led,b.firstChild);
      var ligne=el('div',{'class':'sbx-sous-ligne'}); ligne.appendChild(b); ligne.appendChild(actions(m)); sous.appendChild(ligne);
    });
    if(!l.length&&rub.id==='favoris'){ sous.appendChild(el('p',{'class':'sbx-vide'},'Aucun favori — ★ sur une carte de l’accueil')); }
    else if(l.length>plafond||!l.length){ var tout=el('button',{type:'button','class':'sbx-rub sbx-sous-tout'},'<span></span>'); tout.firstChild.textContent=l.length?'Tout voir ('+l.length+')':'Voir la mosaïque'; tout.addEventListener('click',function(){ va(rub); }); sous.appendChild(tout); }
    sous.hidden=false; grp.querySelector('.sbx-plier').setAttribute('aria-expanded','true');
  }
  function rubriqueDe(id){
    var l=modules(); var m=l.filter(function(x){ return x.id===id; })[0]; if(!m) return 'modules';
    var r=RUBRIQUES.filter(function(x){ return x.motif&&x.motif.test(m.name+' '+m.description+' '+m.category); })[0];
    return r?r.id:'modules';
  }
  var serviceMarque=null;
  function marqueService(){
    var s=(typeof _svc!=='undefined')?_svc:null; if(!s||!s.id) return;
    var rid=rubriqueDe(s.id), grp=$('.sbx-grp[data-grp="'+rid+'"]'); if(!grp) return;
    var rub=RUBRIQUES.filter(function(x){ return x.id===rid; })[0];
    if(grp.querySelector('.sbx-sous').hidden||serviceMarque!==s.id) deplie(grp,rub);
    serviceMarque=s.id; marque(rid);
    Array.prototype.forEach.call(document.querySelectorAll('.sbx-sous-item'),function(b){ b.classList.toggle('on',b.getAttribute('data-open')===s.id); });
    Array.prototype.forEach.call(document.querySelectorAll('.sbx-ctx-liste'),function(e){ e.remove(); });
    var item=grp.querySelector('.sbx-sous-item[data-open="'+s.id+'"]'); if(!item) return;
    var liste=el('div',{'class':'sbx-ctx-liste'}); (item.closest('.sbx-sous-ligne')||item).insertAdjacentElement('afterend',liste);
    fetch('/api/v1/webos/public/menu/'+encodeURIComponent(s.id),{credentials:'same-origin'}).then(function(r){ return r.ok?r.json():null; }).then(function(m){
      var items=(m&&m.items)||[]; if(!items.length||!liste.isConnected) return;
      var cur=(typeof _sub!=='undefined')?_sub:null;
      items.slice(0,24).forEach(function(c){ var path=c.path||(c.slug?('/c/'+c.slug):null); if(!path) return;
        var a=el('a',{'class':'sbx-rub sbx-ctx',href:'#','data-ctx':path,'data-ctxt':c.title||c.slug},'<span></span>'); a.firstChild.textContent=c.title||c.slug;
        if(c.threads!=null){ a.appendChild(el('small',{'class':'mono'},String(c.threads))); }
        if(path===cur) a.classList.add('on'); liste.appendChild(a); });
    }).catch(function(){});
  }
  document.addEventListener('click',function(e){ var cx=e.target.closest&&e.target.closest('.sbx-ctx[data-ctx]'); if(!cx) return;
    Array.prototype.forEach.call(document.querySelectorAll('.sbx-ctx'),function(a){ a.classList.toggle('on',a===cx); }); fermeTiroir(); },true);

  // ── Tiroir (téléphone) ─────────────────────────────────────────────────
  function ouvreTiroir(){ var s=$('.sbx-side'),v=$('.sbx-voile'),m=$('#sbx-menu'); if(!s) return; s.classList.add('ouvert'); if(v) v.classList.add('ouvert'); if(m) m.setAttribute('aria-expanded','true'); }
  function fermeTiroir(){ var s=$('.sbx-side'),v=$('.sbx-voile'),m=$('#sbx-menu'); if(!s) return; s.classList.remove('ouvert'); if(v) v.classList.remove('ouvert'); if(m) m.setAttribute('aria-expanded','false'); }

  // ── Favoris : la rubrique suit la bande ★ de l'accueil (#favbande) ; dépliée, elle se redessine à chaque changement ──
  function favoris(){
    var grp=$('.sbx-grp[data-grp="favoris"]'); if(!grp) return;
    var rub=RUBRIQUES.filter(function(x){ return x.id==='favoris'; })[0];
    if(!grp.querySelector('.sbx-sous').hidden) deplie(grp,rub);
    if(mosaique&&!mosaique.classList.contains('hidden')&&ongletMosaique==='favoris') rendMosaique();
    if(acces) accesRapide();
  }

  // ── Usager : miroir de #who, avatar par le pseudo sbxid (secubox-avatar), liens comptes / identité ──
  var pseudoVu=null;
  function usager(){
    var u=$('.sbx-usager'); if(!u) return;
    var nom=($('#who-nom')||{}).textContent||'Invité', ligne=($('#who-ligne')||{}).textContent||'';
    u.querySelector('b').textContent=nom.trim();
    u.querySelector('i').textContent=ligne.trim().replace(/^[○●]\s*/,'');
    var av=u.querySelector('.av'); if(!av.querySelector('img')) av.textContent=(nom.trim().slice(0,2)||'?').toUpperCase();
    avatar();
  }
  function avatar(){
    fetch('/api/v1/sbxid/moi',{credentials:'same-origin',headers:{Accept:'application/json'}}).then(function(r){ return r.ok?r.json():null; })
      .then(function(m){
        var pseudo=m&&m.identite&&m.identite.pseudo; var liens=$('.sbx-usager-liens'); if(liens) liens.hidden=!pseudo;
        if(!pseudo||pseudo===pseudoVu||!/^[A-Za-z0-9._-]{2,64}$/.test(pseudo)) return; pseudoVu=pseudo;
        // Le module avatar dort entre deux usages (scale-to-zero) : on ne lui demande l'image que s'il est en ligne,
        // sinon un 502 par visite — les initiales suffisent.
        return fetch('/api/v1/webos/public/services',{credentials:'same-origin'}).then(function(r){ return r.ok?r.json():null; }).then(function(d){
          var ok=d&&(d.services||[]).some(function(s){ return s.id==='avatar'&&s.health&&s.health.state==='online'; });
          if(!ok) return;
          var img=new Image(); img.alt=''; img.decoding='async';
          img.onload=function(){ [$('.sbx-usager .av'),$('#who .av')].forEach(function(a){ if(!a) return; a.textContent=''; a.appendChild(img.cloneNode()); }); };
          img.src='/api/v1/avatar/par-nom/'+encodeURIComponent(pseudo);
        });
      }).catch(function(){});
  }

  // ── Notifications : miroir du badge du logo ────────────────────────────
  function notifs(){
    var src=$('#logo-notif'), badge=$('#sbx-notif .sbx-badge'); if(!src||!badge) return;
    var n=src.textContent.trim();
    badge.textContent=n; badge.hidden=src.classList.contains('hidden')||!n;
  }

  // ── Pastille d'état ────────────────────────────────────────────────────
  // Le flag se lit même en v1 : c'est lui qui peut poser la coque. La pastille n'existe qu'une fois la coque construite.
  function etat(){
    function pastille(e,txt){ var p=$('#sbx-version'); if(!p) return; p.setAttribute('data-etat',e); p.querySelector('.txt').textContent=txt; }
    fetch('/api/v1/webos/public/etat',{credentials:'same-origin'}).then(function(r){ if(!r.ok) throw new Error(r.status); return r.json(); })
      .then(function(j){
        ecrit(CLE_BOX,j.hall_v2?'1':'0');
        if(j.hall_v2&&lit(CLE_CHOIX)===null&&root.getAttribute('data-hall')!=='v2'){ root.setAttribute('data-hall','v2'); construis(); }
        pastille(j.en_ligne===false?'off':'ok','SecuBox-DEB'+(j.version?' v'+String(j.version).split('-')[0]:'')+' · '+(j.en_ligne===false?'Hors ligne':'En ligne'));
      })
      .catch(function(){ pastille('off','SecuBox-DEB · Hors ligne'); });
  }

  // ── Le dé SecuBox remplace le médaillon (chargé seulement en v2) ───────
  function de(){
    var logo=$('.logo'), med=$('.logo .medaillon'); if(!logo||!med) return;
    function pose(){
      var d=document.createElement('sbx-dice'); d.setAttribute('speed','4'); d.setAttribute('fov','40');
      var mq=matchMedia('(max-width:720px)'), taille=function(){ d.setAttribute('size',mq.matches?'30':'36'); }; taille();
      if(mq.addEventListener) mq.addEventListener('change',taille); else mq.addListener(taille);
      med.replaceWith(d);
      logo.addEventListener('mouseenter',function(){ d.setAttribute('speed','12'); });
      logo.addEventListener('mouseleave',function(){ d.setAttribute('speed','4'); });
    }
    if(customElements.get('sbx-dice')) return pose();
    var s=document.createElement('script'); s.src='/sbx-dice.js'; s.onload=pose; document.head.appendChild(s);
  }

  // ── Hero : salutation, horloge, système (≤ 5 s), titre radio ───────────
  function hero(){
    var vue=document.getElementById('view-accueil'); if(!vue||!window.SbxUI) return;
    var h=window.SbxUI.Hero({nom:(($('#who-nom')||{}).textContent||'').trim()});
    vue.insertBefore(h,vue.firstChild);
    setInterval(function(){ h.sbxHorloge(); },1000);
    var who=$('#who-nom'); if(who) new MutationObserver(function(){ h.sbxNom(who.textContent.trim()); }).observe(who,{childList:true,characterData:true,subtree:true});
    // Sondage à 5 s, recul exponentiel jusqu'à 60 s quand la box ne répond pas, reprise immédiate au retour.
    var dernier=0, PAS=5000, retard=PAS, tm=0;
    function planifie(){ clearTimeout(tm); tm=setTimeout(sonde,retard); }
    function sonde(){
      if(document.hidden||vue.classList.contains('hidden')){ retard=PAS; return planifie(); }
      fetch('/api/v1/webos/public/systeme',{credentials:'same-origin'}).then(function(r){ if(!r.ok) throw new Error(r.status); return r.json(); })
        .then(function(d){ h.sbxSysteme(d); dernier=Date.now(); retard=PAS; h.removeAttribute('data-stale'); })
        .catch(function(){ retard=Math.min(retard*2,60000); })
        .then(function(){ if(dernier&&Date.now()-dernier>2*PAS) h.setAttribute('data-stale','1'); planifie(); });
      fetch('/api/v1/webos/public/cardlets/radio',{credentials:'same-origin'}).then(function(r){ return r.ok?r.json():null; })
        .then(function(c){ var ok=c&&c.status==='online'&&!c.silence&&c.content; h.sbxRadio(ok?c.content.title:'',ok?c.content.subtitle:''); }).catch(function(){});
    }
    sonde();
    document.addEventListener('visibilitychange',function(){ if(!document.hidden){ retard=PAS; sonde(); } });
  }

  // ── Registre : statut typé sur chaque carte, « Relevé HH:MM:SS », veille sans requête ─────────
  var REG_PAS=15000, regRetard=REG_PAS, regTm=0, regDernier=null;
  function hhmmss(ms){ return new Date(ms).toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit',second:'2-digit'}); }
  function veille(c,dort){
    Array.prototype.forEach.call(c.querySelectorAll('iframe'),function(f){
      if(dort){ if(f.getAttribute('src')){ f.setAttribute('data-src',f.getAttribute('src')); f.removeAttribute('src'); } }
      else if(f.getAttribute('data-src')&&!f.getAttribute('src')){ f.setAttribute('src',f.getAttribute('data-src')); f.removeAttribute('data-src'); }
    });
    var note=c.querySelector('.sbx-veille');
    if(dort&&!note){ note=el('div',{'class':'sbx-veille'},'module en veille — aucune requête tant qu’il dort'); (c.querySelector('.ap-vue')||c.querySelector('.sbx-card-corps')||c).appendChild(note); }
    else if(!dort&&note) note.remove();
  }
  // ── Phase 4 : migration des cartes vers Card, dans l'ordre du prompt (Sécurité, DNS, Réseau, État système = Hero,
  // Appareils, Notifications…). Une carte du lot est habillée SUR PLACE (Card avec hôte) : son cardlet reste dans le
  // corps, ses commandes (⠿ ★ ?) à l'article, l'ancien rendu n'est pas retiré. Hors lot : le pied v2 de la phase 3.
  // Lot 1 : Sécurité, DNS, Réseau, Appareils, Notifications. Lot 2 : Flux d'actualités (metanews, ytflux, billets), Radio dock,
  // Mur de discussion (bbs), Éphéméride, Zigbee, DevWatch, ZIA, Mes comptes, Lyrion, Freebox TV, L'écoute (mood), YTSaS.
  var MIGREES=['securite','acteurs','radar','guardian','dpi','ipv6guard','activite',
    'metanews','ytflux','billets','radio','bbs','ephemeride','zigbee','devwatch','zia','comptes','lyrion','freeboxtv','mood','ytsas'];
  var ICO_CARTE={securite:'bouclier',acteurs:'bouclier',radar:'bouclier',guardian:'globe',dpi:'reseau',ipv6guard:'reseau',activite:'actualite',
    metanews:'actualite',ytflux:'film',billets:'billet',radio:'radio',bbs:'bulle',ephemeride:'calendrier',zigbee:'ampoule',devwatch:'satellite',
    zia:'ia',comptes:'cle',lyrion:'musique',freeboxtv:'ecran',mood:'micro',ytsas:'film'};
  // Une carte de curation a un id à elle (pas de module « securite ») : son statut est celui du module qui la sert.
  var SOURCE_STATUT={securite:'waf',acteurs:'actor',radar:'actor',guardian:'ad-guard',activite:'sbxid',ytflux:'ytsas',comptes:'sbxid',mood:'sbxos-audio-mood',freeboxtv:'freebox',
    'mon-coffre':'vault',contenu:'droplet',cloud:'nextcloud',forums:'bbs'};
  function habille(c){
    var id=c.getAttribute('data-embed');
    if(!window.SbxUI||MIGREES.indexOf(id)<0||c.classList.contains('sbx-card')) return;
    var titre=c.getAttribute('data-label')||id, pied=c.querySelector('.sbx-fcard-pied'); if(pied) pied.remove();
    window.SbxUI.Card({hote:c,icone:ICO_CARTE[id]||'module',titre:titre,source:c.getAttribute('data-host')||'',
      action:{label:'Ouvrir '+titre,attrs:{'data-open':id,'data-mode':'embed'}}});
  }
  function habilleCartes(){ Array.prototype.forEach.call(document.querySelectorAll('#featgrid .fcard[data-embed], #favbande .fcard[data-embed]'),habille); }
  // ── Accès rapide (phase 4) : une Card native sous le Hero, huit tuiles au plus vers le service embarqué —
  // les favoris (bande ★), puis les récents, puis la curation ; pastille du statut typé sur chaque tuile.
  var acces=null;
  function libelle(id){ var F=(typeof FEATURED!=='undefined'&&FEATURED)||[]; var f=F.filter(function(x){ return x.id===id; })[0]; if(f) return f.label||id; var r=(window._reg||{})[id]; return (r&&r.name)||null; }
  function statutDe(id){ var p={}; ((regDernier&&regDernier.services)||[]).forEach(function(s){ p[s.id]=s; }); var s=p[id]||p[SOURCE_STATUT[id]]; return (s&&s.status)||'nosource'; }
  function accesRapide(){
    var vue=document.getElementById('view-accueil'); if(!vue||!window.SbxUI) return;
    if(!acces){
      acces=window.SbxUI.Card({id:'acces-rapide',icone:'module',titre:'Accès rapide',source:'favoris · récents · services',status:'active',
        action:{label:'Tous les modules',onClick:function(){ va(RUBRIQUES.filter(function(r){ return r.id==='modules'; })[0]); }}});
      acces.classList.add('sbx-acces');
      var h=vue.querySelector('.sbx-hero'); if(h) h.insertAdjacentElement('afterend',acces); else vue.insertBefore(acces,vue.firstChild);
    }
    var vus={}, ids=[], absents=window.ABSENTS||{has:function(){ return false; }};
    function pousse(id){ if(!id||vus[id]||absents.has(id)||!libelle(id)) return; vus[id]=1; ids.push(id); }
    Array.prototype.forEach.call(document.querySelectorAll('#favbande .fcard[data-embed]'),function(c){ pousse(c.getAttribute('data-embed')); });
    recents().forEach(pousse);
    ((typeof FEATURED!=='undefined'&&FEATURED)||[]).forEach(function(f){ pousse(f.id); });
    var grille=el('div',{'class':'sbx-tiles'});
    ids.slice(0,8).forEach(function(id){ grille.appendChild(window.SbxUI.Tile({icone:ICO_CARTE[id]||'module',label:libelle(id),status:statutDe(id),attrs:{'data-open':id,'data-mode':'embed',title:'Ouvrir '+libelle(id)}})); });
    acces.corps.textContent=''; acces.corps.appendChild(grille); acces.sbxReleve(new Date());
  }
  // ── Flux d'actualités (phase 4) : une Card native qui fusionne MetaNews (sujets), YouTube (listes du compte, session)
  // et Billets (publics) en NewsItem, en tourniquet entre les sources, neuf entrées au plus, relue toutes les 15 min.
  var flux=null, fluxTm=0, FLUX_PAS=15*60*1000;
  function hote(nom){ return (window.SBX_DOMAINE&&typeof SBX_DOMAINE.hote==='function')?SBX_DOMAINE.hote(nom):nom; }
  function lis(url){ return fetch(url,{credentials:'same-origin'}).then(function(r){ return r.ok?r.json():null; }).catch(function(){ return null; }); }
  function fluxActualites(){
    var vue=document.getElementById('view-accueil'); if(!vue||!window.SbxUI) return;
    if(!flux){
      flux=window.SbxUI.Card({id:'flux',icone:'actualite',titre:'Flux d’actualités',source:'MetaNews · YouTube · Billets',status:'nosource',
        action:{label:'Ouvrir MetaNews',attrs:{'data-open':'metanews','data-mode':'embed'}}});
      flux.classList.add('sbx-flux');
      var apres=vue.querySelector('.sbx-acces')||vue.querySelector('.sbx-hero'); if(apres) apres.insertAdjacentElement('afterend',flux); else vue.insertBefore(flux,vue.firstChild);
    }
    clearTimeout(fluxTm); fluxTm=setTimeout(fluxActualites,FLUX_PAS);
    if(document.hidden) return;
    Promise.all([lis('/api/v1/metanews/topics?limit=6'),lis('/api/v1/ytsas/flux?type=abonnements&limite=6'),lis('/api/v1/billets/feed.json')]).then(function(r){
      var mn=((r[0]&&r[0].topics)||[]).map(function(t){ return {titre:t.title,source:'MetaNews'+(t.source_names&&t.source_names.length?' · '+t.source_names.slice(0,2).join(', '):''),
          date:t.updated_at?t.updated_at*1000:null,vignette:t.vignette?'/api/v1/metanews/img?u='+encodeURIComponent(t.vignette):null,href:'https://'+hote('metanews.gk2.secubox.in')+'/'}; });
      var yt=((r[1]&&r[1].items)||[]).map(function(v){ return {titre:v.titre,source:'YouTube'+(v.chaine?' · '+v.chaine:''),date:null,vignette:v.vignette||null,href:v.url}; });
      var bi=((r[2]&&r[2].items)||[]).map(function(b){ var slug=String(b.url||b.id||'').split('/b/')[1]||''; var im=/<img[^>]+src="(\/media\/[^"]+)"/.exec(b.content_html||'');
          return {titre:b.title,source:'Billets',date:b.date_published?Date.parse(b.date_published):null,vignette:im?'https://'+hote('billets.gk2.secubox.in')+im[1]:null,href:'https://'+hote('billets.gk2.secubox.in')+'/b/'+slug}; });
      var files=[mn,yt,bi], liste=[], i=0;
      while(liste.length<9&&files.some(function(f){ return f.length; })){ var f=files[i%3]; if(f.length) liste.push(f.shift()); i++; }
      var sources=[r[0]&&'MetaNews',r[1]&&'YouTube',r[2]&&'Billets'].filter(Boolean);
      flux.corps.textContent='';
      if(!liste.length){ flux.corps.appendChild(el('p',{'class':'sbx-vide'},'aucune source joignable pour l’instant')); flux.sbxStatut('nosource'); return; }
      var grille=el('div',{'class':'sbx-flux-liste'}); liste.forEach(function(n){ n.cible='_blank'; grille.appendChild(window.SbxUI.NewsItem(n)); }); flux.corps.appendChild(grille);
      flux.querySelector('.sbx-source').textContent=sources.join(' · '); flux.sbxStatut('active'); flux.sbxReleve(new Date());
    });
  }
  function appliqueRegistre(d){
    var parId={}; (d.services||[]).forEach(function(s){ parId[s.id]=s; });
    var t=d.computed_at?d.computed_at*1000:Date.now(), iv=(d.intervalle_s||15)*1000, perime=Date.now()-t>2*iv;
    Array.prototype.forEach.call(document.querySelectorAll('.fcard[data-embed]'),function(c){
      habille(c);
      var id=c.getAttribute('data-embed'), s=parId[id]||parId[SOURCE_STATUT[id]], st=(s&&s.status)||'nosource';
      if(perime) c.setAttribute('data-perime','1'); else c.removeAttribute('data-perime');
      if(c.sbxStatut){ c.sbxStatut(st); c.sbxReleve(new Date(t),perime); }
      else {
        c.setAttribute('data-status',st);
        var pied=c.querySelector('.sbx-fcard-pied'); if(!pied){ pied=el('div',{'class':'sbx-fcard-pied'}); c.appendChild(pied); }
        pied.textContent=(perime?'données périmées · relevé ':'Relevé ')+hhmmss(t)+(st==='idle'?' · en veille':'');
      }
      veille(c,st==='idle');
    });
  }
  function planifieRegistre(){ clearTimeout(regTm); regTm=setTimeout(sondeRegistre,regRetard); }
  function sondeRegistre(){
    if(document.hidden){ regRetard=REG_PAS; return planifieRegistre(); }
    fetch('/api/v1/webos/public/services',{credentials:'same-origin'}).then(function(r){ if(!r.ok) throw new Error(r.status); return r.json(); })
      .then(function(d){
        regRetard=REG_PAS;
        // L'affichage n'applique qu'un cache REMPLI (#3011) : une réponse vide laisse le dernier relevé visible (le pied le dira périmé si cela dure).
        if(!(d&&d.services&&d.services.length)&&regDernier){ appliqueRegistre(regDernier); return; }
        regDernier=d; appliqueRegistre(d); if(acces) accesRapide(); if(mosaique&&!mosaique.classList.contains('hidden')&&ongletMosaique!=='sites') rendMosaique(); })
      .catch(function(){ regRetard=Math.min(regRetard*2,60000); if(regDernier) appliqueRegistre(regDernier); })
      .then(planifieRegistre);
  }
  function registre(){
    sondeRegistre();
    document.addEventListener('visibilitychange',function(){ if(!document.hidden){ regRetard=REG_PAS; sondeRegistre(); if(flux) fluxActualites(); } });
    // Le Hall redessine la mosaïque (registre, favoris) : on rhabille et on repose statut et pied sur les nouvelles cartes.
    ['featgrid','favbande'].forEach(function(id){ var z=document.getElementById(id); if(z) new MutationObserver(function(){ habilleCartes(); if(regDernier) appliqueRegistre(regDernier); }).observe(z,{childList:true}); });
  }
  function composants(cb){
    if(window.SbxUI) return cb();
    var s=document.createElement('script'); s.src='/composants.js'; s.onload=cb; document.head.appendChild(s);
  }

  // ── Construction ───────────────────────────────────────────────────────
  function construis(){
    if(construit||root.getAttribute('data-hall')!=='v2') return;
    var shell=$('.shell'), mast=$('.mast-main'), actions=$('.mast-actions'), theme=$('#theme');
    if(!shell||!mast||!actions) return;
    construit=true;

    // Topbar : menu à gauche ; disposition, notifications, pastille à droite.
    var menu=el('button',{type:'button','class':'sbx-ibtn',id:'sbx-menu','aria-label':'Menu','aria-expanded':'false','aria-controls':'sbx-side'},ico('menu'));
    mast.insertBefore(menu,mast.firstChild);
    var dispo=el('button',{type:'button','class':'sbx-ibtn',id:'sbx-dispo','aria-label':'Disposition compacte','aria-pressed':'false',title:'Disposition'},ico('dispo'));
    var notif=el('button',{type:'button','class':'sbx-ibtn',id:'sbx-notif','aria-label':'Notifications',title:'Diffusions du parc'},ico('cloche')+'<span class="sbx-badge" hidden></span>');
    var version=el('span',{'class':'sbx-version',id:'sbx-version','data-etat':'attente',role:'status'},'<span class="led" aria-hidden="true"></span><span class="txt">SecuBox-DEB · …</span>');
    if(theme){ actions.insertBefore(dispo,theme); actions.insertBefore(notif,theme); theme.innerHTML=ico('theme'); theme.insertAdjacentElement('afterend',version); }
    else { actions.appendChild(dispo); actions.appendChild(notif); actions.appendChild(version); }
    var av=$('#who .av'); if(av) av.innerHTML=ico('usager');
    de(); composants(function(){ hero(); habilleCartes(); if(regDernier) appliqueRegistre(regDernier); accesRapide(); fluxActualites(); }); registre();

    // Corps : sidebar + zone principale.
    var corps=el('div',{'class':'sbx-corps'});
    var side=el('aside',{'class':'sbx-side',id:'sbx-side','aria-label':'Navigation du Hall'});
    var nav=el('nav',{'aria-label':'Rubriques'});
    RUBRIQUES.forEach(function(r){
      var b=el('button',{type:'button','class':'sbx-rub','data-rub':r.id},ico(r.ic)+'<span></span>');
      b.lastChild.textContent=r.nom;
      b.addEventListener('click',function(){ va(r); });
      if(r.nav!=='mosaique'||r.id==='sites'||r.id==='recents'){ nav.appendChild(b); return; }
      // Rubrique dépliable : ses modules (registre), ouverts embarqués, puis la sous-navigation du module courant.
      var grp=el('div',{'class':'sbx-grp'+(r.id==='favoris'?' sbx-favoris':''),'data-grp':r.id}); var ligne=el('div',{'class':'sbx-ligne'}); ligne.appendChild(b);
      var pli=el('button',{type:'button','class':'sbx-plier','aria-expanded':'false','aria-label':'Déplier '+r.nom},ico('chevron'));
      var sous=el('div',{'class':'sbx-sous',hidden:''});
      pli.addEventListener('click',function(){ var o=pli.getAttribute('aria-expanded')==='true'; if(o) plie(grp); else deplie(grp,r); });
      ligne.appendChild(pli); grp.appendChild(ligne); grp.appendChild(sous); nav.appendChild(grp);
    });
    side.appendChild(nav);
    var us=el('button',{type:'button','class':'sbx-usager','aria-label':'Profil et réglages'},'<span class="av"></span><span class="tx"><b></b><i></i></span>');
    us.addEventListener('click',function(){ fermeTiroir(); var w=$('#who'); if(w) w.click(); });
    side.appendChild(us);
    // Avec une identité : « Mes comptes » (carte des comptes SSO, dans le Hall) et l'identité SBX OS.
    var liens=el('div',{'class':'sbx-usager-liens',hidden:''});
    var bc=el('button',{type:'button','class':'sbx-rub','data-open':'comptes','data-mode':'embed'},ico('etoile')+'<span>Mes comptes</span>');
    bc.querySelector('svg').innerHTML=ICONES.usager;
    var ai=el('a',{'class':'sbx-rub',href:'/identite/'},ico('bouclier')+'<span>Mon identité</span>');
    liens.appendChild(bc); liens.appendChild(ai); side.appendChild(liens);
    var voile=el('div',{'class':'sbx-voile'});
    voile.addEventListener('click',fermeTiroir);
    shell.parentNode.insertBefore(corps,shell);
    corps.appendChild(side); corps.appendChild(shell);
    document.body.appendChild(voile);

    // Barre d'onglets.
    var tab=el('nav',{'class':'sbx-tabbar','aria-label':'Navigation rapide'});
    ONGLETS.forEach(function(id){
      var r=RUBRIQUES.filter(function(x){ return x.id===id; })[0];
      var b=el('button',{type:'button','data-rub':r.id,'data-nav':r.nav},ico(r.ic)+'<span></span>');
      b.lastChild.textContent=r.nom;
      b.addEventListener('click',function(e){ e.stopPropagation(); va(r); });
      tab.appendChild(b);
    });
    document.body.appendChild(tab);

    // Comportements.
    menu.addEventListener('click',function(){ if(side.classList.contains('ouvert')) fermeTiroir(); else ouvreTiroir(); });
    document.addEventListener('keydown',function(e){ if(e.key==='Escape') fermeTiroir(); });
    var CLE_DENS=(typeof window.cleProfil==='function')?window.cleProfil('densite'):'sbx.hall.densite';
    function poseDensite(c){ if(c) root.setAttribute('data-densite','compact'); else root.removeAttribute('data-densite'); dispo.setAttribute('aria-pressed',c?'true':'false'); }
    poseDensite(lit(CLE_DENS)==='compact');
    dispo.addEventListener('click',function(){ var c=root.getAttribute('data-densite')!=='compact'; poseDensite(c); ecrit(CLE_DENS,c?'compact':'aere'); });
    notif.addEventListener('click',function(){ var src=$('#logo-notif'); if(src&&!src.classList.contains('hidden')) src.click(); else { var w=$('#who'); if(w) w.click(); } });

    // Hauteur réelle de la topbar, pour la sidebar collante et les cadres (--mast-h).
    var m=$('.mast');
    if(m&&'ResizeObserver' in window){ new ResizeObserver(function(){ root.style.setProperty('--mast-h',m.getBoundingClientRect().height+'px'); }).observe(m); }
    else if(m){ root.style.setProperty('--mast-h',m.getBoundingClientRect().height+'px'); }

    favoris(); usager(); notifs(); suitLesVues();
    var fb=$('#favbande'); if(fb) new MutationObserver(favoris).observe(fb,{childList:true});
    var who=$('#who'); if(who) new MutationObserver(usager).observe(who,{childList:true,characterData:true,subtree:true});
    var ln=$('#logo-notif'); if(ln) new MutationObserver(notifs).observe(ln,{attributes:true,childList:true,characterData:true,subtree:true});
    var accueil=document.getElementById('view-accueil');
    marque(accueil&&!accueil.classList.contains('hidden')?'accueil':'modules');
  }

  function demarre(){ construis(); etat(); }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',demarre); else demarre();
})();
