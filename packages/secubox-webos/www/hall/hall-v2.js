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
  var RUBRIQUES=[
    {id:'accueil',nom:'Accueil',ic:'maison',nav:'accueil'},
    {id:'tableau',nom:'Tableau de bord',ic:'jauge',nav:'accueil',cible:'#tiles'},
    {id:'reseau',nom:'Réseau',ic:'reseau',nav:'systeme',motif:/maillage|réseau|reseau|dns|wireguard|vpn|ipv6|mesh|tor\b|exposition|proxy|hôtes|hotes|lan\b|wan\b/i},
    {id:'securite',nom:'Sécurité',ic:'bouclier',nav:'systeme',motif:/muraille|sécurité|securite|waf|pare-feu|firewall|ban|guardian|coffre|vault|leurre|honeypot|acteur|actor|radar|renseignement|intrusion/i},
    {id:'modules',nom:'Modules',ic:'grille',nav:'systeme'},
    {id:'stockage',nom:'Stockage',ic:'disque',nav:'systeme',motif:/stockage|fichier|cloud|photo|dépôt|depot|torrent|disque|sauvegarde|partage|droplet/i},
    {id:'media',nom:'Média',ic:'media',nav:'systeme',motif:/radio|vidéo|video|peertube|\btv\b|lyrion|musique|podcast|audio|mood|écoute|ecoute|youtube|flux|cinéma|cinema/i},
    {id:'communication',nom:'Communication',ic:'bulle',nav:'systeme',motif:/mail|messag|forum|bbs|chat|voix|voice|social|diffusion|mur\b|gazette|billets|publication|site/i},
    {id:'ia',nom:'IA',ic:'ia',nav:'systeme',motif:/\bia\b|intelligence|zia|lexie|assistant|modèle|modele|llm|vision|oracle/i},
    {id:'outils',nom:'Outils',ic:'outils',nav:'systeme',motif:/outil|toolbox|boîte|boite|surf|viewer|dpi|sonde|ytsas|convert|éphéméride|ephemeride|zigbee|domot|devwatch|compteur/i},
    {id:'systeme',nom:'Système',ic:'systeme',nav:'systeme',motif:/racine|amorce|système|systeme|métrique|metrique|metrics|courbe|journal|paquet|apt\b|noyau|mémoire|memoire|disque|processeur|hub|agrégateur|agregateur|profil|boot|eye/i}
  ];
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
          var actuel=document.querySelector('.sbx-rub.on');
          var deja=actuel&&RUBRIQUES.some(function(r){ return r.id===actuel.getAttribute('data-rub')&&r.nav===v; });
          if(!deja) marque(vues[v]);
          if(v!=='systeme') filtreActif=null;
        }
      });
    });
    Object.keys(vues).forEach(function(v){ var e=document.getElementById('view-'+v); if(e) obs.observe(e,{attributes:true,attributeFilter:['class']}); });
    // Le parc se redessine (registre, sonde) : on réapplique le filtre courant.
    var sb=$('#sysboard'); if(sb) new MutationObserver(function(){ if(filtreActif) filtreParc(filtreActif); }).observe(sb,{childList:true});
  }

  // ── Tiroir (téléphone) ─────────────────────────────────────────────────
  function ouvreTiroir(){ var s=$('.sbx-side'),v=$('.sbx-voile'),m=$('#sbx-menu'); if(!s) return; s.classList.add('ouvert'); if(v) v.classList.add('ouvert'); if(m) m.setAttribute('aria-expanded','true'); }
  function fermeTiroir(){ var s=$('.sbx-side'),v=$('.sbx-voile'),m=$('#sbx-menu'); if(!s) return; s.classList.remove('ouvert'); if(v) v.classList.remove('ouvert'); if(m) m.setAttribute('aria-expanded','false'); }

  // ── Favoris : miroir de la bande (#favbande) ───────────────────────────
  function favoris(){
    var liste=$('.sbx-favlist'), bande=$('#favbande'); if(!liste||!bande) return;
    var cartes=bande.querySelectorAll('.fcard[data-embed], .fcard[data-open]');
    liste.innerHTML='';
    if(!cartes.length){ liste.appendChild(el('p',{'class':'sbx-vide'},'Aucun favori — ★ sur une carte')); return; }
    Array.prototype.forEach.call(cartes,function(c){
      var id=c.getAttribute('data-embed')||c.getAttribute('data-open');
      var t=c.querySelector('h3, .clh b, .t, b'); var nom=(t&&t.textContent.trim())||id;
      var b=el('button',{type:'button','class':'sbx-rub','data-open':id},ico('etoile')+'<span></span>');
      b.lastChild.textContent=nom;
      liste.appendChild(b);   // data-open : la délégation de clic du Hall ouvre le service
    });
  }

  // ── Usager : miroir de #who ────────────────────────────────────────────
  function usager(){
    var u=$('.sbx-usager'); if(!u) return;
    var nom=($('#who-nom')||{}).textContent||'Invité', ligne=($('#who-ligne')||{}).textContent||'';
    u.querySelector('b').textContent=nom.trim();
    u.querySelector('i').textContent=ligne.trim().replace(/^[○●]\s*/,'');
    u.querySelector('.av').textContent=(nom.trim().slice(0,2)||'?').toUpperCase();
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
    var dernier=0;
    function sonde(){
      if(document.hidden||vue.classList.contains('hidden')) return;
      fetch('/api/v1/webos/public/systeme',{credentials:'same-origin'}).then(function(r){ return r.ok?r.json():null; }).then(function(d){ if(d){ h.sbxSysteme(d); dernier=Date.now(); h.removeAttribute('data-stale'); } })
        .catch(function(){}).then(function(){ if(dernier&&Date.now()-dernier>10000) h.setAttribute('data-stale','1'); });
      fetch('/api/v1/webos/public/cardlets/radio',{credentials:'same-origin'}).then(function(r){ return r.ok?r.json():null; })
        .then(function(c){ var ok=c&&c.status==='online'&&!c.silence&&c.content; h.sbxRadio(ok?c.content.title:'',ok?c.content.subtitle:''); }).catch(function(){});
    }
    sonde(); setInterval(sonde,5000);
    document.addEventListener('visibilitychange',function(){ if(!document.hidden) sonde(); });
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
    de(); composants(hero);

    // Corps : sidebar + zone principale.
    var corps=el('div',{'class':'sbx-corps'});
    var side=el('aside',{'class':'sbx-side',id:'sbx-side','aria-label':'Navigation du Hall'});
    var nav=el('nav',{'aria-label':'Rubriques'});
    RUBRIQUES.forEach(function(r){
      var b=el('button',{type:'button','class':'sbx-rub','data-rub':r.id},ico(r.ic)+'<span></span>');
      b.lastChild.textContent=r.nom;
      b.addEventListener('click',function(){ va(r); });
      nav.appendChild(b);
    });
    side.appendChild(nav);
    var fav=el('div',{'class':'sbx-favoris'},'<p class="sbx-titre">Favoris</p><div class="sbx-favlist"></div>');
    side.appendChild(fav);
    var us=el('button',{type:'button','class':'sbx-usager','aria-label':'Profil et réglages'},'<span class="av"></span><span class="tx"><b></b><i></i></span>');
    us.addEventListener('click',function(){ fermeTiroir(); var w=$('#who'); if(w) w.click(); });
    side.appendChild(us);
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
