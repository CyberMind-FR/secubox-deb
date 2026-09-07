// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Aide reverse-design de la carte /micro du BBS (externalisée : CSP script-src 'self', #1238-suite).
(function(){
  function post(m){ if(window.parent!==window){ try{window.parent.postMessage(m,'*'); }catch(e){} } }
  var root=document.querySelector('.mw,.mp,.wrap,.micro,.card,main')||document.body;
  if(getComputedStyle(root).position==='static') root.style.position='relative';
  var on=false,tmr=null,nodes=[];
  function zones(){ var out=[],seen=[];
    function add(sel,label){ var e=root.querySelector(sel); if(e&&seen.indexOf(e)<0){seen.push(e);out.push({el:e,label:label});} }
    add('.h,.head,header,.tete,.clh','En-tête — le service et son état');
    add('.kpis','Indicateurs clés');
    add('form,.msg,.compose,.saisie','Saisie — écrire / coller');
    add('.slice.actif,.slices,.stage,.vue,.np,.list,.mlist,.top,.feed,.threads,.fils,.suite,#chat','Contenu vivant');
    add('#slbar,.sbx-bar,.dots,.footbar,.pied,.bas','Barre du bas');
    return out; }
  function clear(){ nodes.forEach(function(n){n.remove();}); nodes=[]; }
  function draw(){ clear(); var rr=root.getBoundingClientRect(), Z=zones();
    Z.forEach(function(x,k){ if(!x.el)return; var r=x.el.getBoundingClientRect(); if(r.width<2||r.height<2)return;
      var ring=document.createElement('div'); ring.className='sbxaide-ring';
      ring.style.left=(r.left-rr.left-2)+'px'; ring.style.top=(r.top-rr.top-2)+'px';
      ring.style.width=(r.width+4)+'px'; ring.style.height=(r.height+4)+'px'; root.appendChild(ring); nodes.push(ring);
      var pin=document.createElement('div'); pin.className='sbxaide-pin'; pin.textContent=(k+1);
      pin.style.left=(r.left-rr.left+10)+'px'; pin.style.top=(r.top-rr.top)+'px'; root.appendChild(pin); nodes.push(pin);
    });
    report(rr,Z); }
  function report(rr,Z){ rr=rr||root.getBoundingClientRect(); Z=Z||zones();
    post({sbx:'aide-zones',slice:'',vw:rr.width,vh:rr.height,
      zones:Z.map(function(x){ if(!x.el)return null; var r=x.el.getBoundingClientRect(); if(r.width<2||r.height<2)return null;
        return {label:x.label,x:r.left-rr.left,y:r.top-rr.top,w:r.width,h:r.height};}).filter(Boolean)}); }
  function show(v){ on=v; if(v){ draw(); if(tmr)clearInterval(tmr); tmr=setInterval(draw,500);} else { if(tmr){clearInterval(tmr);tmr=null;} clear(); } }
  window.addEventListener('message',function(ev){var d=ev.data; if(!d)return; if(d.sbx==='aide')show(!!d.on); else if(d.sbx==='aide?')report();});
  window.addEventListener('resize',function(){ if(on)draw(); });
})();
