// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Externalisé pour la CSP script-src 'self' (radio/micro, #1238-suite).
(function(){
  var pop=document.createElement('div'); pop.className='radiopop'; document.body.appendChild(pop);
  function esc(t){return String(t==null?'':t).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function at(r){ var w=pop.offsetWidth,h=pop.offsetHeight,m=6;
    var top=r.top-h-m; if(top<m) top=r.bottom+m;
    var left=r.left; if(left+w>innerWidth-m) left=innerWidth-m-w; if(left<m) left=m;
    pop.style.left=left+'px'; pop.style.top=top+'px'; }
  function show(html,el){ pop.innerHTML=html; pop.classList.add('on'); at(el.getBoundingClientRect()); }
  function hide(){ pop.classList.remove('on'); }
  document.addEventListener('mouseover', function(e){
    var li=e.target.closest&&e.target.closest('.file li');
    if(li){ var b=li.querySelector('.nm b'),s=li.querySelector('.nm small'),rg=li.querySelector('.rg');
      show('<b>'+esc(b?b.textContent:'Piste')+'</b>'+(s?(' · '+esc(s.textContent)):'')
        +'<span class="adv">Playlist'+(rg&&rg.textContent?(' · rang '+esc(rg.textContent)):'')+' — elle se répète en favorisant les nouveautés et ce que vous aimez.</span>', li); return; }
    var a2=e.target.closest&&e.target.closest('.attente li');
    if(a2){ var nb=a2.querySelector('.nm b'),v=a2.querySelector('.vote');
      show('<b>'+esc(nb?nb.textContent:'Proposition')+'</b><span class="adv">En attente'+(v&&v.textContent?(' · '+esc(v.textContent.trim())+' ♥'):'')+' — chaque vote la fait monter ; le sysop la valide pour l’antenne.</span>', a2); return; }
    var ch=e.target.closest&&e.target.closest('#chat > *');
    if(ch){ show('<b>💬 Message d’antenne</b><span class="adv">L’antenne est vive et éphémère — les messages passent puis s’estompent.</span>', ch); return; }
  });
  document.addEventListener('mouseout', function(e){ if(e.target.closest&&(e.target.closest('.file li')||e.target.closest('.attente li')||e.target.closest('#chat > *'))) hide(); });
})();
