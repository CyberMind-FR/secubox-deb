/* SPDX-License-Identifier: LicenseRef-CMSD-1.0 · Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
 SbxPouls (#3945) : une mesure est fixe au présent et bat ; elle recule sur ses dernières mesures RÉELLES, rebondit, revient.
 carte(svg,o) · compteur(el,o) · barres(svg,o) · orchestre(liste) · bouton(hôte,classe) · memoire(clé,instantané,pas).
 Options : README de secubox-hub. CSP stricte : ni style ni HTML injectés. Moins de deux mesures : rien ne bouge. */
(function(w,d){'use strict';
var A={},NS='http://www.w3.org/2000/svg',PASSE='var(--sbxp-passe,#ff9f1c)',DIRECT='var(--sbxp-direct,#39ff9c)';
/* Fonctions pures. Une valeur aberrante est « non mesurée » (null), jamais un zéro. */
function nombre(v){return typeof v==='number'&&v>=0&&v<=1e12?v:null}
function borne(v,n){return Math.max(0,Math.min(n-1,v))}
function instants(l){var v=[],vus={};
 (Array.isArray(l)?l:[]).forEach(s=>{if(!s||typeof s!=='object')return;
  var t=Math.floor(nombre(s.t!=null?s.t:s.genere_le)||0),m=null,k=0;if(!t||t>1e11||vus[t])return;
  if(Array.isArray(s.pays)){m={};s.pays.forEach(p=>{var n=p&&typeof p.code==='string'&&/^[A-Z]{2}$/.test(p.code)?nombre(p.n):null;if(n!=null&&k<60){m[p.code]=n;k++}})}
  vus[t]=1;v.push({t:t,m:m})});
 return v.sort((a,b)=>a.t-b.t).slice(-13)}
function serie(v,l){v=Array.isArray(v)?v:[];var x=v.slice(-400),z=v.length-x.length;
 return{v:x.map(nombre),l:x.map((_,i)=>{var t=typeof l==='function'?l(i+z):l&&l[i+z];return typeof t==='string'?t.slice(0,40):''})}}
function melange(a,b,t){return a==null||b==null?(t<.5?a:b):a+(b-a)*t}
function doux(t){return t<.5?2*t*t:1-Math.pow(2-2*t,2)/2}
/* Position (0 = le plus ancien, n-1 = le présent) à ms du départ : recul, rebond, retour, balancement ; null = fini. */
function trajet(ms,n){if(n<2||!(ms>=0))return null;
 var f=n-1,a=Math.min(12e3,Math.max(260,Math.min(700,2600/n))*f),b=a+380,c=b+a*.55,u=(ms-c)/700;
 return ms<a?{p:f*(1-doux(ms/a))}:ms<b?{p:.22*Math.sin(Math.PI*(ms-a)/380)}:ms<c?{p:f*doux((ms-b)/(c-b))}:u<1?{p:f-.32*Math.sin(u*9.4)*Math.pow(1-u,2.2),direct:true}:null}
function ecart(t,ref){var m=Math.round((ref-t)/60);return m<1?'à l’instant':m<60?'il y a '+m+' min':m<1440?'il y a '+Math.floor(m/60)+' h '+String(m%60).padStart(2,'0'):'le '+new Date(t*1e3).toLocaleString('fr-FR',{day:'numeric',month:'short',hour:'2-digit',minute:'2-digit'})}
/* Retards d'image (ms) : machine trop lente si la moyenne de 24 dépasse 25, ou 3 des 10 dernières 50. */
function lent(r){var z=r.slice(-24);return z.length>23&&z.reduce((a,b)=>a+b,0)/24>25||r.slice(-10).filter(x=>x>50).length>2}
A.pur={nombre,instants,serie,melange,trajet,ecart,lent};
if(typeof module==='object'&&module.exports)module.exports=A;
if(!d)return;
w.SbxPouls=A;
/* Un seul minuteur, arrêté dès que rien ne se voit ; une seule mesure recule à la fois. */
var M=new Map(),ordre=null,actif=null,tour=0,prochain=performance.now()+1500,minuteur=0,image=0,uid=0,boutons=[],choix=true,auto=false,libre=false,prevu=0,ignore=2,R=[],longues=[];
function media(q){return w.matchMedia?w.matchMedia(q):{}}
var calme=media('(prefers-reduced-motion:reduce)'),souris=media('(hover:hover)');
function garde(s,k,v){try{if(v)w[s].setItem(k,v);return w[s].getItem(k)}catch(e){return null}}
(()=>{var l=garde('localStorage','sbx-pouls'),s=garde('sessionStorage','sbx-pouls-auto'),nv=w.navigator;choix=l!=='fixe';libre=s==='non';
 auto=s==='fixe'||!libre&&l!=='vivant'&&(nv.hardwareConcurrency<=2||nv.deviceMemory<=2||/[?&]kiosk=1(&|$)/.test(location.search))})();
function marche(){return choix&&!auto&&!calme.matches}
/* Repli automatique : pour cette session, sans toucher au choix retenu. */
function repli(){if(!libre&&!auto){auto=true;garde('sessionStorage','sbx-pouls-auto','fixe');tout()}}
function retard(x){if(x>1e3)ignore=2;else if(ignore)ignore--;else{R.push(x);if(R.length>24)R.shift();if(lent(R))repli()}}
try{new PerformanceObserver(l=>{l.getEntries().forEach(e=>{if(e.startTime>5e3&&vif()&&M.size)longues.push(e.startTime)});longues=longues.filter(t=>t>performance.now()-1e4);if(longues.length>2)repli()}).observe({type:'longtask'})}catch(e){/* absent */}
var oeil=w.IntersectionObserver?new IntersectionObserver(l=>{l.forEach(x=>{M.forEach(m=>{if(m.zone===x.target)m.vu=x.isIntersecting})});reveille()}):null;
function vif(){return marche()&&!d.hidden}
function anime(m){return m.n>1&&m.vu&&m.hote.isConnected}
function survol(m){return souris.matches&&m.zone.matches(':hover')}
function focus(m){var a=d.activeElement;return!!a&&a!==d.body&&m.zone.contains(a)&&a.matches(':focus-visible')}
function liste(){return ordre||Array.from(M.values())}
function reveille(){if(!minuteur&&!image&&vif()&&liste().some(anime)){prevu=performance.now()+(actif?66:180);minuteur=setTimeout(()=>{minuteur=0;image=requestAnimationFrame(tic)},actif?66:180)}}
function tic(t){image=0;if(!vif())return;
 retard(performance.now()-prevu);if(!vif())return;
 var x=t%1700/1700,b=Math.min(1,Math.exp(-Math.pow((x-.12)/.09,2))+.6*Math.exp(-Math.pow((x-.42)/.09,2))),L=liste(),q=actif?1:2,i,m;
 if(actif)avance(actif,t);
 for(i=0;i<L.length;i++){m=L[(tour+i)%L.length];if(m!==actif){if(q&&anime(m)&&!survol(m)&&!focus(m)){q--;m.bt=1;m.bat(b,t)}else if(m.bt){m.bt=0;m.calme()}}}
 if(!actif&&t>=prochain)for(i=0;i<L.length&&!actif;i++){m=L[tour++%L.length];if(anime(m)&&!survol(m)&&!focus(m)){actif=m;m.k=m.av=0;m.dir=false;m.calme()}}
 reveille()}
function avance(m,t){var dt=m.av?Math.min(100,t-m.av):0,r;m.av=t;
 if(!anime(m)||focus(m))return fini(m);
 if(survol(m)){if(!m.gel){m.gel=t;fixer(m)}else if(t-m.gel>8e3)fini(m);return}   // une mesure réelle, datée
 if(m.gel){m.gel=0;m.fige(-1)}
 r=trajet(m.k+=dt,m.n);if(!r)return fini(m);
 m.p=r.p;m.va(r.p,m.dir=!!r.direct)}
function fixer(m){m.p=borne(Math.round(m.p),m.n);m.va(m.p,m.dir=m.p===m.n-1);m.fige(m.p)}
function fini(m){if(actif===m){actif=null;prochain=performance.now()+2400}m.fige(-1);m.repos()}
function tout(){if(!vif()){if(actif)fini(actif);M.forEach(m=>{m.repos()})}
 boutons=boutons.filter(b=>{txt(b,auto?'⏸ fixe (auto)':choix?'💓 vivant':'⏸ fixe');b.setAttribute('aria-pressed',choix&&!auto);return b.isConnected});reveille();w.dispatchEvent(new Event('sbx-pouls'))}
d.addEventListener('visibilitychange',()=>{ignore=2;tout()});
if(calme.addEventListener)calme.addEventListener('change',tout);
w.addEventListener('storage',e=>{if(e.key==='sbx-pouls'){choix=e.newValue!=='fixe';tout()}});
function rien(){}
/* Une clé = une mesure : sa position survit aux éléments refaits par la page ; perdue plus d'une minute, elle est ôtée. */
function prendre(genre,hote,o){var cle=genre+':'+(o.cle||hote.id),m=M.get(cle),z=o.zone||hote,t=performance.now();
 M.forEach((x,k)=>{if(x.hote.isConnected)x.perdu=0;else if(x!==m&&t-(x.perdu=x.perdu||t)>6e4)oter(k,x)});
 if(!m){m={n:0,p:0,vu:!oeil,id:++uid,o:o,fige:rien,calme:rien,maj:p=>A[genre](m.hote,Object.assign({},m.o,p)),fin:()=>{oter(cle,m)},repos:()=>{m.p=m.n-1;m.gel=0;m.calme();m.va(m.p,true)}};M.set(cle,m)}
 if(m.o.sujet!==o.sujet&&actif===m)fini(m);
 m.hote=hote;m.o=o;
 if(z!==m.zone){var y=m.zone;M.forEach(x=>{if(x.zone===z)m.vu=x.vu});m.zone=z;if(oeil){lache(y);oeil.observe(z)}}
 return m}
function lache(z){if(z&&!Array.from(M.values()).some(x=>x.zone===z))oeil.unobserve(z)}
function oter(cle,m){if(actif===m)actif=null;M.delete(cle);if(oeil)lache(m.zone);if(ordre)ordre=ordre.filter(x=>x!==m)}
function pose(m){if(m.n<2&&m.puce)m.puce.remove();if(actif===m&&m.n>1&&vif()){if(m.gel)fixer(m);else m.va(m.p=borne(m.p,m.n),m.dir)}else m.repos();reveille();return m}
function f(v){return Math.round(v).toLocaleString('fr-FR')}
function dis(o,v){return v==null?'—':(o.format||f)(v)}
function att(n,a){for(var k in a){var v=String(a[k]);if(n.getAttribute(k)!==v)n.setAttribute(k,v)}return n}
function sv(t,a,p){var e=att(d.createElementNS(NS,t),a);if(p)p.appendChild(e);return e}
function sty(e,s){for(var k in s)if(e.style[k]!==s[k])e.style[k]=s[k];return e}
function txt(e,t){if(e.textContent!==t)e.textContent=t}
function date(m,t,direct){var h=m.o.quand,e=m.puce,c=direct?DIRECT:PASSE;if(!h)return;
 if(!e){e=m.puce=d.createElement('span');att(e,{'aria-hidden':true,'data-sbxp':'quand',title:'Recul sur les dernières mesures réelles'+(m.cer?' ; l’anneau montre l’écart au présent, agrandi pour être vu.':'.')});
  sty(e,{font:'600 .85rem ui-monospace,Menlo,Consolas,monospace',whiteSpace:'nowrap',flex:'none'});
  if(m.cer)sty(e,{border:'1px solid',borderRadius:'999px',padding:'2px 10px',minWidth:'11.5em',textAlign:'center'})}
 if(e.parentNode!==h){h.appendChild(e);h.style.flexWrap='wrap'}
 txt(e,(direct?'● ':'◀ ')+t);sty(e,{color:c});if(m.cer&&m.cd!==c){m.cd=c;e.style.boxShadow='0 0 12px color-mix(in srgb,'+c+' 45%,transparent)'}}
A.carte=(svg,o)=>{o=o||{};
 var m=prendre('carte',svg,o),ech=nombre(o.echelle)||1,coul=String(o.coul||'#ff2d6f'),S=instants(o.instantanes),n=m.n=S.length,der=n&&S[n-1].m||{},max=1,pic={},codes,sign;
 S.forEach(s=>{for(var c in s.m){pic[c]=Math.max(pic[c]||0,s.m[c]);max=Math.max(max,s.m[c])}});
 function place(c){var z=o.centres,p=typeof z==='function'?z(c):z&&Object.prototype.hasOwnProperty.call(z,c)?[(z[c][1]+180)/3,(90-z[c][0])/3]:null;return p&&isFinite(p[0])&&isFinite(p[1])?p:null}
 function val(i,c){var x=S[i].m;return x&&x[c]!=null?x[c]:null}
 codes=Object.keys(pic).filter(place).sort((a,b)=>pic[b]-pic[a]).slice(0,40);
 sign=[coul,ech,codes].join();
 if(m.sign!==sign){if(m.g){m.g.remove();m.h.remove()}m.sign=sign;m.cer={};
  function calque(nom){return sty(sv('svg',{'data-sbxp':nom,'aria-hidden':true}),{position:'absolute',inset:'0',width:'100%',height:'100%',margin:'0',background:'none',pointerEvents:'none',willChange:'opacity'})}
  m.g=calque('carte');m.h=calque('battement');m.hb=sv('g',{},m.h);m.hal=sv('g',{},m.g);
  var gr=sv('radialGradient',{id:'sbxp'+m.id},sv('defs',{},m.g));
  [[0,.95],[.35,.38],[1,0]].forEach(x=>{sty(sv('stop',{offset:x[0],'stop-opacity':x[1]},gr),{stopColor:coul})});
  codes.forEach((c,i)=>{var p=place(c),z=m.cer[c]={r:0};
   function rond(ep,fond,g){return sty(sv('circle',{cx:p[0].toFixed(2),cy:p[1].toFixed(2),r:0,'stroke-width':ep*ech},g||m.g),{fill:fond||'none',stroke:ep?coul:'none'})}
   if(i<6)z.halo=[m.hal,m.hb].map(g=>{var h=att(rond(0,0,g),{fill:'url(#sbxp'+m.id+')'});h.style.fill='';return h}).concat(rond(.22,0,m.hb));
   z.ans=[att(rond(1.3),{'stroke-opacity':.28}),rond(.38)];z.coeur=att(rond(.5,'#fff'),{'fill-opacity':.92})})}
 var cadre=svg.parentNode;   // calque à part : le fond n'est jamais redessiné
 if(cadre.getAttribute('data-sbxp')!=='cadre'){cadre=sty(att(d.createElement('div'),{'data-sbxp':'cadre'}),{position:'relative',minWidth:'0'});svg.parentNode.insertBefore(cadre,svg);cadre.appendChild(svg)}
 [m.h,m.g].forEach(e=>{att(e,{viewBox:svg.getAttribute('viewBox')||'0 0 120 60'});if(e.parentNode!==cadre)cadre.appendChild(e)});
 m.va=(p,direct)=>{if(!n)return;sty(m.hal,{opacity:direct?'0.8':'0'});
  var q=borne(p,n),i=Math.floor(q),j=Math.min(n-1,i+1),k=Math.round(q),c,z,v,a,r,e,L=o.liste||{};
  function lu(x){return melange(val(i,x),val(j,x),q-i)}
  for(c in m.cer){z=m.cer[c];v=lu(c);a=der[c];r=z.r=v?ech*(.7+2.5*Math.sqrt(v/max)):0;e=v==null||!a?0:Math.abs(v-a)/a;
   if(direct&&z.halo)[2.9,4.6,2.1].forEach((y,u)=>{att(z.halo[u],{r:(r*y).toFixed(2)})});att(z.coeur,{r:(r*.55).toFixed(2),opacity:o.coeur===false&&direct?0:1});
   z.ans.forEach(x=>{att(x,{r:(r+ech*Math.min(3.2,e*14)).toFixed(2),opacity:direct?0:Math.min(1,e*11).toFixed(2)})})}
  for(c in L)if(!direct||L[c].sbxp){v=direct?der[c]:lu(c);a=v==null||der[c]==null?0:Math.round(v-der[c]);txt(L[c],dis(o,v==null?v:Math.round(v)));L[c].sbxp=!direct;if(o.ecarts&&o.ecarts[c])sty(o.ecarts[c],{color:a>0?PASSE:'var(--sbxp-baisse,#29b6f6)'}),txt(o.ecarts[c],a&&!direct?(a>0?'▲ +':'▼ ')+f(a):'')}
  if(o.fond)sty(o.fond,{opacity:direct?'':'0.18'});
  if(n>1)date(m,direct?o.maintenant||'maintenant':(o.dit||String)(ecart(S[k].t,S[n-1].t))+(S[k].m?'':' : non mesuré'),direct)};
 m.bat=b=>{sty(m.h,{opacity:(.9*b).toFixed(1)})};
 m.calme=()=>{sty(m.h,{opacity:'0'})};
 m.fige=k=>{for(var c in m.cer){var e=m.cer[c].coeur,v=k>=0&&k<n-1?val(k,c):null,t=v==null?'':c+' : '+f(v)+' · '+(o.dit||String)(ecart(S[k].t,S[n-1].t));
  e.textContent='';e.style.pointerEvents=t?'auto':'';if(t){sv('title',{},e).textContent=t;e.setAttribute('data-b',t)}else e.removeAttribute('data-b')}};
 return pose(m)};
function dessiner(m,svg,s,coul){var vb=(svg.getAttribute('viewBox')||'').split(/[ ,]+/).map(Number),W=vb[2]||520,bas=(vb[3]||190)-2,N=s.v.length,pas=W/(N||1),mx=Math.max.apply(null,s.v.concat([1])),sign=[N,W,bas,coul].join();
 if(m.ds!==sign||m.dg.parentNode!==svg){if(m.dg)m.dg.remove();m.ds=sign;m.dg=sv('g',{'data-sbxp':'barres','aria-hidden':true},svg);m.F=[];m.B=[];svg.style.overflow='visible';
  s.v.forEach((_,i)=>{[[m.F,'rgba(159,179,214,.16)'],[m.B,coul]].forEach(x=>{x[0].push(sty(sv('rect',{x:(i*pas).toFixed(2),width:Math.max(1,pas-2).toFixed(2),rx:1.5},m.dg),{fill:x[1]}))})})}
 function haut(e,v,u){var h=(v==null?4:(bas-2)*v/mx)*u;att(e,{y:(bas-h).toFixed(1),height:h.toFixed(1)})}
 s.v.forEach((v,i)=>{haut(m.F[i],v,1)});
 m.trace=p=>{s.v.forEach((v,i)=>{haut(m.B[i],v,Math.max(0,Math.min(1,p-i+1)))})};
 return m.B}
function suite(m,o,svg){var s=m.s=serie(o.valeurs,o.libelles),coul=String(o.coul||'#19f0ff'),N=s.v.length;
 m.n=s.v.filter(v=>v!=null).length>1?N:0;m.trace=rien;m.k0=-1;
 var B=o.barres?Array.from(o.barres).slice(-N||1e9):svg?dessiner(m,svg,s,coul):[];
 m.dit=(k,valeur)=>s.l[k]+(valeur?' : '+(s.v[k]==null?'non mesuré':dis(o,s.v[k])):'');
 m.teint=(p,direct)=>{var k=m.k0=Math.round(p);m.trace(p);
  var on=m.n&&marche();B.forEach((e,i)=>{if(e)sty(e,{opacity:on?String(i>p+.5?.15:i===k?1:.65):'',filter:on&&i===k?'drop-shadow(0 0 6px '+(direct?coul:PASSE)+')':''})})};
 m.bat=(b,t)=>{if(B[m.k0])sty(B[m.k0],{opacity:(.6+.4*b).toFixed(1)});if(m.cs)sty(m.cs,{opacity:t%1100<550?'1':'0.12'})};
 m.calme=()=>{if(marche()&&m.n&&B[m.k0])sty(B[m.k0],{opacity:'1'});if(m.cs)sty(m.cs,{opacity:'1'})};
 m.repos=()=>{m.p=N-1;m.gel=0;m.calme();if(N)m.va(m.p,true)}}
A.barres=(svg,o)=>{o=o||{};var m=prendre('barres',svg,o);suite(m,o,svg);
 m.va=(p,direct)=>{p=borne(p,m.s.v.length);m.teint(p,direct);if(m.n)date(m,direct?o.maintenant||'maintenant':m.dit(Math.round(p),1),direct)};
 return pose(m)};
A.compteur=(el,o)=>{o=o||{};var m=prendre('compteur',el,o),s;suite(m,o,o.svg);s=m.s;
 if(!m.cs){m.tn=d.createTextNode('');m.ch=sty(sv('svg',{viewBox:'0 0 10 14','aria-hidden':true}),{display:'inline-block',width:'.5em',height:'.7em',marginRight:'.25em',verticalAlign:'baseline'});
  sv('path',{d:'M1.5 2.5 8 7l-6.5 4.5',fill:'none',stroke:'currentColor','stroke-width':2},m.ch);
  m.cs=sty(att(d.createElement('i'),{'aria-hidden':true}),{display:'inline-block',width:'.5em',height:'.85em',margin:'0 -.68em 0 .18em',borderRadius:'2px',verticalAlign:'-.08em'})}
 if(m.n&&m.cs.parentNode!==el){m.texte=el.textContent/* le présent */;el.textContent='';el.style.whiteSpace='nowrap';[m.ch,m.tn,m.cs].forEach(e=>{el.appendChild(e)});m.ch.style.display=m.texte.length>8?'none':'inline-block'}
 m.va=(p,direct)=>{var N=s.v.length;p=borne(p,N);m.teint(p,direct);if(!m.n)return;
  var i=Math.floor(p),k=Math.round(p),c=direct?DIRECT:PASSE,F=v=>dis(o,v),der=s.v[N-1]==null?m.texte:F(s.v[N-1]),t=o.total?m.texte:direct?der:F(melange(s.v[i],s.v[Math.min(N-1,i+1)],p-i));
  if(m.tn.nodeValue!==t)m.tn.nodeValue=t;
  if(m.cd!==c){m.cd=c;sty(m.cs,{background:c,boxShadow:'0 0 6px '+c+',0 0 16px '+c})}
  if(direct||o.total){el.removeAttribute('role');el.removeAttribute('aria-label')}else att(el,{role:'img','aria-label':der});
  el.style.textShadow='0 0 14px color-mix(in srgb,'+(direct?o.coul||'#19f0ff':PASSE)+' 55%,transparent)';
  date(m,direct?o.maintenant||'maintenant':m.dit(k,o.total||s.v[k]==null),direct)};
 return pose(m)};
A.vivant=marche;
A.orchestre=l=>{ordre=Array.isArray(l)?l.filter(m=>m&&m.va):null;reveille();return{rejoue:()=>{prochain=0;reveille()}}};
A.bouton=(hote,classe)=>{if(!hote)return null;var b=hote.querySelector('[data-sbxp="vie"]');
 if(!b){b=sty(att(d.createElement('button'),{type:'button','data-sbxp':'vie','class':classe||'',title:'Graphiques : recul sur les dernières mesures réelles, ou figés au présent.'}),{minHeight:'40px',whiteSpace:'nowrap'});
  b.addEventListener('click',()=>{if(auto)auto=false;else garde('localStorage','sbx-pouls',(choix=!choix)?'vivant':'fixe');if(choix){libre=true;garde('sessionStorage','sbx-pouls-auto','non')}tout()});
  hote.appendChild(b);boutons.push(b)}
 tout();return b};
A.memoire=(cle,inst,pas)=>{var K='sbx-pouls:'+cle,l=[],x=instants([inst])[0];
 function rend(s){return{t:s.t,pays:s.m&&Object.keys(s.m).map(c=>({code:c,n:s.m[c]}))}}
 try{l=instants(JSON.parse(sessionStorage.getItem(K)||'[]'))}catch(e){/* illisible */}
 if(x){l=l.filter(s=>s.t<x.t&&s.t>x.t-10800);
  var garde=!l.length||x.t-l[l.length-1].t>=(pas||60);l.push(x);
  if(garde)try{sessionStorage.setItem(K,JSON.stringify(l.slice(-12).map(rend)))}catch(e){/* refusé */}}
 return l.map(rend)};
})(typeof window==='undefined'?{}:window,typeof document==='undefined'?null:document);
