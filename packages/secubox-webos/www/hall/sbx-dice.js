/* SPDX-License-Identifier: LicenseRef-CMSD-1.0
   Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
   Source-Disclosed License — All rights reserved except as expressly granted.
   See LICENCE-CMSD-1.0.md for terms.

   <sbx-dice size="36" speed="4" fov="40"> — le dé SecuBox (moteur de « SecuBox Dice 3D », 3d.<domaine>) :
   canvas 2D sans bibliothèque, matrices 3×3, projection perspective, quads texturés par clip + transform,
   éclairage Lambert. Six textures /dice/face-N.jpg partagées entre instances ; cube uni tant qu'elles
   chargent. Pause quand l'onglet est caché ou l'élément hors écran ; sous prefers-reduced-motion il tourne
   à QUART de vitesse (data-etat="calme") au lieu de se figer — c'est un logo de 36 px, et une préférence
   système posée sur un poste de bureau le laissait immobile sans que l'on sache pourquoi ; localStorage
   sbx_de="fige" le fige sur la face SecuBox (data-etat="fige") ; 30 i/s si le dessin dépasse 8 ms en
   moyenne sur 60 images. */
(function(){
  'use strict';
  var CORNERS=[[-1,-1,-1],[1,-1,-1],[-1,1,-1],[1,1,-1],[-1,-1,1],[1,-1,1],[-1,1,1],[1,1,1]];
  var UV=[[0,0],[1,0],[1,1],[0,1]];
  var FACES=[{v:[3,7,5,1],n:[1,0,0],fi:2},{v:[6,2,0,4],n:[-1,0,0],fi:4},{v:[2,3,7,6],n:[0,1,0],fi:1},
             {v:[1,0,4,5],n:[0,-1,0],fi:3},{v:[6,7,5,4],n:[0,0,1],fi:5},{v:[3,2,0,1],n:[0,0,-1],fi:0}];
  var LV=[0.5,0.8,-0.6], LL=Math.sqrt(LV[0]*LV[0]+LV[1]*LV[1]+LV[2]*LV[2]);
  var SPEEDS=[0.00031,0.00047,0.00019], UNI='#2563EB', ARETE='rgba(96,165,250,.35)', IS=320, R3=Math.sqrt(3);

  var IMGS=null, pretes=0, attente=[];
  function textures(cb){
    if(pretes===6) return cb();
    attente.push(cb);
    if(IMGS) return;
    IMGS=[];
    for(var i=0;i<6;i++){ (function(i){ var im=new Image(); im.onload=function(){ if(++pretes===6){ attente.splice(0).forEach(function(f){ f(); }); } }; im.src='/dice/face-'+i+'.jpg'; IMGS[i]=im; })(i); }
  }

  function Rx(a){var c=Math.cos(a),s=Math.sin(a);return[[1,0,0],[0,c,-s],[0,s,c]];}
  function Ry(a){var c=Math.cos(a),s=Math.sin(a);return[[c,0,s],[0,1,0],[-s,0,c]];}
  function Rz(a){var c=Math.cos(a),s=Math.sin(a);return[[c,-s,0],[s,c,0],[0,0,1]];}
  function mM(A,B){var r=[[0,0,0],[0,0,0],[0,0,0]];for(var i=0;i<3;i++)for(var j=0;j<3;j++)for(var k=0;k<3;k++)r[i][j]+=A[i][k]*B[k][j];return r;}
  function mV(M,v){return[M[0][0]*v[0]+M[0][1]*v[1]+M[0][2]*v[2],M[1][0]*v[0]+M[1][1]*v[1]+M[1][2]*v[2],M[2][0]*v[0]+M[2][1]*v[1]+M[2][2]*v[2]];}
  function dot3(a,b){return a[0]*b[0]+a[1]*b[1]+a[2]*b[2];}
  function proj(p,dist,f,c){var z=p[2]+dist;if(z<1)z=1;return[c+p[0]*f/z,c+p[1]*f/z];}

  function triTex(ctx,img,p0,p1,p2,t0,t1,t2,alpha){
    var x0=t0[0],y0=t0[1],x1=t1[0],y1=t1[1],x2=t2[0],y2=t2[1],u0=p0[0],v0=p0[1],u1=p1[0],v1=p1[1],u2=p2[0],v2=p2[1];
    var det=x0*(y1-y2)-y0*(x1-x2)+(x1*y2-x2*y1); if(Math.abs(det)<0.5)return;
    var a=(u0*(y1-y2)-u1*(y0-y2)+u2*(y0-y1))/det, b=(v0*(y1-y2)-v1*(y0-y2)+v2*(y0-y1))/det;
    var c=(-u0*(x1-x2)+u1*(x0-x2)-u2*(x0-x1))/det, d=(-v0*(x1-x2)+v1*(x0-x2)-v2*(x0-x1))/det;
    ctx.save(); ctx.beginPath(); ctx.moveTo(p0[0],p0[1]); ctx.lineTo(p1[0],p1[1]); ctx.lineTo(p2[0],p2[1]); ctx.closePath(); ctx.clip();
    ctx.transform(a,b,c,d,u0-a*x0-c*y0,v0-b*x0-d*y0); ctx.globalAlpha=alpha; ctx.drawImage(img,0,0,IS,IS); ctx.restore();
  }
  function quadTex(ctx,img,q,alpha){
    var pc=[(q[0][0]+q[1][0]+q[2][0]+q[3][0])*0.25,(q[0][1]+q[1][1]+q[2][1]+q[3][1])*0.25], uc=[IS*0.5,IS*0.5];
    var ts=UV.map(function(u){return[u[0]*IS,u[1]*IS];});
    for(var i=0;i<4;i++){ var j=(i+1)&3; triTex(ctx,img,q[i],q[j],pc,ts[i],ts[j],uc,alpha); }
  }

  var ACTIF=null;
  function reduit(){ if(!ACTIF) ACTIF=matchMedia('(prefers-reduced-motion: reduce)'); return ACTIF; }
  function fige(){ try{ return localStorage.getItem('sbx_de')==='fige'; }catch(e){ return false; } }

  function SbxDice(){ var e=Reflect.construct(HTMLElement,[],SbxDice); e._init(); return e; }
  SbxDice.prototype=Object.create(HTMLElement.prototype,{constructor:{value:SbxDice}});
  Object.setPrototypeOf(SbxDice,HTMLElement);
  SbxDice.observedAttributes=['size','speed','fov','paused'];
  var P=SbxDice.prototype;

  P._init=function(){
    this._cv=document.createElement('canvas'); this._cv.setAttribute('aria-hidden','true');
    this._ax=0.4; this._ay=0.7; this._az=0.2; this._raf=0; this._dernier=0; this._visible=true; this._couts=[]; this._lent=false; this._n=0;
    this._boucle=this._boucle.bind(this); this._relance=this._relance.bind(this);
  };
  P.connectedCallback=function(){
    if(!this._cv.parentNode) this.appendChild(this._cv);
    this.style.display='inline-block'; this.style.lineHeight='0';
    this._taille();
    var mq=reduit(); if(mq.addEventListener) mq.addEventListener('change',this._relance); else mq.addListener(this._relance);
    document.addEventListener('visibilitychange',this._relance);
    var self=this;
    if('IntersectionObserver' in window){ this._io=new IntersectionObserver(function(e){ self._visible=e[0].isIntersecting; self._relance(); }); this._io.observe(this); }
    textures(function(){ self._dessine(); self._relance(); });
    this._dessine(); this._relance();
  };
  P.disconnectedCallback=function(){
    if(this._raf){ cancelAnimationFrame(this._raf); this._raf=0; }
    var mq=reduit(); if(mq.removeEventListener) mq.removeEventListener('change',this._relance); else mq.removeListener(this._relance);
    document.removeEventListener('visibilitychange',this._relance);
    if(this._io){ this._io.disconnect(); this._io=null; }
  };
  P.attributeChangedCallback=function(){ if(this.isConnected){ this._taille(); this._dessine(); this._relance(); } };
  function attr(e,n,d){ var v=parseFloat(e.getAttribute(n)); return isFinite(v)&&v>0?v:d; }
  P._taille=function(){ var s=attr(this,'size',36), r=Math.min(window.devicePixelRatio||1,2); this._cv.width=this._cv.height=Math.round(s*r); this._cv.style.width=this._cv.style.height=s+'px'; };
  P._actif=function(){ return this.isConnected&&!fige()&&!document.hidden&&this._visible&&!this.hasAttribute('paused'); };
  P._relance=function(){
    if(this._actif()){ if(reduit().matches) this.setAttribute('data-etat','calme'); else this.removeAttribute('data-etat'); if(!this._raf){ this._dernier=0; this._raf=requestAnimationFrame(this._boucle); } return; }
    if(this._raf){ cancelAnimationFrame(this._raf); this._raf=0; }
    if(fige()){ this._ax=0; this._ay=0; this._az=0; this.setAttribute('data-etat','fige'); this._dessine(); }
    else this.setAttribute('data-etat','pause');
  };
  P._boucle=function(t){
    this._raf=requestAnimationFrame(this._boucle);
    var dt=this._dernier?Math.min(t-this._dernier,100):16; this._dernier=t;
    var sp=attr(this,'speed',4)*(reduit().matches?0.25:1); this._ax+=SPEEDS[0]*dt*sp; this._ay+=SPEEDS[1]*dt*sp; this._az+=SPEEDS[2]*dt*sp;
    if(this._lent&&(this._n++&1)) return;
    var d0=performance.now(); this._dessine(); this._couts.push(performance.now()-d0);
    if(this._couts.length>=60){ var m=0; for(var i=0;i<60;i++) m+=this._couts[i]; m/=60; this._couts.length=0; this._lent=m>8; this.setAttribute('data-raf-ms',m.toFixed(2)); }
  };
  P.mesure=function(){ return parseFloat(this.getAttribute('data-raf-ms'))||0; };
  P._dessine=function(){
    var cv=this._cv, ctx=cv.getContext('2d'), W=cv.width; if(!ctx||!W) return;
    ctx.clearRect(0,0,W,W);
    var S=W*0.5, fov=attr(this,'fov',40)*Math.PI/180, f=S/Math.tan(fov*0.5), c=S;
    var dist=f*S*R3/(W*0.46)+S*R3;                         /* le coin le plus proche tient dans 92 % du canvas */
    var M=mM(Rz(this._az),mM(Ry(this._ay),Rx(this._ax)));
    var c3=CORNERS.map(function(u){return mV(M,[u[0]*S,u[1]*S,u[2]*S]);});
    var c2=c3.map(function(p){return proj(p,dist,f,c);});
    var vis=[];
    FACES.forEach(function(face){
      var nw=mV(M,face.n); if(nw[2]>=0) return;
      var cz=0; face.v.forEach(function(i){cz+=c3[i][2];});
      var d=dot3(nw,LV)/LL, br=Math.max(0.2,Math.min(1,0.28+0.72*Math.max(0,d)));
      vis.push({face:face,cz:cz/4,br:br});
    });
    vis.sort(function(a,b){return b.cz-a.cz;});
    var tex=pretes===6;
    vis.forEach(function(it){
      var q=it.face.v.map(function(i){return c2[i];});
      ctx.beginPath(); ctx.moveTo(q[0][0],q[0][1]); for(var i=1;i<4;i++) ctx.lineTo(q[i][0],q[i][1]); ctx.closePath();
      if(tex) quadTex(ctx,IMGS[it.face.fi],q,it.br);
      else { ctx.globalAlpha=it.br; ctx.fillStyle=UNI; ctx.fill(); ctx.globalAlpha=1; }
      ctx.strokeStyle=ARETE; ctx.lineWidth=Math.max(1,W/160); ctx.stroke();
    });
  };
  if(!customElements.get('sbx-dice')) customElements.define('sbx-dice',SbxDice);
})();
